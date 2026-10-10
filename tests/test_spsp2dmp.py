# Copyright (c) 2026 devnoname120
# SPDX-License-Identifier: MIT

import builtins
import gzip
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from psp2_core_parse.cli import main
from psp2_core_parse.core import CoreDump, ParseError
from test_core import make_core


# Format/key reference: Princess-of-Sleeping/spsp2dmp-parser, MIT (see LICENSE).
CONTAINER_KEY = bytes.fromhex("c815c36ff2f89564a2f7ae13cb6d47ac")
CONTAINER_IV = bytes(range(16))


def encrypt(data, key=CONTAINER_KEY, iv=CONTAINER_IV):
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def make_container(image=None, *, payload=None, header_size=0x130, reverse=False,
                   padded_length=False):
    if payload is None:
        payload = gzip.compress(make_core() if image is None else image, mtime=0)
    logical_size = len(payload)
    payload += b"\0" * (-len(payload) % 16)
    auxiliary = b"synthetic auxiliary data".ljust(0x60, b"\0")
    header = bytearray(header_size)
    struct.pack_into("<8s5Q", header, 0, b"\0\0FACECS", 2, 1, 2,
                     header_size, len(payload) + len(auxiliary))
    sections = [(0, header_size, len(payload) if padded_length else logical_size, 1, 2, CONTAINER_IV, 0),
                (1, header_size + len(payload), len(auxiliary), 1, 2, CONTAINER_IV, 0)]
    if reverse:
        sections.reverse()
    for index, section in enumerate(sections):
        struct.pack_into("<5Q16sQ", header, 0x30 + 0x40 * index, *section)
    return bytes(header) + encrypt(payload) + encrypt(auxiliary)


def write_dump(tmp_path, raw, suffix=".spsp2dmp"):
    path = tmp_path / ("synthetic" + suffix)
    path.write_bytes(raw)
    return path


@pytest.mark.parametrize("suffix", [".spsp2dmp", ".spsp2tmp", ".spspdmp", ".bin"])
def test_encrypted_input_is_detected_by_magic(tmp_path, suffix):
    image = make_core()
    raw = make_container(image)
    core = CoreDump.read(write_dump(tmp_path, raw, suffix), strict=True)
    assert core.image == image
    assert core.complete
    assert core.compressed
    assert core.note("TEST").description == b"abcd"
    assert core.read_memory(0x81000000, 6) == b"memory"
    assert core.raw_file_sha256 == hashlib.sha256(raw).hexdigest()
    assert core.image_sha256 == hashlib.sha256(image).hexdigest()
    summary = core.summary()
    assert summary["encrypted"] is True
    assert summary["encryption"]["cipher"] == "AES-128-CBC"
    assert summary["encryption"]["hmac_verified"] is False
    assert summary["encryption"]["section_count"] == 2
    assert any(issue.code == "spsp2dmp-hmac-unverified" for issue in core.issues)


@pytest.mark.parametrize("suffix", [".spsp2dmp", ".bin", ".psp2kerndmp"])
def test_read_dump_routes_encrypted_system_dump_by_magic(tmp_path, capsys, suffix):
    from psp2_core_parse import read_dump

    path = write_dump(tmp_path, make_container(), suffix)
    dump = read_dump(path, strict=True)
    assert isinstance(dump, CoreDump)
    assert dump.image == make_core()
    assert main(["info", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["encrypted"] is True


@pytest.mark.parametrize("reverse", [False, True])
def test_section_ids_and_offsets_are_not_hardcoded(tmp_path, reverse):
    raw = make_container(header_size=0x190, reverse=reverse)
    core = CoreDump.read(write_dump(tmp_path, raw), strict=True)
    assert core.image == make_core()


@pytest.mark.parametrize("extra_bytes", range(16))
@pytest.mark.parametrize("padded_length", [False, True])
def test_logical_section_lengths_and_aes_alignment(tmp_path, extra_bytes, padded_length):
    image = make_core(load=bytes(range(32 + extra_bytes)))
    payload = gzip.compress(image, compresslevel=0, mtime=0)
    raw = make_container(payload=payload, padded_length=padded_length)
    core = CoreDump.read(write_dump(tmp_path, raw), strict=True)
    assert core.image == image
    section = core.encryption["sections"][0]
    assert section["encrypted_size"] == (len(payload) + 15) // 16 * 16
    assert section["available_encrypted_size"] == section["encrypted_size"]


def test_aes_padding_is_not_exposed_as_gzip_trailing_data(tmp_path):
    core = CoreDump.read(write_dump(tmp_path, make_container()), strict=True)
    assert not any(issue.code == "gzip-trailing-data" for issue in core.issues)


@pytest.mark.parametrize("cut", [1, 15, 16, 31])
def test_interrupted_ciphertext_salvages_only_complete_blocks(tmp_path, cut):
    image = make_core(load=b"A" * 0x30000)
    payload = gzip.compress(image, compresslevel=0, mtime=0)
    raw = make_container(payload=payload)
    raw = raw[:-(0x60 + cut)]
    path = write_dump(tmp_path, raw, ".spsp2tmp")
    core = CoreDump.read(path)
    assert not core.complete
    assert not core.compression_complete
    assert core.note("TEST").description == b"abcd"
    assert core.loads[0].data
    assert image.startswith(core.image)
    assert any(issue.code == "spsp2dmp-truncated-section" for issue in core.issues)
    with pytest.raises(ParseError, match="truncated|incomplete|missing"):
        CoreDump.read(path, strict=True)


def test_missing_auxiliary_section_is_not_reported_complete(tmp_path):
    path = write_dump(tmp_path, make_container()[:-0x60])
    core = CoreDump.read(path)
    assert core.image == make_core()
    assert core.compression_complete
    assert not core.complete
    with pytest.raises(ParseError):
        CoreDump.read(path, strict=True)


@pytest.mark.parametrize("length", [8, 0x2f, 0x6f, 0x12f])
def test_truncated_headers_are_rejected(tmp_path, length):
    with pytest.raises(ParseError, match="SPSP2DMP.*header"):
        CoreDump.read(write_dump(tmp_path, make_container()[:length]))


@pytest.mark.parametrize("offset,value,message", [
    (0x08, 99, "version"),
    (0x18, 0, "section"),
    (0x18, 2**64 - 1, "header|section"),
    (0x20, 0x70, "header"),
    (0x38, 0x30, "header|overlap"),
    (0x40, 2**64 - 1, "size|bounds"),
    (0x50, 99, "key"),
    (0x70, 0, "duplicate"),
    (0x78, 0x130, "overlap"),
    (0x30, 2, "section.*0|coredump section"),
])
def test_invalid_metadata_fails_cleanly(tmp_path, offset, value, message):
    raw = bytearray(make_container())
    struct.pack_into("<Q", raw, offset, value)
    with pytest.raises(ParseError, match=message):
        CoreDump.read(write_dump(tmp_path, raw))


def test_non_gzip_decrypted_payload_is_rejected(tmp_path):
    path = write_dump(tmp_path, make_container(payload=b"not a gzip member"))
    with pytest.raises(ParseError, match="gzip"):
        CoreDump.read(path)


def test_encrypted_input_has_actionable_missing_dependency_error(tmp_path, monkeypatch):
    path = write_dump(tmp_path, make_container())
    original_import = builtins.__import__

    def without_crypto(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("synthetic missing optional dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_crypto)
    with pytest.raises(ParseError, match=r"pip install .*\[crypto\]"):
        CoreDump.read(path)


def test_plain_input_remains_usable_without_site_packages(tmp_path):
    path = write_dump(tmp_path, gzip.compress(make_core()), ".psp2dmp")
    result = subprocess.run(
        [sys.executable, "-S", "-m", "psp2_core_parse", "info", str(path), "--json"],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["encrypted"] is False


def test_cli_analyze_and_extract_elf(tmp_path, capsys):
    path = write_dump(tmp_path, make_container())
    assert main(["info", str(path)]) == 0
    text = capsys.readouterr().out
    assert "AES-128-CBC" in text
    assert "HMACs: unverified" in text
    assert main(["analyze", str(path)]) == 0
    assert "AES-128-CBC" in capsys.readouterr().out
    output = tmp_path / "plain.psp2dmp"
    assert main(["extract", str(path), "--elf", "--output", str(output)]) == 0
    assert output.read_bytes() == make_core()
    capsys.readouterr()
    assert main(["extract", str(path), "--elf", "--output", str(output)]) == 2
    assert "exists" in capsys.readouterr().err


@pytest.mark.parametrize("alias", ["same-path", "symlink", "hardlink"])
@pytest.mark.parametrize("option", ["--elf", "--kernel-info"])
def test_forced_extraction_cannot_overwrite_input(tmp_path, capsys, alias, option):
    encrypted, _ = make_kernel_info()
    raw = make_container(make_core(note_name=b"KERNEL_INFO\0", description=encrypted))
    path = write_dump(tmp_path, raw)
    output = path
    if alias != "same-path":
        output = tmp_path / "alias.elf"
        if alias == "symlink":
            output.symlink_to(path)
        else:
            import os

            os.link(path, output)
    assert main(["extract", str(path), option, "--output", str(output), "--force"]) == 2
    assert "input" in capsys.readouterr().err
    assert path.read_bytes() == raw


KERNEL_KEK = bytes.fromhex("845c655b503b54717add4999436b5b5b")
KERNEL_KEY_IV = bytes.fromhex("08090a0c0c0d0e0f0001020304050607")
KERNEL_DATA_IV = bytes.fromhex("0be6477340c4460fdbb9c02db13ce964")


def make_kernel_info(*, key_last=False):
    key = bytes(range(32))
    note = bytearray(struct.pack("<3I", 8, 0x5c, 0) + b"CRYPTO\0\0" + bytes(0x5c))
    note[0x44:0x64] = encrypt(key, KERNEL_KEK, KERNEL_KEY_IV)
    load1 = bytes(range(32))
    load2 = bytes(range(48, 96))
    header = bytearray(52)
    header[:16] = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIIIIIHHHHHH", header, 16, 4, 40, 1, 0, 52, 0, 0, 52, 32, 3, 0, 0, 0)
    offset = 52 + 3 * 32
    headers = [
        struct.pack("<8I", 4, offset, 0, 0, len(note), len(note), 4, 4),
        struct.pack("<8I", 1, offset + len(note), 0x40000000, 0x40000000, len(load1), len(load1), 6, 4),
        struct.pack("<8I", 1, offset + len(note) + len(load1), 0x40010000, 0x40010000, len(load2), len(load2), 6, 4),
    ]
    if key_last:
        headers = headers[1:] + headers[:1]
    prefix = bytes(header) + b"".join(headers) + note
    encrypted = prefix + encrypt(load1, key, KERNEL_DATA_IV) + encrypt(load2, key, KERNEL_DATA_IV)
    plain = prefix + load1 + load2
    return bytes(encrypted), bytes(plain)


@pytest.mark.parametrize("key_last", [False, True])
@pytest.mark.parametrize("versioned", [False, True])
def test_kernel_info_decryption_preserves_full_key_and_resets_segment_iv(key_last, versioned):
    from psp2_core_parse.spsp2dmp import decrypt_kernel_info

    encrypted, plain = make_kernel_info(key_last=key_last)
    description = struct.pack("<I", 1) + encrypted if versioned else encrypted
    assert decrypt_kernel_info(description) == plain


@pytest.mark.parametrize("offset,value,message", [
    (28, 0xffffffff, "program.header"),
    (52, 1, "key|PT_NOTE"),
    (52 + 16, 0x60, "key|PT_NOTE"),
    (52 + 32 + 4, 0, "overlap|header"),
    (52 + 32 + 4, 0xffffffff, "truncated|bounds"),
    (52 + 32 + 16, 31, "align|block"),
    (52 + 64 + 4, 52 + 96 + 0x70, "overlap"),
])
def test_malformed_kernel_info_is_rejected(offset, value, message):
    from psp2_core_parse.spsp2dmp import decrypt_kernel_info

    encrypted, _ = make_kernel_info()
    damaged = bytearray(encrypted)
    struct.pack_into("<I", damaged, offset, value)
    with pytest.raises(ParseError, match=message):
        decrypt_kernel_info(damaged)


@pytest.mark.parametrize("description", [b"", b"invalid", b"\x7fELF", b"\x01\0\0\0\x7fELF"])
def test_incomplete_kernel_elf_header_is_rejected(description):
    from psp2_core_parse.spsp2dmp import decrypt_kernel_info

    with pytest.raises(ParseError, match="KERNEL_INFO.*ELF"):
        decrypt_kernel_info(description)


def test_kernel_extraction_does_not_modify_raw_note_or_outer_elf(tmp_path, capsys):
    encrypted, plain = make_kernel_info()
    description = struct.pack("<I", 1) + encrypted
    image = make_core(note_name=b"KERNEL_INFO\0", description=description)
    path = write_dump(tmp_path, make_container(image))
    core = CoreDump.read(path)
    assert core.image == image
    assert core.note("KERNEL_INFO").description == description
    raw_note = tmp_path / "raw-note.bin"
    output = tmp_path / "kernel.elf"
    assert main(["extract", str(path), "--note", "KERNEL_INFO", "--output", str(raw_note)]) == 0
    assert raw_note.read_bytes() == description
    assert main(["extract", str(path), "--kernel-info", "--output", str(output)]) == 0
    assert output.read_bytes() == plain
    parsed = CoreDump.read(output, strict=True)
    assert parsed.read_memory(0x40000000, 32) == bytes(range(32))
    assert path.read_bytes() == make_container(image)
    capsys.readouterr()


def test_missing_kernel_info_is_a_cli_error(tmp_path, capsys):
    path = write_dump(tmp_path, make_container())
    assert main(["extract", str(path), "--kernel-info", "--output", str(tmp_path / "kernel.elf")]) == 2
    assert "KERNEL_INFO" in capsys.readouterr().err
