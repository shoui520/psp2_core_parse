# Copyright (c) 2026 devnoname120
# SPDX-License-Identifier: MIT

import builtins
import gzip
import hashlib
import hmac
import json
import zlib
import struct
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from psp2_core_parse.cli import main
from psp2_core_parse.core import CoreDump, ParseError
from psp2_core_parse.spsp2dmp import KEY_SETS, OPEN_PSID_IV
from psp2_core_parse.support import decode_system, decode_system2
from test_core import make_core


# Format/key reference: Princess-of-Sleeping/spsp2dmp-parser, MIT (see LICENSE).
CONTAINER_KEY = bytes.fromhex("c815c36ff2f89564a2f7ae13cb6d47ac")
CONTAINER_IV = bytes(range(16))
CIPHER_KEY_IDS = [1, 2, 3, 4, 0x10000001, 0x10000002]


def encrypt(data, key=CONTAINER_KEY, iv=CONTAINER_IV):
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def make_caf(payloads, key_ids, *, type_flag=1, key_set="retail", header_size=None,
             reverse=False, padded_length=False):
    keys = KEY_SETS[key_set]
    header_size = header_size or 0x50 + 0x70 * len(payloads)
    body = b""
    entries = []
    for index, (payload, key_id) in enumerate(zip(payloads, key_ids)):
        padded = payload + b"\0" * (-len(payload) % 16)
        encrypted = encrypt(padded, keys["cipher"][key_id])
        size = len(padded) if padded_length else len(payload)
        digest = hmac.new(keys["hmac"][1], encrypted[:size], hashlib.sha256).digest()
        entries.append((
            struct.pack("<5Q16sQ", index, header_size + len(body), size, 1, key_id, CONTAINER_IV, 0),
            struct.pack("<Q32s8x", index, digest),
        ))
        body += encrypted
    if reverse:
        entries.reverse()
    header = struct.pack("<8s5Q", b"\0\0FACECS", 2, type_flag, len(payloads), header_size, len(body))
    header += b"".join(table for table, _ in entries) + b"".join(digest for _, digest in entries)
    header += hmac.new(keys["hmac"][1], header, hashlib.sha256).digest()
    return header.ljust(header_size, b"\0") + body


def make_container(image=None, *, payload=None, header_size=0x130, reverse=False,
                   padded_length=False, key_id=2, key_set="retail", auxiliary=None):
    if payload is None:
        payload = gzip.compress(make_core() if image is None else image, mtime=0)
    if auxiliary is None:
        auxiliary = b"synthetic auxiliary data".ljust(0x60, b"\0")
    return make_caf([payload, auxiliary], [key_id, key_id], key_set=key_set, header_size=header_size,
                    reverse=reverse, padded_length=padded_length)


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
    assert summary["encryption"]["hmac_verified"] is True
    assert summary["encryption"]["key_set"] == "retail"
    assert summary["encryption"]["section_count"] == 2
    assert not core.issues


@pytest.mark.parametrize("suffix", [".spsp2dmp", ".bin", ".psp2kerndmp"])
def test_read_dump_routes_encrypted_system_dump_by_magic(tmp_path, capsys, suffix):
    from psp2_core_parse import read_dump

    path = write_dump(tmp_path, make_container(), suffix)
    dump = read_dump(path, strict=True)
    assert isinstance(dump, CoreDump)
    assert dump.image == make_core()
    assert main(["info", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["encrypted"] is True


def test_producer_keys_match_known_values():
    # Verified against real retail dumps: coredump key IDs 1 and 2, the screenshot key, and the HMAC key.
    retail = KEY_SETS["retail"]
    assert retail["cipher"][1] == bytes.fromhex("53c25972bb6037d92ddd006f212e0add")
    assert retail["cipher"][2] == CONTAINER_KEY
    assert retail["cipher"][0x10000001] == bytes.fromhex("eb24a48394b75420e23ad974e9040923")
    assert retail["hmac"][1] == bytes.fromhex("e2a128f52636f29058871f64ad6d99deb35eb7ca6aa660780ac798b111ba7adf")
    for keys in KEY_SETS.values():
        assert sorted(keys["cipher"]) == CIPHER_KEY_IDS
        assert sorted(keys["hmac"]) == [1, 2, 3]


@pytest.mark.parametrize("key_set", sorted(KEY_SETS))
@pytest.mark.parametrize("key_id", CIPHER_KEY_IDS)
def test_every_key_id_and_key_set_decrypts_and_verifies(tmp_path, key_set, key_id):
    core = CoreDump.read(write_dump(tmp_path, make_container(key_id=key_id, key_set=key_set)), strict=True)
    assert core.image == make_core()
    assert core.encryption["sections"][0]["encryption_key_id"] == key_id
    assert core.encryption["key_set"] == key_set
    assert core.encryption["hmac_verified"] is True
    assert [item["hmac"] for item in core.encryption["sections"]] == ["verified", "verified"]


def test_modified_header_fails_hmac_but_still_decrypts(tmp_path):
    raw = bytearray(make_container())
    raw[0x68] ^= 1  # section 0 metadata padding: covered by the header HMAC, ignored otherwise
    path = write_dump(tmp_path, raw)
    core = CoreDump.read(path)
    assert core.image == make_core()
    assert core.encryption["header_hmac"] == "mismatch"
    assert core.encryption["hmac_verified"] is False
    assert any(issue.code == "spsp2dmp-hmac-mismatch" and issue.severity == "error" for issue in core.issues)
    with pytest.raises(ParseError, match="HMAC"):
        CoreDump.read(path, strict=True)


def test_modified_section_fails_hmac(tmp_path, capsys):
    raw = bytearray(make_container())
    raw[-1] ^= 1
    path = write_dump(tmp_path, raw)
    core = CoreDump.read(path)
    assert core.encryption["header_hmac"] == "verified"
    assert [item["hmac"] for item in core.encryption["sections"]] == ["verified", "mismatch"]
    assert any("section 1 HMAC" in issue.message for issue in core.issues)
    assert main(["info", str(path)]) == 0
    assert "HMACs: FAILED: section 1 mismatch" in capsys.readouterr().out
    with pytest.raises(ParseError, match="HMAC"):
        CoreDump.read(path, strict=True)


def test_truncated_sections_are_not_reported_as_hmac_mismatches(tmp_path):
    core = CoreDump.read(write_dump(tmp_path, make_container()[:-0x60]))
    assert [item["hmac"] for item in core.encryption["sections"]] == ["verified", "truncated"]
    assert core.encryption["hmac_verified"] is False
    assert not any(issue.code.startswith("spsp2dmp-hmac") for issue in core.issues)


def test_access_parameters_section_is_decoded(tmp_path):
    record = struct.pack("<4s9I16xI36x", b"CDAP", 1, 0x03650011, 0x0100, 0x30003, 0x81000101, 0, 0x81000201, 0,
                         0x12345678, 0x9ABCDEF0)
    core = CoreDump.read(write_dump(tmp_path, make_container(key_id=1, auxiliary=record)), strict=True)
    assert core.encryption["access_parameters"] == {
        "section_id": 1, "format_version": 1, "system_version": 0x03650011, "application_version": 0x0100,
        "stop_reason": 0x30003, "pc": 0x81000101, "lr": 0x81000201,
        "pc_module_fingerprint": 0x12345678, "lr_module_fingerprint": 0x9ABCDEF0,
    }


def frame_pixels(width, height):
    return bytes((x * 7 + y * 3 + channel * 50) & 0xFF for y in range(height) for x in range(width)
                 for channel in range(4))


def make_screenshot(frames, *, key_set="retail", compresslevel=9):
    payloads = [
        gzip.compress(struct.pack("<5I", 0, vblank, width, height, 0) + frame_pixels(width, height),
                      compresslevel=compresslevel, mtime=0)
        for vblank, width, height in frames
    ]
    caf = make_caf(payloads, [0x10000001] * len(payloads), type_flag=0, key_set=key_set)
    return struct.pack("<I", 16) + caf + b"\0" * 0x40


def read_png(path):
    data = path.read_bytes()
    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    offset, chunks = 8, {}
    while offset < len(data):
        size, kind = struct.unpack_from(">I4s", data, offset)
        chunks.setdefault(kind, b"")
        chunks[kind] += data[offset + 8 : offset + 8 + size]
        offset += 12 + size
    width, height, depth, color = struct.unpack_from(">2I2B", chunks[b"IHDR"])
    assert (depth, color) == (8, 2)
    rows = zlib.decompress(chunks[b"IDAT"])
    stride = width * 3 + 1
    assert all(rows[row * stride] == 0 for row in range(height))
    return width, height, b"".join(rows[row * stride + 1 : (row + 1) * stride] for row in range(height))


def rgb(pixels):
    return bytes(value for index, value in enumerate(pixels) if index % 4 != 3)


@pytest.mark.parametrize("key_set", sorted(KEY_SETS))
def test_screenshot_is_verified_decrypted_and_exported(tmp_path, capsys, key_set):
    description = make_screenshot([(0, 0, 0), (1234, 24, 8)], key_set=key_set)
    data = decode_system2(description)
    assert data["complete"] and data["hmac_verified"] and data["decrypted"]
    assert data["key_set"] == key_set
    assert data["trailing_size"] == 0x40 and data["trailing_nonzero_bytes"] == 0
    process, shell = data["frames"]
    assert (process["source"], process["width"], process["complete"]) == ("process", 0, True)
    assert (shell["source"], shell["vblank_count"], shell["width"], shell["height"]) == ("shell", 1234, 24, 8)
    assert shell["complete"] and shell["pixel_sha256"] == hashlib.sha256(frame_pixels(24, 8)).hexdigest()

    image = make_core(note_name=b"SYSTEM_INFO2\0", note_type=0x102D, description=description)
    path = write_dump(tmp_path, gzip.compress(image, mtime=0), ".psp2dmp")
    output = tmp_path / "frames"
    assert main(["system2", str(path), "--frames", str(output)]) == 0
    text = capsys.readouterr().out
    assert "HMACs: verified" in text and "Frame 1 (shell): 24x8" in text
    assert sorted(item.name for item in output.iterdir()) == ["shell.png"]
    assert read_png(output / "shell.png") == (24, 8, rgb(frame_pixels(24, 8)))
    assert main(["system2", str(path), "--frames", str(output)]) == 2
    assert "exists" in capsys.readouterr().err


def test_truncated_screenshot_recovers_complete_rows(tmp_path, capsys):
    description = make_screenshot([(0, 0, 0), (5, 64, 32)], compresslevel=0)
    cut = description[: len(description) - 0x40 - 64 * 32 * 2]
    data = decode_system2(cut)
    assert not data["complete"]
    shell = data["frames"][1]
    assert shell["hmac"] == "truncated" and not shell["complete"]
    assert 0 < shell["pixel_bytes"] < 64 * 32 * 4
    image = make_core(note_name=b"SYSTEM_INFO2\0", note_type=0x102D, description=cut)
    path = write_dump(tmp_path, gzip.compress(image, mtime=0), ".psp2dmp")
    assert main(["system2", str(path), "--frames", str(tmp_path / "frames")]) == 0
    rows = shell["pixel_bytes"] // (64 * 4)
    assert f"({rows}/32 rows)" in capsys.readouterr().out
    assert read_png(tmp_path / "frames" / "shell.png") == (64, rows, rgb(frame_pixels(64, 32)[: rows * 64 * 4]))


def test_modified_screenshot_fails_hmac():
    description = bytearray(make_screenshot([(0, 0, 0), (1, 8, 8)]))
    first = decode_system2(bytes(description))["frames"][0]
    description[4 + 0x130 + (first["section_size"] + 15) // 16 * 16 + 1] ^= 1
    data = decode_system2(bytes(description))
    assert data["header_hmac"] == "verified"
    assert [frame["hmac"] for frame in data["frames"]] == ["verified", "mismatch"]
    assert not data["hmac_verified"]


def test_screenshot_hmac_is_verified_without_cryptography(monkeypatch):
    description = make_screenshot([(0, 0, 0), (1, 8, 8)])
    original_import = builtins.__import__

    def without_crypto(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("synthetic missing optional dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_crypto)
    data = decode_system2(description)
    assert data["complete"] and data["hmac_verified"]
    assert not data["decrypted"] and "cryptography" in data["decryption_error"]
    assert [frame["width"] for frame in data["frames"]] == [None, None]


def make_system_info(plaintext, encrypted):
    description = bytearray(0x60)
    struct.pack_into("<I", description, 0, 4)
    description[0x18:0x28] = plaintext
    description[0x38:0x48] = encrypted
    return bytes(description)


@pytest.mark.parametrize("key_set", sorted(KEY_SETS))
def test_encrypted_open_psid_is_verified_against_plaintext(key_set):
    psid = bytes(range(0x40, 0x50))
    data = decode_system(make_system_info(psid, encrypt(psid, KEY_SETS[key_set]["cipher"][2], OPEN_PSID_IV)))
    assert data["open_psid"] == psid.hex()
    assert data["decrypted_open_psid"] == psid.hex()
    assert data["open_psid_key_set"] == key_set
    assert data["open_psid_verified"] is True


def test_encrypted_open_psid_is_decrypted_when_plaintext_is_withheld(tmp_path, capsys):
    psid = bytes(range(0x40, 0x50))
    description = make_system_info(bytes(16), encrypt(psid, KEY_SETS["retail"]["cipher"][2], OPEN_PSID_IV))
    data = decode_system(description)
    assert data["open_psid"] is None
    assert data["decrypted_open_psid"] == psid.hex()
    assert data["open_psid_verified"] is None
    image = make_core(note_name=b"SYSTEM_INFO\0", note_type=0x1001, description=description)
    path = write_dump(tmp_path, gzip.compress(image, mtime=0), ".psp2dmp")
    assert main(["context", str(path)]) == 0
    assert f"OpenPSID: {psid.hex()} (decrypted, retail keys)" in capsys.readouterr().out


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
    assert "HMACs: verified (retail keys)" in text
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
        decrypt_kernel_info(damaged, strict=True)


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
