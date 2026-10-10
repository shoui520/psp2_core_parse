# Copyright (c) 2026 devnoname120
# SPDX-License-Identifier: MIT

import json
import struct
from pathlib import Path

import pytest

from psp2_core_parse.cli import main
from psp2_core_parse.core import ParseError
from test_kerndump import make_blob, make_dump, read_dump, write_dump


LOG_FIXTURE = Path(__file__).parent / "fixtures" / "kernel_log.encrypted.psp2kerndmp"
LOG_PLAINTEXT = b"[synthetic] kernel log fragment\n".ljust(0xB0, b"\x00")


@pytest.mark.parametrize("dump_type", [1, 3])
@pytest.mark.parametrize("blob", [
    LOG_PLAINTEXT,
    bytes(0x80) + b"[synthetic] boot log\n",
    bytes(range(64)),
    struct.pack("<I", 0x48) + bytes(0x44),
    bytes(0x80) + make_blob(),
], ids=["log", "nul-prefixed-log", "binary", "unknown-version", "embedded-header"])
def test_unrecognized_payload_preserves_evidence_without_inventing_records(tmp_path, dump_type, blob):
    path = write_dump(tmp_path, make_dump(blob, dump_type=dump_type, flags=0x10000001))
    dump = read_dump(path)
    assert not dump.complete
    assert not dump.summary()["blob_header_recovered"]
    assert dump.blob == dump.trailing == blob
    assert dump.header == {}
    assert dump.thread() is None
    assert dump.modules() == []
    result = dump.analysis()
    assert result["classification"] == ("KERNEL_PANIC" if dump_type == 1 else "KERNEL_EXCEPTION")
    assert result["classification_source"] == "container"
    assert "not recovered" in result["verdict"]
    assert result["process"] is None
    assert result["primary_crash_thread"] is None
    assert result["fault"] is None
    assert result["kernel_dump"]["kernel_backtrace"] == []
    assert result["kernel_dump"]["user_backtrace"] == []
    assert result["kernel_dump"]["exception_context"] is None
    assert result["kernel_dump"]["saved_thread_registers"] is None
    assert bytes.fromhex(result["kernel_dump"]["trailing_hex"]) == blob
    issue = dump.issues[0]
    assert issue.severity == "error"
    assert issue.code == "unsupported-kernel-blob-header"
    assert issue.file_offset == 0x34
    with pytest.raises(ParseError, match="blob header"):
        read_dump(path, strict=True)


@pytest.mark.parametrize("cut", [0, 1, 3, 4, 15, 0x37])
def test_truncated_blob_header_preserves_available_plaintext(tmp_path, cut):
    blob = make_blob()
    raw = make_dump(blob)[:0x34 + cut]
    path = write_dump(tmp_path, raw)
    dump = read_dump(path)
    assert not dump.complete
    assert dump.header == {}
    assert dump.blob == dump.trailing == blob[:cut]
    assert dump.analysis()["primary_crash_thread"] is None
    with pytest.raises(ParseError, match="truncated"):
        read_dump(path, strict=True)


def test_invalid_backtrace_stride_retains_header_but_not_records(tmp_path):
    blob = bytearray(make_blob())
    struct.pack_into("<I", blob, 0x2C, 8)
    path = write_dump(tmp_path, make_dump(blob))
    dump = read_dump(path)
    assert not dump.complete
    assert dump.summary()["blob_header_recovered"]
    assert dump.header["process_id"] == 0x10001
    assert dump.kernel_backtrace == dump.user_backtrace == []
    assert dump.exception_context is None
    assert dump.saved_thread_registers is None
    assert dump.trailing == blob[0x38:]
    with pytest.raises(ParseError, match="stride"):
        read_dump(path, strict=True)


@pytest.mark.parametrize("command", ["info", "analyze", "context", "validate", "threads", "backtrace", "modules"])
def test_opaque_payload_queries_do_not_crash_or_claim_complete(tmp_path, capsys, command):
    path = write_dump(tmp_path, make_dump(LOG_PLAINTEXT))
    assert main([command, str(path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    if command == "validate":
        assert not result["valid_core"]
        assert not result["blob_header_recovered"]
    elif command == "threads":
        assert result["threads"] == []
        assert not result["complete_inventory"]
    assert main([command, str(path)]) == 0
    assert capsys.readouterr().out.strip()


@pytest.mark.parametrize("command", ["thread", "registers", "backtrace"])
@pytest.mark.parametrize("selector", ["0", "0x1234", "missing"])
def test_opaque_payload_cannot_satisfy_explicit_thread_selector(tmp_path, capsys, command, selector):
    path = write_dump(tmp_path, make_dump(LOG_PLAINTEXT))
    assert main([command, str(path), selector]) == 2
    assert "no thread record" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["thread", "registers"])
def test_opaque_payload_has_no_crash_thread_or_registers(tmp_path, capsys, command):
    path = write_dump(tmp_path, make_dump(LOG_PLAINTEXT))
    assert main([command, str(path), "crash"]) == 2
    assert "recovered" in capsys.readouterr().err


def test_opaque_payload_extraction_and_strict_validation(tmp_path, capsys):
    pytest.importorskip("cryptography")
    dump = read_dump(LOG_FIXTURE)
    assert not dump.complete
    assert dump.info["encrypted"]
    assert dump.info["firmware_version_string"] == "3.600.011"
    assert dump.info["flags"] == 0x20000001
    assert dump.blob == LOG_PLAINTEXT
    output = tmp_path / "plaintext.bin"
    assert main(["extract", str(LOG_FIXTURE), "--blob", "--output", str(output), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert not result["complete"]
    assert result["issues"][0]["code"] == "unsupported-kernel-blob-header"
    assert output.read_bytes() == LOG_PLAINTEXT
    assert main(["validate", str(LOG_FIXTURE), "--strict"]) == 2
    assert "blob header" in capsys.readouterr().err
    strict_output = tmp_path / "strict.bin"
    assert main(["extract", str(LOG_FIXTURE), "--strict", "--blob", "--output", str(strict_output)]) == 2
    capsys.readouterr()
    assert not strict_output.exists()


@pytest.mark.parametrize("cut", [1, 15, 16, 17, 161, 176])
def test_truncated_opaque_ciphertext_retains_only_decryptable_blocks(tmp_path, cut):
    pytest.importorskip("cryptography")
    path = write_dump(tmp_path, LOG_FIXTURE.read_bytes()[:-cut])
    dump = read_dump(path)
    assert not dump.complete
    assert dump.blob == LOG_PLAINTEXT[:(len(LOG_PLAINTEXT) - cut) // 16 * 16]
    assert dump.trailing == dump.blob
    with pytest.raises(ParseError):
        read_dump(path, strict=True)


def test_unrecognized_payload_buckets_do_not_merge_unrelated_evidence(tmp_path, capsys):
    first = write_dump(tmp_path, make_dump(LOG_PLAINTEXT), name="first.psp2kerndmp")
    second = write_dump(tmp_path, make_dump(b"different opaque data"), name="second.psp2kerndmp")
    duplicate = write_dump(tmp_path, first.read_bytes(), name="duplicate.psp2kerndmp")
    assert main(["triage", str(first), str(second), str(duplicate), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["analyzed_count"] == 3
    assert result["group_count"] == 2
    assert main(["compare", str(first), str(second), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert not result["same_bucket"]
    assert "kernel_dump" in result["differences"]
