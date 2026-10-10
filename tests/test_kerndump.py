# Copyright (c) 2026 devnoname120
# SPDX-License-Identifier: MIT

import builtins
import gzip
import json
import struct
from pathlib import Path

import pytest

from psp2_core_parse.cli import main
from psp2_core_parse.core import CoreDump, ParseError


ENCRYPTED_FIXTURE = Path(__file__).parent / "fixtures" / "kernel_panic.encrypted.psp2kerndmp"


def make_blob(header_size=0x38, dump_type=3, saved=True, stride=0x10):
    header = bytearray(header_size)
    struct.pack_into("<4IQ3I", header, 0, header_size, 0x10001, 0x10023, 2,
                     0x123456789ABC, 0x12345678, 0x23456789, 0x34567890)
    counts_offset = 0x24 if header_size == 0x38 else 0x2C
    if header_size == 0x40:
        struct.pack_into("<2I", header, 0x24, 0x10045, 0x9876)
    struct.pack_into("<5I", header, counts_offset, 1, 1, stride, 0, 0x22 if saved else 0)
    traces = struct.pack("<4I", 0x102000, 0x81000101, 0xAABBCCDD, 0x81000000)
    traces += b"X" * (stride - 0x10)
    traces += struct.pack("<4I", 0x82000000, 0x82000201, 0x11223344, 0x82000000)
    traces += b"Y" * (stride - 0x10)
    context = bytearray()
    if dump_type == 3:
        context = bytearray(0x600)
        struct.pack_into("<16I", context, 0, *range(13), 0x102000, 0x81000201, 0x81000100)
        struct.pack_into("<2I", context, 0x40, 4, 0x33)
        struct.pack_into("<2I", context, 0x4C, 0x1122, 0x3344)
        struct.pack_into("<4I", context, 0x70, 0x805, 0, 0xDEADBEEF, 0)
        struct.pack_into("<I", context, 0xD4, 30 << 8)
        struct.pack_into("<2I", context, 0xF0, 0xAABBCCDD, 0x81000000)
        struct.pack_into("<I", context, 0xFC, 1)
        struct.pack_into("<32Q", context, 0x100, *range(0x100000000, 0x100000020))
        for index in range(32):
            struct.pack_into("<4I", context, 0x200 + index * 16,
                             index, 0x81000000 + index * 4, 0x81000100 + index * 4, 0x80001000)
            struct.pack_into("<4I", context, 0x400 + index * 16,
                             0xAABBCCDD, 0x81000000, 0xAABBCCDD, 0x81000000)
    registers = bytearray()
    if saved:
        registers = bytearray(0x60)
        struct.pack_into("<13I", registers, 0, *range(100, 113))
        struct.pack_into("<I", registers, 0x3C, 0xAABB)
        struct.pack_into("<4I", registers, 0x50, 0x103000, 0x81000401, 0x81000301, 0x33)
    return bytes(header + traces + context + registers)


def make_dump(blob=None, *, dump_type=3, offset=0x28, flags=0x10000000):
    if blob is None:
        blob = make_blob(dump_type=dump_type)
    info = struct.pack("<6I16s", 0x03600000, 0x1234, flags, len(blob), offset, 0x5678, bytes(range(16)))
    content = info + bytes(offset - len(info)) + blob
    return struct.pack("<3I", 0, dump_type, len(content)) + content


def write_dump(tmp_path, raw=None, name="sample.psp2kerndmp"):
    path = tmp_path / name
    path.write_bytes(make_dump() if raw is None else raw)
    return path


def read_dump(path, **kwargs):
    from psp2_core_parse import read_dump as read
    return read(path, **kwargs)


@pytest.mark.parametrize("header_size", [0x38, 0x40])
@pytest.mark.parametrize("dump_type", [1, 3])
def test_analyze_kernel_dump(tmp_path, capsys, header_size, dump_type):
    path = write_dump(tmp_path, make_dump(make_blob(header_size, dump_type), dump_type=dump_type))
    assert main(["analyze", str(path), "--json"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["dump"]["format"] == "psp2kerndmp"
    assert value["dump"]["complete"]
    assert value["classification"] == ("KERNEL_PANIC" if dump_type == 1 else "KERNEL_DATA_ABORT")
    kernel = value["kernel_dump"]
    assert kernel["header"]["size"] == header_size
    assert kernel["header"]["system_time_us"] == 0x123456789ABC
    assert kernel["header"]["process_id"] == 0x10001
    assert kernel["header"]["thread_id"] == 0x10023
    assert kernel["kernel_backtrace"][0]["fingerprint"] == 0xAABBCCDD
    assert kernel["user_backtrace"][0]["fingerprint"] == 0x11223344
    assert kernel["user_backtrace"][0]["module_base"] == 0x82000000
    assert kernel["saved_thread_registers"]["pc"] == 0x81000301
    if dump_type == 3:
        assert kernel["exception_context"]["registers"]["pc"] == 0x81000100
        assert kernel["exception_context"]["registers"]["vfp_d"][31] == 0x10000001F
        assert value["fault"]["address"] == 0xDEADBEEF
        assert value["fault"]["status"]["write"]
    else:
        assert kernel["exception_context"] is None
        assert value["fault"] is None


def test_waypoint_ring_has_no_duplicate_slot(tmp_path):
    value = read_dump(write_dump(tmp_path)).analysis()["kernel_dump"]
    points = value["exception_context"]["waypoints"]
    assert len(points) == 32
    assert [point["index"] for point in points] == [31] + list(range(31))
    assert points[0]["target_module"]["offset"] == 0x17C


def test_extended_backtrace_stride_and_relative_blob_offset(tmp_path):
    blob = make_blob(stride=0x18)
    dump = read_dump(write_dump(tmp_path, make_dump(blob, offset=0x40)))
    value = dump.analysis()["kernel_dump"]
    assert value["kernel_backtrace"][0]["extra_hex"] == (b"X" * 8).hex()
    assert value["user_backtrace"][0]["pc"] == 0x82000201
    assert value["exception_context"]["registers"]["pc"] == 0x81000100
    assert dump.blob == blob


def test_detection_does_not_depend_on_extension(tmp_path, capsys):
    path = write_dump(tmp_path, name="renamed.bin")
    assert main(["info", str(path), "--json"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["format"] == "psp2kerndmp"
    assert value["firmware_version_string"] == "3.600.000"


@pytest.mark.parametrize("command", ["info", "analyze", "threads", "registers", "backtrace", "modules", "context", "validate"])
def test_kernel_queries_json_and_text(tmp_path, capsys, command):
    path = write_dump(tmp_path)
    assert main([command, str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)
    assert main([command, str(path)]) == 0
    assert capsys.readouterr().out.strip()


def test_thread_selector_is_validated(tmp_path, capsys):
    path = write_dump(tmp_path)
    assert main(["thread", str(path), "0x10023", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["uid"] == 0x10023
    assert main(["registers", str(path), "0xBAD"]) == 2
    assert "not found" in capsys.readouterr().err


def test_extract_plaintext_blob_without_overwriting(tmp_path, capsys):
    path = write_dump(tmp_path)
    output = tmp_path / "blob.bin"
    args = ["extract", str(path), "--blob", "--output", str(output)]
    assert main(args) == 0
    assert output.read_bytes() == make_blob()
    assert main(args) == 2
    assert "--force" in capsys.readouterr().err
    assert main(args + ["--force"]) == 0


@pytest.mark.parametrize("args", [["memory", "0x81000000", "16"], ["notes"], ["map"], ["waits"]])
def test_unavailable_kernel_queries_are_explicit(tmp_path, capsys, args):
    path = write_dump(tmp_path)
    assert main([args[0], str(path), *args[1:]]) == 2
    assert "not available for .psp2kerndmp" in capsys.readouterr().err


def test_images_are_not_silently_ignored(tmp_path, capsys):
    path = write_dump(tmp_path)
    assert main(["analyze", str(path), "--image", "module=missing.elf"]) == 2
    assert "image" in capsys.readouterr().err


def test_truncation_salvages_only_complete_records(tmp_path, capsys):
    path = write_dump(tmp_path, make_dump()[:-1])
    dump = read_dump(path)
    assert not dump.complete
    assert dump.analysis()["kernel_dump"]["saved_thread_registers"] is None
    assert dump.analysis()["kernel_dump"]["exception_context"] is not None
    with pytest.raises(ParseError, match="truncated"):
        read_dump(path, strict=True)
    assert main(["validate", str(path), "--json"]) == 0
    assert not json.loads(capsys.readouterr().out)["valid_core"]
    assert main(["validate", str(path), "--strict"]) == 2


@pytest.mark.parametrize("cut", [0x38, 0x38 + 15, 0x38 + 16, 0x38 + 31, 0x38 + 32 + 0x3FF])
def test_truncated_backtraces_do_not_shift_later_records(tmp_path, cut):
    raw = make_dump()
    dump = read_dump(write_dump(tmp_path, raw[:0x34 + cut]))
    value = dump.analysis()["kernel_dump"]
    assert not dump.complete
    assert len(value["kernel_backtrace"]) == int(cut >= 0x48)
    assert len(value["user_backtrace"]) == int(cut >= 0x58)
    assert value["exception_context"] is None
    assert value["saved_thread_registers"] is None


@pytest.mark.parametrize("offset,value,match", [
    (4, 9, "type"),
    (8, 0x20, "content"),
    (0x14, 0, "flags"),
    (0x18, 0xFFFFFFFF, "blob"),
    (0x1C, 0, "offset"),
    (0x1C, 0xFFFFFFFF, "offset"),
])
def test_invalid_container_fields_are_rejected(tmp_path, offset, value, match):
    raw = bytearray(make_dump())
    struct.pack_into("<I", raw, offset, value)
    with pytest.raises(ParseError, match=match):
        read_dump(write_dump(tmp_path, raw))


@pytest.mark.parametrize("offset,value,match", [
    (0x34, 0x39, "header"),
    (0x34 + 0x2C, 8, "stride"),
])
def test_invalid_blob_fields_are_salvaged_unless_strict(tmp_path, offset, value, match):
    raw = bytearray(make_dump())
    struct.pack_into("<I", raw, offset, value)
    path = write_dump(tmp_path, raw)
    dump = read_dump(path)
    assert not dump.complete
    assert dump.blob == raw[0x34:]
    with pytest.raises(ParseError, match=match):
        read_dump(path, strict=True)


def test_huge_backtrace_counts_are_bounded_by_available_bytes(tmp_path):
    raw = bytearray(make_dump(make_blob(dump_type=1, saved=False), dump_type=1))
    struct.pack_into("<I", raw, 0x34 + 0x24, 0xFFFFFFFF)
    dump = read_dump(write_dump(tmp_path, raw))
    value = dump.analysis()["kernel_dump"]
    assert not dump.complete
    assert len(value["kernel_backtrace"]) == 2
    assert value["user_backtrace"] == []


def test_panic_without_saved_registers_does_not_require_exception_context(tmp_path):
    path = write_dump(tmp_path, make_dump(make_blob(dump_type=1, saved=False), dump_type=1))
    dump = read_dump(path, strict=True)
    assert dump.complete
    assert dump.analysis()["kernel_dump"]["exception_context"] is None
    assert dump.analysis()["kernel_dump"]["saved_thread_registers"] is None


def test_unknown_tail_is_preserved(tmp_path):
    blob = make_blob() + b"opaque module records"
    value = read_dump(write_dump(tmp_path, make_dump(blob))).analysis()["kernel_dump"]
    assert value["trailing_hex"] == b"opaque module records".hex()


def test_triage_and_compare_kernel_dumps(tmp_path, capsys):
    first = write_dump(tmp_path, name="first.psp2kerndmp")
    second = write_dump(tmp_path, name="second.psp2kerndmp")
    assert main(["triage", str(first), str(second), "--json"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["analyzed_count"] == 2
    assert value["group_count"] == 1
    assert main(["compare", str(first), str(second), "--json"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["same_bucket"]
    assert value["difference_count"] == 0


@pytest.mark.parametrize("compressed", [False, True])
def test_elf_still_uses_existing_loader_even_with_kernel_extension(tmp_path, compressed):
    from test_core import make_core
    raw = make_core()
    if compressed:
        raw = gzip.compress(raw)
    dump = read_dump(write_dump(tmp_path, raw))
    assert isinstance(dump, CoreDump)
    assert dump.complete
    assert dump.read_memory(0x81000000, 6) == b"memory"


def test_openssl_encrypted_known_answer_preserves_final_block_and_padding():
    pytest.importorskip("cryptography")
    dump = read_dump(ENCRYPTED_FIXTURE, strict=True)
    assert dump.info["encrypted"]
    assert dump.blob == make_blob(0x40, 1) + b"\x10" * 16
    assert dump.saved_thread_registers["pc"] == 0x81000301
    assert dump.trailing == b"\x10" * 16


def test_encrypted_blob_extraction(tmp_path, capsys):
    pytest.importorskip("cryptography")
    output = tmp_path / "decrypted.bin"
    assert main(["extract", str(ENCRYPTED_FIXTURE), "--blob", "--output", str(output)]) == 0
    assert output.read_bytes() == make_blob(0x40, 1) + b"\x10" * 16


def test_missing_optional_crypto_is_actionable_and_plaintext_still_works(tmp_path, capsys, monkeypatch):
    real_import = builtins.__import__

    def without_crypto(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("crypto deliberately unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_crypto)
    assert main(["analyze", str(ENCRYPTED_FIXTURE)]) == 2
    assert "psp2-core-parse[kernel]" in capsys.readouterr().err
    assert main(["analyze", str(write_dump(tmp_path))]) == 0


@pytest.mark.parametrize("cut", [1, 15, 16, 17, 32, 47, 48, 80, 120])
def test_truncated_ciphertext_only_recovers_whole_aes_blocks(tmp_path, cut):
    pytest.importorskip("cryptography")
    raw = ENCRYPTED_FIXTURE.read_bytes()[:-cut]
    expected = make_blob(0x40, 1) + b"\x10" * 16
    expected = expected[:(len(expected) - cut) // 16 * 16]
    dump = read_dump(write_dump(tmp_path, raw))
    assert not dump.complete
    assert dump.blob == expected
    with pytest.raises(ParseError, match="truncated"):
        read_dump(write_dump(tmp_path, raw), strict=True)


def test_non_block_aligned_ciphertext_size_is_rejected(tmp_path):
    raw = bytearray(ENCRYPTED_FIXTURE.read_bytes())
    struct.pack_into("<I", raw, 0x18, len(raw) - 0x34 - 1)
    with pytest.raises(ParseError, match="AES block size"):
        read_dump(write_dump(tmp_path, raw))


def test_encrypted_flag_takes_precedence_over_plaintext_flag(tmp_path):
    pytest.importorskip("cryptography")
    raw = bytearray(ENCRYPTED_FIXTURE.read_bytes())
    struct.pack_into("<I", raw, 0x14, 0x30000000)
    assert read_dump(write_dump(tmp_path, raw)).blob == make_blob(0x40, 1) + b"\x10" * 16


@pytest.mark.parametrize("exception_code,classification", [(4, "KERNEL_PREFETCH_ABORT"), (6, "KERNEL_UNDEFINED_INSTRUCTION"), (9, "KERNEL_EXCEPTION_9")])
def test_exception_codes_use_the_recorded_fault_kind(tmp_path, exception_code, classification):
    blob = bytearray(make_blob())
    context = 0x38 + 0x20
    struct.pack_into("<I", blob, context + 0xFC, exception_code)
    struct.pack_into("<I", blob, context + 0x74, 2)
    struct.pack_into("<I", blob, context + 0x7C, 0x12345678)
    struct.pack_into("<I", blob, context + 0xD8, 3 << 2)
    result = read_dump(write_dump(tmp_path, make_dump(blob))).analysis()
    assert result["classification"] == classification
    if exception_code == 4:
        assert result["fault"]["address"] == 0x12345678
        assert result["fault"]["status"]["status_name"] == "debug event"
        assert "write" not in result["fault"]["status"]
        assert result["kernel_dump"]["exception_context"]["debug_event"]["name"] == "BKPT instruction"
    else:
        assert result["fault"] is None


def test_non_debug_abort_does_not_claim_a_debug_event(tmp_path):
    result = read_dump(write_dump(tmp_path)).analysis()
    assert result["kernel_dump"]["exception_context"]["debug_event"] is None


def test_unknown_module_sentinel_does_not_become_a_module(tmp_path):
    blob = bytearray(make_blob())
    struct.pack_into("<I", blob, 0x38 + 8, 0xFFFFFFFF)
    struct.pack_into("<I", blob, 0x38 + 0x20 + 0xF0, 0xFFFFFFFF)
    result = read_dump(write_dump(tmp_path, make_dump(blob))).analysis()
    kernel = result["kernel_dump"]
    assert kernel["kernel_backtrace"][0]["module"] is None
    assert kernel["exception_context"]["fault_module"] is None
    assert all(module["fingerprint"] != 0xFFFFFFFF for module in kernel["modules"])


def test_waypoints_stop_at_exception_but_not_t2ee_trap(tmp_path):
    blob = bytearray(make_blob())
    waypoints = 0x38 + 0x20 + 0x200
    struct.pack_into("<I", blob, waypoints + 31 * 16 + 12, 0x80000052)
    struct.pack_into("<I", blob, waypoints + 12, 0x800000C2)
    points = read_dump(write_dump(tmp_path, make_dump(blob))).exception_context["waypoints"]
    assert [point["index"] for point in points] == [31, 0]
    assert points[1]["exception_cause"] == "precise data abort"


def test_compare_includes_recorded_kernel_backtraces(tmp_path, capsys):
    first = write_dump(tmp_path, name="first.psp2kerndmp")
    blob = bytearray(make_blob())
    struct.pack_into("<I", blob, 0x38 + 0x10 + 4, 0x82000301)
    second = write_dump(tmp_path, make_dump(blob), name="second.psp2kerndmp")
    assert main(["compare", str(first), str(second), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["same_bucket"]
    assert "kernel_dump" in result["differences"]


def test_mixed_format_triage_and_compare(tmp_path, capsys):
    from test_core import make_core
    kernel = write_dump(tmp_path)
    elf = write_dump(tmp_path, make_core(), name="elf.psp2dmp")
    assert main(["triage", str(kernel), str(elf), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["analyzed_count"] == 2
    for left, right in ((kernel, elf), (elf, kernel)):
        assert main(["compare", str(left), str(right), "--json"]) == 0
        assert not json.loads(capsys.readouterr().out)["same_bucket"]


def test_blob_extraction_is_rejected_for_elf(tmp_path, capsys):
    from test_core import make_core
    path = write_dump(tmp_path, make_core(), name="elf.psp2dmp")
    output = tmp_path / "blob.bin"
    assert main(["extract", str(path), "--blob", "--output", str(output)]) == 2
    assert "requires a .psp2kerndmp" in capsys.readouterr().err
    assert not output.exists()


@pytest.mark.parametrize("alias", ["same-path", "symlink", "hardlink"])
def test_forced_blob_extraction_cannot_overwrite_input(tmp_path, capsys, alias):
    path = write_dump(tmp_path)
    raw = path.read_bytes()
    output = path
    if alias != "same-path":
        output = tmp_path / "alias.bin"
        if alias == "symlink":
            output.symlink_to(path)
        else:
            import os

            os.link(path, output)
    assert main(["extract", str(path), "--blob", "--output", str(output), "--force"]) == 2
    assert "input" in capsys.readouterr().err
    assert path.read_bytes() == raw
