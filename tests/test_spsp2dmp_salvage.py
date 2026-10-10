import json
import struct

import pytest

pytest.importorskip("cryptography")

from psp2_core_parse.cli import main
from psp2_core_parse.core import CoreDump, ParseError
from psp2_core_parse.spsp2dmp import decrypt_kernel_info
from test_core import make_core
from test_spsp2dmp import make_container, make_kernel_info, write_dump


@pytest.mark.parametrize("cut", [1, 7, 8, 15, 16, 17, 31, 32, 47, 48, 49, 65, 79, 80])
@pytest.mark.parametrize("versioned", [False, True])
def test_truncated_kernel_recovers_only_plaintext_blocks(tmp_path, cut, versioned):
    encrypted, plain = make_kernel_info()
    description = encrypted[:-cut]
    if versioned:
        description = struct.pack("<QI", 8, len(encrypted)) + description
    issues = []
    recovered = decrypt_kernel_info(description, issues=issues)
    expected_size = len(encrypted) - 80 + (80 - cut) // 16 * 16
    assert recovered == plain[:expected_size]
    assert issues
    assert any(issue.code == "kernel-info-truncated-segment" for issue in issues)
    path = tmp_path / "partial.elf"
    path.write_bytes(recovered)
    core = CoreDump.read(path)
    assert not core.complete
    assert all(segment.data == plain[segment.file_offset:segment.file_offset + len(segment.data)] for segment in core.loads)
    with pytest.raises(ParseError):
        decrypt_kernel_info(description, strict=True)


def test_truncated_kernel_warns_without_an_explicit_issue_sink():
    encrypted, plain = make_kernel_info()
    with pytest.warns(RuntimeWarning, match="KERNEL_INFO"):
        recovered = decrypt_kernel_info(encrypted[:-1])
    assert recovered == plain[:-16]


def test_truncated_kernel_cli_returns_partial_output_and_warnings(tmp_path, capsys):
    encrypted, plain = make_kernel_info()
    description = struct.pack("<QI", 8, len(encrypted)) + encrypted[:-1]
    path = write_dump(tmp_path, make_container(make_core(note_name=b"KERNEL_INFO\0", description=description)))
    output = tmp_path / "partial.elf"
    assert main(["extract", str(path), "--kernel-info", "--output", str(output), "--json"]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["complete"] is False
    assert report["issues"]
    assert "warning" in captured.err
    assert output.read_bytes() == plain[:-16]
    strict_output = tmp_path / "strict.elf"
    assert main(["extract", str(path), "--kernel-info", "--output", str(strict_output), "--strict"]) == 2
    assert not strict_output.exists()


def test_missing_kernel_key_preserves_metadata_without_ciphertext(tmp_path):
    encrypted, _ = make_kernel_info()
    damaged = bytearray(encrypted)
    struct.pack_into("<I", damaged, 52 + 16, 0x60)
    issues = []
    recovered = decrypt_kernel_info(damaged, issues=issues)
    assert recovered == damaged[:len(damaged) - 80]
    path = tmp_path / "metadata.elf"
    path.write_bytes(recovered)
    core = CoreDump.read(path)
    assert all(not segment.data for segment in core.loads)
    assert any(issue.code == "kernel-info-missing-key" for issue in issues)


def test_overlapping_kernel_segments_preserve_only_unambiguous_prefix():
    encrypted, plain = make_kernel_info()
    damaged = bytearray(encrypted)
    overlap_start = len(damaged) - 80 + 16
    struct.pack_into("<I", damaged, 52 + 64 + 4, overlap_start)
    expected = bytearray(plain[:overlap_start])
    struct.pack_into("<I", expected, 52 + 64 + 4, overlap_start)
    issues = []
    assert decrypt_kernel_info(damaged, issues=issues) == expected
    assert any(issue.code == "kernel-info-overlapping-segments" for issue in issues)
    with pytest.raises(ParseError, match="overlap"):
        decrypt_kernel_info(damaged, strict=True)


def test_partial_kernel_program_header_table_preserves_metadata():
    encrypted, _ = make_kernel_info()
    prefix = encrypted[:52 + 32 + 7]
    issues = []
    assert decrypt_kernel_info(prefix, issues=issues) == prefix
    assert any(issue.code == "kernel-info-truncated-program-headers" for issue in issues)


def test_kernel_data_can_precede_its_program_header_table():
    encrypted, plain = make_kernel_info()
    header = bytearray(encrypted[:52])
    data = encrypted[148:]
    struct.pack_into("<I", header, 28, 52 + len(data))
    table = bytearray(encrypted[52:148])
    for index in range(3):
        offset = struct.unpack_from("<I", table, index * 32 + 4)[0]
        struct.pack_into("<I", table, index * 32 + 4, offset - 96)
    rearranged = bytes(header) + data + bytes(table)
    expected = bytes(header) + plain[148:] + bytes(table)
    issues = []
    assert decrypt_kernel_info(rearranged, issues=issues, strict=True) == expected
    assert issues == []


def test_default_info_displays_salvaged_dump_and_warning(tmp_path, capsys):
    path = write_dump(tmp_path, make_container()[:-1])
    assert main(["info", str(path), "--json"]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["complete"] is False
    assert result["notes"]
    assert "warning" in captured.err
