import struct

import pytest

pytest.importorskip("cryptography")

from psp2_core_parse.cli import main
from psp2_core_parse.core import CoreDump, ParseError
from psp2_core_parse.spsp2dmp import decrypt_kernel_info
from test_core import make_core
from test_spsp2dmp import make_container, make_kernel_info, write_dump


def make_version8_core(*, short_segment=False):
    encrypted, plain = make_kernel_info()
    description = struct.pack("<QI", 8, len(encrypted)) + encrypted
    image = bytearray(make_core(
        note_name=b"KERNEL_INFO".ljust(16, b"\0"), note_type=0x3000,
        description=description, load=b"",
    ))
    if short_segment:
        size = struct.unpack_from("<I", image, 52 + 16)[0]
        struct.pack_into("<I", image, 52 + 16, size - 8)
    return bytes(image), description, plain


@pytest.mark.parametrize("key_last", [False, True])
def test_version8_kernel_wrapper(key_last):
    encrypted, plain = make_kernel_info(key_last=key_last)
    description = struct.pack("<QI", 8, len(encrypted)) + encrypted
    assert decrypt_kernel_info(description) == plain


@pytest.mark.parametrize("adjustment", [-1, 1, 0x100000])
def test_version8_wrapper_rejects_length_mismatch(adjustment):
    encrypted, _ = make_kernel_info()
    description = struct.pack("<QI", 8, len(encrypted) + adjustment) + encrypted
    with pytest.raises(ParseError, match="KERNEL_INFO"):
        decrypt_kernel_info(description, strict=True)


@pytest.mark.parametrize("version", [9, 0x100000008])
def test_unknown_kernel_wrapper_version_is_rejected(version):
    encrypted, _ = make_kernel_info()
    with pytest.raises(ParseError, match="KERNEL_INFO"):
        decrypt_kernel_info(struct.pack("<QI", version, len(encrypted)) + encrypted)


@pytest.mark.parametrize("length", [4, 8, 11])
def test_incomplete_version8_wrapper_is_rejected(length):
    with pytest.raises(ParseError, match="KERNEL_INFO"):
        decrypt_kernel_info(struct.pack("<QI", 8, 128)[:length])


def test_correctly_sized_version8_note_is_strictly_valid(tmp_path):
    image, description, plain = make_version8_core()
    path = write_dump(tmp_path, make_container(image))
    core = CoreDump.read(path, strict=True)
    assert core.note("KERNEL_INFO").description == description
    assert decrypt_kernel_info(description) == plain


def test_eight_byte_segment_underreport_recovers_with_warning(tmp_path):
    image, description, plain = make_version8_core(short_segment=True)
    path = write_dump(tmp_path, make_container(image))
    core = CoreDump.read(path, strict=True)
    note = core.note("KERNEL_INFO")
    assert note.description == description
    assert note.complete
    assert core.image == image
    assert core.program_headers[0].file_size == len(description) + 20
    assert decrypt_kernel_info(note.description) == plain
    assert core.complete
    assert any(i.code == "kernel-info-segment-size" and i.severity == "warning" for i in core.issues)
    assert not any(i.code == "truncated-note-description" for i in core.issues)


@pytest.mark.parametrize("cut", range(1, 9))
def test_segment_recovery_does_not_invent_missing_bytes(tmp_path, cut):
    image, description, _ = make_version8_core(short_segment=True)
    path = write_dump(tmp_path, make_container(image[:-cut]))
    core = CoreDump.read(path)
    assert core.note("KERNEL_INFO").description == description[:-cut]
    assert not core.note("KERNEL_INFO").complete
    assert not core.complete
    with pytest.raises(ParseError):
        decrypt_kernel_info(core.note("KERNEL_INFO").description, strict=True)


@pytest.mark.parametrize("relative_start,size", [(0, 8), (4, 4), (-4, 12)])
def test_segment_recovery_never_consumes_another_segment(tmp_path, relative_start, size):
    image, _, _ = make_version8_core(short_segment=True)
    image = bytearray(image)
    segment_end = 116 + struct.unpack_from("<I", image, 52 + 16)[0]
    struct.pack_into("<I", image, 84 + 4, segment_end + relative_start)
    struct.pack_into("<I", image, 84 + 16, size)
    struct.pack_into("<I", image, 84 + 20, size)
    core = CoreDump.read(write_dump(tmp_path, make_container(image)))
    assert not core.note("KERNEL_INFO").complete
    assert not any(i.code == "kernel-info-segment-size" for i in core.issues)


@pytest.mark.parametrize("offset,value", [(116 + 8, 0x1234), (144, 9), (152, 1)])
def test_recovery_is_limited_to_the_observed_kernel_layout(tmp_path, offset, value):
    image, _, _ = make_version8_core(short_segment=True)
    image = bytearray(image)
    struct.pack_into("<I", image, offset, value)
    core = CoreDump.read(write_dump(tmp_path, make_container(image)))
    assert not core.note("KERNEL_INFO").complete
    assert not any(i.code == "kernel-info-segment-size" for i in core.issues)


def test_real_layout_cli_preserves_input_and_raw_note(tmp_path, capsys):
    image, description, plain = make_version8_core(short_segment=True)
    raw = make_container(image)
    path = write_dump(tmp_path, raw)
    output = tmp_path / "kernel.elf"
    note_output = tmp_path / "note.bin"
    assert main(["extract", str(path), "--kernel-info", "--output", str(output)]) == 0
    assert output.read_bytes() == plain
    assert main(["extract", str(path), "--note", "KERNEL_INFO", "--output", str(note_output)]) == 0
    assert note_output.read_bytes() == description
    assert path.read_bytes() == raw
    strict_output = tmp_path / "strict.elf"
    assert main(["extract", str(path), "--strict", "--kernel-info", "--output", str(strict_output)]) == 0
    assert strict_output.read_bytes() == plain
    stderr = capsys.readouterr().err
    assert "warning" in stderr
    assert "kernel-info-segment-size" in stderr
