import gzip
import struct

from psp2_core_parse.core import CoreDump


def make_core(note_name=b"TEST\0", note_type=0x1234, description=b"abcd", load=b"memory"):
    note = struct.pack("<3I", len(note_name), len(description), note_type)
    note += note_name + b"\0" * ((-len(note_name)) & 3)
    note += description + b"\0" * ((-len(description)) & 3)
    phoff = 52
    note_offset = phoff + 64
    load_offset = note_offset + len(note)
    header = bytearray(52)
    header[:16] = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIIIIIHHHHHH", header, 16, 4, 40, 1, 0, phoff, 0, 0, 52, 32, 2, 0, 0, 0)
    ph_note = struct.pack("<8I", 4, note_offset, 0, 0, len(note), len(note), 4, 4)
    ph_load = struct.pack("<8I", 1, load_offset, 0x81000000, 0, len(load), len(load), 5, 0x1000)
    return bytes(header) + ph_note + ph_load + note + load


def test_complete_core_and_memory(tmp_path):
    path = tmp_path / "sample.psp2dmp"
    path.write_bytes(gzip.compress(make_core()))
    core = CoreDump.read(path)
    assert core.complete
    assert core.note("TEST").description == b"abcd"
    assert core.read_memory(0x81000000, 6) == b"memory"
    assert core.loads[0].permissions == "r-x"


def test_truncated_gzip_salvages_prefix(tmp_path):
    raw = gzip.compress(make_core(load=b"A" * 0x20000), compresslevel=0)
    path = tmp_path / "sample.tmp"
    path.write_bytes(raw[:-100])
    core = CoreDump.read(path)
    assert not core.complete
    assert not core.compression_complete
    assert core.note("TEST").description == b"abcd"
    assert core.loads[0].data
    assert any(item.code == "truncated-gzip" for item in core.issues)
