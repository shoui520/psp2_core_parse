from types import SimpleNamespace

import pytest

import psp2_core_parse.symbols as symbols
from psp2_core_parse.core import ParseError
from psp2_core_parse.execution import AddressLocation
from psp2_core_parse.symbols import (
    ElfImage,
    ImageSegment,
    SourcePathMap,
    Symbolizer,
    disassemble_address,
    disassemble_image,
)


def test_encrypted_or_non_elf_image_is_rejected(tmp_path):
    path = tmp_path / "module.self"
    path.write_bytes(b"SCE\0" + b"\0" * 100)
    with pytest.raises(ParseError, match="decrypt"):
        ElfImage.read(path)


def test_source_path_map_builds_objdump_prefix_options(tmp_path, monkeypatch):
    local_source = tmp_path / "source"
    local_source.mkdir()
    mapping = SourcePathMap.parse(f"/build/tree={local_source}")
    image = ElfImage(tmp_path / "application.elf", "application", (), b"", 0, 0, 0, 0)
    invoked = []

    monkeypatch.setattr(symbols, "_vita_tool", lambda name: name)

    def fake_run(arguments):
        invoked.append(arguments)
        return """application.elf: file format elf32-littlearm

Disassembly of section .text:

1000 <main>:
int main(void) {
1000:\t2000      movs r0, #0
1002:\t4770      bx lr
"""

    monkeypatch.setattr(symbols, "_run", fake_run)
    result = disassemble_image(
        image, 0x1000, 0x1004, 0x1000,
        thumb=True, source_map=mapping,
    )

    command = invoked[0]
    assert command[:4] == ["objdump", "-d", "-C", "-S"]
    assert f"--prefix={local_source}" in command
    assert "--prefix-strip=2" in command
    assert command[-1] == str(image.path)
    assert result["source_interleaved"]
    assert "!!! 1000:" in result["text"]


class FakeCore:
    def __init__(self, base, data):
        self.base = base
        self.data = data

    def captured_ranges(self, start, stop):
        first = max(start, self.base)
        last = min(stop, self.base + len(self.data))
        return [(first, last)] if first < last else []

    def read_memory(self, address, size):
        offset = address - self.base
        return self.data[offset : offset + size]


class FakeModules:
    def __init__(self, location):
        self.location = location

    def locate(self, address):
        return self.location if self.location.segment_start <= address < self.location.segment_start + self.location.segment_size else None


def test_captured_code_wins_when_supplied_elf_differs(tmp_path, monkeypatch):
    runtime_base = 0x81000000
    target = runtime_base + 0x20
    captured = bytes([0xAA]) * 0x100
    image_bytes = bytes([0xBB]) * 0x100
    image = ElfImage(
        tmp_path / "application.elf", "application",
        (ImageSegment(1, 0x1000, 0, len(image_bytes), len(image_bytes), 5),),
        image_bytes, 0, 0, 0, 0,
    )
    location = AddressLocation(target, 0, 1, "application", 1, runtime_base, 0x100, "r-x", 0x20)
    execution = SimpleNamespace(modules=FakeModules(location))

    monkeypatch.setattr(symbols, "_vita_tool", lambda name: name)
    monkeypatch.setattr(symbols, "_run", lambda arguments: "0x1020\nmain\nmain.c:4\n")
    monkeypatch.setattr(
        symbols, "disassemble_bytes",
        lambda data, address, thumb=False: f"Disassembly of section .data:\n\n{target:x}:\tdeff\tudf #255",
    )

    result = disassemble_address(
        FakeCore(runtime_base, captured), execution, Symbolizer((image,)), target,
        thumb=True, before=16, after=64,
    )

    assert result["status"] == "available"
    assert result["source"] == "captured-memory"
    assert result["byte_comparison"] == "mismatch"
    assert result["bytes"] == captured[0x10:0x60].hex()
    assert result["target_instruction_marked"]
    assert any("authoritative" in item for item in result["warnings"])


def test_matching_captured_code_uses_mixed_source_elf(tmp_path, monkeypatch):
    runtime_base = 0x81000000
    target = runtime_base + 0x20
    code = bytes(range(0x100))
    image = ElfImage(
        tmp_path / "application.elf", "application",
        (ImageSegment(1, 0x1000, 0, len(code), len(code), 5),),
        code, 0, 0, 0, 0,
    )
    location = AddressLocation(target, 0, 1, "application", 1, runtime_base, 0x100, "r-x", 0x20)
    execution = SimpleNamespace(modules=FakeModules(location))

    monkeypatch.setattr(symbols, "_vita_tool", lambda name: name)

    def fake_run(arguments):
        if arguments[0] == "addr2line":
            return "0x1020\nmain\nmain.c:4\n"
        return """Disassembly of section .text:

1020 <main>:
int value = *pointer;
1020:\t681b      ldr r3, [r3, #0]
"""

    monkeypatch.setattr(symbols, "_run", fake_run)
    result = disassemble_address(
        FakeCore(runtime_base, code), execution, Symbolizer((image,)), target,
        thumb=True, before=16, after=64,
    )

    assert result["status"] == "available"
    assert result["source"] == "captured-memory+verified-image"
    assert result["byte_comparison"] == "match"
    assert result["source_interleaved"]
    assert "!!! 1020:" in result["text"]
