from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Union

from .core import CoreDump, ParseError
from .execution import AddressLocation, ExecutionContext


class ToolError(RuntimeError):
    pass


def _vita_tool(name: str) -> str:
    found = shutil.which(f"arm-vita-eabi-{name}")
    if found:
        return found
    root = os.environ.get("VITASDK")
    roots = [Path(root)] if root else []
    roots.extend((Path.home() / "vitasdk", Path("/usr/local/vitasdk"), Path("/opt/vitasdk")))
    for candidate_root in roots:
        candidate = candidate_root / "bin" / f"arm-vita-eabi-{name}"
        if candidate.is_file():
            return str(candidate)
    raise ToolError(
        f"arm-vita-eabi-{name} was not found in PATH, $VITASDK, ~/vitasdk, "
        "/usr/local/vitasdk, or /opt/vitasdk"
    )


def _run(arguments: list[str]) -> str:
    try:
        process = subprocess.run(arguments, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError(f"cannot run {arguments[0]}: {exc}") from exc
    if process.returncode:
        detail = process.stderr.strip() or process.stdout.strip() or f"exit status {process.returncode}"
        raise ToolError(detail)
    return process.stdout


@dataclass(frozen=True)
class ImageSegment:
    index: int
    virtual_address: int
    file_offset: int
    file_size: int
    memory_size: int
    flags: int

    def summary(self) -> dict:
        return {
            "index": self.index,
            "virtual_address": self.virtual_address,
            "file_offset": self.file_offset,
            "file_size": self.file_size,
            "memory_size": self.memory_size,
            "flags": self.flags,
        }


@dataclass(frozen=True)
class ElfImage:
    path: Path
    module_name: str
    segments: tuple[ImageSegment, ...]
    data: bytes
    section_header_offset: int
    section_header_size: int
    section_header_count: int
    section_name_index: int

    @classmethod
    def read(cls, path: Union[Path, str], *, module_name: Optional[str] = None) -> "ElfImage":
        path = Path(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ParseError(f"cannot read image {path}: {exc}") from exc
        if len(data) < 52 or data[:4] != b"\x7fELF" or data[4:6] != b"\x01\x01":
            raise ParseError(f"{path} is not a little-endian ELF32 image; encrypted SELF files must be decrypted first")
        (_type, machine, version, _entry, phoff, shoff, _flags, _ehsize, phentsize, phnum,
         shentsize, shnum, shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
        if machine != 40 or version != 1 or phentsize < 32:
            raise ParseError(f"{path} is not a supported ARM ELF32 image")
        if phoff + phentsize * phnum > len(data):
            raise ParseError(f"{path} has a truncated program-header table")
        if shnum and (shentsize < 40 or shoff + shentsize * shnum > len(data)):
            raise ParseError(f"{path} has an invalid or truncated section-header table")
        segments = []
        for item in range(phnum):
            fields = struct.unpack_from("<8I", data, phoff + item * phentsize)
            if fields[0] != 1:
                continue
            segments.append(ImageSegment(len(segments) + 1, fields[2], fields[1], fields[4], fields[5], fields[6]))
        if not segments:
            raise ParseError(f"{path} contains no PT_LOAD segments")
        inferred = path.name
        for suffix in (".elf", ".self", ".suprx", ".skprx", ".prx"):
            if inferred.lower().endswith(suffix):
                inferred = inferred[:-len(suffix)]
                break
        return cls(path.resolve(), module_name or inferred, tuple(segments), data, shoff, shentsize, shnum, shstrndx)

    def section_headers(self) -> tuple[dict, ...]:
        raw_headers = []
        for index in range(self.section_header_count):
            values = struct.unpack_from(
                "<10I", self.data, self.section_header_offset + index * self.section_header_size
            )
            raw_headers.append({
                "index": index, "name_offset": values[0], "type": values[1],
                "flags": values[2], "address": values[3], "file_offset": values[4],
                "size": values[5], "link": values[6], "info": values[7],
                "alignment": values[8], "entry_size": values[9], "name": "",
            })
        if 0 <= self.section_name_index < len(raw_headers):
            strings = raw_headers[self.section_name_index]
            start, end = strings["file_offset"], strings["file_offset"] + strings["size"]
            table = self.data[start:end] if 0 <= start <= end <= len(self.data) else b""
            for section in raw_headers:
                offset = section["name_offset"]
                if offset < len(table):
                    section["name"] = table[offset:].split(b"\0", 1)[0].decode("utf-8", errors="replace")
        return tuple(raw_headers)

    def linked_bytes(self, address: int, size: int) -> bytes:
        for segment in self.segments:
            if segment.virtual_address <= address and address + size <= segment.virtual_address + segment.file_size:
                offset = segment.file_offset + address - segment.virtual_address
                return self.data[offset : offset + size]
        raise ParseError(f"ELF address 0x{address:08x}+0x{size:x} is not file-backed in {self.path}")

    def image_address(self, location: AddressLocation) -> int:
        segment = next((item for item in self.segments if item.index == location.segment_number), None)
        if segment is None:
            raise ParseError(
                f"{self.path.name} has no PT_LOAD corresponding to runtime segment {location.segment_number}"
            )
        if location.offset >= segment.memory_size:
            raise ParseError(
                f"runtime offset 0x{location.offset:x} is outside image segment {segment.index}"
            )
        return segment.virtual_address + location.offset

    def summary(self) -> dict:
        return {
            "path": str(self.path),
            "module_name": self.module_name,
            "segments": [item.summary() for item in self.segments],
            "section_count": self.section_header_count,
        }


def parse_image_spec(spec: str) -> ElfImage:
    if "=" in spec:
        module_name, path = spec.split("=", 1)
        if not module_name or not path:
            raise ParseError(f"invalid image specification {spec!r}; expected MODULE=PATH")
        return ElfImage.read(path, module_name=module_name)
    return ElfImage.read(spec)


@dataclass(frozen=True)
class Symbolizer:
    images: tuple[ElfImage, ...]

    @classmethod
    def from_specs(cls, specs: Iterable[str]) -> "Symbolizer":
        return cls(tuple(parse_image_spec(spec) for spec in specs))

    def image_for_module(self, name: str) -> Optional[ElfImage]:
        exact = [item for item in self.images if item.module_name == name]
        if len(exact) == 1:
            return exact[0]
        folded = [item for item in self.images if item.module_name.casefold() == name.casefold()]
        return folded[0] if len(folded) == 1 else None

    def symbolize(self, location: AddressLocation) -> dict:
        image = self.image_for_module(location.module_name)
        result = location.summary()
        result.update({"image": None, "image_address": None, "function": None, "source": None, "symbolized": False})
        if image is None:
            result["error"] = f"no image supplied for module {location.module_name}"
            return result
        try:
            image_address = image.image_address(location)
            output = _run([
                _vita_tool("addr2line"), "-a", "-f", "-C", "-e", str(image.path), f"0x{image_address:x}",
            ])
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            if lines and lines[0].startswith("0x"):
                lines = lines[1:]
            result.update({
                "image": str(image.path),
                "image_address": image_address,
                "function": lines[0] if lines else None,
                "source": lines[1] if len(lines) > 1 else None,
                "symbolized": bool(lines and lines[0] != "??"),
            })
        except (ParseError, ToolError) as exc:
            result["error"] = str(exc)
        return result

    def symbolize_address(self, execution: ExecutionContext, address: int) -> dict:
        location = execution.modules.locate(address) if execution.modules else None
        if location is None:
            return {"address": address, "symbolized": False, "error": "address is not in a captured module segment"}
        return self.symbolize(location)


def disassemble_bytes(data: bytes, address: int, *, thumb: bool = False) -> str:
    if not data:
        raise ParseError("no bytes are available to disassemble")
    temporary = tempfile.NamedTemporaryFile(prefix="psp2-core-parse-", suffix=".bin", delete=False)
    path = Path(temporary.name)
    try:
        temporary.write(data)
        temporary.close()
        command = [
            _vita_tool("objdump"), "-D", "-b", "binary", "-m", "arm",
            f"--adjust-vma=0x{address:x}",
        ]
        if thumb:
            command.extend(["-M", "force-thumb"])
        command.append(str(path))
        return _run(command)
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def disassemble_core(core: CoreDump, address: int, size: int, *, thumb: bool = False) -> dict:
    address &= ~1
    data = core.read_memory(address, size)
    return {
        "address": address,
        "size": len(data),
        "thumb": thumb,
        "bytes": data.hex(),
        "text": disassemble_bytes(data, address, thumb=thumb),
    }
