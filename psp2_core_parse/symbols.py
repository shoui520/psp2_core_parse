from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Optional, Union

from .core import CoreDump, ParseError
from .execution import AddressLocation, ExecutionContext


class ToolError(RuntimeError):
    pass


@dataclass(frozen=True)
class SourcePathMap:
    old_prefix: str
    local_prefix: Path
    prefix_strip: int

    @classmethod
    def parse(cls, spec: str) -> "SourcePathMap":
        if "=" not in spec:
            raise ParseError(f"invalid source mapping {spec!r}; expected OLD=LOCAL")
        old, local = spec.split("=", 1)
        old_path = PurePosixPath(old)
        if not old or not local or not old_path.is_absolute():
            raise ParseError(f"invalid source mapping {spec!r}; OLD must be an absolute build path")
        local_path = Path(local).expanduser().resolve()
        if not local_path.is_dir():
            raise ParseError(f"source mapping directory does not exist: {local_path}")
        return cls(old, local_path, len(old_path.parts) - 1)

    def summary(self) -> dict:
        return {
            "old_prefix": self.old_prefix,
            "local_prefix": str(self.local_prefix),
            "prefix_strip": self.prefix_strip,
        }


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


_INSTRUCTION_LINE = re.compile(r"^\s*(?:!!!\s+)?[0-9a-fA-F]+:\s")
_SYMBOL_LINE = re.compile(r"^\s*[0-9a-fA-F]+\s+<[^>]+>:\s*$")


def _objdump_body(output: str) -> str:
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("Disassembly of section "):
            lines = lines[index + 1 :]
            break
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def _mark_instruction(text: str, address: int) -> tuple[str, bool]:
    pattern = re.compile(rf"^(\s*){address:x}:\s", re.IGNORECASE)
    lines = []
    marked = False
    for line in text.splitlines():
        if not marked and pattern.match(line):
            lines.append(f"!!! {line.strip()} !!!")
            marked = True
        else:
            lines.append(line)
    return "\n".join(lines), marked


def _contains_source_lines(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or _INSTRUCTION_LINE.match(line) or _SYMBOL_LINE.match(line):
            continue
        return True
    return False


def disassemble_image(
    image: ElfImage,
    start_address: int,
    stop_address: int,
    target_address: int,
    *,
    thumb: bool = False,
    include_source: bool = True,
    source_map: Optional[SourcePathMap] = None,
) -> dict:
    if stop_address <= start_address:
        raise ParseError("invalid ELF disassembly range")
    command = [_vita_tool("objdump"), "-d", "-C"]
    if include_source:
        command.append("-S")
        if source_map is not None:
            command.extend((
                f"--prefix={source_map.local_prefix}",
                f"--prefix-strip={source_map.prefix_strip}",
                "-I", str(source_map.local_prefix),
            ))
    command.extend((
        f"--start-address=0x{start_address:x}",
        f"--stop-address=0x{stop_address:x}",
    ))
    if thumb:
        command.extend(("-M", "force-thumb"))
    command.append(str(image.path))
    text, marked = _mark_instruction(_objdump_body(_run(command)), target_address)
    return {
        "text": text,
        "target_instruction_marked": marked,
        "source_interleaving_requested": include_source,
        "source_interleaved": include_source and _contains_source_lines(text),
    }


def _aligned_window(address: int, before: int, after: int, thumb: bool) -> tuple[int, int]:
    if before < 0 or after <= 0:
        raise ParseError("disassembly context must have non-negative before bytes and positive after bytes")
    alignment = 2 if thumb else 4
    start = max(0, address - before)
    start -= start % alignment
    stop = min(0x100000000, address + after)
    stop = min(0x100000000, (stop + alignment - 1) & ~(alignment - 1))
    return start, stop


def _captured_window(
    core: CoreDump,
    requested_start: int,
    requested_stop: int,
    target: int,
    instruction_width: int,
) -> tuple[int, bytes]:
    for start, stop in core.captured_ranges(requested_start, requested_stop):
        if start <= target and target + instruction_width <= stop:
            return start, core.read_memory(start, stop - start)
    raise ParseError(f"instruction at 0x{target:08x} is not captured")


def _image_window(
    image: ElfImage,
    location: AddressLocation,
    target: int,
    requested_start: int,
    requested_stop: int,
    instruction_width: int,
) -> tuple[int, int, bytes]:
    image_address = image.image_address(location)
    segment = next((item for item in image.segments if item.index == location.segment_number), None)
    if segment is None:
        raise ParseError(f"{image.path.name} has no image segment {location.segment_number}")
    file_stop = segment.virtual_address + segment.file_size
    before = target - requested_start
    after = requested_stop - target
    start = max(segment.virtual_address, image_address - before)
    stop = min(file_stop, image_address + after)
    if image_address + instruction_width > stop:
        raise ParseError(f"faulting instruction is not file-backed in {image.path}")
    return start, image_address, image.linked_bytes(start, stop - start)


def disassemble_address(
    core: CoreDump,
    execution: ExecutionContext,
    symbolizer: Symbolizer,
    address: int,
    *,
    thumb: bool = False,
    before: int = 16,
    after: int = 64,
    include_source: bool = True,
    source_map: Optional[SourcePathMap] = None,
) -> dict:
    """Disassemble around a runtime address without treating an unverified ELF as authoritative."""
    target = address & ~1
    instruction_width = 2 if thumb else 4
    requested_start, requested_stop = _aligned_window(target, before, after, thumb)
    location = execution.modules.locate(target) if execution.modules else None
    symbol = symbolizer.symbolize(location) if location and symbolizer.images else None
    image = symbolizer.image_for_module(location.module_name) if location else None
    result = {
        "status": "unavailable",
        "address": target,
        "runtime_address": target,
        "requested_start": requested_start,
        "requested_stop": requested_stop,
        "before": before,
        "after": after,
        "thumb": thumb,
        "instruction_width": instruction_width,
        "runtime_location": location.summary() if location else None,
        "symbol": symbol,
        "source": None,
        "size": 0,
        "bytes": "",
        "text": None,
        "target_instruction_marked": False,
        "source_interleaving_requested": include_source,
        "source_interleaved": False,
        "source_map": source_map.summary() if source_map else None,
        "captured_memory": None,
        "image_memory": None,
        "byte_comparison": "not-compared",
        "warnings": [],
        "errors": [],
    }

    captured_start = None
    captured_data = None
    try:
        captured_start, captured_data = _captured_window(
            core, requested_start, requested_stop, target, instruction_width
        )
        result["captured_memory"] = {
            "available": True, "start_address": captured_start,
            "stop_address": captured_start + len(captured_data),
            "size": len(captured_data), "bytes": captured_data.hex(), "error": None,
        }
    except ParseError as exc:
        result["captured_memory"] = {
            "available": False, "start_address": None, "stop_address": None,
            "size": 0, "bytes": "", "error": str(exc),
        }

    image_start = None
    image_address = None
    image_data = None
    if image is not None and location is not None:
        try:
            image_start, image_address, image_data = _image_window(
                image, location, target, requested_start, requested_stop, instruction_width
            )
            result["image_memory"] = {
                "available": True, "image": str(image.path),
                "start_address": image_start, "target_address": image_address,
                "stop_address": image_start + len(image_data),
                "size": len(image_data), "bytes": image_data.hex(), "error": None,
            }
        except ParseError as exc:
            result["image_memory"] = {
                "available": False, "image": str(image.path),
                "start_address": None, "target_address": None, "stop_address": None,
                "size": 0, "bytes": "", "error": str(exc),
            }

    if captured_data is not None and image is not None and location is not None and image_address is not None:
        try:
            compare_address = image_address + captured_start - target
            comparison_bytes = image.linked_bytes(compare_address, len(captured_data))
            if comparison_bytes == captured_data:
                result["byte_comparison"] = "match"
            else:
                result["byte_comparison"] = "mismatch"
                result["warnings"].append(
                    "captured code differs from the supplied ELF; captured memory is authoritative"
                )
        except ParseError as exc:
            result["warnings"].append(f"could not compare captured and ELF code: {exc}")

    use_image = image_data is not None and (
        captured_data is None or result["byte_comparison"] == "match"
    )
    if use_image and image is not None and image_start is not None and image_address is not None:
        try:
            rendered = disassemble_image(
                image, image_start, image_start + len(image_data), image_address,
                thumb=thumb, include_source=include_source, source_map=source_map,
            )
            result.update(rendered)
            if not rendered["target_instruction_marked"]:
                result["warnings"].append("objdump did not emit the exact target instruction")
            result.update({
                "status": "available",
                "source": "supplied-image" if captured_data is None else "captured-memory+verified-image",
                "start_address": target - (image_address - image_start),
                "stop_address": target - (image_address - image_start) + len(image_data),
                "image": str(image.path),
                "image_address": image_address,
                "image_start_address": image_start,
                "size": len(image_data),
                "bytes": image_data.hex(),
            })
            return result
        except (ParseError, ToolError) as exc:
            result["errors"].append(f"ELF disassembly failed: {exc}")

    if captured_data is not None and captured_start is not None:
        try:
            text, marked = _mark_instruction(
                _objdump_body(disassemble_bytes(captured_data, captured_start, thumb=thumb)), target
            )
            if not marked:
                result["warnings"].append("objdump did not emit the exact target instruction")
            result.update({
                "status": "available", "source": "captured-memory",
                "start_address": captured_start, "stop_address": captured_start + len(captured_data),
                "size": len(captured_data), "bytes": captured_data.hex(), "text": text,
                "target_instruction_marked": marked, "source_interleaved": False,
            })
            return result
        except (ParseError, ToolError) as exc:
            result["errors"].append(f"captured-memory disassembly failed: {exc}")

    if image is None:
        if location is None:
            result["errors"].append("runtime address is not mapped by MODULE_INFO")
        elif symbolizer.images:
            result["errors"].append(f"no supplied image matches module {location.module_name}")
        else:
            result["errors"].append("no decrypted image was supplied")
    if result["captured_memory"] and result["captured_memory"]["error"]:
        result["errors"].append(result["captured_memory"]["error"])
    if result["image_memory"] and result["image_memory"]["error"]:
        result["errors"].append(result["image_memory"]["error"])
    result["error"] = "; ".join(dict.fromkeys(result["errors"])) or "disassembly is unavailable"
    return result
