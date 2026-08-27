from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Union

from .binary import align, c_string, ranges_merge


PT_LOAD = 1
PT_NOTE = 4
ELFCLASS32 = 1
ELFDATA2LSB = 1
EM_ARM = 40
ET_CORE = 4


class ParseError(ValueError):
    """The input cannot be interpreted as a Vita coredump."""


@dataclass(frozen=True)
class ParseIssue:
    severity: str
    code: str
    message: str
    file_offset: Optional[int] = None
    program_header: Optional[int] = None

    def summary(self) -> dict:
        result = {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }
        if self.file_offset is not None:
            result["file_offset"] = self.file_offset
        if self.program_header is not None:
            result["program_header"] = self.program_header
        return result


@dataclass(frozen=True)
class ProgramHeader:
    index: int
    segment_type: int
    file_offset: int
    virtual_address: int
    physical_address: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int
    available_size: int

    @property
    def complete(self) -> bool:
        return self.available_size == self.file_size

    @property
    def missing_size(self) -> int:
        return self.file_size - self.available_size

    def summary(self) -> dict:
        return {
            "index": self.index,
            "type": self.segment_type,
            "file_offset": self.file_offset,
            "virtual_address": self.virtual_address,
            "physical_address": self.physical_address,
            "file_size": self.file_size,
            "memory_size": self.memory_size,
            "flags": self.flags,
            "alignment": self.alignment,
            "available_size": self.available_size,
            "missing_size": self.missing_size,
            "complete": self.complete,
        }


@dataclass(frozen=True)
class Note:
    name: str
    note_type: int
    description: bytes
    declared_size: int
    segment_index: int
    file_offset: int
    complete: bool

    @property
    def format_version(self) -> Optional[int]:
        if len(self.description) < 4:
            return None
        return struct.unpack_from("<I", self.description)[0]

    @property
    def missing_size(self) -> int:
        return self.declared_size - len(self.description)

    def summary(self) -> dict:
        return {
            "name": self.name,
            "type": self.note_type,
            "format_version": self.format_version,
            "size": len(self.description),
            "declared_size": self.declared_size,
            "missing_size": self.missing_size,
            "complete": self.complete,
            "segment_index": self.segment_index,
            "file_offset": self.file_offset,
            "sha256": hashlib.sha256(self.description).hexdigest(),
        }


@dataclass(frozen=True)
class LoadSegment:
    index: int
    file_offset: int
    virtual_address: int
    physical_address: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int
    data: bytes

    @property
    def available_size(self) -> int:
        return len(self.data)

    @property
    def complete(self) -> bool:
        return len(self.data) == self.file_size

    @property
    def captured_end(self) -> int:
        return self.virtual_address + len(self.data)

    @property
    def memory_end(self) -> int:
        return self.virtual_address + self.memory_size

    @property
    def permissions(self) -> str:
        return "".join(
            (
                "r" if self.flags & 4 else "-",
                "w" if self.flags & 2 else "-",
                "x" if self.flags & 1 else "-",
            )
        )

    def contains(self, address: int, size: int = 1) -> bool:
        return (
            size >= 0
            and address >= self.virtual_address
            and address + size <= self.captured_end
        )

    def summary(self) -> dict:
        return {
            "index": self.index,
            "file_offset": self.file_offset,
            "virtual_address": self.virtual_address,
            "physical_address": self.physical_address,
            "file_size": self.file_size,
            "memory_size": self.memory_size,
            "available_size": len(self.data),
            "missing_size": self.file_size - len(self.data),
            "complete": self.complete,
            "flags": self.flags,
            "permissions": self.permissions,
            "alignment": self.alignment,
            "sha256": hashlib.sha256(self.data).hexdigest(),
        }


@dataclass(frozen=True)
class MemoryExtent:
    address: int
    size: int
    data: Optional[bytes]
    segment_index: Optional[int]

    @property
    def captured(self) -> bool:
        return self.data is not None

    def summary(self) -> dict:
        return {
            "address": self.address,
            "size": self.size,
            "captured": self.captured,
            "segment_index": self.segment_index,
            "sha256": hashlib.sha256(self.data).hexdigest() if self.data is not None else None,
        }


@dataclass
class CoreDump:
    path: Path
    compressed: bool
    compression_complete: bool
    raw_file_sha256: str
    image_sha256: str
    raw_file_size: int
    image_size: int
    elf_type: int
    machine: int
    flags: int
    program_header_offset: int
    program_header_size: int
    declared_program_header_count: int
    program_headers: list[ProgramHeader] = field(default_factory=list)
    notes: list[Note] = field(default_factory=list)
    loads: list[LoadSegment] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)
    image: bytes = field(default=b"", repr=False)

    @classmethod
    def read(cls, path: Union[Path, str], *, strict: bool = False) -> "CoreDump":
        path = Path(path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ParseError(f"cannot read {path}: {exc}") from exc
        compressed = raw.startswith(b"\x1f\x8b")
        issues: list[ParseIssue] = []
        if compressed:
            image, compression_complete = _decompress_gzip(raw, issues)
        else:
            image, compression_complete = raw, True
        core = cls._from_elf(
            path,
            raw,
            image,
            compressed,
            compression_complete,
            issues,
        )
        if strict:
            failures = [issue for issue in core.issues if issue.severity == "error"]
            if failures:
                raise ParseError("; ".join(issue.message for issue in failures))
        return core

    @classmethod
    def _from_elf(
        cls,
        path: Path,
        raw: bytes,
        image: bytes,
        compressed: bool,
        compression_complete: bool,
        issues: list[ParseIssue],
    ) -> "CoreDump":
        if len(image) < 52:
            raise ParseError(
                f"{path} has only 0x{len(image):x} decompressed bytes; ELF32 header is incomplete"
            )
        if image[:4] != b"\x7fELF":
            raise ParseError(f"{path} does not begin with an ELF header")
        if image[4] != ELFCLASS32:
            raise ParseError(f"unsupported ELF class {image[4]}; Vita cores are ELF32")
        if image[5] != ELFDATA2LSB:
            raise ParseError(f"unsupported ELF byte order {image[5]}; Vita cores are little-endian")
        (
            elf_type,
            machine,
            elf_version,
            _entry,
            phoff,
            _shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            _shentsize,
            _shnum,
            _shstrndx,
        ) = struct.unpack_from("<HHIIIIIHHHHHH", image, 16)
        if elf_version != 1:
            issues.append(ParseIssue("warning", "elf-version", f"unexpected ELF version {elf_version}"))
        if ehsize < 52:
            raise ParseError(f"invalid ELF header size 0x{ehsize:x}")
        if phnum and phentsize < 32:
            raise ParseError(f"invalid program-header size 0x{phentsize:x}")
        if elf_type != ET_CORE:
            issues.append(ParseIssue("warning", "elf-type", f"ELF type is {elf_type}, expected ET_CORE (4)"))
        if machine != EM_ARM:
            issues.append(ParseIssue("warning", "elf-machine", f"ELF machine is {machine}, expected ARM (40)"))

        available_phnum = 0
        if phoff <= len(image) and phentsize:
            available_phnum = min(phnum, (len(image) - phoff) // phentsize)
        if available_phnum < phnum:
            issues.append(
                ParseIssue(
                    "error",
                    "truncated-program-header-table",
                    f"program-header table declares {phnum} entries but only {available_phnum} are available",
                    phoff + available_phnum * phentsize,
                )
            )

        headers: list[ProgramHeader] = []
        notes: list[Note] = []
        loads: list[LoadSegment] = []
        for index in range(available_phnum):
            header_offset = phoff + index * phentsize
            values = struct.unpack_from("<8I", image, header_offset)
            segment_type, file_offset, vaddr, paddr, file_size, mem_size, seg_flags, seg_align = values
            if file_size == 0:
                available = 0
            elif file_offset >= len(image):
                available = 0
            else:
                available = min(file_size, len(image) - file_offset)
            header = ProgramHeader(
                index,
                segment_type,
                file_offset,
                vaddr,
                paddr,
                file_size,
                mem_size,
                seg_flags,
                seg_align,
                available,
            )
            headers.append(header)
            if not header.complete:
                issues.append(
                    ParseIssue(
                        "error",
                        "truncated-program-segment",
                        f"program segment {index} is missing 0x{header.missing_size:x} of 0x{file_size:x} bytes",
                        file_offset + available,
                        index,
                    )
                )
            if segment_type == PT_LOAD:
                if file_size > mem_size:
                    issues.append(
                        ParseIssue(
                            "warning",
                            "load-filesz-exceeds-memsz",
                            f"PT_LOAD {index} file size 0x{file_size:x} exceeds memory size 0x{mem_size:x}",
                            header_offset,
                            index,
                        )
                    )
                payload = image[file_offset : file_offset + available] if available else b""
                loads.append(
                    LoadSegment(
                        index,
                        file_offset,
                        vaddr,
                        paddr,
                        file_size,
                        mem_size,
                        seg_flags,
                        seg_align,
                        payload,
                    )
                )
            elif segment_type == PT_NOTE and available:
                payload = image[file_offset : file_offset + available]
                notes.extend(_parse_notes(payload, index, file_offset, file_size, issues))

        return cls(
            path=path,
            compressed=compressed,
            compression_complete=compression_complete,
            raw_file_sha256=hashlib.sha256(raw).hexdigest(),
            image_sha256=hashlib.sha256(image).hexdigest(),
            raw_file_size=len(raw),
            image_size=len(image),
            elf_type=elf_type,
            machine=machine,
            flags=flags,
            program_header_offset=phoff,
            program_header_size=phentsize,
            declared_program_header_count=phnum,
            program_headers=headers,
            notes=notes,
            loads=loads,
            issues=issues,
            image=image,
        )

    @property
    def complete(self) -> bool:
        return self.compression_complete and not any(
            issue.severity == "error" for issue in self.issues
        )

    def notes_named(self, name: str) -> list[Note]:
        return [note for note in self.notes if note.name == name]

    def notes_typed(self, note_type: int) -> list[Note]:
        return [note for note in self.notes if note.note_type == note_type]

    def note(self, name: str) -> Optional[Note]:
        matches = self.notes_named(name)
        return matches[-1] if matches else None

    def note_type(self, note_type: int) -> Optional[Note]:
        matches = self.notes_typed(note_type)
        return matches[-1] if matches else None

    def captured_ranges(self, start: int = 0, end: int = 0x100000000) -> list[tuple[int, int]]:
        if start < 0 or end < start:
            raise ParseError("invalid captured-range bounds")
        return ranges_merge(
            (
                max(start, segment.virtual_address),
                min(end, segment.captured_end),
            )
            for segment in self.loads
            if max(start, segment.virtual_address) < min(end, segment.captured_end)
        )

    def captured_bytes(self, start: int, end: int) -> int:
        return sum(last - first for first, last in self.captured_ranges(start, end))

    def memory_extents(self, address: int, size: int) -> list[MemoryExtent]:
        if address < 0 or size < 0 or address + size > 0x100000000:
            raise ParseError("invalid 32-bit memory range")
        if size == 0:
            return []
        end = address + size
        boundaries = {address, end}
        for segment in self.loads:
            first = max(address, segment.virtual_address)
            last = min(end, segment.captured_end)
            if first < last:
                boundaries.update((first, last))
        ordered = sorted(boundaries)
        result: list[MemoryExtent] = []
        for first, last in zip(ordered, ordered[1:]):
            candidates = [segment for segment in self.loads if segment.contains(first, last - first)]
            if candidates:
                segment = min(candidates, key=lambda item: item.index)
                offset = first - segment.virtual_address
                data = segment.data[offset : offset + last - first]
                extent = MemoryExtent(first, last - first, data, segment.index)
            else:
                extent = MemoryExtent(first, last - first, None, None)
            if (
                result
                and result[-1].captured == extent.captured
                and result[-1].segment_index == extent.segment_index
                and result[-1].address + result[-1].size == extent.address
            ):
                previous = result[-1]
                combined = (
                    previous.data + extent.data
                    if previous.data is not None and extent.data is not None
                    else None
                )
                result[-1] = MemoryExtent(previous.address, previous.size + extent.size, combined, previous.segment_index)
            else:
                result.append(extent)
        return result

    def read_memory(self, address: int, size: int) -> bytes:
        extents = self.memory_extents(address, size)
        missing = next((extent for extent in extents if not extent.captured), None)
        if missing is not None:
            raise ParseError(
                f"memory 0x{missing.address:08x}-0x{missing.address + missing.size:08x} is not captured"
            )
        return b"".join(extent.data or b"" for extent in extents)

    def load_alias_groups(self) -> list[list[int]]:
        groups: dict[tuple[int, int, str], list[int]] = {}
        for segment in self.loads:
            key = (
                segment.virtual_address,
                len(segment.data),
                hashlib.sha256(segment.data).hexdigest(),
            )
            groups.setdefault(key, []).append(segment.index)
        return [indices for indices in groups.values() if len(indices) > 1]

    def summary(self) -> dict:
        severities: dict[str, int] = {}
        for issue in self.issues:
            severities[issue.severity] = severities.get(issue.severity, 0) + 1
        return {
            "path": str(self.path),
            "compressed": self.compressed,
            "compression_complete": self.compression_complete,
            "complete": self.complete,
            "raw_file_size": self.raw_file_size,
            "image_size": self.image_size,
            "raw_file_sha256": self.raw_file_sha256,
            "image_sha256": self.image_sha256,
            "elf_type": self.elf_type,
            "machine": self.machine,
            "flags": self.flags,
            "declared_program_header_count": self.declared_program_header_count,
            "available_program_header_count": len(self.program_headers),
            "notes": [note.summary() for note in self.notes],
            "load_segments": [segment.summary() for segment in self.loads],
            "load_alias_groups": self.load_alias_groups(),
            "captured_bytes": sum(end - start for start, end in self.captured_ranges()),
            "issue_counts": severities,
            "issues": [issue.summary() for issue in self.issues],
        }


def _decompress_gzip(raw: bytes, issues: list[ParseIssue]) -> tuple[bytes, bool]:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = bytearray()
    cursor = 0
    chunk_size = 0x10000
    error: Optional[zlib.error] = None
    while cursor < len(raw):
        chunk = raw[cursor : cursor + chunk_size]
        cursor += len(chunk)
        try:
            output.extend(decoder.decompress(chunk))
        except zlib.error as exc:
            error = exc
            break
        if decoder.eof:
            break
    if error is not None:
        issues.append(
            ParseIssue(
                "error",
                "gzip-error",
                f"gzip stream failed after 0x{len(output):x} output bytes: {error}",
                cursor - len(chunk),
            )
        )
    elif not decoder.eof:
        issues.append(
            ParseIssue(
                "error",
                "truncated-gzip",
                f"gzip stream ended before its trailer after 0x{len(output):x} output bytes",
                len(raw),
            )
        )
    elif decoder.unused_data and any(decoder.unused_data):
        issues.append(
            ParseIssue(
                "warning",
                "gzip-trailing-data",
                f"gzip member is followed by 0x{len(decoder.unused_data):x} bytes",
                len(raw) - len(decoder.unused_data),
            )
        )
    return bytes(output), decoder.eof and error is None


def _parse_notes(
    data: bytes,
    segment_index: int,
    segment_file_offset: int,
    declared_segment_size: int,
    issues: list[ParseIssue],
) -> Iterable[Note]:
    offset = 0
    while offset < len(data):
        remaining = len(data) - offset
        if remaining < 12:
            if any(data[offset:]):
                issues.append(
                    ParseIssue(
                        "error",
                        "truncated-note-header",
                        f"PT_NOTE {segment_index} ends with {remaining} bytes of a note header",
                        segment_file_offset + offset,
                        segment_index,
                    )
                )
            break
        name_size, description_size, note_type = struct.unpack_from("<3I", data, offset)
        note_header_offset = offset
        offset += 12
        name_end = offset + name_size
        if name_end > len(data):
            issues.append(
                ParseIssue(
                    "error",
                    "truncated-note-name",
                    f"PT_NOTE {segment_index} note name declares 0x{name_size:x} bytes",
                    segment_file_offset + offset,
                    segment_index,
                )
            )
            break
        name = c_string(data[offset:name_end])
        description_offset = align(name_end, 4)
        if description_offset > len(data):
            description = b""
        else:
            description = data[
                description_offset : min(len(data), description_offset + description_size)
            ]
        complete = len(description) == description_size
        yield Note(
            name=name,
            note_type=note_type,
            description=description,
            declared_size=description_size,
            segment_index=segment_index,
            file_offset=segment_file_offset + description_offset,
            complete=complete,
        )
        if not complete:
            issues.append(
                ParseIssue(
                    "error",
                    "truncated-note-description",
                    f"{name or '<unnamed>'} declares 0x{description_size:x} description bytes but only 0x{len(description):x} are available",
                    segment_file_offset + description_offset + len(description),
                    segment_index,
                )
            )
            break
        next_offset = align(description_offset + description_size, 4)
        if next_offset <= note_header_offset:
            issues.append(
                ParseIssue(
                    "error",
                    "invalid-note-size",
                    f"PT_NOTE {segment_index} note does not advance",
                    segment_file_offset + note_header_offset,
                    segment_index,
                )
            )
            break
        offset = next_offset
    if len(data) < declared_segment_size and not data:
        issues.append(
            ParseIssue(
                "error",
                "missing-note-segment",
                f"PT_NOTE {segment_index} payload is unavailable",
                segment_file_offset,
                segment_index,
            )
        )
