# Copyright (c) 2026 psp2_core_parse contributors
# SPDX-License-Identifier: MIT

"""KERNEL_INFO: the SceCrashDump core inside a kernel coredump (title NPXS19998).

On a kernel exception, assertion, panic or bus error, SceSysmem (or
SceKernelBusError) fills the sysroot shared memory and calls monitor call
0x122. The secure world then encrypts the kernel's DRAM and mapped pages into
a reserved window and powers off. On the next boot SceCrashDump turns that
record into an ARM ELF core, which SceCoredump stores as the KERNEL_INFO note.
The core's notes, all owned by "PSP2", are:

  0x1000  the crash header: kind, CPU, monitor-call arguments, session ID, wrapped key
  0x1001  the physical address of each mapped page
  0x1100  the kernel TTY's last 4 KiB
  0x1200  SceSysmem's exception dump (kind 0)
  0x1201  SceSysmem's assertion or panic dump (kind 1)
  0x1202  SceKernelBusError's record (kind 2)

Its PT_LOAD segments hold physical memory: the DRAM range at its p_paddr,
then the mapped pages in page-list order.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field
from typing import Optional

from .buserror import decode_bus_error
from .core import ParseError, ParseIssue
from .execution import decode_fault_status
from .kerndump import _EXCEPTION_CODES, decode_debug_dump


NOTE_NAMES = {
    0x1000: "CRASH_INFO",
    0x1001: "PAGE_LIST",
    0x1100: "KERNEL_TTY",
    0x1200: "EXCEPTION_DUMP",
    0x1201: "FAULT_DUMP",
    0x1202: "BUS_ERROR",
}

KIND_NAMES = {0: "kernel exception", 1: "kernel assertion or panic", 2: "bus error"}

PAGE_SIZE = 0x1000

_FAULT_LINE = re.compile(r"\*\*\* Kernel (Assertion failed|Panic|[\w ]+? Exception) at [^\n]*")


def _firmware(version: int) -> str:
    return f"{version >> 24:x}.{(version >> 16) & 0xFF:02x}"


def _crash_header(data: bytes) -> dict:
    if len(data) < 0x20:
        raise ValueError("crash header is truncated")
    size, firmware, _, cpu, kind, ttbr0, vbar, sysroot = struct.unpack_from("<8I", data)
    return {
        "size": size, "firmware_version": firmware, "firmware": _firmware(firmware),
        "cpu": cpu, "kind": kind, "kind_name": KIND_NAMES.get(kind, f"unknown kind {kind}"),
        "ttbr0": ttbr0, "vbar": vbar, "sysroot": sysroot,
        "session_id": data[0x20:0x30].hex() if len(data) >= 0x30 else None,
        "wrapped_key_present": len(data) >= 0x50,
    }


def _tty(data: bytes) -> dict:
    # A ring copied oldest first: the part never written is zero.
    text = data.replace(b"\0", b"").decode("utf-8", "replace")
    lines = text.splitlines()
    match = None
    for match in _FAULT_LINE.finditer(text):
        pass
    return {
        "size": len(data), "text": text, "line_count": len(lines),
        "fault_line": match.group(0) if match else None,
        "fault_kind": match.group(1) if match else None,
    }


@dataclass
class KernelInfo:
    image: bytes = field(repr=False)
    issues: list[ParseIssue] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)
    segments: list[dict] = field(default_factory=list)
    crash: Optional[dict] = None
    pages: list[int] = field(default_factory=list)
    tty: Optional[dict] = None
    dump: Optional[dict] = None
    bus_error: Optional[dict] = None
    _memory: list[tuple[int, bytes]] = field(default_factory=list, repr=False)

    @classmethod
    def parse(cls, description: bytes, *, strict: bool = False) -> "KernelInfo":
        from .spsp2dmp import decrypt_kernel_info

        issues: list[ParseIssue] = []
        image = decrypt_kernel_info(description, strict=strict, issues=issues)
        result = cls(image, issues)
        result._parse_elf()
        if strict:
            failures = [issue for issue in result.issues if issue.severity == "error"]
            if failures:
                raise ParseError("; ".join(issue.message for issue in failures))
        return result

    @property
    def complete(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    def _issue(self, code: str, message: str, offset: Optional[int] = None) -> None:
        self.issues.append(ParseIssue("error", code, message, offset))

    def _parse_elf(self) -> None:
        image = self.image
        phoff = struct.unpack_from("<I", image, 28)[0]
        phentsize, phnum = struct.unpack_from("<2H", image, 42)
        loads = []
        for index in range(phnum):
            at = phoff + index * phentsize
            if at + 32 > len(image):
                self._issue("kernel-info-program-headers", f"KERNEL_INFO program header {index} was not captured", at)
                break
            kind, offset, _, paddr, filesz, _, flags, _ = struct.unpack_from("<8I", image, at)
            available = max(0, min(filesz, len(image) - offset))
            if kind == 4:
                self._parse_notes(image[offset:offset + available], offset, filesz)
            elif kind == 1:
                loads.append((index, offset, paddr, filesz, available, flags))
        self._map_loads(loads)

    def _parse_notes(self, data: bytes, base: int, declared: int) -> None:
        if len(data) < declared:
            self._issue("kernel-info-notes-truncated", f"KERNEL_INFO notes: 0x{len(data):x}/0x{declared:x} bytes captured", base + len(data))
        at = 0
        while at + 12 <= len(data):
            name_size, size, kind = struct.unpack_from("<3I", data, at)
            name_at = at + 12
            start = name_at + ((name_size + 3) & ~3)
            owner = data[name_at:name_at + name_size].split(b"\0", 1)[0].decode("latin-1")
            description = data[start:start + size]
            note = {
                "owner": owner, "type": kind, "name": NOTE_NAMES.get(kind, f"0x{kind:x}"),
                "file_offset": base + start, "size": size, "available_size": len(description),
                "sha256": hashlib.sha256(description).hexdigest(), "status": "decoded", "error": None,
            }
            self.notes.append(note)
            if len(description) < size:
                self._issue("kernel-info-note-truncated", f"KERNEL_INFO note {note['name']}: 0x{len(description):x}/0x{size:x} bytes captured", base + start)
                note["status"] = "partial"
            try:
                self._decode_note(kind, description, note)
            except (ValueError, struct.error) as exc:
                note["status"], note["error"] = "error", str(exc)
                self._issue("kernel-info-note-decoder", f"KERNEL_INFO note {note['name']}: {exc}", base + start)
            at = start + ((size + 3) & ~3)

    def _decode_note(self, kind: int, data: bytes, note: dict) -> None:
        if kind == 0x1000:
            self.crash = _crash_header(data)
        elif kind == 0x1001:
            self.pages = list(struct.unpack_from(f"<{len(data) // 4}I", data))
        elif kind == 0x1100:
            self.tty = _tty(data)
        elif kind in (0x1200, 0x1201):
            issues: list[ParseIssue] = []
            dump = decode_debug_dump(data, exception=kind == 0x1200, file_offset=note["file_offset"], issues=issues)
            self.issues.extend(issues)
            trailing = dump.pop("trailing")
            self.dump = {"kind": "exception" if kind == 0x1200 else "fault", **dump, "trailing_size": len(trailing)}
            if issues:
                note["status"] = "partial"
        elif kind == 0x1202:
            self.bus_error = decode_bus_error(data)
            if not self.bus_error["complete"]:
                note["status"] = "partial"
        else:
            note["status"] = "inventory"

    def _map_loads(self, loads: list[tuple]) -> None:
        for index, offset, paddr, size, available, flags in loads:
            data = self.image[offset:offset + available]
            role = "dram" if paddr else "pages"
            segment = {
                "index": index, "role": role, "physical_address": paddr if paddr else None,
                "file_offset": offset, "size": size, "available_size": available,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            if available < size:
                self._issue("kernel-info-segment-truncated", f"KERNEL_INFO segment {index}: 0x{available:x}/0x{size:x} bytes recovered", offset + available)
            if role == "dram":
                self._memory.append((paddr, data))
            else:
                segment["page_count"] = size // PAGE_SIZE
                if len(self.pages) * PAGE_SIZE != size:
                    self._issue("kernel-info-page-list", f"KERNEL_INFO page list names {len(self.pages)} pages; segment {index} holds 0x{size:x} bytes")
                for page_index, address in enumerate(self.pages):
                    page = data[page_index * PAGE_SIZE:(page_index + 1) * PAGE_SIZE]
                    if page:
                        self._memory.append((address, page))
            self.segments.append(segment)
        self._memory.sort(key=lambda item: item[0])

    def read_physical(self, address: int, size: int) -> Optional[bytes]:
        """Captured physical memory, or None when any byte is missing."""
        result = bytearray()
        while size:
            for base, data in self._memory:
                if base <= address < base + len(data):
                    chunk = data[address - base:address - base + size]
                    break
            else:
                return None
            result += chunk
            address += len(chunk)
            size -= len(chunk)
        return bytes(result)

    def analysis(self) -> dict:
        """The classification, verdict and failure bucket of the kernel crash."""
        kind = self.crash["kind"] if self.crash else None
        dump = self.dump or {}
        header = dump.get("header") or {}
        context = dump.get("exception_context")
        fault = None
        location = None
        if kind == 2 or (kind is None and self.bus_error):
            classification = "KERNEL_BUS_ERROR"
        elif dump.get("kind") == "exception" and context:
            code = context["exception_code"]
            classification = _EXCEPTION_CODES.get(code, f"KERNEL_EXCEPTION_{code}")
            location = context["fault_module"]
            if classification in ("KERNEL_DATA_ABORT", "KERNEL_PREFETCH_ABORT"):
                instruction = classification == "KERNEL_PREFETCH_ABORT"
                registers = context["registers"]
                fault = {
                    "address": registers["ifar" if instruction else "dfar"],
                    "status": decode_fault_status(registers["ifsr" if instruction else "dfsr"], instruction=instruction),
                }
        elif kind == 0:
            classification = "KERNEL_EXCEPTION"
        elif kind == 1:
            reported = (self.tty or {}).get("fault_kind")
            classification = {"Assertion failed": "KERNEL_ASSERTION", "Panic": "KERNEL_PANIC"}.get(reported, "KERNEL_ASSERTION_OR_PANIC")
        else:
            classification = "KERNEL_CRASH"
        frames = dump.get("kernel_backtrace") or []
        if location is None and frames:
            location = frames[0]["module"]

        components = [classification]
        if self.crash:
            components.append(f"fw={self.crash['firmware_version']:08x}")
        if location:
            components.append(location["notation"])
        elif context:
            components.append(f"pc=0x{context['registers']['pc']:08x}")
        if header and dump.get("kind") == "fault":
            components.append(":".join(f"{header[key]:08x}" for key in ("file_hash", "line_hash", "function_hash")))
        if fault:
            components.append(f"fs:{fault['status']['status_code']:02x}")
        if classification == "KERNEL_BUS_ERROR" and self.bus_error and self.bus_error["ocp"]:
            components.extend(f"ocp:{item['target']}" for item in self.bus_error["ocp"]["target_errors"])
        canonical = "|".join(components)

        verdict = f"{classification.replace('_', ' ').capitalize()} recorded by SceCrashDump"
        if self.crash:
            verdict += f" on CPU {self.crash['cpu']}"
        if location:
            verdict += f" at {location['notation']}"
        verdict += "."
        if fault:
            status = fault["status"]
            access = "instruction fetch" if "write" not in status else "write" if status["write"] else "read"
            verdict += f" The MMU reported {status['status_name']} during a {access} at 0x{fault['address']:08x}."
        if classification == "KERNEL_BUS_ERROR" and self.bus_error and self.bus_error["ocp"]:
            ocp = self.bus_error["ocp"]
            targets = ", ".join(f"{item['target']} (0x{item['address']:08x})" for item in ocp["target_errors"])
            if targets:
                verdict += f" OCP target errors: {targets}."
            if ocp["buses_in_error"]:
                verdict += f" Buses in error: {', '.join(ocp['buses_in_error'])}."
        if self.tty and self.tty["fault_line"]:
            verdict += f" Kernel TTY: {self.tty['fault_line'].strip()}"
        return {
            "classification": classification,
            "verdict": verdict,
            "fault": fault,
            "location": location,
            "failure_bucket": {
                "canonical": canonical,
                "sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                "components": components,
            },
        }

    def summary(self) -> dict:
        return {
            "complete": self.complete,
            "elf_size": len(self.image),
            "elf_sha256": hashlib.sha256(self.image).hexdigest(),
            "crash": self.crash,
            "notes": self.notes,
            "segments": self.segments,
            "page_count": len(self.pages),
            "pages": self.pages,
            "tty": self.tty,
            "dump": self.dump,
            "bus_error": self.bus_error,
            "analysis": self.analysis(),
            "issues": [issue.summary() for issue in self.issues],
        }
