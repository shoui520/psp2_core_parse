# Copyright (c) 2026 devnoname120
# SPDX-License-Identifier: MIT

"""Development-kit kernel dumps, based on Princess of Sleeping's parser.

Format definitions and decryption parameters:
https://github.com/Princess-of-Sleeping/psp2kerndmp-parser
Copyright (c) 2022 Princess-of-Sleeping; MIT notice in LICENSES/psp2kerndmp-parser.txt.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from .core import ParseError, ParseIssue
from .execution import decode_fault_status


ENCRYPTED = 0x20000000
PLAINTEXT = 0x10000000
_KEY = bytes.fromhex("235a93c1021f1553b83d4761ecfdb4ef6319d247e1c529642573a6babd38cb1a")
_IV = bytes.fromhex("47fb050ea6f5fecbcc019de0901fc167")
_EXCEPTION_CODES = {1: "KERNEL_DATA_ABORT", 4: "KERNEL_PREFETCH_ABORT", 6: "KERNEL_UNDEFINED_INSTRUCTION"}
_WAYPOINT_EVENTS = ("direct branch", "indirect branch", "exception", "DMB/DSB/ISB", "debug entry", "debug exit", "reserved 6", "reserved 7")
_EXCEPTION_CAUSES = (
    "unknown", "halting debug-mode", "secure monitor", "reserved 3",
    "imprecise data abort", "T2EE trap", "reserved 6", "reserved 7",
    "reset", "undefined instruction", "SVC", "prefetch abort",
    "precise data abort", "software watchpoint", "IRQ", "FIQ",
)
_DEBUG_EVENTS = {
    0: "halt request", 1: "breakpoint", 2: "asynchronous watchpoint",
    3: "BKPT instruction", 4: "external debug request", 5: "vector catch",
    8: "OS unlock catch", 10: "synchronous watchpoint",
}


def looks_like_kernel_dump(prefix: bytes) -> bool:
    if len(prefix) < 0x34:
        return False
    _, dump_type, content_size, _, _, flags, blob_size, offset = struct.unpack_from("<8I", prefix)
    return (
        dump_type in (1, 3) and bool(flags & (ENCRYPTED | PLAINTEXT))
        and 0x28 <= offset <= content_size and 4 <= blob_size <= content_size - offset
    )


def _decrypt(data: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise ParseError(
            "encrypted .psp2kerndmp requires cryptography; install psp2-core-parse[kernel]"
        ) from exc
    decryptor = Cipher(algorithms.AES(_KEY), modes.CBC(_IV)).decryptor()
    # The container supplies the byte count; removing PKCS#7 padding would discard evidence.
    return decryptor.update(data) + decryptor.finalize()


def _module(fingerprint: int, base: int, address: int) -> Optional[dict]:
    if fingerprint == 0xFFFFFFFF:
        return None
    return {
        "fingerprint": fingerprint, "module_base": base,
        "address": address, "offset": (address - base) & 0xFFFFFFFF,
        "notation": f"0x{fingerprint:08x}+0x{(address - base) & 0xFFFFFFFF:x}",
    }


def _registers(gpr: list[int], cpsr: int) -> dict:
    return {
        "gpr": gpr, "sp": gpr[13], "lr": gpr[14], "pc": gpr[15],
        "cpsr": cpsr, "thumb": bool(cpsr & 0x20),
    }


def _saved_registers(data: bytes) -> dict:
    gpr = list(struct.unpack_from("<13I", data)) + list(struct.unpack_from("<3I", data, 0x50))
    result = _registers(gpr, struct.unpack_from("<I", data, 0x5C)[0])
    result.update({
        "source": "saved-thread", "fpscr": struct.unpack_from("<I", data, 0x3C)[0],
        "unknown_34": struct.unpack_from("<2I", data, 0x34),
        "unknown_40": struct.unpack_from("<4I", data, 0x40),
    })
    return result


def _exception_context(data: bytes, modules: bytes) -> dict:
    words = struct.unpack_from("<64I", data)
    registers = _registers(list(words[:16]), words[0x44 // 4])
    registers["source"] = "exception"
    registers["spsr"] = registers["cpsr"]
    for name, offset in (
        ("cpacr", 0x48), ("fpscr", 0x4C), ("fpexc", 0x50), ("contextidr", 0x54),
        ("tpidrurw", 0x58), ("tpidruro", 0x5C), ("tpidrprw", 0x60), ("ttbr1", 0x64),
        ("dacr", 0x6C), ("dfsr", 0x70), ("ifsr", 0x74), ("dfar", 0x78), ("ifar", 0x7C),
        ("par", 0x80), ("teehbr", 0x84), ("pmcr", 0x88), ("pmcntenset", 0x8C),
        ("pmcntenset_copy", 0x90), ("pmselr", 0x94), ("pmccntr", 0x98), ("pmuserenr", 0x9C),
        ("dbgdscr", 0xD8),
    ):
        registers[name] = words[offset // 4]
    registers["performance_counters"] = [
        {"event_type": words[0x28 + index * 2], "count": words[0x29 + index * 2]}
        for index in range(6)
    ]
    registers["vfp_d"] = list(struct.unpack_from("<32Q", data, 0x100))
    debug_code = (registers["dbgdscr"] >> 2) & 0xF
    cursor = (words[0xD4 // 4] >> 8) & 0x1F
    waypoints = []
    for step in range(1, 33):
        index = (cursor + step) & 0x1F
        flags, pc, target, event = struct.unpack_from("<4I", data, 0x200 + index * 16)
        if not event & 0x80000000:
            continue
        point = {
            "index": index, "flags": flags, "pc": pc, "target_pc": target,
            "event": event, "event_name": _WAYPOINT_EVENTS[event & 7],
            "source_module": None, "target_module": None,
        }
        for slot, name, address in ((index * 2, "source_module", pc), (index * 2 + 1, "target_module", target)):
            if (slot + 1) * 8 <= len(modules):
                point[name] = _module(*struct.unpack_from("<2I", modules, slot * 8), address)
        if event & 7 == 2:
            point["exception_cause"] = _EXCEPTION_CAUSES[(event >> 4) & 0xF]
        elif event & 7 < 2:
            mode = event & 0x1800
            point["instruction_set"] = (
                "ARM" if mode == 0 else "Jazelle" if mode == 0x800
                else ("Thumb-32" if event & 0x200 else "Thumb-16") if mode == 0x1000
                else ("ThumbEE-32" if event & 0x200 else "ThumbEE-16")
            )
            point["link"] = bool(event & 0x100)
            point["taken"] = bool(event & 0x400)
        waypoints.append(point)
        if event & 7 == 2 and event & 0xF0 != 0x50:
            break
    return {
        "exception_kind": words[0x40 // 4], "exception_code": words[0xFC // 4],
        "registers": registers,
        "fault_module": _module(words[0xF0 // 4], words[0xF4 // 4], registers["pc"]),
        "debug_event": (
            {"code": debug_code, "name": _DEBUG_EVENTS.get(debug_code, "reserved")}
            if registers["ifsr"] & 0x40F == 2 else None
        ),
        "waypoint_cursor": cursor, "waypoints": waypoints,
    }


@dataclass
class KernelDump:
    path: Path
    raw_file_size: int
    raw_file_sha256: str
    container: dict
    info: dict
    blob: bytes = field(repr=False)
    issues: list[ParseIssue] = field(default_factory=list)
    header: dict = field(default_factory=dict)
    kernel_backtrace: list[dict] = field(default_factory=list)
    user_backtrace: list[dict] = field(default_factory=list)
    exception_context: Optional[dict] = None
    saved_thread_registers: Optional[dict] = None
    trailing: bytes = field(default=b"", repr=False)

    @classmethod
    def read(cls, path: Union[Path, str], *, strict: bool = False) -> "KernelDump":
        path = Path(path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ParseError(f"cannot read {path}: {exc}") from exc
        if len(raw) < 0x34:
            raise ParseError("truncated .psp2kerndmp container header (requires 0x34 bytes)")
        unknown, dump_type, content_size = struct.unpack_from("<3I", raw)
        if dump_type not in (1, 3):
            raise ParseError(f"unsupported .psp2kerndmp type {dump_type}")
        if content_size < 0x28:
            raise ParseError(".psp2kerndmp content is smaller than its information header")
        fw, unknown_10, flags, blob_size, offset, unknown_20, session = struct.unpack_from("<6I16s", raw, 12)
        if not flags & (ENCRYPTED | PLAINTEXT):
            raise ParseError(f"unsupported .psp2kerndmp flags 0x{flags:08x}: no plaintext/encrypted marker")
        if not 0x28 <= offset <= content_size:
            raise ParseError(f"invalid .psp2kerndmp blob offset 0x{offset:x}")
        if blob_size < 4 or blob_size > content_size - offset:
            raise ParseError(".psp2kerndmp blob size exceeds the declared content or is smaller than a header word")
        encrypted = bool(flags & ENCRYPTED)
        if encrypted and blob_size % 16:
            raise ParseError("encrypted .psp2kerndmp blob size is not a multiple of the AES block size (16)")
        issues = []
        if 12 + content_size > len(raw):
            issues.append(ParseIssue("error", "truncated-kernel-container", "truncated .psp2kerndmp content", len(raw)))
        elif 12 + content_size < len(raw):
            issues.append(ParseIssue("warning", "kernel-container-tail", f"{len(raw) - 12 - content_size} bytes follow the declared container", 12 + content_size))
        blob = raw[12 + offset:12 + offset + blob_size]
        if encrypted:
            blob = _decrypt(blob[:len(blob) - len(blob) % 16])
        dump = cls(
            path, len(raw), hashlib.sha256(raw).hexdigest(),
            {"unknown_00": unknown, "type": dump_type, "content_size": content_size},
            {
                "firmware_version": fw,
                "firmware_version_string": f"{fw >> 24:X}.{(fw >> 12) & 0xFFF:03X}.{fw & 0xFFF:03X}",
                "unknown_10": unknown_10, "flags": flags, "blob_size": blob_size,
                "blob_offset": offset, "blob_file_offset": 12 + offset,
                "unknown_20": unknown_20, "session_id": session.hex(), "encrypted": encrypted,
            },
            blob, issues,
        )
        dump._decode_blob()
        if strict and not dump.complete:
            raise ParseError("; ".join(issue.message for issue in dump.issues if issue.severity == "error"))
        return dump

    @property
    def complete(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    def _record(self, offset: int, size: int, name: str) -> Optional[bytes]:
        if offset + size <= len(self.blob):
            return self.blob[offset:offset + size]
        self.issues.append(ParseIssue(
            "error", "truncated-kernel-record", f"truncated {name} at blob offset 0x{offset:x} (requires 0x{size:x} bytes)",
            self.info["blob_file_offset"] + min(offset, len(self.blob)),
        ))
        return None

    def _decode_blob(self) -> None:
        self.trailing = self.blob
        if self._record(0, 4, "blob header") is None:
            return
        size = struct.unpack_from("<I", self.blob)[0]
        if size not in (0x38, 0x40):
            self.issues.append(ParseIssue(
                "error", "unsupported-kernel-blob-header",
                f"unsupported .psp2kerndmp blob header size 0x{size:x}; "
                "preserving container metadata and uninterpreted plaintext",
                self.info["blob_file_offset"],
            ))
            return
        if self._record(0, size, "blob header") is None:
            return
        _, pid, tid, cpu, time, file_hash, line_hash, func_hash = struct.unpack_from("<4IQ3I", self.blob)
        counts_offset = 0x24 if size == 0x38 else 0x2C
        kernel_count, user_count, stride, unknown_size, context_flags = struct.unpack_from("<5I", self.blob, counts_offset)
        self.header = {
            "size": size, "process_id": pid, "thread_id": tid, "cpu_id": cpu,
            "system_time_us": time, "file_hash": file_hash, "line_hash": line_hash, "function_hash": func_hash,
            "kernel_backtrace_count": kernel_count, "user_backtrace_count": user_count,
            "backtrace_element_size": stride, "unknown_size": unknown_size, "context_flags": context_flags,
        }
        if size == 0x40:
            self.header.update(zip(("uid_24", "unknown_28"), struct.unpack_from("<2I", self.blob, 0x24)))
        if (kernel_count or user_count) and stride < 0x10:
            self.issues.append(ParseIssue(
                "error", "invalid-kernel-backtrace-stride",
                f"invalid kernel backtrace element stride 0x{stride:x}; subsequent records are uninterpreted",
                self.info["blob_file_offset"] + counts_offset + 8,
            ))
            self.trailing = self.blob[size:]
            return
        offset = used = size
        for name, count, records in (
            ("kernel backtrace", kernel_count, self.kernel_backtrace),
            ("user backtrace", user_count, self.user_backtrace),
        ):
            available = min(count, max(0, len(self.blob) - offset) // stride) if count else 0
            if available < count:
                self.issues.append(ParseIssue("error", "truncated-kernel-backtrace", f"truncated {name}: {available}/{count} records available"))
            for index in range(available):
                start = offset + index * stride
                sp, pc, fingerprint, base = struct.unpack_from("<4I", self.blob, start)
                records.append({
                    "index": index, "sp": sp, "pc": pc, "fingerprint": fingerprint, "module_base": base,
                    "module": _module(fingerprint, base, pc), "extra_hex": self.blob[start + 16:start + stride].hex(),
                })
                used = start + stride
            # Later records follow the declared arrays, never the salvaged array lengths.
            offset += count * stride
        if self.container["type"] == 3:
            context = self._record(offset, 0x400, "exception context")
            modules = self._record(offset + 0x400, 0x200, "waypoint module table")
            if context is not None:
                available_modules = self.blob[offset + 0x400:offset + 0x600]
                self.exception_context = _exception_context(context, available_modules)
                used = offset + 0x400
                if modules is not None:
                    used += 0x200
            offset += 0x600
        if context_flags == 0x22:
            registers = self._record(offset, 0x60, "saved thread registers")
            if registers is not None:
                self.saved_thread_registers = _saved_registers(registers)
                used = offset + 0x60
        self.trailing = self.blob[used:]

    def summary(self) -> dict:
        return {
            "path": str(self.path), "format": "psp2kerndmp", "complete": self.complete,
            "raw_file_size": self.raw_file_size, "raw_file_sha256": self.raw_file_sha256,
            "container": self.container, **self.info,
            "available_blob_size": len(self.blob), "blob_sha256": hashlib.sha256(self.blob).hexdigest(),
            "blob_header_recovered": bool(self.header),
            "issues": [issue.summary() for issue in self.issues],
        }

    def modules(self) -> list[dict]:
        modules = {}
        evidence = [("kernel-backtrace", frame["module"]) for frame in self.kernel_backtrace]
        evidence += [("user-backtrace", frame["module"]) for frame in self.user_backtrace]
        if self.exception_context:
            evidence.append(("fault-pc", self.exception_context["fault_module"]))
            for point in self.exception_context["waypoints"]:
                evidence.extend((("waypoint-source", point["source_module"]), ("waypoint-target", point["target_module"])))
        for source, module in evidence:
            if module is None:
                continue
            key = (module["fingerprint"], module["module_base"])
            entry = modules.setdefault(key, {"fingerprint": key[0], "module_base": key[1], "sources": []})
            if source not in entry["sources"]:
                entry["sources"].append(source)
        return list(modules.values())

    def thread(self) -> Optional[dict]:
        if not self.header:
            return None
        context = self.exception_context
        return {
            "index": 0, "uid": self.header["thread_id"], "name": None,
            "process_id": self.header["process_id"], "cpu_id": self.header["cpu_id"],
            "registers": context["registers"] if context else self.saved_thread_registers,
            "pc_location": context["fault_module"] if context else None,
        }

    def analysis(self) -> dict:
        context = self.exception_context
        if self.container["type"] == 1:
            classification = "KERNEL_PANIC"
        elif context:
            code = context["exception_code"]
            classification = _EXCEPTION_CODES.get(code, f"KERNEL_EXCEPTION_{code}")
        else:
            classification = "KERNEL_EXCEPTION"
        fault = None
        if context and classification in ("KERNEL_DATA_ABORT", "KERNEL_PREFETCH_ABORT"):
            instruction = classification == "KERNEL_PREFETCH_ABORT"
            registers = context["registers"]
            fault = {
                "address": registers["ifar" if instruction else "dfar"],
                "status": decode_fault_status(registers["ifsr" if instruction else "dfsr"], instruction=instruction),
            }
        location = context["fault_module"] if context else None
        if location is None and self.kernel_backtrace:
            location = self.kernel_backtrace[0]["module"]
        site = location["notation"] if location else "unknown"
        if context and location is None:
            site = f"pc=0x{context['registers']['pc']:08x}"
        canonical = f"{classification}|fw={self.info['firmware_version']:08x}|{site}"
        if not self.header:
            canonical += f"|unparsed-sha256={self.raw_file_sha256}"
        elif self.container["type"] == 1:
            canonical += "|" + ":".join(f"{self.header[key]:08x}" for key in ("file_hash", "line_hash", "function_hash"))
        verdict = classification.replace("_", " ").capitalize()
        verdict += (
            " recorded in .psp2kerndmp." if self.header else
            " indicated by container; diagnostic blob header was not recovered."
        )
        return {
            "dump": self.summary(), "classification": classification,
            "classification_source": "exception-context" if context else "container",
            "verdict": verdict,
            "process": {"process_id": self.header["process_id"]} if self.header else None,
            "primary_crash_thread": self.thread(),
            "failure_bucket": {"canonical": canonical, "sha256": hashlib.sha256(canonical.encode()).hexdigest()},
            "fault": fault,
            "kernel_dump": {
                "header": self.header, "kernel_backtrace": self.kernel_backtrace,
                "user_backtrace": self.user_backtrace, "exception_context": self.exception_context,
                "saved_thread_registers": self.saved_thread_registers, "modules": self.modules(),
                "trailing_size": len(self.trailing), "trailing_hex": self.trailing.hex(),
            },
            "limitations": [
                "This format does not contain ELF notes, captured memory, or a complete module/thread inventory.",
                "Backtraces are producer-saved records, not independently verified unwinds.",
                "Source hashes and unrecognized trailing records are preserved without guessing their meaning.",
            ],
        }
