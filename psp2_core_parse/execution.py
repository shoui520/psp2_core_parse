from __future__ import annotations

import struct
import hashlib
from dataclasses import dataclass
from typing import Optional

from .binary import BoundsError, c_string, s32, u16, u32
from .core import CoreDump, Note, ParseError


THREAD_STATUS_NAMES = {
    0x01: "running",
    0x02: "ready",
    0x04: "standby",
    0x08: "waiting",
    0x10: "dormant",
    0x20: "dead",
    0x40: "deleted",
    0x80: "stagnant",
    0x100: "suspended",
}


STOP_REASON_NAMES = {
    0x00000: "no reason",
    0x10001: "process suspended",
    0x10002: "thread suspended",
    0x10003: "application suspended",
    0x10004: "AppMgr hang detection",
    0x10005: "spontaneous exit",
    0x10006: "stack overflow",
    0x10007: "illegal-context syscall",
    0x10008: "critical-usage syscall",
    0x10009: "illegal syscall number",
    0x20001: "hardware watchpoint",
    0x20002: "software watchpoint",
    0x20003: "hardware breakpoint",
    0x20004: "software breakpoint",
    0x20005: "startup failure",
    0x20006: "PRX stop-init",
    0x20007: "DTrace breakpoint",
    0x30002: "undefined-instruction exception",
    0x30003: "prefetch-abort exception",
    0x30004: "data-abort exception",
    0x40001: "VFP exception",
    0x40002: "NEON exception",
    0x60080: "integer division by zero",
}


FAULT_STATUS_NAMES = {
    0x01: "alignment fault",
    0x02: "debug event",
    0x03: "access-flag fault, section",
    0x04: "instruction-cache maintenance fault",
    0x05: "translation fault, section",
    0x06: "access-flag fault, page",
    0x07: "translation fault, page",
    0x08: "synchronous external abort",
    0x09: "domain fault, section",
    0x0B: "domain fault, page",
    0x0C: "external abort on translation, level 1",
    0x0D: "permission fault, section",
    0x0E: "external abort on translation, level 2",
    0x0F: "permission fault, page",
    0x10: "TLB conflict abort",
    0x16: "asynchronous external abort",
    0x18: "synchronous parity/ECC error",
    0x1C: "parity/ECC error on translation, level 1",
    0x1E: "parity/ECC error on translation, level 2",
}


def stop_reason_name(code: int) -> str:
    if code in STOP_REASON_NAMES:
        return STOP_REASON_NAMES[code]
    if 0x80000 <= code <= 0x800FF:
        return "unrecoverable error"
    return "unknown"


def status_name(status: int) -> str:
    if status in THREAD_STATUS_NAMES:
        return THREAD_STATUS_NAMES[status]
    parts = [name for bit, name in THREAD_STATUS_NAMES.items() if status & bit]
    return "|".join(parts) if parts else "unknown"


def decode_fault_status(value: int, *, instruction: bool = False) -> dict:
    code = (value & 0xF) | ((value >> 6) & 0x10)
    result = {
        "raw": value,
        "status_code": code,
        "status_name": FAULT_STATUS_NAMES.get(code, "reserved or implementation-defined"),
        "domain": (value >> 4) & 0xF,
        "long_descriptor_format": bool(value & (1 << 9)),
        "external_abort_type": bool(value & (1 << 12)),
    }
    if not instruction:
        result["write"] = bool(value & (1 << 11))
        result["far_not_valid"] = bool(value & (1 << 16))
    return result


@dataclass(frozen=True)
class ProcessInfo:
    format_version: int
    capture_status: int
    process_id: int
    process_flags: int
    name: str
    path: str
    producer_words_0x30: tuple[int, int, int, int]
    parent_process_id: int
    producer_words_0x44: tuple[int, int, int, int, int]
    declared_path_size: int
    footer_words: tuple[int, ...]
    accounting_value: Optional[int]
    complete: bool
    trailing: bytes
    raw: bytes

    @classmethod
    def parse(cls, data: bytes) -> "ProcessInfo":
        if len(data) < 0x5C:
            raise ParseError("PROCESS_INFO is shorter than its fixed prefix")
        path_size = u32(data, 0x58)
        path_offset = 0x5C
        serialized_size = (path_size + 3) & ~3
        footer_offset = path_offset + serialized_size
        complete = footer_offset + 0x18 <= len(data)
        available = min(path_size, max(0, len(data) - path_offset))
        path = data[path_offset:path_offset + available].split(b"\0", 1)[0].decode("utf-8", errors="replace")
        footer = tuple(struct.unpack_from("<4I", data, footer_offset)) if footer_offset + 0x10 <= len(data) else ()
        accounting = struct.unpack_from("<Q", data, footer_offset + 0x10)[0] if complete else None
        used = min(len(data), footer_offset + 0x18)
        return cls(
            u32(data, 0),
            u32(data, 4),
            u32(data, 8),
            u32(data, 0x0C),
            c_string(data, 0x10, 0x20),
            path,
            struct.unpack_from("<4I", data, 0x30),
            u32(data, 0x40),
            struct.unpack_from("<5I", data, 0x44),
            path_size,
            footer,
            accounting,
            complete,
            data[used:],
            data,
        )

    def summary(self) -> dict:
        return {
            "format_version": self.format_version,
            "capture_status": self.capture_status,
            "process_id": self.process_id,
            "process_flags": self.process_flags,
            "name": self.name,
            "path": self.path,
            "producer_words_0x30": list(self.producer_words_0x30),
            "parent_process_id": self.parent_process_id,
            "producer_words_0x44": list(self.producer_words_0x44),
            "declared_path_size": self.declared_path_size,
            "footer_words": list(self.footer_words),
            "accounting_value": self.accounting_value,
            "complete": self.complete,
            "trailing_size": len(self.trailing),
            "trailing_nonzero_bytes": sum(value != 0 for value in self.trailing),
            "trailing_sha256": hashlib.sha256(self.trailing).hexdigest(),
            "raw_size": len(self.raw),
            "raw_sha256": hashlib.sha256(self.raw).hexdigest(),
        }


@dataclass(frozen=True)
class ModuleSegment:
    number: int
    producer_word: int
    attributes: int
    start: int
    size: int
    alignment: int

    @property
    def end(self) -> int:
        return self.start + self.size

    @property
    def permissions(self) -> str:
        value = self.attributes & 7
        return "".join(("r" if value & 4 else "-", "w" if value & 2 else "-", "x" if value & 1 else "-"))

    def contains(self, address: int) -> bool:
        address &= ~1
        return self.start <= address < self.end

    def summary(self) -> dict:
        return {
            "number": self.number,
            "producer_word": self.producer_word,
            "attributes": self.attributes,
            "permissions": self.permissions,
            "start": self.start,
            "end": self.end,
            "size": self.size,
            "alignment": self.alignment,
        }


@dataclass(frozen=True)
class Module:
    index: int
    uid: int
    name: str
    segments: tuple[ModuleSegment, ...]
    header_words: tuple[int, ...]
    footer_words: tuple[int, ...]
    complete: bool = True

    def summary(self) -> dict:
        return {
            "index": self.index,
            "uid": self.uid,
            "name": self.name,
            "complete": self.complete,
            "segments": [segment.summary() for segment in self.segments],
            "header_words": list(self.header_words),
            "footer_words": list(self.footer_words),
        }


@dataclass(frozen=True)
class AddressLocation:
    address: int
    module_index: int
    module_uid: int
    module_name: str
    segment_number: int
    segment_start: int
    segment_size: int
    permissions: str
    offset: int

    @property
    def notation(self) -> str:
        return f"{self.module_name}@{self.segment_number}+0x{self.offset:x}"

    def summary(self) -> dict:
        return {
            "address": self.address,
            "module_index": self.module_index,
            "module_uid": self.module_uid,
            "module_name": self.module_name,
            "segment_number": self.segment_number,
            "segment_start": self.segment_start,
            "segment_size": self.segment_size,
            "permissions": self.permissions,
            "offset": self.offset,
            "notation": self.notation,
        }


@dataclass(frozen=True)
class ModuleInfo:
    format_version: int
    declared_count: int
    modules: tuple[Module, ...]
    trailing: bytes
    complete: bool

    @classmethod
    def parse(cls, data: bytes, *, salvage: bool = True) -> "ModuleInfo":
        if len(data) < 8:
            raise ParseError("MODULE_INFO is truncated")
        version, count = struct.unpack_from("<2I", data)
        offset = 8
        modules: list[Module] = []
        complete = True
        for index in range(count):
            if offset + 0x50 > len(data):
                complete = False
                break
            header = data[offset : offset + 0x50]
            segment_count = u32(header, 0x4C)
            if segment_count > 64:
                if salvage:
                    complete = False
                    break
                raise ParseError(f"MODULE_INFO module {index} has implausible segment count {segment_count}")
            offset += 0x50
            segments: list[ModuleSegment] = []
            module_complete = True
            for segment_index in range(segment_count):
                if offset + 0x14 > len(data):
                    complete = module_complete = False
                    break
                segments.append(ModuleSegment(segment_index + 1, *struct.unpack_from("<5I", data, offset)))
                offset += 0x14
            footer = ()
            if module_complete:
                if offset + 0x10 <= len(data):
                    footer = struct.unpack_from("<4I", data, offset)
                    offset += 0x10
                else:
                    complete = module_complete = False
            modules.append(
                Module(
                    index,
                    u32(header, 4),
                    c_string(header, 0x24, 0x28),
                    tuple(segments),
                    struct.unpack("<20I", header),
                    tuple(footer),
                    module_complete,
                )
            )
            if not module_complete:
                break
        return cls(version, count, tuple(modules), data[offset:], complete and len(modules) == count)

    def locate(self, address: int, *, executable_only: bool = False) -> Optional[AddressLocation]:
        normalized = address & ~1
        candidates: list[tuple[int, Module, ModuleSegment]] = []
        for module in self.modules:
            for segment in module.segments:
                if segment.contains(normalized) and (not executable_only or "x" in segment.permissions):
                    candidates.append((segment.size, module, segment))
        if not candidates:
            return None
        _size, module, segment = min(candidates, key=lambda item: item[0])
        return AddressLocation(
            address,
            module.index,
            module.uid,
            module.name,
            segment.number,
            segment.start,
            segment.size,
            segment.permissions,
            normalized - segment.start,
        )

    def summary(self) -> dict:
        return {
            "format_version": self.format_version,
            "declared_count": self.declared_count,
            "decoded_count": len(self.modules),
            "complete": self.complete,
            "trailing_size": len(self.trailing),
            "trailing_nonzero_bytes": sum(value != 0 for value in self.trailing),
            "trailing_sha256": hashlib.sha256(self.trailing).hexdigest(),
            "modules": [module.summary() for module in self.modules],
        }


@dataclass(frozen=True)
class Thread:
    index: int
    record_size: int
    uid: int
    name: str
    attributes: int
    producer_word_0x2c: int
    status: int
    status_word: int
    entry: int
    stack_base: int
    stack_size: int
    producer_words_0x40: tuple[int, int, int]
    initial_priority: int
    current_priority: int
    initial_cpu_affinity: int
    current_cpu_affinity: int
    current_cpu_id: int
    wait_type: int
    wait_id: int
    run_clocks: int
    scheduler_word: int
    stop_reason: int
    producer_words_0x78: tuple[int, ...]
    recorded_pc: int
    producer_word_0xa0: Optional[int]
    extended_context_words_0xa4: tuple[int, ...]
    raw: bytes
    complete: bool

    @property
    def stack_end(self) -> int:
        return self.stack_base + self.stack_size

    @property
    def status_name(self) -> str:
        return status_name(self.status)

    @property
    def stop_reason_name(self) -> str:
        return stop_reason_name(self.stop_reason)

    def summary(self) -> dict:
        return {
            "index": self.index,
            "record_size": self.record_size,
            "complete": self.complete,
            "uid": self.uid,
            "name": self.name,
            "attributes": self.attributes,
            "producer_word_0x2c": self.producer_word_0x2c,
            "status": self.status,
            "status_word": self.status_word,
            "status_name": self.status_name,
            "entry": self.entry,
            "stack_base": self.stack_base,
            "stack_size": self.stack_size,
            "stack_end": self.stack_end,
            "producer_words_0x40": list(self.producer_words_0x40),
            "initial_priority": self.initial_priority,
            "current_priority": self.current_priority,
            "initial_cpu_affinity": self.initial_cpu_affinity,
            "current_cpu_affinity": self.current_cpu_affinity,
            "current_cpu_id": self.current_cpu_id,
            "wait_type": self.wait_type,
            "wait_id": self.wait_id,
            "run_clocks": self.run_clocks,
            "scheduler_word": self.scheduler_word,
            "stop_reason": self.stop_reason,
            "stop_reason_name": self.stop_reason_name,
            "producer_words_0x78": list(self.producer_words_0x78),
            "recorded_pc": self.recorded_pc,
            "producer_word_0xa0": self.producer_word_0xa0,
            "extended_context_words_0xa4": list(self.extended_context_words_0xa4),
            "raw_sha256": hashlib.sha256(self.raw).hexdigest(),
        }


@dataclass(frozen=True)
class ThreadInfo:
    format_version: int
    declared_count: int
    threads: tuple[Thread, ...]
    trailing: bytes
    complete: bool

    @classmethod
    def parse(cls, data: bytes, *, salvage: bool = True) -> "ThreadInfo":
        if len(data) < 8:
            raise ParseError("THREAD_INFO is truncated")
        version, count = struct.unpack_from("<2I", data)
        offset = 8
        threads: list[Thread] = []
        complete = True
        for index in range(count):
            if offset + 4 > len(data):
                complete = False
                break
            size = u32(data, offset)
            if size < 0xA0:
                if salvage:
                    complete = False
                    break
                raise ParseError(f"THREAD_INFO record {index} has invalid size 0x{size:x}")
            raw = data[offset : min(len(data), offset + size)]
            record_complete = len(raw) == size
            if len(raw) < 0xA0:
                complete = False
                break
            threads.append(
                Thread(
                    index=index,
                    record_size=size,
                    uid=u32(raw, 4),
                    name=c_string(raw, 8, 0x20),
                    attributes=u32(raw, 0x28),
                    producer_word_0x2c=u32(raw, 0x2C),
                    status=u16(raw, 0x30),
                    status_word=u32(raw, 0x30),
                    entry=u32(raw, 0x34),
                    stack_base=u32(raw, 0x38),
                    stack_size=u32(raw, 0x3C),
                    producer_words_0x40=struct.unpack_from("<3I", raw, 0x40),
                    initial_priority=s32(raw, 0x4C),
                    current_priority=s32(raw, 0x50),
                    initial_cpu_affinity=u32(raw, 0x54),
                    current_cpu_affinity=u32(raw, 0x58),
                    current_cpu_id=s32(raw, 0x5C),
                    wait_type=u32(raw, 0x60),
                    wait_id=u32(raw, 0x64),
                    run_clocks=u32(raw, 0x68) | (u32(raw, 0x6C) << 32),
                    scheduler_word=u32(raw, 0x70),
                    stop_reason=u32(raw, 0x74),
                    producer_words_0x78=struct.unpack_from("<9I", raw, 0x78),
                    recorded_pc=u32(raw, 0x9C),
                    producer_word_0xa0=u32(raw, 0xA0) if len(raw) >= 0xA4 else None,
                    extended_context_words_0xa4=tuple(
                        u32(raw, item) for item in range(0xA4, min(len(raw), 0xC8), 4)
                    ),
                    raw=raw,
                    complete=record_complete,
                )
            )
            offset += size
            if not record_complete:
                complete = False
                break
        return cls(version, count, tuple(threads), data[min(offset, len(data)):], complete and len(threads) == count)

    def by_uid(self, uid: int) -> Optional[Thread]:
        return next((thread for thread in self.threads if thread.uid == uid), None)

    def summary(self) -> dict:
        return {
            "format_version": self.format_version,
            "declared_count": self.declared_count,
            "decoded_count": len(self.threads),
            "complete": self.complete,
            "trailing_size": len(self.trailing),
            "trailing_nonzero_bytes": sum(value != 0 for value in self.trailing),
            "trailing_sha256": hashlib.sha256(self.trailing).hexdigest(),
            "threads": [thread.summary() for thread in self.threads],
        }


@dataclass(frozen=True)
class ThreadRegisters:
    index: int
    record_size: int
    thread_uid: int
    gpr: tuple[int, ...]
    cpsr: int
    tpidrurw: int
    producer_word_0x50: int
    vfp_d: tuple[int, ...]
    producer_system_words: tuple[int, ...]
    ifsr: int
    ifar: int
    dfsr: int
    dfar: int
    raw: bytes
    complete: bool

    @property
    def sp(self) -> int:
        return self.gpr[13]

    @property
    def lr(self) -> int:
        return self.gpr[14]

    @property
    def pc(self) -> int:
        return self.gpr[15]

    @property
    def thumb(self) -> bool:
        return bool(self.cpsr & (1 << 5)) or bool(self.pc & 1)

    @property
    def processor_mode(self) -> int:
        return self.cpsr & 0x1F

    @property
    def poison_gpr_count(self) -> int:
        return sum(value == 0xDEADBEEF for value in self.gpr)

    @property
    def vfp_poisoned(self) -> bool:
        if not self.vfp_d:
            return False
        poison_halves = {0x7F80DEAD, 0x7FF8DEAD}
        halves = [part for value in self.vfp_d for part in (value & 0xFFFFFFFF, value >> 32)]
        return sum(value in poison_halves for value in halves) >= len(halves) // 2

    def fault_for_stop_reason(self, stop_reason: int) -> Optional[dict]:
        if stop_reason == 0x30004:
            decoded = decode_fault_status(self.dfsr)
            decoded.update({"kind": "data-abort", "address": self.dfar, "address_register": "DFAR", "status_register": "DFSR"})
            return decoded
        if stop_reason == 0x30003:
            decoded = decode_fault_status(self.ifsr, instruction=True)
            decoded.update({"kind": "prefetch-abort", "address": self.ifar, "address_register": "IFAR", "status_register": "IFSR"})
            return decoded
        return None

    def summary(self, stop_reason: int = 0) -> dict:
        return {
            "index": self.index,
            "record_size": self.record_size,
            "complete": self.complete,
            "thread_uid": self.thread_uid,
            "gpr": list(self.gpr),
            "sp": self.sp,
            "lr": self.lr,
            "pc": self.pc,
            "cpsr": self.cpsr,
            "thumb": self.thumb,
            "processor_mode": self.processor_mode,
            "tpidrurw": self.tpidrurw,
            "producer_word_0x50": self.producer_word_0x50,
            "vfp_d": list(self.vfp_d),
            "vfp_poisoned": self.vfp_poisoned,
            "producer_system_words": list(self.producer_system_words),
            "ifsr": self.ifsr,
            "ifar": self.ifar,
            "dfsr": self.dfsr,
            "dfar": self.dfar,
            "ifsr_decoded": decode_fault_status(self.ifsr, instruction=True),
            "dfsr_decoded": decode_fault_status(self.dfsr),
            "fault": self.fault_for_stop_reason(stop_reason),
            "poison_gpr_count": self.poison_gpr_count,
            "raw_sha256": hashlib.sha256(self.raw).hexdigest(),
        }


@dataclass(frozen=True)
class PartialThreadRegisters:
    index: int
    declared_record_size: int
    raw: bytes

    def summary(self) -> dict:
        gpr_count = min(16, max(0, (len(self.raw) - 8) // 4))
        used = 8 + gpr_count * 4 if len(self.raw) >= 8 else (len(self.raw) // 4) * 4
        vfp_count = min(32, max(0, (len(self.raw) - 0x54) // 8))
        return {
            "index": self.index,
            "declared_record_size": self.declared_record_size,
            "available_size": len(self.raw),
            "complete": False,
            "thread_uid": u32(self.raw, 4) if len(self.raw) >= 8 else None,
            "gpr_prefix": list(struct.unpack_from(f"<{gpr_count}I", self.raw, 8)) if gpr_count else [],
            "available_gpr_count": gpr_count,
            "cpsr": u32(self.raw, 0x48) if len(self.raw) >= 0x4C else None,
            "tpidrurw": u32(self.raw, 0x4C) if len(self.raw) >= 0x50 else None,
            "producer_word_0x50": u32(self.raw, 0x50) if len(self.raw) >= 0x54 else None,
            "vfp_d_prefix": list(struct.unpack_from(f"<{vfp_count}Q", self.raw, 0x54)) if vfp_count else [],
            "available_vfp_d_count": vfp_count,
            "producer_system_words_prefix": [
                u32(self.raw, offset) for offset in range(0x154, min(len(self.raw), 0x168), 4)
                if offset + 4 <= len(self.raw)
            ],
            "ifsr": u32(self.raw, 0x168) if len(self.raw) >= 0x16C else None,
            "ifar": u32(self.raw, 0x16C) if len(self.raw) >= 0x170 else None,
            "dfsr": u32(self.raw, 0x170) if len(self.raw) >= 0x174 else None,
            "dfar": u32(self.raw, 0x174) if len(self.raw) >= 0x178 else None,
            "unaligned_tail_hex": self.raw[used:].hex(),
            "raw_hex": self.raw.hex(),
            "raw_sha256": hashlib.sha256(self.raw).hexdigest(),
        }


@dataclass(frozen=True)
class ThreadRegisterInfo:
    format_version: int
    declared_count: int
    records: tuple[ThreadRegisters, ...]
    partial_records: tuple[PartialThreadRegisters, ...]
    trailing: bytes
    complete: bool

    @classmethod
    def parse(cls, data: bytes, *, salvage: bool = True) -> "ThreadRegisterInfo":
        if len(data) < 8:
            raise ParseError("THREAD_REG_INFO is truncated")
        version, count = struct.unpack_from("<2I", data)
        offset = 8
        records: list[ThreadRegisters] = []
        partial_records: list[PartialThreadRegisters] = []
        complete = True
        for index in range(count):
            if offset + 4 > len(data):
                complete = False
                break
            size = u32(data, offset)
            if size < 8:
                if salvage:
                    complete = False
                    break
                raise ParseError(f"THREAD_REG_INFO record {index} has invalid size 0x{size:x}")
            raw = data[offset : min(len(data), offset + size)]
            record_complete = len(raw) == size
            if not record_complete or size < 0x178:
                partial_records.append(PartialThreadRegisters(index, size, raw))
                offset += len(raw)
                complete = False
                if not record_complete:
                    break
                continue
            gpr = struct.unpack_from("<16I", raw, 8)
            cpsr = u32(raw, 0x48)
            tpidrurw = u32(raw, 0x4C)
            producer_word = u32(raw, 0x50)
            vfp_count = max(0, min(32, (len(raw) - 0x54) // 8))
            vfp = struct.unpack_from(f"<{vfp_count}Q", raw, 0x54) if vfp_count else ()
            system_words = tuple(
                u32(raw, item) for item in range(0x154, min(len(raw), 0x168), 4)
            )
            fault_words = [u32(raw, item) for item in (0x168, 0x16C, 0x170, 0x174)]
            records.append(
                ThreadRegisters(
                    index,
                    size,
                    u32(raw, 4),
                    tuple(gpr),
                    cpsr,
                    tpidrurw,
                    producer_word,
                    tuple(vfp),
                    system_words,
                    *fault_words,
                    raw,
                    record_complete,
                )
            )
            offset += size
            if not record_complete:
                complete = False
                break
        return cls(
            version,
            count,
            tuple(records),
            tuple(partial_records),
            data[min(offset, len(data)):],
            complete and len(records) == count,
        )

    def by_uid(self, uid: int) -> Optional[ThreadRegisters]:
        return next((record for record in self.records if record.thread_uid == uid), None)

    def summary(self) -> dict:
        return {
            "format_version": self.format_version,
            "declared_count": self.declared_count,
            "decoded_count": len(self.records),
            "partial_record_count": len(self.partial_records),
            "complete": self.complete,
            "trailing_size": len(self.trailing),
            "trailing_nonzero_bytes": sum(value != 0 for value in self.trailing),
            "trailing_sha256": hashlib.sha256(self.trailing).hexdigest(),
            "records": [record.summary() for record in self.records],
            "partial_records": [record.summary() for record in self.partial_records],
        }


@dataclass(frozen=True)
class StackRecord:
    index: int
    capture_status: int
    thread_uid: int
    producer_word_0x08: int
    producer_word_0x0c: int

    def summary(self) -> dict:
        return {
            "index": self.index,
            "capture_status": self.capture_status,
            "thread_uid": self.thread_uid,
            "producer_word_0x08": self.producer_word_0x08,
            "producer_word_0x0c": self.producer_word_0x0c,
        }


@dataclass(frozen=True)
class StackInfo:
    format_version: int
    declared_count: int
    records: tuple[StackRecord, ...]
    trailing: bytes
    complete: bool

    @classmethod
    def parse(cls, data: bytes) -> "StackInfo":
        if len(data) < 8:
            raise ParseError("STACK_INFO is truncated")
        version, count = struct.unpack_from("<2I", data)
        available = min(count, (len(data) - 8) // 0x10)
        records = tuple(
            StackRecord(index, *struct.unpack_from("<4I", data, 8 + index * 0x10))
            for index in range(available)
        )
        used = 8 + available * 0x10
        return cls(version, count, records, data[used:], available == count)

    def by_uid(self, uid: int) -> Optional[StackRecord]:
        return next((record for record in self.records if record.thread_uid == uid), None)

    def summary(self) -> dict:
        return {
            "format_version": self.format_version,
            "declared_count": self.declared_count,
            "decoded_count": len(self.records),
            "complete": self.complete,
            "record_size": 0x10,
            "trailing_size": len(self.trailing),
            "trailing_nonzero_bytes": sum(value != 0 for value in self.trailing),
            "trailing_sha256": hashlib.sha256(self.trailing).hexdigest(),
            "records": [record.summary() for record in self.records],
        }


@dataclass(frozen=True)
class ExecutionContext:
    process: Optional[ProcessInfo]
    modules: Optional[ModuleInfo]
    threads: Optional[ThreadInfo]
    registers: Optional[ThreadRegisterInfo]
    stacks: Optional[StackInfo]
    errors: tuple[dict, ...]

    @classmethod
    def parse(cls, core: CoreDump) -> "ExecutionContext":
        errors: list[dict] = []

        def parse(name: str, parser):
            note = core.note(name)
            if note is None:
                return None
            try:
                return parser(note.description)
            except (ParseError, BoundsError, struct.error, ValueError) as exc:
                errors.append({"note": name, "error": str(exc)})
                return None

        return cls(
            parse("PROCESS_INFO", ProcessInfo.parse),
            parse("MODULE_INFO", ModuleInfo.parse),
            parse("THREAD_INFO", ThreadInfo.parse),
            parse("THREAD_REG_INFO", ThreadRegisterInfo.parse),
            parse("STACK_INFO", StackInfo.parse),
            tuple(errors),
        )

    @property
    def crashed_threads(self) -> tuple[Thread, ...]:
        if self.threads is None:
            return ()
        return tuple(thread for thread in self.threads.threads if thread.stop_reason)

    @property
    def primary_crash_thread(self) -> Optional[Thread]:
        crashed = self.crashed_threads
        if not crashed:
            return None
        return min(crashed, key=lambda item: (item.status != 1, item.index))

    def thread_summary(self, core: CoreDump, thread: Thread, *, stack_candidates: int = 16) -> dict:
        registers = self.registers.by_uid(thread.uid) if self.registers else None
        stack_record = self.stacks.by_uid(thread.uid) if self.stacks else None
        item = thread.summary()
        item["primary_crash_thread"] = self.primary_crash_thread == thread
        item["registers"] = registers.summary(thread.stop_reason) if registers else None
        item["stack_record"] = stack_record.summary() if stack_record else None
        item["pc_location"] = None
        item["lr_location"] = None
        if registers is not None and self.modules is not None:
            pc = self.modules.locate(registers.pc)
            lr = self.modules.locate(registers.lr)
            item["pc_location"] = pc.summary() if pc else None
            item["lr_location"] = lr.summary() if lr else None
        item["stack_captured_at_sp"] = bool(
            registers and any(segment.contains(registers.sp, 4) for segment in core.loads)
        )
        item["stack_return_candidates"] = (
            self._stack_candidates(core, thread, registers, stack_candidates)
            if registers is not None
            else []
        )
        return item

    def _stack_candidates(
        self,
        core: CoreDump,
        thread: Thread,
        registers: ThreadRegisters,
        limit: int,
    ) -> list[dict]:
        if limit <= 0:
            return []
        if self.modules is None or not (thread.stack_base <= registers.sp < thread.stack_end):
            return []
        captured = core.captured_ranges(registers.sp, min(thread.stack_end, registers.sp + 0x10000))
        if not captured or captured[0][0] != registers.sp:
            return []
        data = core.read_memory(registers.sp, (captured[0][1] - registers.sp) & ~3)
        result: list[dict] = []
        for offset in range(0, len(data), 4):
            value = struct.unpack_from("<I", data, offset)[0]
            location = self.modules.locate(value, executable_only=True)
            if location is None:
                continue
            result.append(
                {
                    "stack_address": registers.sp + offset,
                    "value": value,
                    "location": location.summary(),
                    "qualification": "stack scan candidate; not an unwind-verified frame",
                }
            )
            if len(result) >= limit:
                break
        return result

    def summary(self, core: CoreDump, *, stack_candidates: int = 16) -> dict:
        threads = (
            [self.thread_summary(core, thread, stack_candidates=stack_candidates) for thread in self.threads.threads]
            if self.threads
            else []
        )
        primary = self.primary_crash_thread
        return {
            "process": self.process.summary() if self.process else None,
            "modules": self.modules.summary() if self.modules else None,
            "thread_info_version": self.threads.format_version if self.threads else None,
            "thread_register_info_version": self.registers.format_version if self.registers else None,
            "stack_info_version": self.stacks.format_version if self.stacks else None,
            "thread_info": self.threads.summary() if self.threads else None,
            "thread_register_info": self.registers.summary() if self.registers else None,
            "stack_info": self.stacks.summary() if self.stacks else None,
            "thread_count": len(threads),
            "crashed_thread_indices": [thread.index for thread in self.crashed_threads],
            "primary_crash_thread_index": primary.index if primary else None,
            "threads": threads,
            "errors": list(self.errors),
        }
