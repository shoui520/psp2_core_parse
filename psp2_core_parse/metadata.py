from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional

from .core import CoreDump, ParseError


# This is the 50-entry table used by SceCoredump 3.68. Entries 0x4002 and
# 0x4003 are internal capture stages and do not normally become ELF notes.
PRODUCER_NOTE_ORDER: tuple[tuple[int, str], ...] = (
    (0x1000, "COREFILE_INFO"),
    (0x1003, "THREAD_INFO"),
    (0x100A, "SEMAPHORE_INFO"),
    (0x100B, "EVENTFLAG_INFO"),
    (0x100C, "MUTEX_INFO"),
    (0x100D, "LWMUTEX_INFO"),
    (0x1010, "MESG_PIPE_INFO"),
    (0x1011, "CALLBACK_INFO"),
    (0x1013, "TIMER_INFO"),
    (0x1014, "RWLOCK_INFO"),
    (0x1015, "CONDVAR_INFO"),
    (0x1016, "LWCONDVAR_INFO"),
    (0x1030, "SMPL_EVENT_INFO"),
    (0x1004, "THREAD_REG_INFO"),
    (0x1002, "PROCESS_INFO"),
    (0x1001, "SYSTEM_INFO"),
    (0x101C, "APP_INFO"),
    (0x101A, "HW_INFO"),
    (0x101D, "BUILD_VER_INFO"),
    (0x101B, "STACK_INFO"),
    (0x1005, "MODULE_INFO"),
    (0x1006, "LIBRARY_INFO"),
    (0x1019, "META_DATA_INFO"),
    (0x4002, "INTERNAL_CAPTURE_4002"),
    (0x4003, "INTERNAL_CAPTURE_4003"),
    (0x1007, "MEM_BLK_INFO"),
    (0x1009, "FILE_INFO"),
    (0x1017, "FIBER_INFO"),
    (0x1018, "ULT_INFO"),
    (0x101E, "EXTNL_PROC_INFO"),
    (0x101F, "BUDGET_INFO"),
    (0x1020, "APP_LIST_INFO"),
    (0x1021, "DEVICE_INFO"),
    (0x102F, "SYS_DEVICE_INFO"),
    (0x1022, "USER_INFO"),
    (0x1023, "ULT_SEMA_INFO"),
    (0x1024, "ULT_MUTEX_INFO"),
    (0x1029, "ULT_COND_INFO"),
    (0x1028, "ULT_RWLOCK_INFO"),
    (0x1027, "ULT_QUEUE_INFO"),
    (0x1025, "ULT_Q_POOL_INFO"),
    (0x1026, "ULT_WQPOOL_INFO"),
    (0x102A, "TTY_INFO"),
    (0x102B, "SCREENSHOT_INFO"),
    (0x102C, "EVENT_LOG_INFO"),
    (0x102D, "SYSTEM_INFO2"),
    (0x2000, "GPU_INFO"),
    (0x2001, "GPU_ACT_INFO"),
    (0x1031, "TTY_INFO2"),
    (0x102E, "SUMMARY_INFO"),
)

NOTE_TYPE_NAMES = dict(PRODUCER_NOTE_ORDER)
NOTE_TYPE_NAMES[0x3000] = "KERNEL_INFO"


@dataclass(frozen=True)
class SummaryEntry:
    index: int
    note_type: int
    planned_size: int
    written_size: int

    @property
    def producer_name(self) -> Optional[str]:
        return NOTE_TYPE_NAMES.get(self.note_type)

    @property
    def status(self) -> str:
        if self.producer_name == "SUMMARY_INFO" and self.written_size == 0:
            return "self-reference"
        if self.planned_size == self.written_size:
            return "complete" if self.planned_size else "not-present"
        if self.written_size == 0:
            return "omitted"
        if self.written_size < self.planned_size:
            return "truncated"
        return "larger-than-planned"

    def summary(self, captured_name: Optional[str] = None) -> dict:
        return {
            "index": self.index,
            "note_type": self.note_type,
            "producer_name": self.producer_name,
            "captured_name": captured_name,
            "planned_size": self.planned_size,
            "written_size": self.written_size,
            "missing_size": max(0, self.planned_size - self.written_size),
            "status": self.status,
        }


@dataclass(frozen=True)
class SummaryInfo:
    format_version: int
    producer_word: int
    declared_count: int
    entries: tuple[SummaryEntry, ...]
    trailing: bytes
    complete: bool

    @classmethod
    def parse(cls, data: bytes, *, salvage: bool = True) -> "SummaryInfo":
        if len(data) < 12:
            raise ParseError("SUMMARY_INFO is shorter than its three-word header")
        version, producer_word, count = struct.unpack_from("<3I", data)
        available = min(count, (len(data) - 12) // 12)
        entries = tuple(
            SummaryEntry(index, *struct.unpack_from("<3I", data, 12 + index * 12))
            for index in range(available)
        )
        if not salvage and available != count:
            raise ParseError(f"SUMMARY_INFO declares {count} entries but only {available} are available")
        used = 12 + available * 12
        return cls(version, producer_word, count, entries, data[used:], available == count)

    def summary(self, core: Optional[CoreDump] = None) -> dict:
        captured_names = (
            {note.note_type: note.name for note in core.notes} if core is not None else {}
        )
        entries = [entry.summary(captured_names.get(entry.note_type)) for entry in self.entries]
        incomplete = [
            entry for entry in entries
            if entry["status"] not in ("complete", "not-present", "self-reference")
        ]
        mismatched_names = [
            entry for entry in entries
            if entry["captured_name"]
            and entry["producer_name"]
            and entry["captured_name"] != entry["producer_name"]
        ]
        return {
            "format_version": self.format_version,
            "producer_word": self.producer_word,
            "declared_count": self.declared_count,
            "decoded_count": len(self.entries),
            "complete": self.complete,
            "incomplete_count": len(incomplete),
            "mismatched_name_count": len(mismatched_names),
            "trailing_size": len(self.trailing),
            "trailing_nonzero_bytes": sum(value != 0 for value in self.trailing),
            "trailing_sha256": hashlib.sha256(self.trailing).hexdigest(),
            "entries": entries,
        }


def summary_info(core: CoreDump) -> Optional[SummaryInfo]:
    note = core.note("SUMMARY_INFO") or core.note_type(0x102E)
    return SummaryInfo.parse(note.description) if note is not None else None
