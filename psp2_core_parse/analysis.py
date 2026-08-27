from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional

from .core import CoreDump, ParseError
from .execution import ExecutionContext, Thread, ThreadRegisters
from .kernel import KernelObjectRegistry
from .metadata import SummaryInfo, summary_info
from .support import (
    decode_application,
    decode_build,
    decode_budgets,
    decode_corefile,
    parse_memory_blocks,
    supporting_context,
)
from .tty import TtyInfo


CLASSIFICATIONS = {
    0x10001: "PROCESS_SUSPENDED",
    0x10002: "THREAD_SUSPENDED",
    0x10003: "APPLICATION_SUSPENDED",
    0x10004: "APPMGR_HANG",
    0x10005: "SPONTANEOUS_EXIT",
    0x10006: "STACK_OVERFLOW",
    0x10007: "ILLEGAL_CONTEXT_SYSCALL",
    0x10008: "CRITICAL_USAGE_SYSCALL",
    0x10009: "ILLEGAL_SYSCALL",
    0x20001: "HARDWARE_WATCHPOINT",
    0x20002: "SOFTWARE_WATCHPOINT",
    0x20003: "HARDWARE_BREAKPOINT",
    0x20004: "SOFTWARE_BREAKPOINT",
    0x20005: "STARTUP_FAILURE",
    0x20006: "PRX_STOP_INIT",
    0x20007: "DTRACE_BREAKPOINT",
    0x30002: "UNDEFINED_INSTRUCTION",
    0x30003: "PREFETCH_ABORT",
    0x30004: "DATA_ABORT",
    0x40001: "VFP_EXCEPTION",
    0x40002: "NEON_EXCEPTION",
    0x60080: "INTEGER_DIVISION_BY_ZERO",
}


def _safe_decode(core: CoreDump, note_name: str, decoder) -> tuple[Optional[dict], Optional[str]]:
    note = core.note(note_name)
    if note is None:
        return None, None
    try:
        return decoder(note.description), None
    except (ParseError, struct.error, ValueError) as exc:
        return None, str(exc)


def _location(execution: ExecutionContext, address: int) -> Optional[dict]:
    if execution.modules is None:
        return None
    value = execution.modules.locate(address)
    return value.summary() if value else None


def _address_evidence(core: CoreDump, address: int) -> dict:
    if not 0 <= address <= 0xFFFFFFFF:
        return {"address": address, "captured": False, "classification": "outside-32-bit-address-space"}
    captured = bool(core.captured_ranges(address, min(0x100000000, address + 1)))
    if address < 0x1000:
        classification = "null-page"
    elif address < 0x10000:
        classification = "low-address"
    elif address >= 0xFFFF0000:
        classification = "high-vector-or-sentinel-range"
    else:
        classification = "ordinary-address"
    result = {"address": address, "captured": captured, "classification": classification}
    if captured:
        available = next((segment.captured_end - address for segment in core.loads if segment.contains(address)), 0)
        size = min(16, available)
        result["bytes"] = core.read_memory(address, size).hex() if size else ""
    return result


def _memory_block_evidence(core: CoreDump, address: int) -> list[dict]:
    note = core.note("MEM_BLK_INFO")
    if note is None:
        return []
    try:
        _version, _count, blocks, _trailing, _complete = parse_memory_blocks(note.description)
    except (ParseError, struct.error, ValueError):
        return []
    return [item.summary(core) for item in blocks if item.base <= address < item.end]


def _instruction_evidence(core: CoreDump, registers: ThreadRegisters) -> dict:
    address = registers.pc & ~1
    width = 2 if registers.thumb else 4
    evidence = _address_evidence(core, address)
    evidence.update({"thumb": registers.thumb, "width": width})
    try:
        raw = core.read_memory(address, width)
    except ParseError:
        raw = b""
    evidence["instruction_bytes"] = raw.hex() if raw else None
    if len(raw) == 2:
        value = struct.unpack_from("<H", raw)[0]
        evidence["instruction_word"] = value
        evidence["looks_like_thumb_udf"] = value & 0xFF00 == 0xDE00
        evidence["looks_like_thumb_bkpt"] = value & 0xFF00 == 0xBE00
    elif len(raw) == 4:
        value = struct.unpack_from("<I", raw)[0]
        evidence["instruction_word"] = value
        evidence["looks_like_arm_udf"] = value & 0x0FF000F0 == 0x07F000F0
    return evidence


def _stack_evidence(core: CoreDump, execution: ExecutionContext, thread: Thread, registers: Optional[ThreadRegisters]) -> dict:
    stack_record = execution.stacks.by_uid(thread.uid) if execution.stacks else None
    result = {
        "base": thread.stack_base,
        "end": thread.stack_end,
        "size": thread.stack_size,
        "producer_record": stack_record.summary() if stack_record else None,
    }
    if registers is None:
        result.update({"sp": None, "sp_in_stack": None})
        return result
    in_stack = thread.stack_base <= registers.sp <= thread.stack_end
    result.update({
        "sp": registers.sp,
        "sp_in_stack": in_stack,
        "bytes_below_sp": registers.sp - thread.stack_base if in_stack else None,
        "descending_stack_bytes_used": thread.stack_end - registers.sp if in_stack else None,
        "sp_captured": bool(core.captured_ranges(registers.sp, min(0x100000000, registers.sp + 1))),
        "near_low_guard": in_stack and registers.sp - thread.stack_base < 0x1000,
    })
    return result


def _dump_integrity(core: CoreDump, summary: Optional[SummaryInfo]) -> dict:
    errors = [item.summary() for item in core.issues if item.severity == "error"]
    warnings = [item.summary() for item in core.issues if item.severity != "error"]
    summary_result = summary.summary(core) if summary else None
    return {
        "complete": core.complete,
        "compression_complete": core.compression_complete,
        "program_headers": {
            "declared": core.declared_program_header_count,
            "available": len(core.program_headers),
        },
        "note_count": len(core.notes),
        "load_count": len(core.loads),
        "captured_bytes": sum(end - start for start, end in core.captured_ranges()),
        "error_count": len(errors),
        "warning_count": len(warnings),
        "errors": errors,
        "warnings": warnings,
        "producer_summary": summary_result,
        "salvage_used": not core.complete,
    }


def _tty_tail(core: CoreDump, limit: int) -> dict:
    result = []
    for note_name in ("TTY_INFO", "TTY_INFO2"):
        note = core.note(note_name)
        if note is None:
            continue
        try:
            parsed = TtyInfo.parse(note.description)
            lines = parsed.lines()
            result.append({
                "note": note_name,
                "complete": parsed.complete and note.complete,
                "line_count": len(lines),
                "tail": [item.summary() for item in lines[-limit:]] if limit > 0 else [],
            })
        except (ParseError, struct.error, ValueError) as exc:
            result.append({"note": note_name, "error": str(exc)})
    return {"streams": result}


def _budget_snapshot(core: CoreDump) -> dict:
    value, error = _safe_decode(core, "BUDGET_INFO", decode_budgets)
    if value is None:
        return {"available": False, "error": error}
    return {
        "available": True,
        "complete": value["complete"],
        "budget_count": value["decoded_count"],
        "partition_count": sum(len(item["partitions"]) for item in value["budgets"]),
        "region_count": sum(
            len(partition["regions"])
            for budget in value["budgets"]
            for partition in budget["partitions"]
        ),
        "qualification": "SceCoredump preserves opaque producer region words; no size/free semantics are inferred.",
    }


def _failure_bucket(classification: str, thread: Optional[Thread], registers: Optional[ThreadRegisters], execution: ExecutionContext) -> dict:
    components = [classification]
    pc_component = "pc-unknown"
    if registers is not None:
        location = execution.modules.locate(registers.pc) if execution.modules else None
        pc_component = location.notation if location else f"pc:0x{registers.pc & ~1:08x}"
    components.append(pc_component)
    if thread is not None:
        components.append(f"stop:0x{thread.stop_reason:x}")
    if thread is not None and registers is not None:
        fault = registers.fault_for_stop_reason(thread.stop_reason)
        if fault:
            components.append(f"fs:{fault['status_code']:02x}")
            access = "execute" if fault["kind"] == "prefetch-abort" else "write" if fault.get("write") else "read"
            components.append(f"access:{access}")
    canonical = "|".join(components)
    return {
        "canonical": canonical,
        "sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "components": components,
        "aslr_independent": "@" in pc_component,
    }


@dataclass(frozen=True)
class Analysis:
    result: dict

    @classmethod
    def build(cls, core: CoreDump, *, tty_lines: int = 12, stack_candidates: int = 16) -> "Analysis":
        execution = ExecutionContext.parse(core)
        kernel = KernelObjectRegistry.parse(core)
        primary = execution.primary_crash_thread
        registers = execution.registers.by_uid(primary.uid) if primary and execution.registers else None
        classification = CLASSIFICATIONS.get(primary.stop_reason, "UNKNOWN_STOP_REASON") if primary else "NO_CRASH_THREAD"
        fault = registers.fault_for_stop_reason(primary.stop_reason) if primary and registers else None
        fault_evidence = None
        if fault:
            fault_evidence = {
                **fault,
                "address_evidence": _address_evidence(core, fault["address"]),
                "memory_blocks": _memory_block_evidence(core, fault["address"]),
            }
        app, app_error = _safe_decode(core, "APP_INFO", decode_application)
        build, build_error = _safe_decode(core, "BUILD_VER_INFO", decode_build)
        corefile, corefile_error = _safe_decode(core, "COREFILE_INFO", decode_corefile)
        summary = None
        try:
            summary = summary_info(core)
        except (ParseError, struct.error, ValueError):
            pass
        primary_summary = execution.thread_summary(core, primary, stack_candidates=stack_candidates) if primary else None
        if primary_summary is not None:
            primary_summary["stack_evidence"] = _stack_evidence(core, execution, primary, registers)
            primary_summary["instruction_evidence"] = _instruction_evidence(core, registers) if registers else None
            primary_summary["waiting_on"] = [item.summary() for item in kernel.waiting_objects(primary.uid)]
        context = supporting_context(core, execution)
        result = {
            "schema": "psp2_core_parse.analysis.v1",
            "classification": classification,
            "verdict": _verdict(classification, primary, registers, execution),
            "failure_bucket": _failure_bucket(classification, primary, registers, execution),
            "container": core.summary(),
            "dump": _dump_integrity(core, summary),
            "corefile": corefile,
            "process": execution.process.summary() if execution.process else None,
            "application": app,
            "build": build,
            "metadata_errors": {"corefile": corefile_error, "application": app_error, "build": build_error},
            "primary_crash_thread": primary_summary,
            "fault": fault_evidence,
            "crashed_threads": [execution.thread_summary(core, item, stack_candidates=stack_candidates) for item in execution.crashed_threads],
            "execution_context": execution.summary(core, stack_candidates=stack_candidates),
            "supporting_context": context,
            "thread_overview": _thread_overview(execution),
            "module_count": len(execution.modules.modules) if execution.modules else 0,
            "modules": [item.summary() for item in execution.modules.modules] if execution.modules else [],
            "kernel_objects": kernel.summary(),
            "budgets": _budget_snapshot(core),
            "tty": _tty_tail(core, tty_lines),
            "decoder_errors": [*execution.errors, *kernel.errors],
        }
        return cls(result)

    def summary(self) -> dict:
        return self.result


def _verdict(classification: str, thread: Optional[Thread], registers: Optional[ThreadRegisters], execution: ExecutionContext) -> str:
    if thread is None:
        return "No thread with a nonzero producer stop reason was recovered."
    where = "an unknown address"
    if registers is not None:
        location = execution.modules.locate(registers.pc) if execution.modules else None
        where = location.notation if location else f"0x{registers.pc & ~1:08x}"
    text = f"{thread.name or '<unnamed>'} stopped with {thread.stop_reason_name} at {where}."
    if registers is not None:
        fault = registers.fault_for_stop_reason(thread.stop_reason)
        if fault:
            access = "instruction fetch" if fault["kind"] == "prefetch-abort" else "write" if fault.get("write") else "read"
            text += f" The MMU reported {fault['status_name']} during a {access} at 0x{fault['address']:08x}."
    if classification == "STACK_OVERFLOW":
        text += " The producer explicitly classified the stop as stack overflow."
    return text


def _thread_overview(execution: ExecutionContext) -> dict:
    if execution.threads is None:
        return {"count": 0, "status_counts": {}, "threads": []}
    counts: dict[str, int] = {}
    threads = []
    for item in execution.threads.threads:
        counts[item.status_name] = counts.get(item.status_name, 0) + 1
        threads.append({
            "index": item.index, "uid": item.uid, "name": item.name,
            "status": item.status_name, "wait_type": item.wait_type,
            "wait_id": item.wait_id, "stop_reason": item.stop_reason,
            "stop_reason_name": item.stop_reason_name,
        })
    return {"count": len(threads), "status_counts": counts, "threads": threads}


def analyze(core: CoreDump, *, tty_lines: int = 12, stack_candidates: int = 16) -> dict:
    return Analysis.build(core, tty_lines=tty_lines, stack_candidates=stack_candidates).summary()
