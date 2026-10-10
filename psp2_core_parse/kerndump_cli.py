# Copyright (c) 2026 devnoname120
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json

from .core import ParseError
from .kerndump import KernelDump


_COMMANDS = {"analyze", "info", "threads", "thread", "registers", "backtrace", "modules", "context", "validate", "extract"}


def _register_lines(registers: dict) -> list[str]:
    lines = []
    for row in range(0, 16, 4):
        lines.append("  ".join(f"r{index:<2}=0x{registers['gpr'][index]:08x}" for index in range(row, row + 4)))
    lines.append(f"SP=0x{registers['sp']:08x} LR=0x{registers['lr']:08x} PC=0x{registers['pc']:08x} CPSR=0x{registers['cpsr']:08x}")
    for name, value in registers.items():
        if name not in ("sp", "lr", "pc", "cpsr", "thumb") and type(value) is int:
            lines.append(f"{name.upper()}=0x{value:08x}")
    vfp = registers.get("vfp_d", [])
    for row in range(0, len(vfp), 4):
        lines.append("  ".join(f"d{index:<2}=0x{vfp[index]:016x}" for index in range(row, min(row + 4, len(vfp)))))
    return lines


def _backtrace_lines(dump: KernelDump) -> list[str]:
    lines = []
    for label, frames in (("Kernel", dump.kernel_backtrace), ("User", dump.user_backtrace)):
        lines.append(f"{label} backtrace (producer-saved):")
        for frame in frames:
            lines.append(
                f"  #{frame['index']} PC=0x{frame['pc']:08x} SP=0x{frame['sp']:08x} "
                f"base=0x{frame['module_base']:08x} fingerprint=0x{frame['fingerprint']:08x}"
            )
        if not frames:
            lines.append("  No records recovered.")
    return lines


def _info_lines(dump: KernelDump) -> list[str]:
    lines = [
        str(dump.path),
        f"PS Vita kernel dump: {'complete' if dump.complete else 'SALVAGED'}",
        f"Firmware: {dump.info['firmware_version_string']}; type={dump.container['type']}",
        f"Input: {dump.raw_file_size} bytes; blob: {len(dump.blob)}/{dump.info['blob_size']} bytes; encrypted={dump.info['encrypted']}",
    ]
    if dump.header:
        lines += [
            f"PID=0x{dump.header['process_id']:08x} TID=0x{dump.header['thread_id']:08x} CPU={dump.header['cpu_id']}",
            f"System time: {dump.header['system_time_us']} microseconds",
            f"Source hashes: file=0x{dump.header['file_hash']:08x} line=0x{dump.header['line_hash']:08x} function=0x{dump.header['function_hash']:08x}",
        ]
    else:
        lines.append("Diagnostic blob header: not recovered; thread/register details unavailable.")
    lines.append(f"SHA-256: {dump.raw_file_sha256}")
    return lines


def _analysis_text(dump: KernelDump, result: dict) -> str:
    lines = _info_lines(dump) + ["", result["verdict"], ""] + _backtrace_lines(dump)
    context = dump.exception_context
    if context:
        lines += ["", "Fault registers:"] + _register_lines(context["registers"])
        module = context["fault_module"]
        lines.append(f"Fault module: {module['notation'] if module else 'not recorded'}")
        fault = result["fault"]
        if fault:
            status = fault["status"]
            access = "write" if status.get("write") else "read" if "write" in status else "execute"
            lines.append(f"Fault address=0x{fault['address']:08x}; {access}; {status['status_name']}")
        lines.append("Waypoints:")
        for point in context["waypoints"]:
            detail = point.get("exception_cause", point.get("instruction_set", point["event_name"]))
            module = point["target_module"]
            lines.append(
                f"  ({point['index']:2}) PC=0x{point['pc']:08x} TARGET=0x{point['target_pc']:08x} "
                f"{detail} [{module['notation'] if module else 'no module info'}]"
            )
    if dump.saved_thread_registers:
        lines += ["", "Saved thread registers:"] + _register_lines(dump.saved_thread_registers)
    if dump.trailing:
        label = "trailing blob" if dump.header else "blob"
        lines.append(f"Uninterpreted {label} bytes: {len(dump.trailing)} (preserved by extract --blob and JSON)")
    lines.extend(f"{issue.severity}: {issue.message}" for issue in dump.issues)
    lines += ["", "Limitations:"] + result["limitations"]
    return "\n".join(lines)


def command_kernel_dump(args, dump: KernelDump) -> tuple[object, str]:
    command = args.command
    if command not in _COMMANDS:
        raise ParseError(f"{command} is not available for .psp2kerndmp; this format has no ELF notes or captured memory")
    if getattr(args, "image", None):
        raise ParseError("image-backed symbolization is not available for .psp2kerndmp; module records contain fingerprints and bases, not a complete module map")
    if command in ("thread", "registers", "backtrace"):
        selector = getattr(args, "selector", "crash")
        if selector != "crash":
            if not dump.header:
                raise ParseError("no thread record was recovered from the kernel dump")
            try:
                selected = int(selector, 0) in (0, dump.header["thread_id"])
            except ValueError:
                selected = False
            if not selected:
                raise ParseError(f"thread {selector!r} was not found in the kernel dump")
    if command == "analyze":
        result = dump.analysis()
        return result, _analysis_text(dump, result)
    if command == "info":
        return dump.summary(), "\n".join(_info_lines(dump) + [f"{issue.severity}: {issue.message}" for issue in dump.issues])
    if command in ("threads", "thread"):
        thread = dump.thread()
        if thread is None:
            if command == "thread":
                raise ParseError("no thread record was recovered from the kernel dump")
            return {"threads": [], "complete_inventory": False}, "No thread record was recovered from the kernel dump."
        result = {"threads": [thread], "complete_inventory": False} if command == "threads" else thread
        return result, f"Captured thread: TID=0x{thread['uid']:08x} PID=0x{thread['process_id']:08x} CPU={thread['cpu_id']}"
    if command == "registers":
        fault = dump.exception_context["registers"] if dump.exception_context else None
        saved = dump.saved_thread_registers
        if fault is None and saved is None:
            raise ParseError("no register context was recovered from the kernel dump")
        result = {"fault_registers": fault, "saved_thread_registers": saved}
        lines = []
        for label, registers in (("Fault registers", fault), ("Saved thread registers", saved)):
            if registers is not None:
                lines += [label + ":"] + _register_lines(registers)
        return result, "\n".join(lines)
    if command == "backtrace":
        return {
            "kernel_backtrace": dump.kernel_backtrace, "user_backtrace": dump.user_backtrace,
            "unwind_verified": False, "source": "producer-saved",
        }, "\n".join(_backtrace_lines(dump))
    if command == "modules":
        result = {"modules": dump.modules(), "complete_inventory": False}
        lines = ["Module identities referenced by saved records (not a complete module map):"]
        lines += [f"  fingerprint=0x{module['fingerprint']:08x} base=0x{module['module_base']:08x}" for module in result["modules"]]
        return result, "\n".join(lines)
    if command == "context":
        result = {"container": dump.container, "info": dump.info, "header": dump.header, "exception_context": dump.exception_context}
        return result, json.dumps(result, indent=2)
    if command == "validate":
        result = {
            "format": "psp2kerndmp", "valid_core": dump.complete,
            "blob_header_recovered": bool(dump.header),
            "core_issues": [issue.summary() for issue in dump.issues],
            "kernel_backtrace_count": len(dump.kernel_backtrace), "user_backtrace_count": len(dump.user_backtrace),
            "exception_context_recovered": dump.exception_context is not None,
            "saved_registers_recovered": dump.saved_thread_registers is not None,
            "trailing_size": len(dump.trailing),
        }
        lines = [f"Kernel dump: {'complete' if dump.complete else 'salvaged'}; {len(dump.issues)} issue(s)"]
        lines.extend(f"{issue.severity}: {issue.message}" for issue in dump.issues)
        return result, "\n".join(lines)
    if not args.blob:
        raise ParseError("ELF notes and captured memory are not available for .psp2kerndmp; use extract --blob")
    if args.output.exists() and args.output.samefile(dump.path):
        raise ParseError("extraction output must not overwrite the input dump")
    if args.output.exists() and not args.force:
        raise ParseError(f"{args.output} exists; use --force to overwrite it")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(dump.blob)
    result = {
        "source": "kernel dump plaintext blob", "output": str(args.output), "size": len(dump.blob),
        "complete": dump.complete, "issues": [issue.summary() for issue in dump.issues],
    }
    lines = [f"Wrote {len(dump.blob)} plaintext blob bytes to {args.output}"]
    lines.extend(f"{issue.severity}: {issue.message}" for issue in dump.issues)
    return result, "\n".join(lines)
