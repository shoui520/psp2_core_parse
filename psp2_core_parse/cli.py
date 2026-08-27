from __future__ import annotations

import argparse
import difflib
import json
import struct
import sys
from pathlib import Path
from typing import Iterable, Optional

from . import __version__
from .analysis import analyze
from .core import CoreDump, ParseError
from .execution import AddressLocation, ExecutionContext, Thread
from .kernel import KernelObjectRegistry
from .support import decode_note, parse_memory_blocks, supporting_context
from .symbols import Symbolizer, ToolError, disassemble_bytes, disassemble_core
from .tty import TtyInfo


def integer(value: str) -> int:
    try:
        result = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer {value!r}") from exc
    if not 0 <= result <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("value is outside the 32-bit unsigned range")
    return result


def positive_integer(value: str) -> int:
    result = integer(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return result


def _json(value) -> str:
    return json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False)


def _hex(value: Optional[int], width: int = 8) -> str:
    return "-" if value is None else f"0x{value:0{width}x}"


def _size(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB")
    number = float(value)
    for unit in units:
        if number < 1024 or unit == units[-1]:
            return f"{number:.0f} {unit}" if unit == "B" else f"{number:.1f} {unit}"
        number /= 1024
    return f"{value} B"


def _hexdump(data: bytes, address: int) -> str:
    result = []
    for offset in range(0, len(data), 16):
        row = data[offset : offset + 16]
        groups = " ".join(f"{item:02x}" for item in row)
        printable = "".join(chr(item) if 0x20 <= item < 0x7F else "." for item in row)
        result.append(f"{address + offset:08x}  {groups:<47}  |{printable}|")
    return "\n".join(result)


def _add_core_arguments(parser: argparse.ArgumentParser, *, images: bool = False) -> None:
    parser.add_argument("core", type=Path, help="Vita .psp2dmp or interrupted .tmp dump")
    parser.add_argument("--strict", action="store_true", help="reject any structurally incomplete input")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    if images:
        parser.add_argument(
            "--image", action="append", default=[], metavar="[MODULE=]ELF",
            help="decrypted ELF/SELF image for symbols (repeatable)",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="psp2-core-parse",
        description="PlayStation Vita psp2core coredump analyzer and debugger",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    item = commands.add_parser("analyze", help="produce an evidence-led crash diagnosis")
    _add_core_arguments(item, images=True)
    item.add_argument("--tty-lines", type=int, default=12)
    item.add_argument("--stack-candidates", type=int, default=16)

    item = commands.add_parser("info", help="show container integrity and inventory")
    _add_core_arguments(item)

    item = commands.add_parser("notes", help="inventory or decode ELF notes")
    _add_core_arguments(item)
    item.add_argument("name", nargs="?", help="decode only this note name")
    item.add_argument("--raw", action="store_true", help="include the raw description as hex")

    item = commands.add_parser("threads", help="list threads and crash state")
    _add_core_arguments(item)

    item = commands.add_parser("thread", help="inspect one thread")
    _add_core_arguments(item, images=True)
    item.add_argument("selector", help="thread index, UID, name, or 'crash'")
    item.add_argument("--stack-candidates", type=int, default=32)

    item = commands.add_parser("registers", help="show the full register file for a thread")
    _add_core_arguments(item)
    item.add_argument("selector", nargs="?", default="crash")

    item = commands.add_parser("stack", help="inspect a thread stack and return-address candidates")
    _add_core_arguments(item, images=True)
    item.add_argument("selector", nargs="?", default="crash")
    item.add_argument("--bytes", type=positive_integer, default=0x100)
    item.add_argument("--candidates", type=int, default=64)

    item = commands.add_parser("backtrace", help="build a qualified PC/LR/stack-scan trace")
    _add_core_arguments(item, images=True)
    item.add_argument("selector", nargs="?", default="crash")
    item.add_argument("--candidates", type=int, default=64)
    item.add_argument("--max-frames", type=int, default=32, help="maximum ARM EHABI frames when images are supplied")

    item = commands.add_parser("modules", help="list runtime modules and segments")
    _add_core_arguments(item)

    item = commands.add_parser("memory-blocks", help="inspect declared process memory blocks and capture coverage")
    _add_core_arguments(item)
    item.add_argument("--address", type=integer, help="show only blocks containing this address")
    item.add_argument("--captured-only", action="store_true", help="show only blocks with captured bytes")

    item = commands.add_parser("libraries", help="query libraries and their NID/address entries")
    _add_core_arguments(item)
    item.add_argument("--name", help="case-insensitive library-name substring")
    item.add_argument("--nid", type=integer, help="match an exact NID")
    item.add_argument("--address", type=integer, help="match an exact runtime address")

    item = commands.add_parser("files", help="list file objects recorded by SceCoredump")
    _add_core_arguments(item)
    item.add_argument("--process", type=integer, help="filter by process ID")

    item = commands.add_parser("apps", help="list applications present at capture time")
    _add_core_arguments(item)

    item = commands.add_parser("processes", help="show the crashed process and external process snapshot")
    _add_core_arguments(item)

    item = commands.add_parser("budgets", help="inspect exact budget, partition, and producer-region records")
    _add_core_arguments(item)
    item.add_argument("--name", help="case-insensitive budget or partition-name substring")

    item = commands.add_parser("events", help="inspect the captured system event-log ring")
    _add_core_arguments(item)
    item.add_argument("--title-id", help="filter by title ID")
    item.add_argument("--flags", "--code", dest="flags", type=integer, help="filter by exact event flags")

    item = commands.add_parser("callbacks", help="list captured callback objects")
    _add_core_arguments(item)

    item = commands.add_parser("timers", help="list timers and waiting threads")
    _add_core_arguments(item)

    item = commands.add_parser("devices", help="inspect process and system-device snapshots")
    _add_core_arguments(item)

    item = commands.add_parser("summary", help="show SceCoredump's 50-stage collection summary")
    _add_core_arguments(item)

    item = commands.add_parser("context", help="show system, build, application, and producer context")
    _add_core_arguments(item)

    item = commands.add_parser("system2", help="inspect or extract the SCECAF display-surface container")
    _add_core_arguments(item)
    item.add_argument("--output", type=Path, help="write the raw SCECAF container (without note version word)")
    item.add_argument("--force", action="store_true")

    item = commands.add_parser("map", help="show captured PT_LOAD memory ranges")
    _add_core_arguments(item)

    item = commands.add_parser("address", help="resolve and inspect a runtime address")
    _add_core_arguments(item, images=True)
    item.add_argument("address", type=integer)
    item.add_argument("--bytes", type=positive_integer, default=32)

    item = commands.add_parser("memory", help="read captured memory")
    _add_core_arguments(item)
    item.add_argument("address", type=integer)
    item.add_argument("size", type=positive_integer)

    item = commands.add_parser("xref", help="find captured little-endian references to a value")
    _add_core_arguments(item)
    item.add_argument("value", type=integer)
    item.add_argument("--limit", type=positive_integer, default=256)

    item = commands.add_parser("search", help="search captured memory")
    _add_core_arguments(item)
    group = item.add_mutually_exclusive_group(required=True)
    group.add_argument("--hex", dest="hex_pattern", metavar="HEX")
    group.add_argument("--ascii", dest="ascii_pattern", metavar="TEXT")
    item.add_argument("--limit", type=positive_integer, default=256)

    item = commands.add_parser("disasm", help="disassemble captured or supplied-image code with VitaSDK objdump")
    _add_core_arguments(item, images=True)
    item.add_argument("address", nargs="?", type=integer, help="defaults to the crash PC")
    item.add_argument("--bytes", type=positive_integer, default=64)
    mode = item.add_mutually_exclusive_group()
    mode.add_argument("--thumb", action="store_true")
    mode.add_argument("--arm", action="store_true")

    item = commands.add_parser("waits", help="show kernel waiters, owners, and wait cycles")
    _add_core_arguments(item)
    item.add_argument("--active", action="store_true", help="omit inactive objects")

    item = commands.add_parser("object", help="resolve a kernel-object UID")
    _add_core_arguments(item)
    item.add_argument("uid", type=integer)

    item = commands.add_parser("tty", help="show captured TTY streams and timeline")
    _add_core_arguments(item)
    item.add_argument("--stream", choices=("TTY_INFO", "TTY_INFO2"))
    item.add_argument("--tail", type=positive_integer)
    item.add_argument("--ansi", action="store_true", help="preserve ANSI control sequences")

    item = commands.add_parser("validate", help="exercise all decoders and report coverage")
    _add_core_arguments(item)

    item = commands.add_parser("triage", help="group and rank multiple dumps")
    item.add_argument("paths", nargs="+", type=Path)
    item.add_argument("--strict", action="store_true")
    item.add_argument("--json", action="store_true")

    item = commands.add_parser("compare", help="compare two crash diagnoses")
    item.add_argument("left", type=Path)
    item.add_argument("right", type=Path)
    item.add_argument("--strict", action="store_true")
    item.add_argument("--json", action="store_true")

    item = commands.add_parser("extract", help="extract a note, load segment, or memory range")
    _add_core_arguments(item)
    source = item.add_mutually_exclusive_group(required=True)
    source.add_argument("--note", metavar="NAME")
    source.add_argument("--load", type=int, metavar="PROGRAM_HEADER_INDEX")
    source.add_argument("--memory", nargs=2, type=integer, metavar=("ADDRESS", "SIZE"))
    item.add_argument("--output", required=True, type=Path)
    item.add_argument("--force", action="store_true")
    return parser


def _core(args) -> CoreDump:
    return CoreDump.read(args.core, strict=args.strict)


def _execution(core: CoreDump) -> ExecutionContext:
    return ExecutionContext.parse(core)


def _thread(execution: ExecutionContext, selector: str) -> Thread:
    if execution.threads is None:
        raise ParseError("THREAD_INFO was not recovered")
    if selector == "crash":
        if execution.primary_crash_thread is None:
            raise ParseError("no crashed thread was recovered")
        return execution.primary_crash_thread
    try:
        number = int(selector, 0)
    except ValueError:
        matches = [item for item in execution.threads.threads if item.name == selector]
    else:
        matches = [item for item in execution.threads.threads if item.index == number or item.uid == number]
    if not matches:
        raise ParseError(f"thread {selector!r} was not found")
    if len(matches) > 1:
        raise ParseError(f"thread selector {selector!r} is ambiguous")
    return matches[0]


def _symbolizer(args) -> Symbolizer:
    return Symbolizer.from_specs(getattr(args, "image", ()))


def _location_from_summary(location: dict) -> AddressLocation:
    return AddressLocation(
        location["address"], location["module_index"], location["module_uid"],
        location["module_name"], location["segment_number"], location["segment_start"],
        location["segment_size"], location["permissions"], location["offset"],
    )


def _symbol_text(symbol: Optional[dict]) -> Optional[str]:
    if not symbol:
        return None
    function = symbol.get("function")
    source = symbol.get("source")
    if function and function != "??":
        return f"{function} at {source}" if source and source != "??:0" else function
    error = symbol.get("error")
    return f"unresolved ({error})" if error else None


def _location_text(location: dict, symbol: Optional[dict] = None) -> str:
    text = location["notation"]
    detail = _symbol_text(symbol)
    return f"{text}  {detail}" if detail else text


def _symbolize_thread(result: dict, symbolizer: Symbolizer) -> None:
    for key in ("pc_location", "lr_location"):
        location = result.get(key)
        if not location:
            continue
        image = symbolizer.image_for_module(location["module_name"])
        if image is None:
            continue
        result[f"{key}_symbol"] = symbolizer.symbolize(_location_from_summary(location))
    for candidate in result.get("stack_return_candidates", ()):
        location = candidate.get("location")
        if location and symbolizer.image_for_module(location["module_name"]):
            candidate["symbol"] = symbolizer.symbolize(_location_from_summary(location))


def command_analyze(args) -> tuple[dict, str]:
    core = _core(args)
    result = analyze(core, tty_lines=max(0, args.tty_lines), stack_candidates=max(0, args.stack_candidates))
    symbolizer = _symbolizer(args)
    primary = result.get("primary_crash_thread")
    if primary and symbolizer.images:
        _symbolize_thread(primary, symbolizer)
    from .report import render_analysis_report
    return result, render_analysis_report(result)


def command_info(args) -> tuple[dict, str]:
    core = _core(args)
    result = core.summary()
    text = "\n".join((
        f"{core.path}",
        f"ELF32 ARM core: {'complete' if core.complete else 'SALVAGED'}",
        f"Input: {_size(core.raw_file_size)}; decompressed: {_size(core.image_size)}",
        f"Program headers: {len(core.program_headers)}/{core.declared_program_header_count}",
        f"Notes: {len(core.notes)}; loads: {len(core.loads)}; captured: {_size(result['captured_bytes'])}",
        f"Issues: {result['issue_counts'] or 'none'}",
        f"SHA-256: {core.raw_file_sha256}",
    ))
    return result, text


def command_notes(args) -> tuple[object, str]:
    core = _core(args)
    execution = _execution(core)
    notes = [item for item in core.notes if args.name is None or item.name == args.name]
    if args.name and not notes:
        raise ParseError(f"note {args.name!r} was not found")
    decoded = []
    lines = []
    for note in notes:
        item = decode_note(note, core, execution).summary()
        if args.raw:
            item["raw_hex"] = note.description.hex()
        decoded.append(item)
        lines.append(
            f"{note.name:<20} type={_hex(note.note_type, 4)} version={note.format_version!s:<4} "
            f"size=0x{len(note.description):x}/0x{note.declared_size:x} {item['status']}"
        )
        if args.name:
            lines.append(_json(item["data"]))
    return decoded, "\n".join(lines)


def command_threads(args) -> tuple[dict, str]:
    core = _core(args); execution = _execution(core)
    result = execution.summary(core)
    lines = []
    for item in result["threads"]:
        marker = "*" if item["primary_crash_thread"] else " "
        registers = item.get("registers")
        pc = item.get("pc_location", {}).get("notation") if item.get("pc_location") else _hex(registers["pc"] if registers else None)
        lines.append(
            f"{marker} #{item['index']:<3} {_hex(item['uid'])} {item['status_name']:<14} "
            f"stop={_hex(item['stop_reason'], 5)} pc={pc:<30} {item['name']}"
        )
    return result, "\n".join(lines)


def command_thread(args) -> tuple[dict, str]:
    core = _core(args); execution = _execution(core); thread = _thread(execution, args.selector)
    result = execution.thread_summary(core, thread, stack_candidates=max(0, args.stack_candidates))
    _symbolize_thread(result, _symbolizer(args))
    registers = result.get("registers")
    lines = [
        f"Thread #{thread.index} {thread.name} uid={_hex(thread.uid)}",
        f"Status: {thread.status_name}; stop: {thread.stop_reason_name} ({_hex(thread.stop_reason, 5)})",
        f"Stack: {_hex(thread.stack_base)}-{_hex(thread.stack_end)} ({_size(thread.stack_size)})",
    ]
    if registers:
        lines.append(f"PC={_hex(registers['pc'])} LR={_hex(registers['lr'])} SP={_hex(registers['sp'])} CPSR={_hex(registers['cpsr'])}")
        for label, key in (("PC symbol", "pc_location_symbol"), ("LR symbol", "lr_location_symbol")):
            detail = _symbol_text(result.get(key))
            if detail:
                lines.append(f"{label}: {detail}")
    if result["stack_return_candidates"]:
        lines.append("Stack-scan return candidates:")
        lines.extend(
            f"  {_hex(item['stack_address'])}: {_location_text(item['location'], item.get('symbol'))}"
            for item in result["stack_return_candidates"]
        )
    return result, "\n".join(lines)


def command_registers(args) -> tuple[dict, str]:
    core = _core(args); execution = _execution(core); thread = _thread(execution, args.selector)
    registers = execution.registers.by_uid(thread.uid) if execution.registers else None
    if registers is None:
        raise ParseError(f"no register record for thread {_hex(thread.uid)}")
    result = registers.summary(thread.stop_reason)
    lines = [f"Thread #{thread.index} {thread.name} uid={_hex(thread.uid)}"]
    for row in range(0, 16, 4):
        lines.append("  ".join(f"r{index:<2}={_hex(result['gpr'][index])}" for index in range(row, row + 4)))
    lines.extend((
        f"cpsr={_hex(result['cpsr'])} tpidrurw={_hex(result['tpidrurw'])} thumb={result['thumb']}",
        f"IFSR={_hex(result['ifsr'])} IFAR={_hex(result['ifar'])} DFSR={_hex(result['dfsr'])} DFAR={_hex(result['dfar'])}",
        f"VFP: {len(result['vfp_d'])} D registers; poisoned={result['vfp_poisoned']}",
    ))
    return result, "\n".join(lines)


def command_stack(args) -> tuple[dict, str]:
    core = _core(args); execution = _execution(core); thread = _thread(execution, args.selector)
    summary = execution.thread_summary(core, thread, stack_candidates=max(0, args.candidates))
    registers = execution.registers.by_uid(thread.uid) if execution.registers else None
    if registers is None:
        raise ParseError("thread has no recovered SP")
    start = registers.sp
    end = min(thread.stack_end, start + args.bytes)
    ranges = core.captured_ranges(start, end)
    data = b""
    if ranges and ranges[0][0] == start:
        data = core.read_memory(start, ranges[0][1] - start)
    symbolizer = _symbolizer(args)
    for candidate in summary["stack_return_candidates"]:
        location = execution.modules.locate(candidate["value"]) if execution.modules else None
        if location and symbolizer.images:
            candidate["symbol"] = symbolizer.symbolize(location)
    result = {
        "thread": {"index": thread.index, "uid": thread.uid, "name": thread.name},
        "stack_base": thread.stack_base, "stack_end": thread.stack_end, "sp": registers.sp,
        "requested_size": args.bytes, "captured_size": len(data), "bytes": data.hex(),
        "candidates": summary["stack_return_candidates"],
    }
    text = f"SP {_hex(start)}; captured {len(data)}/{args.bytes} bytes\n{_hexdump(data, start)}"
    if result["candidates"]:
        text += "\nReturn candidates:\n" + "\n".join(
            f"  {_hex(item['stack_address'])}: {_location_text(item['location'], item.get('symbol'))}"
            for item in result["candidates"]
        )
    return result, text


def command_backtrace(args) -> tuple[dict, str]:
    core = _core(args); execution = _execution(core); thread = _thread(execution, args.selector)
    summary = execution.thread_summary(core, thread, stack_candidates=max(0, args.candidates))
    registers = execution.registers.by_uid(thread.uid) if execution.registers else None
    if registers is None:
        raise ParseError("thread has no recovered register context")
    symbolizer = _symbolizer(args)
    frames = []
    for kind, address, location_data, qualification in (
        ("pc", registers.pc, summary.get("pc_location"), "architectural PC"),
        ("lr", registers.lr, summary.get("lr_location"), "architectural LR; not unwind-verified"),
    ):
        frame = {"kind": kind, "address": address, "location": location_data, "qualification": qualification}
        location = execution.modules.locate(address) if execution.modules else None
        if location and symbolizer.images:
            frame["symbol"] = symbolizer.symbolize(location)
        frames.append(frame)
    for item in summary["stack_return_candidates"]:
        frame = {"kind": "stack-scan", "address": item["value"], "stack_address": item["stack_address"], "location": item["location"], "qualification": item["qualification"]}
        location = execution.modules.locate(item["value"]) if execution.modules else None
        if location and symbolizer.images:
            frame["symbol"] = symbolizer.symbolize(location)
        frames.append(frame)
    ehabi = None
    if symbolizer.images:
        from .unwind import unwind_thread
        ehabi = unwind_thread(core, execution, thread, symbolizer, max_frames=args.max_frames)
    result = {
        "thread": {"index": thread.index, "uid": thread.uid, "name": thread.name},
        "ehabi": ehabi,
        "fallback_frames": frames,
        "unwind_verified": bool(ehabi and ehabi["verified_frame_count"]),
    }
    lines = []
    if ehabi:
        lines.append(f"ARM EHABI: {ehabi['status']}; verified transitions={ehabi['verified_frame_count']}; stop={ehabi['stop']['code']}")
        for frame in ehabi["frames"]:
            where = frame["runtime_location"]["notation"] if frame.get("runtime_location") else _hex(frame["pc"])
            symbol = frame.get("symbol", {}).get("function")
            lines.append(f"#{frame['index']:<2} {frame['source']:<18} {where}" + (f"  {symbol}" if symbol and symbol != "??" else ""))
    if not ehabi or not ehabi["verified_frame_count"]:
        if ehabi:
            lines.append("Qualified fallback (not unwind-verified):")
        for index, frame in enumerate(frames):
            where = frame["location"]["notation"] if frame.get("location") else _hex(frame["address"])
            symbol = frame.get("symbol", {}).get("function")
            lines.append(f"#{index:<2} {frame['kind']:<10} {where}" + (f"  {symbol}" if symbol else ""))
        lines.append("Qualification: PC is architectural; LR and stack-scan entries are not unwind-verified.")
    return result, "\n".join(lines)


def command_modules(args) -> tuple[object, str]:
    core = _core(args); execution = _execution(core)
    if execution.modules is None:
        raise ParseError("MODULE_INFO was not recovered")
    result = execution.modules.summary()
    lines = []
    for module in execution.modules.modules:
        lines.append(f"#{module.index:<3} {_hex(module.uid)} {module.name} {'complete' if module.complete else 'partial'}")
        lines.extend(
            f"    seg{segment.number} {_hex(segment.start)}-{_hex(segment.end)} {segment.permissions} {_size(segment.size)}"
            for segment in module.segments
        )
    return result, "\n".join(lines)


def _decoded_note_data(core: CoreDump, name: str, execution: Optional[ExecutionContext] = None) -> dict:
    note = core.note(name)
    if note is None:
        raise ParseError(f"{name} was not recovered")
    item = decode_note(note, core, execution)
    if item.error or item.data is None:
        raise ParseError(f"cannot decode {name}: {item.error or 'no decoded data'}")
    return item.data


def command_memory_blocks(args) -> tuple[dict, str]:
    core = _core(args)
    data = _decoded_note_data(core, "MEM_BLK_INFO")
    blocks = data["blocks"]
    if args.address is not None:
        blocks = [item for item in blocks if item["base"] <= args.address < item["end"]]
    if args.captured_only:
        blocks = [item for item in blocks if item["captured_bytes"]]
    result = {**data, "selected_count": len(blocks), "blocks": blocks}
    lines = [
        f"{_hex(item['base'])}-{_hex(item['end'])} {_size(item['size']):>10} "
        f"captured={_size(item['captured_bytes']):>10} uid={_hex(item['uid'])} {item['name']}"
        for item in blocks
    ]
    return result, "\n".join(lines) or "No matching memory blocks."


def command_libraries(args) -> tuple[dict, str]:
    core = _core(args)
    data = _decoded_note_data(core, "LIBRARY_INFO")
    selected = []
    for library in data["records"]:
        if args.name and args.name.casefold() not in library["name"].casefold():
            continue
        entries = [
            item for item in library["entries"]
            if (args.nid is None or item["nid"] == args.nid)
            and (args.address is None or item["address"] == args.address)
        ]
        if (args.nid is not None or args.address is not None) and not entries:
            continue
        selected_library = dict(library)
        if args.nid is not None or args.address is not None:
            selected_library["matching_entries"] = entries
        selected.append(selected_library)
    result = {
        "format_version": data["format_version"],
        "declared_count": data["declared_count"],
        "complete": data["complete"],
        "filters": {"name": args.name, "nid": args.nid, "address": args.address},
        "selected_count": len(selected),
        "records": selected,
    }
    lines = []
    show_entries = args.nid is not None or args.address is not None
    for library in selected:
        lines.append(
            f"{_hex(library['uid'])} module={_hex(library['module_uid'])} "
            f"entries={library['decoded_entry_count']:<4} {library['name']}"
        )
        if show_entries:
            lines.extend(
                f"    {item['class']:<9} nid={_hex(item['nid'])} address={_hex(item['address'])}"
                for item in library["matching_entries"]
            )
    return result, "\n".join(lines) or "No matching libraries or entries."


def command_files(args) -> tuple[dict, str]:
    core = _core(args)
    data = _decoded_note_data(core, "FILE_INFO")
    records = [item for item in data["records"] if args.process is None or item["process_id"] == args.process]
    result = {**data, "selected_count": len(records), "records": records}
    lines = []
    for item in records:
        labels = [value for value in item["strings"] if value]
        lines.append(
            f"{_hex(item['uid'])} pid={_hex(item['process_id'])} status={_hex(item['capture_status'])} "
            + (" | ".join(labels) if labels else "(no producer strings)")
        )
    return result, "\n".join(lines) or "No matching file records."


def command_apps(args) -> tuple[dict, str]:
    core = _core(args)
    data = _decoded_note_data(core, "APP_LIST_INFO")
    lines = [
        f"{item['title_id']:<10} pid={_hex(item['process_id'])} {item['path'] or '(no path)'}"
        for item in data["records"]
    ]
    return data, "\n".join(lines)


def command_processes(args) -> tuple[dict, str]:
    core = _core(args)
    execution = _execution(core)
    current = execution.process.summary() if execution.process else None
    external = _decoded_note_data(core, "EXTNL_PROC_INFO", execution)
    result = {"current": current, "external": external}
    lines = []
    if current:
        lines.append(f"* {_hex(current['process_id'])} {current['name']:<24} {current['path']}")
    lines.extend(
        f"  {_hex(item['process_id'])} {item['name']:<24} {item['path']}"
        for item in external["records"]
    )
    return result, "\n".join(lines)


def command_budgets(args) -> tuple[dict, str]:
    core = _core(args)
    data = _decoded_note_data(core, "BUDGET_INFO")
    needle = args.name.casefold() if args.name else None
    selected = []
    for budget in data["budgets"]:
        partitions = [
            item for item in budget["partitions"]
            if needle is None or needle in budget["name"].casefold() or needle in item["name"].casefold()
        ]
        if partitions:
            selected.append({**budget, "partitions": partitions})
    result = {
        **data,
        "qualification": "Region slots are reported as copied producer words; size/free semantics are not inferred.",
        "selected_count": len(selected),
        "budgets": selected,
    }
    lines = []
    for budget in selected:
        lines.append(f"{_hex(budget['uid'])} {budget['name']} ({len(budget['partitions'])} partitions)")
        lines.extend(
            f"    {_hex(item['uid'])} regions={item['decoded_region_count']} "
            f"word@28={_hex(item['producer_word_0x28'])} {item['name']}"
            for item in budget["partitions"]
        )
    lines.append("Qualification: region values are opaque producer words; no utilization is claimed.")
    return result, "\n".join(lines)


def command_events(args) -> tuple[dict, str]:
    core = _core(args)
    data = _decoded_note_data(core, "EVENT_LOG_INFO")
    records = [
        item for item in data["records"]
        if (args.title_id is None or item["title_id"] == args.title_id)
        and (args.flags is None or item["flags"] == args.flags)
    ]
    result = {**data, "selected_count": len(records), "records": records}
    lines = [
        f"#{item['index']:<2} size=0x{item['record_size']:x} title={item['title_id'] or '-':<12} "
        f"flags={_hex(item['flags'])} ppid={_hex(item['parent_process_id'])} "
        f"item={item['item']['kind']} "
        f"{item['item'].get('title_id') or ' '.join(item['item'].get('addresses', []))}"
        for item in records
    ]
    return result, "\n".join(lines) or "No matching event records."


def _object_note_command(args, note_name: str) -> tuple[dict, str]:
    core = _core(args)
    data = _decoded_note_data(core, note_name)
    lines = []
    for item in data["records"]:
        line = f"{_hex(item['uid'])} pid={_hex(item['process_id'])} {item['name']}"
        waiters = item.get("waiters", [])
        if waiters:
            line += " waiters=" + ",".join(_hex(waiter["thread_uid"]) for waiter in waiters)
        lines.append(line)
    return data, "\n".join(lines) or f"{note_name} contains no records."


def command_callbacks(args) -> tuple[dict, str]:
    return _object_note_command(args, "CALLBACK_INFO")


def command_timers(args) -> tuple[dict, str]:
    return _object_note_command(args, "TIMER_INFO")


def command_devices(args) -> tuple[dict, str]:
    core = _core(args)
    result = {}
    lines = []
    for name in ("DEVICE_INFO", "SYS_DEVICE_INFO"):
        note = core.note(name)
        if note is None:
            continue
        data = _decoded_note_data(core, name)
        result[name] = data
        if name == "DEVICE_INFO":
            lines.append(f"DEVICE_INFO: {len(data['id_lists'])} producer ID lists")
            lines.extend(
                f"  list {item['index']}: " + ", ".join(_hex(value) for value in item["values"])
                for item in data["id_lists"]
            )
        else:
            lines.append(f"SYS_DEVICE_INFO: {len(data['records'])} records")
            lines.extend(f"  {item['description']} ({len(item['payload_words'])} payload words)" for item in data["records"])
    if not result:
        raise ParseError("no device snapshot was recovered")
    return result, "\n".join(lines)


def command_summary(args) -> tuple[dict, str]:
    core = _core(args)
    data = _decoded_note_data(core, "SUMMARY_INFO")
    lines = [
        f"#{item['index']:<2} {item['producer_name']:<24} {item['status']:<14} "
        f"written=0x{item['written_size']:x}/0x{item['planned_size']:x}"
        for item in data["entries"]
    ]
    return data, "\n".join(lines)


def command_context(args) -> tuple[dict, str]:
    core = _core(args)
    names = ("COREFILE_INFO", "SYSTEM_INFO", "APP_INFO", "HW_INFO", "BUILD_VER_INFO", "META_DATA_INFO", "GPU_ACT_INFO")
    result = {}
    lines = []
    for name in names:
        note = core.note(name)
        if note is None:
            continue
        data = _decoded_note_data(core, name)
        result[name] = data
        if name == "APP_INFO":
            lines.append(f"APP: {data['title_id']} {data['title_name']} {data['title_version']}")
        elif name == "BUILD_VER_INFO":
            lines.append("BUILD: " + (", ".join(data["unique_branch_strings"]) or "no branch strings"))
        elif name == "GPU_ACT_INFO":
            lines.append(
                f"GPU activity producer record: {'empty' if data['empty'] else str(data['payload_size']) + ' bytes'}"
            )
        else:
            lines.append(f"{name}: version={data.get('format_version')} size={data.get('raw_size', len(note.description))}")
    return result, "\n".join(lines)


def command_system2(args) -> tuple[dict, str]:
    core = _core(args)
    note = core.note("SYSTEM_INFO2")
    if note is None:
        raise ParseError("SYSTEM_INFO2 was not recovered")
    data = _decoded_note_data(core, "SYSTEM_INFO2")
    result = dict(data)
    lines = [
        f"Container: {data['container_magic_le64']} ({'valid' if data['container_magic_valid'] else 'unexpected'} magic)",
        f"Header: 0x{data['declared_header_size']:x}; payload: {_size(data['payload_size'])}; raw note: {_size(data['raw_size'])}",
        f"Producer surface count word: {data['producer_surface_count_word']}",
        "Qualification: SceCoredump emits this SCECAF container from display surfaces; payload encoding is retained, not guessed.",
    ]
    if args.output is not None:
        if args.output.exists() and not args.force:
            raise ParseError(f"{args.output} exists; use --force to overwrite it")
        payload = note.description[4:]
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload)
        except OSError as exc:
            raise ParseError(f"cannot write {args.output}: {exc}") from exc
        result["output"] = str(args.output)
        result["output_size"] = len(payload)
        lines.append(f"Wrote {len(payload)} bytes to {args.output}")
    return result, "\n".join(lines)


def command_map(args) -> tuple[object, str]:
    core = _core(args)
    result = [item.summary() for item in core.loads]
    lines = [
        f"ph{item.index:<3} {_hex(item.virtual_address)}-{_hex(item.memory_end)} {item.permissions} "
        f"captured=0x{len(item.data):x}/0x{item.file_size:x}"
        for item in core.loads
    ]
    return result, "\n".join(lines)


def command_address(args) -> tuple[dict, str]:
    core = _core(args); execution = _execution(core)
    location = execution.modules.locate(args.address) if execution.modules else None
    symbolizer = _symbolizer(args)
    symbol = symbolizer.symbolize(location) if location and symbolizer.images else None
    extents = [item.summary() for item in core.memory_extents(args.address, args.bytes)]
    data = b""
    if extents and extents[0]["captured"]:
        first_size = extents[0]["size"]
        data = core.read_memory(args.address, first_size)
    blocks = []
    note = core.note("MEM_BLK_INFO")
    if note:
        try:
            blocks = [item.summary(core) for item in parse_memory_blocks(note.description)[2] if item.base <= args.address < item.end]
        except (ParseError, struct.error, ValueError):
            pass
    image_memory = None
    if not data and location and symbolizer.images:
        image = symbolizer.image_for_module(location.module_name)
        if image is not None:
            try:
                image_address = image.image_address(location)
                image_data = image.linked_bytes(image_address, args.bytes)
                image_memory = {
                    "image": str(image.path), "image_address": image_address,
                    "runtime_address": args.address, "size": len(image_data),
                    "bytes": image_data.hex(), "error": None,
                }
            except ParseError as exc:
                image_memory = {
                    "image": str(image.path), "image_address": None,
                    "runtime_address": args.address, "size": 0, "bytes": "",
                    "error": str(exc),
                }
    result = {
        "address": args.address,
        "module": location.summary() if location else None,
        "symbol": symbol,
        "memory_extents": extents,
        "bytes": data.hex(),
        "supplied_image_memory": image_memory,
        "memory_blocks": blocks,
    }
    lines = [f"Address {_hex(args.address)}"]
    lines.append(f"Module: {location.notation}" if location else "Module: not mapped by MODULE_INFO")
    symbol_detail = _symbol_text(symbol)
    if symbol_detail:
        lines.append(f"Symbol: {symbol_detail}")
    lines.append(f"Captured: {len(data)} contiguous byte(s)")
    if data:
        lines.append(_hexdump(data, args.address))
    elif image_memory:
        if image_memory["error"]:
            lines.append(f"Supplied image bytes: unavailable ({image_memory['error']})")
        else:
            lines.append(
                f"Supplied image bytes: {image_memory['size']} from {image_memory['image']} "
                f"at ELF {_hex(image_memory['image_address'])}"
            )
            lines.append(_hexdump(bytes.fromhex(image_memory["bytes"]), args.address))
    if blocks:
        lines.append("Memory blocks: " + ", ".join(item["name"] or _hex(item["uid"]) for item in blocks))
    return result, "\n".join(lines)


def command_memory(args) -> tuple[dict, str]:
    core = _core(args); data = core.read_memory(args.address, args.size)
    return {"address": args.address, "size": len(data), "bytes": data.hex()}, _hexdump(data, args.address)


def _search(core: CoreDump, pattern: bytes, limit: int) -> list[dict]:
    if not pattern:
        raise ParseError("empty search pattern")
    results = []
    seen = set()
    for segment in core.loads:
        offset = 0
        while len(results) < limit:
            found = segment.data.find(pattern, offset)
            if found < 0:
                break
            address = segment.virtual_address + found
            if address not in seen:
                results.append({"address": address, "segment_index": segment.index})
                seen.add(address)
            offset = found + 1
        if len(results) >= limit:
            break
    return results


def command_xref(args) -> tuple[dict, str]:
    core = _core(args); execution = _execution(core)
    matches = _search(core, struct.pack("<I", args.value), args.limit)
    for item in matches:
        location = execution.modules.locate(item["address"]) if execution.modules else None
        item["location"] = location.summary() if location else None
    result = {"value": args.value, "match_count": len(matches), "limit": args.limit, "matches": matches}
    text = "\n".join(f"{_hex(item['address'])}  {item['location']['notation'] if item['location'] else '-'}" for item in matches)
    return result, text or "No references found."


def command_search(args) -> tuple[dict, str]:
    core = _core(args)
    if args.hex_pattern is not None:
        try:
            pattern = bytes.fromhex(args.hex_pattern)
        except ValueError as exc:
            raise ParseError(f"invalid hex pattern: {exc}") from exc
        representation = pattern.hex()
    else:
        pattern = args.ascii_pattern.encode()
        representation = args.ascii_pattern
    matches = _search(core, pattern, args.limit)
    result = {"pattern": representation, "pattern_size": len(pattern), "match_count": len(matches), "limit": args.limit, "matches": matches}
    return result, "\n".join(f"{_hex(item['address'])}  ph{item['segment_index']}" for item in matches) or "No matches found."


def command_disasm(args) -> tuple[dict, str]:
    core = _core(args); execution = _execution(core)
    address = args.address
    thumb = args.thumb
    if address is None:
        thread = execution.primary_crash_thread
        registers = execution.registers.by_uid(thread.uid) if thread and execution.registers else None
        if registers is None:
            raise ParseError("no crash PC was recovered; supply an address")
        address = registers.pc
        if not args.arm and not args.thumb:
            thumb = registers.thumb
    elif not args.arm and not args.thumb:
        thumb = bool(address & 1)
    runtime_address = address & ~1
    symbolizer = _symbolizer(args)
    location = execution.modules.locate(runtime_address) if execution.modules else None
    symbol = symbolizer.symbolize(location) if location and symbolizer.images else None
    try:
        result = disassemble_core(core, runtime_address, args.bytes, thumb=thumb)
        result["source"] = "captured-memory"
    except ParseError as captured_error:
        if not symbolizer.images:
            raise
        if location is None:
            raise ParseError(
                f"{captured_error}; runtime address {_hex(runtime_address)} is not mapped by MODULE_INFO"
            ) from captured_error
        image = symbolizer.image_for_module(location.module_name)
        if image is None:
            raise ParseError(
                f"{captured_error}; no supplied image matches module {location.module_name}"
            ) from captured_error
        image_address = image.image_address(location)
        data = image.linked_bytes(image_address, args.bytes)
        result = {
            "address": runtime_address, "size": len(data), "thumb": thumb,
            "bytes": data.hex(), "text": disassemble_bytes(data, runtime_address, thumb=thumb),
            "source": "supplied-image", "image": str(image.path),
            "image_address": image_address, "runtime_location": location.summary(),
            "captured_memory_error": str(captured_error),
        }
    if symbol:
        result["symbol"] = symbol
    lines = [
        "Source: captured memory" if result["source"] == "captured-memory" else (
            f"Source: supplied image {result['image']} at ELF {_hex(result['image_address'])} "
            f"for runtime {_hex(runtime_address)}"
        )
    ]
    symbol_detail = _symbol_text(symbol)
    if symbol_detail:
        lines.append(f"Symbol: {symbol_detail}")
    lines.append(result["text"])
    return result, "\n".join(lines)


def command_waits(args) -> tuple[dict, str]:
    registry = KernelObjectRegistry.parse(_core(args)); result = registry.summary()
    objects = result["active_objects"] if args.active else [item.summary() for item in registry.objects]
    view = {**result, "objects": objects}
    lines = []
    for item in objects:
        lines.append(
            f"{_hex(item['uid'])} {item['kind']:<31} owner={_hex(item['owner_thread_uid'])} "
            f"waiters={item['waiting_thread_count']:<3} {item['name']}"
        )
    graph = result["wait_graph"]
    lines.append(f"Wait graph: {graph['edge_count']} edges, {graph['cycle_count']} cycles")
    return view, "\n".join(lines)


def command_object(args) -> tuple[dict, str]:
    registry = KernelObjectRegistry.parse(_core(args)); item = registry.resolve(args.uid)
    if item is None:
        raise ParseError(f"kernel object {_hex(args.uid)} was not found or is ambiguous")
    result = item.summary()
    lines = [
        f"{item.kind} {item.name} uid={_hex(item.uid)} pid={_hex(item.process_id)}",
        f"attributes={_hex(item.attributes)} owner={_hex(item.owner_thread_uid)} waiters={item.waiting_thread_count}",
        _json(item.state),
    ]
    lines.extend(f"  waiter {_hex(waiter.thread_uid)} pid={_hex(waiter.process_id)} role={waiter.role}" for waiter in item.waiters)
    return result, "\n".join(lines)


def command_tty(args) -> tuple[object, str]:
    core = _core(args); results = []; texts = []
    names = (args.stream,) if args.stream else ("TTY_INFO", "TTY_INFO2")
    for name in names:
        note = core.note(name)
        if note is None:
            continue
        parsed = TtyInfo.parse(note.description)
        summary = parsed.summary(preserve_ansi=args.ansi)
        lines = parsed.lines(preserve_ansi=args.ansi)
        if args.tail is not None:
            lines = lines[-args.tail:]
            summary["selected_lines"] = [item.summary() for item in lines]
        results.append({"note": name, **summary})
        texts.append(f"== {name} ==\n" + "\n".join(item.text for item in lines))
    if not results:
        raise ParseError("no requested TTY stream was recovered")
    return results, "\n".join(texts)


def command_validate(args) -> tuple[dict, str]:
    core = _core(args); execution = _execution(core); context = supporting_context(core, execution)
    registry = KernelObjectRegistry.parse(core)
    note_results = []
    for item in context["decoded"]:
        data = item.get("data") or {}
        note_results.append({
            "name": item["name"],
            "type": item["type"],
            "status": item["status"],
            "decoder": item["decoder"],
            "error": item["error"],
            "description_size": item["size"],
            "declared_description_size": item["declared_size"],
            "description_complete": item["complete"],
            "description_sha256": item["sha256"],
            "decoder_complete": data.get("complete"),
            "trailing_size": data.get("trailing_size"),
            "trailing_nonzero_bytes": data.get("trailing_nonzero_bytes"),
            "trailing_sha256": data.get("trailing_sha256"),
            "evidence_preserved": True,
            "interpreted_or_inventoried": item["status"] != "error",
        })
    decoder_errors = [item for item in note_results if item["status"] == "error"]
    nonzero_trailing = [
        item for item in note_results if (item["trailing_nonzero_bytes"] or 0) > 0
    ]
    result = {
        "valid_core": core.complete,
        "salvage_valid": not decoder_errors and not execution.errors and not registry.errors,
        "core_issues": [item.summary() for item in core.issues],
        "note_coverage": context["coverage"],
        "note_results": note_results,
        "raw_evidence_preserved_count": sum(item["evidence_preserved"] for item in note_results),
        "interpreted_or_inventoried_count": sum(item["interpreted_or_inventoried"] for item in note_results),
        "nonzero_decoder_trailing_count": len(nonzero_trailing),
        "nonzero_decoder_trailing": nonzero_trailing,
        "execution_errors": list(execution.errors),
        "kernel_errors": list(registry.errors),
        "kernel_incomplete_tables": [item.summary() for item in registry.tables if not item.complete],
    }
    text = "\n".join((
        f"Container: {'complete' if core.complete else 'salvaged'} ({len(core.issues)} issue(s))",
        f"Notes: {context['coverage']['decoded_count']} decoded, {context['coverage']['partial_count']} partial, "
        f"{context['coverage']['inventory_count']} inventoried, {context['coverage']['error_count']} errors",
        f"Raw note evidence preserved: {result['raw_evidence_preserved_count']}/{len(note_results)}; "
        f"interpreted/inventoried: {result['interpreted_or_inventoried_count']}/{len(note_results)}; "
        f"non-zero decoder tails: {len(nonzero_trailing)}",
        f"Execution decoder errors: {len(execution.errors)}; kernel decoder errors: {len(registry.errors)}",
        f"Incomplete kernel tables: {len(result['kernel_incomplete_tables'])}",
    ))
    return result, text


def _paths(paths: Iterable[Path]) -> list[Path]:
    result = []
    for path in paths:
        if path.is_dir():
            result.extend(item for item in sorted(path.iterdir()) if item.is_file())
        else:
            result.append(path)
    return result


def command_triage(args) -> tuple[dict, str]:
    rows = []; failures = []
    for path in _paths(args.paths):
        try:
            core = CoreDump.read(path, strict=args.strict)
            value = analyze(core, tty_lines=0, stack_candidates=0)
            thread = value.get("primary_crash_thread") or {}
            registers = thread.get("registers") or {}
            rows.append({
                "path": str(path), "complete": core.complete, "classification": value["classification"],
                "bucket": value["failure_bucket"]["canonical"], "bucket_sha256": value["failure_bucket"]["sha256"],
                "thread": thread.get("name"), "pc": registers.get("pc"),
                "pc_location": (thread.get("pc_location") or {}).get("notation"),
                "fault_address": (value.get("fault") or {}).get("address"),
            })
        except (OSError, ParseError, struct.error, ValueError) as exc:
            failures.append({"path": str(path), "error": str(exc)})
    groups: dict[str, list[int]] = {}
    for index, row in enumerate(rows):
        groups.setdefault(row["bucket"], []).append(index)
    result = {
        "input_count": len(rows) + len(failures), "analyzed_count": len(rows), "failure_count": len(failures),
        "group_count": len(groups),
        "groups": [
            {"bucket": bucket, "count": len(indices), "row_indices": indices, "paths": [rows[item]["path"] for item in indices]}
            for bucket, indices in sorted(groups.items(), key=lambda pair: (-len(pair[1]), pair[0]))
        ],
        "rows": rows, "failures": failures,
    }
    lines = [f"Analyzed {len(rows)}/{len(rows)+len(failures)} dumps; {len(groups)} failure groups"]
    lines.extend(f"{group['count']:>4}  {group['bucket']}" for group in result["groups"])
    if failures:
        lines.append("Failures:")
        lines.extend(f"  {item['path']}: {item['error']}" for item in failures)
    return result, "\n".join(lines)


def _compare_view(value: dict) -> dict:
    thread = value.get("primary_crash_thread") or {}
    registers = thread.get("registers") or {}
    return {
        "classification": value["classification"], "verdict": value["verdict"],
        "bucket": value["failure_bucket"]["canonical"], "complete": value["dump"]["complete"],
        "process": value.get("process"), "application": value.get("application"),
        "thread": {"name": thread.get("name"), "uid": thread.get("uid"), "stop_reason": thread.get("stop_reason")},
        "registers": {key: registers.get(key) for key in ("pc", "lr", "sp", "cpsr", "dfsr", "dfar", "ifsr", "ifar")},
        "pc_location": thread.get("pc_location"), "lr_location": thread.get("lr_location"),
        "fault": value.get("fault"), "thread_overview": value.get("thread_overview"),
        "kernel_wait_graph": value.get("kernel_objects", {}).get("wait_graph"),
        "budgets": value.get("budgets"),
    }


def command_compare(args) -> tuple[dict, str]:
    left = _compare_view(analyze(CoreDump.read(args.left, strict=args.strict), tty_lines=0))
    right = _compare_view(analyze(CoreDump.read(args.right, strict=args.strict), tty_lines=0))
    differences = {}
    for key in left:
        if left[key] != right[key]:
            differences[key] = {"left": left[key], "right": right[key]}
    result = {"left_path": str(args.left), "right_path": str(args.right), "same_bucket": left["bucket"] == right["bucket"], "difference_count": len(differences), "differences": differences}
    before = _json(left).splitlines(); after = _json(right).splitlines()
    text = "\n".join(difflib.unified_diff(before, after, fromfile=str(args.left), tofile=str(args.right), lineterm=""))
    return result, text or "No selected diagnostic differences."


def command_extract(args) -> tuple[dict, str]:
    core = _core(args)
    if args.output.exists() and not args.force:
        raise ParseError(f"{args.output} exists; use --force to overwrite it")
    if args.note is not None:
        note = core.note(args.note)
        if note is None:
            raise ParseError(f"note {args.note!r} was not found")
        data = note.description; source = f"note {args.note}"
    elif args.load is not None:
        matches = [item for item in core.loads if item.index == args.load]
        if not matches:
            raise ParseError(f"PT_LOAD program-header index {args.load} was not found")
        data = matches[0].data; source = f"PT_LOAD ph{args.load}"
    else:
        address, size = args.memory
        data = core.read_memory(address, size); source = f"memory {_hex(address)}+0x{size:x}"
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(data)
    except OSError as exc:
        raise ParseError(f"cannot write {args.output}: {exc}") from exc
    result = {"source": source, "output": str(args.output), "size": len(data)}
    return result, f"Wrote {len(data)} bytes from {source} to {args.output}"


COMMANDS = {
    "analyze": command_analyze, "info": command_info, "notes": command_notes,
    "threads": command_threads, "thread": command_thread, "registers": command_registers,
    "stack": command_stack, "backtrace": command_backtrace, "modules": command_modules,
    "memory-blocks": command_memory_blocks, "libraries": command_libraries,
    "files": command_files, "apps": command_apps, "processes": command_processes,
    "budgets": command_budgets, "events": command_events,
    "callbacks": command_callbacks, "timers": command_timers, "devices": command_devices,
    "summary": command_summary, "context": command_context, "system2": command_system2,
    "map": command_map, "address": command_address, "memory": command_memory,
    "xref": command_xref, "search": command_search, "disasm": command_disasm,
    "waits": command_waits, "object": command_object, "tty": command_tty,
    "validate": command_validate, "triage": command_triage, "compare": command_compare,
    "extract": command_extract,
}


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result, text = COMMANDS[args.command](args)
    except (ParseError, ToolError, OSError, struct.error, ValueError) as exc:
        print(f"psp2-core-parse: error: {exc}", file=sys.stderr)
        return 2
    print(_json(result) if args.json else text)
    return 0
