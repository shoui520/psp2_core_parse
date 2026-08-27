from __future__ import annotations

import shlex
from typing import Optional


ANALYSIS_BANNER = """*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************"""


def _hex(value: Optional[int], width: int = 8) -> str:
    return "unavailable" if value is None else f"0x{value:0{width}x}"


def _size(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB")
    number = float(value)
    for unit in units:
        if number < 1024 or unit == units[-1]:
            return f"{number:.0f} {unit}" if unit == "B" else f"{number:.1f} {unit}"
        number /= 1024
    return f"{value} B"


def _heading(lines: list[str], name: str) -> None:
    lines.extend(("", f"{name}:"))


def _field(lines: list[str], name: str, value) -> None:
    lines.append(f"    {name:<27}: {value}")


def _support(result: dict, name: str) -> Optional[dict]:
    values = result.get("supporting_context", {}).get("by_name", {}).get(name, [])
    if not values:
        return None
    return values[-1].get("data")


def _location(thread: dict, key: str) -> str:
    registers = thread.get("registers") or {}
    address = registers.get(key)
    location = thread.get(f"{key}_location")
    return location["notation"] if location else _hex(address)


def render_analysis_report(result: dict) -> str:
    """Render the default, comprehensive evidence report for ``analyze``."""
    lines = [ANALYSIS_BANNER, "", result["classification"], "", result["verdict"]]

    dump = result["dump"]
    container = result["container"]
    execution = result["execution_context"]
    coverage = result["supporting_context"]["coverage"]
    primary = result.get("primary_crash_thread") or {}
    process = result.get("process") or {}
    application = result.get("application") or {}
    fault = result.get("fault")
    kernel = result["kernel_objects"]

    _heading(lines, "PSP2CORE_ANALYSIS_SUMMARY")
    _field(lines, "Analyzer schema", result["schema"])
    _field(lines, "Classification", result["classification"])
    _field(lines, "Failure bucket", result["failure_bucket"]["canonical"])
    _field(lines, "Failure hash", result["failure_bucket"]["sha256"])
    _field(lines, "Dump completeness", "complete" if dump["complete"] else "SALVAGED PREFIX")
    _field(lines, "Notes / PT_LOAD", f"{dump['note_count']} / {dump['load_count']}")
    _field(lines, "Captured memory", f"0x{dump['captured_bytes']:x} ({_size(dump['captured_bytes'])})")
    _field(lines, "Process", f"{process.get('name') or 'unavailable'} ({_hex(process.get('process_id'))})")
    _field(lines, "Application", f"{application.get('title_id') or 'unavailable'} {application.get('title_name') or ''}".rstrip())
    _field(lines, "Threads / modules", f"{execution['thread_count']} / {result['module_count']}")
    _field(lines, "Kernel objects / active", f"{kernel['object_count']} / {kernel['active_object_count']}")
    _field(lines, "Wait edges / cycles", f"{kernel['wait_graph']['edge_count']} / {kernel['wait_graph']['cycle_count']}")
    _field(lines, "Decoded / partial notes", f"{coverage['decoded_count']} / {coverage['partial_count']}")

    _heading(lines, "DUMP_FILE")
    lines.append(f"    {container['path']}")
    _heading(lines, "DUMP_FILE_ATTRIBUTES")
    _field(lines, "Compression", "gzip" if container["compressed"] else "none")
    _field(lines, "Compression complete", str(container["compression_complete"]).lower())
    _field(lines, "ELF class / machine", f"ELF32 / {container['machine']}")
    _field(lines, "ELF type / flags", f"{container['elf_type']} / {_hex(container['flags'])}")
    _field(lines, "Input size", f"0x{container['raw_file_size']:x} ({_size(container['raw_file_size'])})")
    _field(lines, "ELF image size", f"0x{container['image_size']:x} ({_size(container['image_size'])})")
    _field(
        lines,
        "Program headers",
        f"{container['available_program_header_count']} / {container['declared_program_header_count']}",
    )
    _field(lines, "File SHA-256", container["raw_file_sha256"])
    _field(lines, "Image SHA-256", container["image_sha256"])
    _field(lines, "Structural issues", container["issue_counts"] or "none")
    for issue in container["issues"]:
        lines.append(f"        {issue['severity']} {issue['code']}: {issue['message']}")

    _heading(lines, "NOTE_DECODER_COVERAGE")
    _field(lines, "Recovered notes", len(container["notes"]))
    _field(lines, "Decoded", coverage["decoded_count"])
    _field(lines, "Partial", coverage["partial_count"])
    _field(lines, "Inventory only", coverage["inventory_count"])
    _field(lines, "Decoder errors", coverage["error_count"])
    if coverage["inventory_names"]:
        _field(lines, "Inventory names", ", ".join(coverage["inventory_names"]))
    if coverage["error_names"]:
        _field(lines, "Error names", ", ".join(coverage["error_names"]))
    if result["decoder_errors"]:
        _field(lines, "Execution/kernel errors", len(result["decoder_errors"]))
        for error in result["decoder_errors"]:
            lines.append(f"        {error}")

    _heading(lines, "NOTE_INVENTORY")
    decoded_notes = result["supporting_context"]["decoded"]
    for index, note in enumerate(decoded_notes):
        lines.append(
            f"    [{index:02d}] type={_hex(note['type'], 4)} v={str(note['format_version']):<4} "
            f"size=0x{note['size']:x}/0x{note['declared_size']:x} "
            f"{note['status']:<9} {note['name']}"
        )
        lines.append(f"         sha256={note['sha256']}")
        if note.get("error"):
            lines.append(f"         decoder error: {note['error']}")
        data = note.get("data") or {}
        for partial in data.get("partial_records", []):
            lines.append(
                f"         partial record #{partial['index']}: available=0x{partial['available_size']:x}/"
                f"0x{partial['declared_record_size']:x} uid={_hex(partial.get('thread_uid'))} "
                f"GPR-prefix={partial['available_gpr_count']} sha256={partial['raw_sha256']}"
            )

    producer_summary = dump.get("producer_summary")
    _heading(lines, "SCECOREDUMP_COLLECTION_STAGES")
    if producer_summary is None:
        lines.append("    SUMMARY_INFO unavailable; planned-versus-written stages cannot be reconciled.")
    else:
        _field(lines, "Format / entries", f"{producer_summary['format_version']} / {producer_summary['decoded_count']}")
        _field(lines, "Incomplete entries", producer_summary["incomplete_count"])
        for item in producer_summary["entries"]:
            lines.append(
                f"    [{item['index']:02d}] {_hex(item['note_type'], 4)} {item['producer_name']:<24} "
                f"{item['status']:<14} written=0x{item['written_size']:x}/0x{item['planned_size']:x}"
            )

    app = _support(result, "APP_INFO")
    system = _support(result, "SYSTEM_INFO")
    hardware = _support(result, "HW_INFO")
    build = _support(result, "BUILD_VER_INFO")
    corefile = _support(result, "COREFILE_INFO")
    metadata = _support(result, "META_DATA_INFO")
    system2 = _support(result, "SYSTEM_INFO2")
    gpu_activity = _support(result, "GPU_ACT_INFO")
    _heading(lines, "CAPTURE_ENVIRONMENT")
    if app:
        _field(lines, "Title ID", app["title_id"] or "unavailable")
        _field(lines, "Title", app["title_name"] or "unavailable")
        _field(lines, "Title version", app["title_version"] or "unavailable")
    else:
        lines.append("    APP_INFO unavailable")
    if system:
        _field(lines, "System producer words", " ".join(_hex(value) for value in system["software_version_words"]))
    if hardware:
        _field(lines, "Hardware revision word", _hex(hardware["hardware_revision_word"]))
        _field(lines, "Hardware flags word", _hex(hardware["hardware_flags_word"]))
    if build:
        _field(lines, "Build branch", ", ".join(build["unique_branch_strings"]) or "unavailable")
    if corefile:
        _field(lines, "Corefile kind / subtype", f"{_hex(corefile['producer_kind'])} / {_hex(corefile['producer_subtype'])}")
    if metadata:
        _field(lines, "Metadata entries", f"{metadata['decoded_count']} / {metadata['declared_count']}")
        for item in metadata["entries"]:
            lines.append(
                f"        [{item['index']:02d}] id={_hex(item['identifier'])} "
                f"payload=0x{item['payload_size']:x}/0x{item['declared_payload_size']:x}"
            )
        _field(lines, "Metadata planned padding", f"0x{metadata['trailing_size']:x}; nonzero={metadata['trailing_nonzero_bytes']}")
    if system2:
        _field(
            lines,
            "SYSTEM_INFO2 SCECAF",
            f"magic={system2['container_magic_le64']} header=0x{system2['declared_header_size']:x} "
            f"payload=0x{system2['payload_size']:x}",
        )
        _field(lines, "SCECAF surface count word", system2["producer_surface_count_word"])
        _field(lines, "SCECAF payload SHA-256", system2["payload_sha256"])
    if gpu_activity:
        _field(
            lines,
            "GPU activity producer note",
            "empty ordinary record" if gpu_activity["empty"] else f"0x{gpu_activity['payload_size']:x} payload bytes",
        )

    _heading(lines, "PROCESS_CONTEXT")
    if process:
        _field(lines, "Name", process["name"] or "unnamed")
        _field(lines, "Process ID", _hex(process["process_id"]))
        _field(lines, "Capture status / process flags", f"{_hex(process['capture_status'])} / {_hex(process['process_flags'])}")
        _field(lines, "Parent process ID", _hex(process["parent_process_id"]))
        _field(lines, "Executable", process["path"] or "unavailable")
        _field(lines, "Path bytes", process.get("declared_path_size"))
        _field(lines, "Producer words 0x30", " ".join(_hex(value) for value in process.get("producer_words_0x30", [])))
        _field(lines, "Producer words 0x44", " ".join(_hex(value) for value in process.get("producer_words_0x44", [])))
        _field(lines, "Producer footer", " ".join(_hex(value) for value in process.get("footer_words", [])) or "unavailable")
        _field(lines, "Accounting value", _hex(process.get("accounting_value"), 16))
    else:
        lines.append("    PROCESS_INFO unavailable")

    applications = _support(result, "APP_LIST_INFO")
    external = _support(result, "EXTNL_PROC_INFO")
    _heading(lines, "APPLICATION_AND_PROCESS_SET")
    if applications:
        _field(lines, "Applications", f"{applications['decoded_count']} / {applications['declared_count']}")
        for item in applications["records"]:
            lines.append(
                f"        {item['title_id']:<10} pid={_hex(item['process_id'])} "
                f"path={item['path'] or '<none>'}"
            )
    else:
        lines.append("    APP_LIST_INFO unavailable")
    if external:
        _field(lines, "External processes", f"{external['decoded_count']} / {external['declared_count']}")
        for item in external["records"]:
            lines.append(
                f"        {item['name'] or '<unnamed>'} pid={_hex(item['process_id'])} "
                f"ppid={_hex(item['parent_process_id'])} flags={_hex(item['process_flags'])} "
                f"path={item['path'] or '<none>'}"
            )
    else:
        lines.append("    EXTNL_PROC_INFO unavailable")

    _heading(lines, "FAULT_EVIDENCE")
    if fault is None:
        lines.append("    No applicable architectural FAR/FSR pair was recovered for this stop reason.")
    else:
        access = "execute" if fault["kind"] == "prefetch-abort" else "write" if fault.get("write") else "read"
        _field(lines, "Exception kind / access", f"{fault['kind']} / {access}")
        _field(lines, "Fault address", f"{_hex(fault['address'])} from {fault['address_register']}")
        _field(lines, "Fault status", f"{fault['status_name']} ({fault['status_register']}={_hex(fault['raw'])})")
        _field(lines, "Status code / domain", f"{_hex(fault['status_code'], 2)} / {fault['domain']}")
        _field(lines, "FAR not valid", str(fault.get("far_not_valid", False)).lower())
        _field(lines, "Long descriptor format", str(fault["long_descriptor_format"]).lower())
        evidence = fault["address_evidence"]
        _field(lines, "Address classification", evidence["classification"])
        _field(lines, "Address bytes captured", str(evidence["captured"]).lower())
        _field(lines, "Matching memory blocks", len(fault["memory_blocks"]))
        for block in fault["memory_blocks"]:
            lines.append(
                f"        [{block['index']:02d}] {_hex(block['base'])}-{_hex(block['end'])} "
                f"uid={_hex(block['uid'])} {block['name']}"
            )

    _heading(lines, "CPU_THREADS")
    _field(lines, "Thread count", execution["thread_count"])
    _field(lines, "Crashed indices", execution["crashed_thread_indices"] or "none")
    for thread in execution["threads"]:
        marker = "*" if thread["primary_crash_thread"] else " "
        registers = thread.get("registers")
        lines.append(
            f"  {marker} [{thread['index']:03d}] uid={_hex(thread['uid'])} {thread['status_name']:<12} "
            f"cpu={thread['current_cpu_id']:>2} pri={thread['current_priority']:>3} {thread['name'] or '<unnamed>'}"
        )
        lines.append(
            f"        stop={thread['stop_reason_name']}({_hex(thread['stop_reason'], 5)}) "
            f"wait-type={thread['wait_type']} wait-id={_hex(thread['wait_id'])}"
        )
        if registers:
            lines.append(
                f"        PC={_location(thread, 'pc')} LR={_location(thread, 'lr')} "
                f"SP={_hex(registers['sp'])} CPSR={_hex(registers['cpsr'])} "
                f"stack-at-SP={str(thread['stack_captured_at_sp']).lower()}"
            )

    _heading(lines, "PRIMARY_CRASH_REGISTER_CONTEXT")
    registers = primary.get("registers")
    if not registers:
        lines.append("    Full primary-thread register context unavailable.")
    else:
        _field(lines, "Thread", f"#{primary['index']} {primary['name']} uid={_hex(primary['uid'])}")
        gpr = registers["gpr"]
        for base in range(0, 16, 4):
            values = []
            for index in range(base, base + 4):
                name = {13: "SP", 14: "LR", 15: "PC"}.get(index, f"R{index}")
                values.append(f"{name:<3}={gpr[index]:08x}")
            lines.append("        " + "  ".join(values))
        _field(lines, "CPSR / TPIDRURW", f"{_hex(registers['cpsr'])} / {_hex(registers['tpidrurw'])}")
        _field(lines, "Thumb / processor mode", f"{str(registers['thumb']).lower()} / {_hex(registers['processor_mode'], 2)}")
        _field(lines, "IFSR / IFAR", f"{_hex(registers['ifsr'])} / {_hex(registers['ifar'])}")
        _field(lines, "DFSR / DFAR", f"{_hex(registers['dfsr'])} / {_hex(registers['dfar'])}")
        _field(lines, "Producer system words", " ".join(_hex(value) for value in registers["producer_system_words"]))
        _field(lines, "Register word 0x50", _hex(registers.get("producer_word_0x50")))
        _field(lines, "Thread word 0x2c", _hex(primary.get("producer_word_0x2c")))
        _field(lines, "Thread words 0x78", " ".join(_hex(value) for value in primary.get("producer_words_0x78", [])))
        _field(lines, "Thread recorded PC", _hex(primary.get("recorded_pc")))
        _field(lines, "Thread word 0xa0", _hex(primary.get("producer_word_0xa0")))
        _field(lines, "Thread context 0xa4", " ".join(_hex(value) for value in primary.get("extended_context_words_0xa4", [])) or "none")
        pc_symbol = primary.get("pc_location_symbol")
        lr_symbol = primary.get("lr_location_symbol")
        if pc_symbol:
            _field(lines, "PC symbol", f"{pc_symbol.get('function') or '??'} at {pc_symbol.get('source') or '??'}")
        if lr_symbol:
            _field(lines, "LR symbol", f"{lr_symbol.get('function') or '??'} at {lr_symbol.get('source') or '??'}")
        _field(lines, "VFP debugger poison", str(registers["vfp_poisoned"]).lower())
        lines.append("    VFP D0-D31:")
        for base in range(0, 32, 4):
            lines.append(
                "        " + "  ".join(
                    f"D{index:<2}=0x{registers['vfp_d'][index]:016x}" for index in range(base, base + 4)
                )
            )

    disassembly = result.get("disassembly")
    if disassembly is not None:
        address = disassembly.get("runtime_address")
        _heading(lines, f"DISASSEMBLY AROUND {_hex(address)}")
        if disassembly["status"] != "available":
            _field(lines, "Status", disassembly["status"])
            _field(lines, "Reason", disassembly.get("error") or "unavailable")
        else:
            _field(lines, "Selection", disassembly.get("selection_reason") or "requested address")
            _field(lines, "Runtime PC", _hex(address))
            location = disassembly.get("runtime_location")
            if location:
                _field(lines, "Runtime location", location["notation"])
            if disassembly.get("image_address") is not None:
                _field(lines, "ELF PC", _hex(disassembly["image_address"]))
                _field(lines, "Image", disassembly["image"])
            _field(lines, "Mode", "Thumb" if disassembly["thumb"] else "ARM")
            _field(lines, "Byte source", disassembly["source"])
            _field(lines, "Captured / ELF match", disassembly["byte_comparison"])
            _field(lines, "Source interleaved", str(disassembly["source_interleaved"]).lower())
            captured = disassembly.get("captured_memory") or {}
            image_memory = disassembly.get("image_memory") or {}
            _field(lines, "Captured code", f"0x{captured.get('size', 0):x} bytes" if captured.get("available") else "unavailable")
            if image_memory:
                _field(lines, "ELF code", f"0x{image_memory.get('size', 0):x} bytes" if image_memory.get("available") else "unavailable")
            symbol = disassembly.get("symbol") or {}
            if symbol.get("function") and symbol["function"] != "??":
                detail = symbol["function"]
                if symbol.get("source") and symbol["source"] != "??:0":
                    detail += f" at {symbol['source']}"
                _field(lines, "Symbol", detail)
            for warning in disassembly.get("warnings", []):
                lines.append(f"    WARNING: {warning}")
            for error in disassembly.get("errors", []):
                lines.append(f"    NOTE: {error}")
            lines.append("")
            lines.extend(f"    {line}" if line else "" for line in disassembly["text"].splitlines())

    _heading(lines, "STACK_AND_INSTRUCTION_EVIDENCE")
    stack = primary.get("stack_evidence")
    instruction = primary.get("instruction_evidence")
    if stack:
        _field(lines, "Stack range", f"{_hex(stack['base'])}-{_hex(stack['end'])} size=0x{stack['size']:x}")
        _field(lines, "SP / in stack / captured", f"{_hex(stack['sp'])} / {stack['sp_in_stack']} / {stack['sp_captured']}")
        descending = stack.get("descending_stack_bytes_used")
        _field(lines, "Descending bytes used", f"0x{descending:x}" if descending is not None else "unavailable")
        _field(lines, "Near low guard", str(stack["near_low_guard"]).lower())
        if stack["producer_record"]:
            _field(
                lines,
                "Stack producer words 08/0c",
                f"{_hex(stack['producer_record']['producer_word_0x08'])} / "
                f"{_hex(stack['producer_record']['producer_word_0x0c'])}",
            )
    if instruction:
        _field(lines, "Instruction address", _hex(instruction["address"]))
        _field(lines, "Instruction captured", str(instruction["captured"]).lower())
        _field(lines, "Instruction mode / width", f"{'Thumb' if instruction['thumb'] else 'ARM'} / {instruction['width']}")
        _field(lines, "Instruction bytes", instruction["instruction_bytes"] or "unavailable")
    candidates = primary.get("stack_return_candidates", [])
    lines.append("    Stack-scan return candidates:")
    if candidates:
        for item in candidates:
            symbol = item.get("symbol") or {}
            function = symbol.get("function")
            source = symbol.get("source")
            symbol_text = ""
            if function and function != "??":
                symbol_text = f"  {function}"
                if source and source != "??:0":
                    symbol_text += f" at {source}"
            lines.append(
                f"        [{item['stack_address']:08x}] {item['value']:08x} -> "
                f"{item['location']['notation']}{symbol_text}"
            )
    else:
        lines.append("        none recovered")
    lines.append("    Stack-scan entries are candidates, not unwind-verified frames.")

    _heading(lines, "LOADED_MODULES")
    _field(lines, "Module count", result["module_count"])
    for module in result["modules"]:
        lines.append(
            f"    [{module['index']:02d}] uid={_hex(module['uid'])} "
            f"{'complete' if module['complete'] else 'PARTIAL'} {module['name'] or '<unnamed>'}"
        )
        for segment in module["segments"]:
            lines.append(
                f"         @{segment['number']} {segment['permissions']} {_hex(segment['start'])}-{_hex(segment['end'])} "
                f"size=0x{segment['size']:x} attr={_hex(segment['attributes'])}"
            )

    memory_blocks = _support(result, "MEM_BLK_INFO")
    _heading(lines, "CAPTURED_MEMORY")
    _field(lines, "PT_LOAD ranges", len(container["load_segments"]))
    for load in container["load_segments"]:
        lines.append(
            f"    ph{load['index']:<3} {load['permissions']} {_hex(load['virtual_address'])}-"
            f"{_hex(load['virtual_address'] + load['memory_size'])} "
            f"captured=0x{load['available_size']:x}/0x{load['file_size']:x} missing=0x{load['missing_size']:x}"
        )
    if memory_blocks:
        _field(lines, "Memory blocks", f"{memory_blocks['decoded_count']} / {memory_blocks['declared_count']}")
        for block in memory_blocks["blocks"]:
            lines.append(
                f"    [{block['index']:02d}] {_hex(block['base'])}-{_hex(block['end'])} "
                f"size=0x{block['size']:x} captured=0x{block['captured_bytes']:x} "
                f"uid={_hex(block['uid'])} {block['name'] or '<unnamed>'}"
            )

    libraries = _support(result, "LIBRARY_INFO")
    _heading(lines, "CAPTURED_LIBRARY_SET")
    if libraries:
        _field(lines, "Libraries", f"{libraries['decoded_count']} / {libraries['declared_count']}")
        _field(lines, "Total NID/address entries", sum(item["decoded_entry_count"] for item in libraries["records"]))
        for base in range(0, len(libraries["records"]), 3):
            lines.append(
                "        " + ", ".join(
                    f"{item['name']}[{item['decoded_entry_count']}]" for item in libraries["records"][base:base + 3]
                )
            )
        lines.append("    Use `libraries --nid/--address` for exact entry-level lookup; all pairs are present in JSON.")
    else:
        lines.append("    LIBRARY_INFO unavailable")

    files = _support(result, "FILE_INFO")
    _heading(lines, "FILE_RECORDS")
    if files:
        _field(lines, "Files", f"{files['decoded_count']} / {files['declared_count']}")
        for item in files["records"]:
            values = " | ".join(value for value in item["strings"] if value) or "<empty producer strings>"
            lines.append(
                f"        uid={_hex(item['uid'])} pid={_hex(item['process_id'])} "
                f"status={_hex(item['capture_status'])} {values}"
            )
    else:
        lines.append("    FILE_INFO unavailable")

    events = _support(result, "EVENT_LOG_INFO")
    _heading(lines, "SYSTEM_EVENT_RECORDS")
    if events:
        _field(lines, "Format / records", f"{events['format_version']} / {events['decoded_count']}")
        _field(lines, "Capture status", _hex(events["capture_status"]))
        for item in events["records"]:
            payload = item["item"]
            payload_identity = payload.get("title_id") or ",".join(
                value for value in payload.get("addresses", []) if value
            )
            lines.append(
                f"    [{item['index']:02d}] title={item['title_id'] or '<none>'} "
                f"flags={_hex(item['flags'])} ppid={_hex(item['parent_process_id'])} "
                f"time={_hex(item['time'], 16)} item={payload['kind']}"
                f"{f'({payload_identity})' if payload_identity else ''}"
            )
            lines.append(
                f"         data@04={_hex(item['data_0x04'])} data@1c={_hex(item['producer_word_0x1c'])} "
                f"data@38={_hex(item['producer_word_0x38'])} item-size=0x{item['item_size']:x} "
                f"reserved@20={' '.join(_hex(value) for value in item['reserved_words_0x20'])}"
            )
            if payload["kind"] == "process":
                lines.append(
                    f"         item pid={_hex(payload['process_id'])} budget-type={_hex(payload['budget_type'])} "
                    f"data@40={_hex(payload['producer_word_0x40'])} data@4c={_hex(payload['producer_word_0x4c'])}"
                )
            elif "producer_word_0x40" in payload:
                lines.append(f"         item data@40={_hex(payload['producer_word_0x40'])}")
        _field(lines, "Ring padding", f"0x{events['trailing_size']:x}; nonzero={events['trailing_nonzero_bytes']}")
        lines.append("    Record order and SceKernelDebugEventLog fields are preserved; raw words/hashes remain in JSON.")
    else:
        lines.append("    EVENT_LOG_INFO unavailable")

    budgets = _support(result, "BUDGET_INFO")
    _heading(lines, "PROCESS_MEMORY_BUDGET_RECORDS")
    if budgets:
        _field(lines, "Budgets", f"{budgets['decoded_count']} / {budgets['declared_count']}")
        for budget in budgets["budgets"]:
            lines.append(f"    {budget['name'] or '<unnamed>'} uid={_hex(budget['uid'])}:")
            for partition in budget["partitions"]:
                lines.append(
                    f"        {partition['name'] or '<unnamed>'} uid={_hex(partition['uid'])} "
                    f"word@28={_hex(partition['producer_word_0x28'])} regions={partition['decoded_region_count']}"
                )
                for region in partition["regions"]:
                    lines.append(
                        f"            [{region['index']}] " + " ".join(_hex(value) for value in region["producer_words"])
                    )
        lines.append("    Region slots are exact producer words; size/free/utilization semantics are not inferred.")
    else:
        lines.append("    BUDGET_INFO unavailable")

    device = _support(result, "DEVICE_INFO")
    system_devices = _support(result, "SYS_DEVICE_INFO")
    _heading(lines, "DEVICE_RECORDS")
    if device:
        for item in device["id_lists"]:
            lines.append(
                f"    DEVICE list {item['index']}: " + (", ".join(_hex(value) for value in item["values"]) or "empty")
            )
    if system_devices:
        for item in system_devices["records"]:
            lines.append(
                f"    SYS_DEVICE [{item['index']}] size=0x{item['record_size']:x} {item['description']}"
            )
            lines.append("        payload: " + " ".join(_hex(value) for value in item["payload_words"]))
    if not device and not system_devices:
        lines.append("    DEVICE_INFO and SYS_DEVICE_INFO unavailable")

    callbacks = _support(result, "CALLBACK_INFO")
    timers = _support(result, "TIMER_INFO")
    _heading(lines, "ASYNCHRONOUS_KERNEL_OBJECTS")
    _field(lines, "Callbacks", callbacks["decoded_count"] if callbacks else 0)
    if callbacks:
        for item in callbacks["records"]:
            lines.append(
                f"        callback uid={_hex(item['uid'])} pid={_hex(item['process_id'])} "
                f"thread={_hex(item['thread_uid'])} {item['name']}"
            )
    _field(lines, "Timers", timers["decoded_count"] if timers else 0)
    if timers:
        for item in timers["records"]:
            waiters = ",".join(_hex(value["thread_uid"]) for value in item["waiters"]) or "none"
            lines.append(
                f"        timer uid={_hex(item['uid'])} pid={_hex(item['process_id'])} "
                f"waiters={waiters} {item['name']}"
            )

    _heading(lines, "KERNEL_OBJECTS_AND_WAIT_GRAPH")
    _field(lines, "Tables / objects", f"{kernel['table_count']} / {kernel['object_count']}")
    _field(lines, "Kinds", ", ".join(f"{name}={count}" for name, count in kernel["object_counts"].items()))
    _field(lines, "Active objects", kernel["active_object_count"])
    for item in kernel["active_objects"]:
        lines.append(
            f"    {_hex(item['uid'])} {item['kind']:<24} owner={_hex(item['owner_thread_uid'])} "
            f"waiters={item['waiting_thread_count']} {item['name'] or '<unnamed>'}"
        )
        if item["state"]:
            lines.append("        state: " + " ".join(f"{name}={_hex(value) if isinstance(value, int) else value}" for name, value in item["state"].items()))
    graph = kernel["wait_graph"]
    _field(lines, "Wait edges / cycles", f"{graph['edge_count']} / {graph['cycle_count']}")
    for edge in graph["edges"]:
        lines.append(
            f"        thread {_hex(edge['from_thread_uid'])} -> {edge['object_kind']} "
            f"{_hex(edge['object_uid'])} {edge['object_name'] or '<unnamed>'} -> owner {_hex(edge['to_owner_thread_uid'])}"
        )
    for cycle in graph["cycles"]:
        lines.append("        cycle: " + " -> ".join(_hex(value) for value in cycle))
    for table in kernel["tables"]:
        lines.append(
            f"    table {table['note_name']:<20} {table['decoded_count']}/{table['declared_count']} "
            f"{'complete' if table['complete'] else 'PARTIAL'} trailing=0x{table['trailing_size']:x}"
        )

    _heading(lines, "TTY_LOG_EVIDENCE")
    streams = result["tty"]["streams"]
    if not streams:
        lines.append("    No TTY stream was recovered.")
    for stream in streams:
        _field(lines, f"{stream['note']} lines", f"{stream.get('line_count', 0)}; complete={stream.get('complete', False)}")
        for item in stream.get("tail", []):
            lines.append(f"        {item['text']}")
    lines.append("    TTY timestamps and order are producer log evidence, not necessarily the exact exception time.")

    _heading(lines, "FAILURE_IDENTITY")
    _field(lines, "Process name", process.get("name") or "unavailable")
    _field(lines, "Process ID", _hex(process.get("process_id")))
    _field(lines, "Thread", f"{primary.get('name') or 'unavailable'} ({_hex(primary.get('uid'))})")
    _field(lines, "PC", _location(primary, "pc") if primary else "unavailable")
    _field(lines, "Fault address", _hex(fault.get("address")) if fault else "not applicable")
    _field(lines, "Failure bucket", result["failure_bucket"]["canonical"])
    _field(lines, "Failure hash", result["failure_bucket"]["sha256"])

    path = shlex.quote(container["path"])
    pc_symbol = primary.get("pc_location_symbol") if primary else None
    image_path = pc_symbol.get("image") if pc_symbol else None
    module_name = pc_symbol.get("module_name") if pc_symbol else None
    supplied_image = (
        f" --image {shlex.quote(f'{module_name}={image_path}')}"
        if image_path and module_name else ""
    )
    suggested_image = supplied_image or " --image MODULE=DECRYPTED.elf"
    _heading(lines, "FOLLOWUP_COMMANDS")
    if primary:
        lines.append(f"    psp2-core-parse thread {path} crash{supplied_image}")
        lines.append(f"    psp2-core-parse backtrace {path} crash{suggested_image}")
    if registers:
        lines.append(
            f"    psp2-core-parse address {path} {_hex(registers['pc'])}{suggested_image}"
        )
        lines.append(
            f"    psp2-core-parse disasm {path} {_hex(registers['pc'])}{suggested_image}"
        )
    lines.extend((
        f"    psp2-core-parse libraries {path} --address ADDRESS",
        f"    psp2-core-parse notes {path} NOTE_NAME --json",
    ))
    return "\n".join(lines)
