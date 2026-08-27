from __future__ import annotations

import bisect
import struct
from typing import Optional, Sequence

from .core import CoreDump, ParseError
from .execution import ExecutionContext, Thread
from .symbols import ElfImage, Symbolizer


SHT_ARM_EXIDX = 0x70000001
EXIDX_CANTUNWIND = 1


def _prel31(place: int, value: int) -> int:
    offset = value & 0x7FFFFFFF
    if offset & 0x40000000:
        offset -= 0x80000000
    return (place + offset) & 0xFFFFFFFF


def _exidx_entries(image: ElfImage) -> list[dict]:
    entries = []
    for section in image.section_headers():
        if section["type"] != SHT_ARM_EXIDX:
            continue
        start, end = section["file_offset"], section["file_offset"] + section["size"]
        if not 0 <= start <= end <= len(image.data):
            raise ParseError(f"{image.path} section {section['name'] or section['index']} exceeds the image")
        data = image.data[start:end]
        entry_size = section["entry_size"] or 8
        if entry_size < 8 or len(data) % entry_size:
            raise ParseError(f"{image.path} has a malformed ARM.exidx section")
        for offset in range(0, len(data), entry_size):
            function_word, unwind_word = struct.unpack_from("<2I", data, offset)
            place = section["address"] + offset
            entries.append({
                "function_address": _prel31(place, function_word),
                "entry_address": place,
                "unwind_word": unwind_word,
                "section_name": section["name"],
            })
    entries.sort(key=lambda item: item["function_address"])
    for index, item in enumerate(entries):
        item["function_end"] = entries[index + 1]["function_address"] if index + 1 < len(entries) else None
    return entries


def _compact_bytecode(image: ElfImage, entry: dict) -> dict:
    word = entry["unwind_word"]
    if word == EXIDX_CANTUNWIND:
        return {"status": "cantunwind", "personality": None, "bytecode": [], "source": "exidx"}
    source = "inline"
    extab_address = None
    if not word & 0x80000000:
        extab_address = _prel31(entry["entry_address"] + 4, word)
        word = struct.unpack_from("<I", image.linked_bytes(extab_address, 4))[0]
        source = "extab"
    if not word & 0x80000000:
        return {"status": "unsupported-generic-personality", "personality": None, "bytecode": [], "source": source, "extab_address": extab_address}
    personality = (word >> 24) & 0xF
    if personality == 0:
        bytecode = [(word >> shift) & 0xFF for shift in (16, 8, 0)]
    elif personality in (1, 2) and source == "extab":
        additional_words = (word >> 16) & 0xFF
        bytecode = [(word >> 8) & 0xFF, word & 0xFF]
        if additional_words:
            raw = image.linked_bytes(extab_address + 4, additional_words * 4)
            for value in struct.unpack(f"<{additional_words}I", raw):
                bytecode.extend((value >> shift) & 0xFF for shift in (24, 16, 8, 0))
    else:
        return {"status": "unsupported-compact-personality", "personality": personality, "bytecode": [], "source": source, "extab_address": extab_address}
    return {"status": "available", "personality": personality, "bytecode": bytecode, "source": source, "extab_address": extab_address}


def _uleb128(bytecode: Sequence[int], cursor: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while cursor < len(bytecode) and shift <= 28:
        byte = bytecode[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, cursor
        shift += 7
    raise ParseError("truncated or oversized EHABI ULEB128 operand")


def execute_compact_bytecode(
    core: CoreDump,
    registers: Sequence[int],
    stack_base: int,
    stack_end: int,
    bytecode: Sequence[int],
) -> dict:
    """Execute the standard ARM EHABI integer/VSP compact-model subset."""
    if len(registers) != 16:
        raise ParseError("EHABI register state must contain r0 through r15")
    state = list(registers)
    operations = []
    reads = []
    cursor = 0
    pc_restored = False

    def pop(register_numbers: Sequence[int]) -> None:
        nonlocal pc_restored
        address = state[13]
        restored_sp: Optional[int] = None
        values = []
        for register_number in register_numbers:
            if not stack_base <= address or address + 4 > stack_end:
                raise ParseError(f"EHABI pop at 0x{address:08x} leaves the retained thread stack")
            value = struct.unpack_from("<I", core.read_memory(address, 4))[0]
            reads.append({"address": address, "register": register_number, "value": value})
            values.append((register_number, value))
            address += 4
        for register_number, value in values:
            state[register_number] = value
            if register_number == 13:
                restored_sp = value
            elif register_number == 15:
                pc_restored = True
        state[13] = restored_sp if restored_sp is not None else address

    while cursor < len(bytecode):
        opcode = bytecode[cursor]
        cursor += 1
        if opcode <= 0x3F:
            amount = ((opcode & 0x3F) << 2) + 4
            state[13] += amount; operations.append(f"vsp += 0x{amount:x}")
        elif opcode <= 0x7F:
            amount = ((opcode & 0x3F) << 2) + 4
            state[13] -= amount; operations.append(f"vsp -= 0x{amount:x}")
        elif opcode <= 0x8F:
            if cursor >= len(bytecode):
                raise ParseError("truncated EHABI register mask")
            mask = ((opcode & 0xF) << 8) | bytecode[cursor]; cursor += 1
            if mask == 0:
                raise ParseError("EHABI refused-to-unwind opcode")
            selected = [number for number in range(4, 16) if mask & (1 << (number - 4))]
            pop(selected); operations.append("pop {" + ",".join(f"r{x}" for x in selected) + "}")
        elif opcode <= 0x9F:
            register_number = opcode & 0xF
            if register_number in (13, 15):
                raise ParseError(f"reserved EHABI set-vsp opcode 0x{opcode:02x}")
            state[13] = state[register_number]; operations.append(f"vsp = r{register_number}")
        elif opcode <= 0xA7:
            selected = list(range(4, 5 + (opcode & 7)))
            pop(selected); operations.append("pop {" + ",".join(f"r{x}" for x in selected) + "}")
        elif opcode <= 0xAF:
            selected = list(range(4, 5 + (opcode & 7))) + [14]
            pop(selected); operations.append("pop {" + ",".join(f"r{x}" for x in selected) + "}")
        elif opcode == 0xB0:
            if not pc_restored:
                state[15] = state[14]
            operations.append("finish")
            return {"registers": state, "operations": operations, "stack_reads": reads, "finished": True, "pc_restored": pc_restored}
        elif opcode == 0xB1:
            if cursor >= len(bytecode):
                raise ParseError("truncated EHABI low-register mask")
            mask = bytecode[cursor]; cursor += 1
            if not mask or mask & 0xF0:
                raise ParseError("invalid EHABI low-register mask")
            selected = [number for number in range(4) if mask & (1 << number)]
            pop(selected); operations.append("pop {" + ",".join(f"r{x}" for x in selected) + "}")
        elif opcode == 0xB2:
            value, cursor = _uleb128(bytecode, cursor)
            amount = 0x204 + (value << 2)
            state[13] += amount; operations.append(f"vsp += 0x{amount:x}")
        elif opcode == 0xB3:
            if cursor >= len(bytecode):
                raise ParseError("truncated EHABI VFP-pop operand")
            count = (bytecode[cursor] & 0xF) + 1; cursor += 1
            state[13] += count * 8; operations.append(f"pop {count} VFP registers")
        elif 0xB8 <= opcode <= 0xBF or 0xD0 <= opcode <= 0xD7:
            count = (opcode & 7) + 1
            state[13] += count * 8; operations.append(f"pop {count} VFP registers")
        elif opcode in (0xC8, 0xC9):
            if cursor >= len(bytecode):
                raise ParseError("truncated EHABI VFP-pop operand")
            count = (bytecode[cursor] & 0xF) + 1; cursor += 1
            state[13] += count * 8; operations.append(f"pop {count} VFP registers")
        else:
            raise ParseError(f"unsupported EHABI opcode 0x{opcode:02x}")
    raise ParseError("EHABI bytecode ended without a finish opcode")


def unwind_thread(
    core: CoreDump,
    execution: ExecutionContext,
    thread: Thread,
    symbolizer: Symbolizer,
    *,
    max_frames: int = 32,
) -> dict:
    if not 1 <= max_frames <= 256:
        raise ParseError("maximum EHABI frame count must be between 1 and 256")
    if execution.modules is None:
        raise ParseError("MODULE_INFO is required for EHABI unwinding")
    registers = execution.registers.by_uid(thread.uid) if execution.registers else None
    if registers is None:
        return {"status": "registers-not-retained", "frames": [], "verified_frame_count": 0}
    state = list(registers.gpr)
    frames = []
    seen = set()
    cache: dict[str, list[dict]] = {}
    stop = None
    for frame_index in range(max_frames):
        pc, sp = state[15], state[13]
        key = (pc & ~1, sp)
        if key in seen:
            stop = {"code": "repeated-state", "detail": "PC/SP state repeated"}; break
        seen.add(key)
        location = execution.modules.locate(pc, executable_only=True)
        frame = {
            "index": frame_index, "pc": pc, "sp": sp, "lr": state[14],
            "source": "captured-registers" if frame_index == 0 else "arm-ehabi",
            "runtime_location": location.summary() if location else None,
        }
        frames.append(frame)
        if location is None:
            stop = {"code": "unmapped-runtime-pc", "frame": frame_index}; break
        image = symbolizer.image_for_module(location.module_name)
        if image is None:
            stop = {"code": "no-matched-image", "frame": frame_index, "module": location.module_name}; break
        try:
            linked_pc = image.image_address(location)
        except ParseError as exc:
            stop = {"code": "segment-mismatch", "frame": frame_index, "detail": str(exc)}; break
        lookup_pc = (linked_pc & ~1) - ((2 if pc & 1 else 4) if frame_index else 0)
        frame.update({
            "image_path": str(image.path), "elf_virtual_address": linked_pc,
            "lookup_elf_address": lookup_pc, "symbol": symbolizer.symbolize(location),
        })
        try:
            cache_key = str(image.path)
            if cache_key not in cache:
                cache[cache_key] = _exidx_entries(image)
            entries = cache[cache_key]
        except ParseError as exc:
            stop = {"code": "invalid-arm-exidx", "frame": frame_index, "detail": str(exc)}; break
        if not entries:
            stop = {"code": "no-arm-exidx", "frame": frame_index}; break
        starts = [item["function_address"] for item in entries]
        index = bisect.bisect_right(starts, lookup_pc) - 1
        if index < 0:
            stop = {"code": "no-exidx-entry", "frame": frame_index}; break
        entry = entries[index]
        if entry["function_end"] is not None and lookup_pc >= entry["function_end"]:
            stop = {"code": "no-exidx-entry", "frame": frame_index}; break
        try:
            program = _compact_bytecode(image, entry)
        except ParseError as exc:
            stop = {"code": "invalid-unwind-program", "frame": frame_index, "detail": str(exc)}; break
        if program["status"] != "available":
            stop = {"code": program["status"], "frame": frame_index}; break
        try:
            transition = execute_compact_bytecode(core, state, thread.stack_base, thread.stack_end, program["bytecode"])
        except ParseError as exc:
            stop = {"code": "unwind-step-failed", "frame": frame_index, "detail": str(exc)}; break
        next_state = transition["registers"]
        frame["unwind"] = {
            "entry_address": entry["entry_address"], "function_address": entry["function_address"],
            "function_end": entry["function_end"], "personality": program["personality"],
            "program_source": program["source"], "bytecode": program["bytecode"],
            "operations": transition["operations"], "stack_reads": transition["stack_reads"],
        }
        if next_state[15] in (0, 0xFFFFFFFF):
            stop = {"code": "end-of-stack", "frame": frame_index}; break
        if next_state[13] <= sp or next_state[13] > thread.stack_end:
            stop = {"code": "non-progressing-stack", "frame": frame_index, "detail": f"SP 0x{sp:08x} -> 0x{next_state[13]:08x}"}; break
        state = next_state
    else:
        stop = {"code": "frame-limit", "frame": max_frames - 1}
    return {
        "status": "complete" if stop and stop["code"] == "end-of-stack" else "stopped",
        "frames": frames,
        "verified_frame_count": max(0, sum(frame["source"] == "arm-ehabi" for frame in frames)),
        "stop": stop,
        "qualification": "Only transitions executed from a matched ARM EHABI table are unwind-verified.",
    }
