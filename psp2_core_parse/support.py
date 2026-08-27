from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from .binary import BoundsError, c_string, u32, words
from .core import CoreDump, Note, ParseError
from .execution import ExecutionContext
from .kernel import PARSERS as KERNEL_PARSERS
from .metadata import SummaryInfo
from .tty import TtyInfo


PRINTABLE_STRING = re.compile(rb"[ -~]{4,}\x00")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _text_field(data: bytes) -> str:
    """Decode a producer-sized string, stopping at optional NUL padding."""
    return data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _trailing(data: bytes, offset: int) -> dict:
    raw = data[min(offset, len(data)):]
    return {
        "trailing_size": len(raw),
        "trailing_nonzero_bytes": sum(value != 0 for value in raw),
        "trailing_sha256": _hash(raw),
    }


def _strings(data: bytes, *, limit: int = 128) -> list[dict]:
    result = []
    for match in PRINTABLE_STRING.finditer(data):
        result.append(
            {
                "offset": match.start(),
                "value": match.group()[:-1].decode("utf-8", errors="replace"),
            }
        )
        if len(result) >= limit:
            break
    return result


def decode_corefile(data: bytes) -> dict:
    if len(data) < 16:
        raise ParseError("COREFILE_INFO is truncated")
    return {
        "format_version": u32(data, 0),
        "capture_status": u32(data, 4),
        "producer_kind": u32(data, 8),
        "producer_subtype": u32(data, 0x0C),
        "producer_words": list(words(data, 0x10)),
        "raw_size": len(data),
    }


def decode_system(data: bytes) -> dict:
    if len(data) < 0x14:
        raise ParseError("SYSTEM_INFO is truncated")
    return {
        "format_version": u32(data, 0),
        "capture_status": u32(data, 4),
        "software_version_words": [u32(data, 8), u32(data, 0x10)],
        "raw_words": list(words(data)),
        "raw_size": len(data),
    }


def decode_application(data: bytes) -> dict:
    if len(data) < 0x9C:
        raise ParseError("APP_INFO is shorter than its fixed prefix")
    return {
        "format_version": u32(data, 0),
        "capture_status": u32(data, 4),
        "title_id": c_string(data, 8, 10),
        "title_name": c_string(data, 0x12, 0x80),
        "title_version": c_string(data, 0x92, 8),
        "tail_words": list(words(data, 0x9C)),
        "raw_size": len(data),
    }


def decode_hardware(data: bytes) -> dict:
    if len(data) < 0x10:
        raise ParseError("HW_INFO is truncated")
    return {
        "format_version": u32(data, 0),
        "capture_status": u32(data, 4),
        "hardware_revision_word": u32(data, 8),
        "hardware_flags_word": u32(data, 0x0C),
        "raw_words": list(words(data)),
        "raw_size": len(data),
    }


def decode_build(data: bytes) -> dict:
    if len(data) < 0x14:
        raise ParseError("BUILD_VER_INFO is truncated")
    branches = []
    for offset in (0x14, 0x54, 0x94):
        if offset < len(data):
            value = c_string(data, offset, 0x40)
            if value:
                branches.append(value)
    return {
        "format_version": u32(data, 0),
        "header_words": list(words(data, 0, min(0x14, len(data)))),
        "branch_strings": branches,
        "unique_branch_strings": list(dict.fromkeys(branches)),
        "tail_words": list(words(data, min(0xD4, len(data)))),
        "raw_size": len(data),
    }


@dataclass(frozen=True)
class MemoryBlock:
    index: int
    capture_status: int
    uid: int
    name: str
    attributes: int
    base: int
    size: int
    producer_word_3: int
    producer_word_4: int
    memory_type_word: int
    access_word: int
    type_word: int

    @property
    def end(self) -> int:
        return self.base + self.size

    def summary(self, core: Optional[CoreDump] = None) -> dict:
        result = {
            "index": self.index,
            "capture_status": self.capture_status,
            "uid": self.uid,
            "name": self.name,
            "attributes": self.attributes,
            "base": self.base,
            "end": self.end,
            "size": self.size,
            "memory_type_word": self.memory_type_word,
            "access_word": self.access_word,
            "type_word": self.type_word,
            "producer_words": [self.producer_word_3, self.producer_word_4],
        }
        if core is not None:
            result["captured_bytes"] = core.captured_bytes(self.base, self.end)
            result["captured_ranges"] = [
                {"start": start, "end": end}
                for start, end in core.captured_ranges(self.base, self.end)
            ]
        return result


def parse_memory_blocks(data: bytes) -> tuple[int, int, tuple[MemoryBlock, ...], bytes, bool]:
    if len(data) < 8:
        raise ParseError("MEM_BLK_INFO is truncated")
    version, count = struct.unpack_from("<2I", data)
    record_size = 0x48
    available = min(count, (len(data) - 8) // record_size)
    records = []
    for index in range(available):
        offset = 8 + index * record_size
        fields = struct.unpack_from("<8I", data, offset + 0x28)
        records.append(
            MemoryBlock(
                index,
                u32(data, offset),
                u32(data, offset + 4),
                c_string(data, offset + 8, 0x20),
                *fields,
            )
        )
    used = 8 + available * record_size
    return version, count, tuple(records), data[used:], available == count


def decode_memory_blocks(data: bytes, core: Optional[CoreDump] = None) -> dict:
    version, count, records, trailing, complete = parse_memory_blocks(data)
    return {
        "format_version": version,
        "declared_count": count,
        "decoded_count": len(records),
        "record_size": 0x48,
        "complete": complete,
        "blocks": [record.summary(core) for record in records],
        **_trailing(data, len(data) - len(trailing)),
    }


def decode_files(data: bytes) -> dict:
    if len(data) < 8:
        raise ParseError("FILE_INFO is truncated")
    version, count = struct.unpack_from("<2I", data)
    offset = 8
    records = []
    complete = True
    for index in range(count):
        start = offset
        if offset + 0x48 > len(data):
            complete = False
            break
        fixed = data[offset:offset + 0x48]
        offset += 0x48
        values = []
        lengths = []
        field_complete = True
        for _ in range(2):
            if offset + 4 > len(data):
                field_complete = False
                break
            length = u32(data, offset)
            lengths.append(length)
            offset += 4
            available = min(length, len(data) - offset)
            raw_value = data[offset:offset + available]
            values.append(_text_field(raw_value))
            if available != length:
                offset = len(data)
                field_complete = False
                break
            padded = _align4(length)
            if offset + padded > len(data):
                offset = len(data)
                field_complete = False
                break
            offset += padded
        records.append(
            {
                "index": index,
                "record_offset": start,
                "record_size": offset - start,
                "complete": field_complete and len(values) == 2,
                "capture_status": u32(fixed, 0),
                "uid": u32(fixed, 4),
                "process_id": u32(fixed, 0x10),
                "producer_words": list(words(fixed, 8)),
                "string_lengths": lengths,
                "strings": values,
            }
        )
        if not field_complete:
            complete = False
            break
    return {
        "format_version": version,
        "declared_count": count,
        "decoded_count": len(records),
        "fixed_record_size": 0x48,
        "complete": complete and len(records) == count,
        "records": records,
        **_trailing(data, offset),
    }


def decode_metadata(data: bytes) -> dict:
    if len(data) < 8:
        raise ParseError("META_DATA_INFO is truncated")
    version, count = struct.unpack_from("<2I", data)
    offset = 8
    entries = []
    complete = True
    for index in range(count):
        if offset + 8 > len(data):
            complete = False
            break
        identifier, payload_size = struct.unpack_from("<2I", data, offset)
        offset += 8
        available = min(payload_size, len(data) - offset)
        payload = data[offset:offset + available]
        record_complete = available == payload_size
        if record_complete and offset + _align4(payload_size) <= len(data):
            offset += _align4(payload_size)
        else:
            offset = len(data)
            record_complete = False
        entries.append({
            "index": index,
            "identifier": identifier,
            "declared_payload_size": payload_size,
            "payload_size": len(payload),
            "payload_sha256": _hash(payload),
            "payload_nonzero_bytes": sum(value != 0 for value in payload),
            "complete": record_complete,
        })
        if not record_complete:
            complete = False
            break
    return {
        "format_version": version,
        "declared_count": count,
        "decoded_count": len(entries),
        "complete": complete and len(entries) == count,
        "entries": entries,
        "raw_size": len(data),
        **_trailing(data, offset),
    }


def decode_system_devices(data: bytes) -> dict:
    if len(data) < 4:
        raise ParseError("SYS_DEVICE_INFO is truncated")
    version = u32(data, 0)
    offset = 4
    records = []
    complete = True
    while offset < len(data):
        if offset + 8 > len(data):
            complete = False
            break
        size, description_size = struct.unpack_from("<2I", data, offset)
        if size < 8 or size % 4:
            complete = False
            break
        raw = data[offset : min(len(data), offset + size)]
        record_complete = len(raw) == size and description_size <= max(0, len(raw) - 8)
        payload_offset = min(len(raw), (8 + description_size + 3) & ~3)
        records.append(
            {
                "index": len(records),
                "record_size": size,
                "complete": record_complete,
                "description_size": description_size,
                "description": c_string(raw, 8, min(description_size, max(0, len(raw) - 8))),
                "payload_words": list(words(raw, payload_offset)),
            }
        )
        offset += size
        if not record_complete:
            complete = False
            break
    return {
        "format_version": version,
        "record_count": len(records),
        "complete": complete,
        "records": records,
        **_trailing(data, offset),
    }


def decode_system2(data: bytes) -> dict:
    if len(data) < 0x30:
        raise ParseError("SYSTEM_INFO2 is truncated")
    header_size = u32(data, 0x24)
    valid_header = 0x30 <= header_size <= len(data) and not header_size % 4
    payload_start = header_size if valid_header else min(len(data), 0x30)
    payload = data[payload_start:]
    magic_bytes = data[4:12]
    return {
        "format_version": u32(data, 0),
        "complete": valid_header,
        "container_magic_bytes": magic_bytes.hex(),
        "container_magic_le64": magic_bytes[::-1].rstrip(b"\x00").decode("ascii", errors="replace"),
        "container_magic_valid": magic_bytes == b"\x00\x00FACECS",
        "declared_header_size": header_size,
        "header_size_valid": valid_header,
        "header_words": list(words(data, 0, payload_start)),
        "header_sha256": _hash(data[:payload_start]),
        "payload_size": len(payload),
        "payload_sha256": _hash(payload),
        "payload_nonzero_bytes": sum(value != 0 for value in payload),
        "expected_single_rgba_surface_bytes": 960 * 544 * 4,
        "producer_surface_count_word": u32(data, 0x1C),
        "raw_size": len(data),
    }


def decode_libraries(data: bytes) -> dict:
    if len(data) < 8:
        raise ParseError("LIBRARY_INFO is truncated")
    version, count = struct.unpack_from("<2I", data)
    offset = 8
    records = []
    complete = True
    for index in range(count):
        start = offset
        if offset + 0x24 > len(data):
            complete = False
            break
        header = data[offset:offset + 0x24]
        primary_count = u32(header, 0x14)
        secondary_count = u32(header, 0x18)
        value_count = u32(header, 0x20)
        offset += 0x24
        entries = []
        record_complete = True
        for entry_index in range(primary_count + secondary_count):
            if offset + 8 > len(data):
                record_complete = False
                break
            nid, address = struct.unpack_from("<2I", data, offset)
            entries.append({
                "index": entry_index,
                "class": "primary" if entry_index < primary_count else "secondary",
                "nid": nid,
                "address": address,
            })
            offset += 8
        producer_values = []
        if record_complete:
            for _ in range(value_count):
                if offset + 4 > len(data):
                    record_complete = False
                    break
                producer_values.append(u32(data, offset))
                offset += 4
        name_length = None
        name = ""
        if record_complete:
            if offset + 4 > len(data):
                record_complete = False
            else:
                name_length = u32(data, offset)
                offset += 4
                available = min(name_length, len(data) - offset)
                raw_name = data[offset:offset + available]
                name = _text_field(raw_name)
                if available != name_length or offset + _align4(name_length) > len(data):
                    offset = len(data)
                    record_complete = False
                else:
                    offset += _align4(name_length)
        records.append({
            "index": index,
            "record_offset": start,
            "record_size": offset - start,
            "complete": record_complete,
            "capture_status": u32(header, 0),
            "uid": u32(header, 4),
            "module_uid": u32(header, 8),
            "producer_words": [u32(header, 0x0C), u32(header, 0x10), u32(header, 0x1C)],
            "primary_entry_count": primary_count,
            "secondary_entry_count": secondary_count,
            "decoded_entry_count": len(entries),
            "entries": entries,
            "declared_producer_value_count": value_count,
            "producer_values": producer_values,
            "declared_name_size": name_length,
            "name": name,
        })
        if not record_complete:
            complete = False
            break
    return {
        "format_version": version,
        "declared_count": count,
        "decoded_count": len(records),
        "complete": complete and len(records) == count,
        "records": records,
        "raw_size": len(data),
        **_trailing(data, offset),
    }


def decode_budgets(data: bytes) -> dict:
    if len(data) < 8:
        raise ParseError("BUDGET_INFO is truncated")
    version, count = struct.unpack_from("<2I", data)
    offset = 8
    budgets = []
    complete = True
    for budget_index in range(count):
        if offset + 0x2C > len(data):
            complete = False
            break
        header = data[offset : offset + 0x2C]
        partition_count = u32(header, 0x28)
        offset += 0x2C
        partitions = []
        for partition_index in range(partition_count):
            if offset + 0x210 > len(data):
                complete = False
                break
            raw = data[offset : offset + 0x210]
            region_count = min(u32(raw, 0x2C), 8)
            regions = []
            for region_index in range(region_count):
                region_offset = 0x34 + region_index * 0x3C
                region = raw[region_offset:region_offset + 0x3C]
                regions.append({
                    "index": region_index,
                    "producer_words": list(words(region, 0, 0x14)),
                    "serialized_slot_size": len(region),
                    "raw_sha256": _hash(region),
                    "raw_nonzero_bytes": sum(value != 0 for value in region),
                })
            partitions.append(
                {
                    "index": partition_index,
                    "capture_status": u32(raw, 0),
                    "uid": u32(raw, 4),
                    "name": c_string(raw, 8, 0x20),
                    "producer_word_0x28": u32(raw, 0x28),
                    "declared_region_count": u32(raw, 0x2C),
                    "decoded_region_count": len(regions),
                    "regions": regions,
                    "raw_sha256": _hash(raw),
                }
            )
            offset += 0x210
        budgets.append(
            {
                "index": budget_index,
                "capture_status": u32(header, 0),
                "uid": u32(header, 4),
                "name": c_string(header, 8, 0x20),
                "declared_partition_count": partition_count,
                "partitions": partitions,
            }
        )
        if len(partitions) != partition_count:
            break
    return {
        "format_version": version,
        "declared_count": count,
        "decoded_count": len(budgets),
        "complete": complete and len(budgets) == count,
        "budgets": budgets,
        **_trailing(data, offset),
    }


def decode_event_log(data: bytes) -> dict:
    if len(data) < 12:
        raise ParseError("EVENT_LOG_INFO is truncated")
    version, capture_status, count = struct.unpack_from("<3I", data)
    offset = 12
    records = []
    complete = True
    for index in range(count):
        if offset + 4 > len(data):
            complete = False
            break
        size = u32(data, offset)
        if size < 4 or size % 4:
            complete = False
            break
        raw = data[offset : min(len(data), offset + size)]
        if len(raw) < min(size, 0x40):
            complete = False
            break
        item_data = _decode_event_log_item(raw)
        record_complete = (
            len(raw) == size
            and item_data["complete"]
            and size == 0x40 + item_data["declared_size"]
        )
        records.append(
            {
                "index": index,
                "record_offset": offset,
                "record_size": size,
                "complete": record_complete,
                "size_consistent_with_item": size == 0x40 + item_data["declared_size"],
                "data_0x04": u32(raw, 4) if len(raw) >= 8 else None,
                "title_id": c_string(raw, 8, 0x0C) if len(raw) >= 0x14 else "",
                "flags": u32(raw, 0x14) if len(raw) >= 0x18 else None,
                "parent_process_id": u32(raw, 0x18) if len(raw) >= 0x1C else None,
                "producer_word_0x1c": u32(raw, 0x1C) if len(raw) >= 0x20 else None,
                "reserved_words_0x20": list(words(raw, 0x20, min(0x10, max(0, len(raw) - 0x20)))),
                "time": struct.unpack_from("<Q", raw, 0x30)[0] if len(raw) >= 0x38 else None,
                "producer_word_0x38": u32(raw, 0x38) if len(raw) >= 0x3C else None,
                "item_size": u32(raw, 0x3C) if len(raw) >= 0x40 else None,
                "item": item_data,
                "raw_words": list(words(raw)),
                "raw_nonzero_bytes": sum(value != 0 for value in raw),
                "raw_sha256": _hash(raw),
            }
        )
        offset += size
        if not record_complete:
            complete = False
            if len(raw) != size:
                break
    trailing = data[min(offset, len(data)):]
    return {
        "format_version": version,
        "capture_status": capture_status,
        "declared_count": count,
        "decoded_count": len(records),
        "complete": complete and len(records) == count,
        "records": records,
        "trailing_size": len(trailing),
        "trailing_nonzero_bytes": sum(value != 0 for value in trailing),
        "trailing_sha256": _hash(trailing),
    }


def _decode_event_log_item(raw: bytes) -> dict:
    """Decode the public SceKernelDebugEventLog union at record offset 0x40."""
    if len(raw) < 0x40:
        return {"kind": "unavailable", "raw_hex": "", "raw_sha256": _hash(b"")}
    declared = u32(raw, 0x3C)
    payload = raw[0x40:min(len(raw), 0x40 + declared)]
    item = {
        "declared_size": declared,
        "available_size": len(payload),
        "complete": len(payload) == declared,
        "raw_hex": payload.hex(),
        "raw_sha256": _hash(payload),
    }
    if declared == 0x1C:
        item.update({
            "kind": "process",
            "producer_word_0x40": u32(raw, 0x40) if len(raw) >= 0x44 else None,
            "process_id": u32(raw, 0x44) if len(raw) >= 0x48 else None,
            "budget_type": u32(raw, 0x48) if len(raw) >= 0x4C else None,
            "producer_word_0x4c": u32(raw, 0x4C) if len(raw) >= 0x50 else None,
            "title_id": c_string(raw, 0x50, 0x0C) if len(raw) >= 0x5C else "",
        })
    elif declared == 4:
        item.update({
            "kind": "network-word",
            "producer_word_0x40": u32(raw, 0x40) if len(raw) >= 0x44 else None,
        })
    elif declared == 0x54:
        item.update({
            "kind": "network-addresses",
            "producer_word_0x40": u32(raw, 0x40) if len(raw) >= 0x44 else None,
            "addresses": [c_string(raw, 0x44 + index * 0x10, 0x10) for index in range(5)],
        })
    else:
        item["kind"] = "unknown"
    return item


def decode_callbacks(data: bytes) -> dict:
    if len(data) < 8:
        raise ParseError("CALLBACK_INFO is truncated")
    version, count = struct.unpack_from("<2I", data)
    size = 0x48
    available = min(count, (len(data) - 8) // size)
    records = []
    for index in range(available):
        raw = data[8 + index * size : 8 + (index + 1) * size]
        records.append(
            {
                "index": index,
                "capture_status": u32(raw, 0),
                "uid": u32(raw, 4),
                "process_id": u32(raw, 8),
                "thread_uid": u32(raw, 0x0C),
                "name": c_string(raw, 0x10, 0x20),
                "producer_words": list(words(raw, 0x30)),
            }
        )
    return {
        "format_version": version,
        "declared_count": count,
        "decoded_count": available,
        "complete": available == count,
        "records": records,
        **_trailing(data, 8 + available * size),
    }


def decode_timers(data: bytes) -> dict:
    if len(data) < 8:
        raise ParseError("TIMER_INFO is truncated")
    version, count = struct.unpack_from("<2I", data)
    offset = 8
    records = []
    complete = True
    for index in range(count):
        start = offset
        if offset + 0x64 > len(data):
            complete = False
            break
        producer_size = u32(data, offset)
        waiter_count = u32(data, offset + 0x60)
        serialized_waiter_count = min(waiter_count, 0x140)
        expected_producer_size = 0x70 + waiter_count * 8
        serialized_size = 0x70 + serialized_waiter_count * 8
        if producer_size != expected_producer_size or producer_size % 8:
            complete = False
            break
        raw = data[offset:min(len(data), offset + serialized_size)]
        record_complete = len(raw) == serialized_size
        waiters = []
        waiter_offset = 0x64
        for waiter_index in range(serialized_waiter_count):
            if waiter_offset + 8 > len(raw):
                record_complete = False
                break
            process_id, thread_uid = struct.unpack_from("<2I", raw, waiter_offset)
            waiters.append({"index": waiter_index, "process_id": process_id, "thread_uid": thread_uid})
            waiter_offset += 8
        footer = raw[waiter_offset:min(len(raw), waiter_offset + 0x0C)]
        if len(footer) != 0x0C:
            record_complete = False
        records.append(
            {
                "index": index,
                "producer_size": producer_size,
                "expected_producer_size": expected_producer_size,
                "serialized_size": serialized_size,
                "complete": record_complete,
                "uid": u32(raw, 4) if len(raw) >= 8 else None,
                "process_id": u32(raw, 8) if len(raw) >= 12 else None,
                "name": c_string(raw, 0x0C, 0x20) if len(raw) >= 0x2C else "",
                "attributes": u32(raw, 0x2C) if len(raw) >= 0x30 else None,
                "producer_words": list(words(raw, 0x30, min(max(0, len(raw) - 0x30), 0x30))),
                "producer_u64_values": [
                    struct.unpack_from("<Q", raw, item)[0]
                    for item in range(0x38, min(len(raw), 0x60), 8)
                    if item + 8 <= len(raw)
                ],
                "declared_waiter_count": waiter_count,
                "serialized_waiter_count": serialized_waiter_count,
                "waiters": waiters,
                "footer_words": list(words(footer)),
                "sha256": _hash(raw),
            }
        )
        offset += serialized_size
        if not record_complete:
            complete = False
            break
    return {
        "format_version": version,
        "declared_count": count,
        "decoded_count": len(records),
        "complete": complete and len(records) == count,
        "records": records,
        **_trailing(data, offset),
    }


def decode_app_list(data: bytes) -> dict:
    if len(data) < 8:
        raise ParseError("APP_LIST_INFO is truncated")
    version, count = struct.unpack_from("<2I", data)
    offset = 8
    records = []
    complete = True
    for index in range(count):
        start = offset
        if offset + 0x4C > len(data):
            complete = False
            break
        fixed = data[offset:offset + 0x4C]
        path_size = u32(fixed, 0x48)
        offset += 0x4C
        available = min(path_size, len(data) - offset)
        raw_path = data[offset:offset + available]
        record_complete = available == path_size and offset + _align4(path_size) <= len(data)
        if record_complete:
            offset += _align4(path_size)
        else:
            offset = len(data)
        records.append({
            "index": index,
            "record_offset": start,
            "record_size": offset - start,
            "complete": record_complete,
            "capture_status": u32(fixed, 0),
            "producer_word_1": u32(fixed, 4),
            "producer_word_2": u32(fixed, 8),
            "process_id": u32(fixed, 0x0C),
            "producer_word_4": u32(fixed, 0x10),
            "title_id": c_string(fixed, 0x14, 0x20),
            "producer_words_0x34": list(words(fixed, 0x34, 0x14)),
            "declared_path_size": path_size,
            "path": _text_field(raw_path),
        })
        if not record_complete:
            complete = False
            break
    return {
        "format_version": version,
        "declared_count": count,
        "decoded_count": len(records),
        "complete": complete and len(records) == count,
        "records": records,
        "raw_size": len(data),
        **_trailing(data, offset),
    }


def decode_external_processes(data: bytes) -> dict:
    if len(data) < 8:
        raise ParseError("EXTNL_PROC_INFO is truncated")
    version, count = struct.unpack_from("<2I", data)
    offset = 8
    records = []
    complete = True
    for index in range(count):
        start = offset
        if offset + 0x5C > len(data):
            complete = False
            break
        fixed = data[offset:offset + 0x5C]
        path_size = u32(fixed, 0x58)
        offset += 0x5C
        available = min(path_size, len(data) - offset)
        raw_path = data[offset:offset + available]
        record_complete = available == path_size and offset + _align4(path_size) + 0x10 <= len(data)
        footer = b""
        if record_complete:
            offset += _align4(path_size)
            footer = data[offset:offset + 0x10]
            offset += 0x10
        else:
            offset = len(data)
        records.append({
            "index": index,
            "record_offset": start,
            "record_size": offset - start,
            "complete": record_complete,
            "capture_status": u32(fixed, 0),
            "process_id": u32(fixed, 4),
            "process_info_word_0x18": u32(fixed, 8),
            "process_flags": u32(fixed, 0x0C),
            "name": c_string(fixed, 0x10, 0x20),
            "producer_words_0x30": list(words(fixed, 0x30, 0x10)),
            "parent_process_id": u32(fixed, 0x40),
            "producer_words_0x44": list(words(fixed, 0x44, 0x14)),
            "declared_path_size": path_size,
            "path": _text_field(raw_path),
            "footer_words": list(words(footer)),
        })
        if not record_complete:
            complete = False
            break
    return {
        "format_version": version,
        "declared_count": count,
        "decoded_count": len(records),
        "complete": complete and len(records) == count,
        "records": records,
        "raw_size": len(data),
        **_trailing(data, offset),
    }


def decode_device(data: bytes) -> dict:
    if len(data) < 0x40:
        raise ParseError("DEVICE_INFO is truncated")
    fixed = data[4:0x40]
    offset = 0x40
    lists = []
    complete = True
    for index in range(2):
        if offset + 4 > len(data):
            complete = False
            break
        count = u32(data, offset)
        offset += 4
        available = min(count, (len(data) - offset) // 4)
        values = list(words(data, offset, available * 4))
        offset += available * 4
        lists.append({"index": index, "declared_count": count, "values": values, "complete": available == count})
        if available != count:
            complete = False
            break
    return {
        "format_version": u32(data, 0),
        "capture_status": u32(fixed, 0),
        "fixed_producer_words": list(words(fixed, 4)),
        "id_lists": lists,
        "complete": complete and len(lists) == 2,
        "raw_size": len(data),
        **_trailing(data, offset),
    }


def decode_gpu_activity(data: bytes) -> dict:
    if len(data) < 12:
        raise ParseError("GPU_ACT_INFO is truncated")
    version, activity_word, payload_size = struct.unpack_from("<3I", data)
    available = min(payload_size, len(data) - 12)
    payload = data[12 : 12 + available]
    return {
        "format_version": version,
        "producer_activity_word": activity_word,
        "declared_payload_size": payload_size,
        "payload_size": available,
        "complete": available == payload_size,
        "empty": activity_word == 0 and payload_size == 0,
        "payload_sha256": _hash(payload),
        "payload_nonzero_bytes": sum(value != 0 for value in payload),
        **_trailing(data, 12 + available),
    }


def decode_blob(data: bytes) -> dict:
    return {
        "format_version": u32(data, 0) if len(data) >= 4 else None,
        "raw_size": len(data),
        "sha256": _hash(data),
        "nonzero_bytes": sum(value != 0 for value in data),
        "header_words": list(words(data, 0, min(len(data), 0x80))),
        "strings": _strings(data),
    }


Decoder = Callable[[bytes], dict]


DECODERS: dict[str, Decoder] = {
    "COREFILE_INFO": decode_corefile,
    "SYSTEM_INFO": decode_system,
    "APP_INFO": decode_application,
    "HW_INFO": decode_hardware,
    "BUILD_VER_INFO": decode_build,
    "MEM_BLK_INFO": decode_memory_blocks,
    "FILE_INFO": decode_files,
    "META_DATA_INFO": decode_metadata,
    "SYS_DEVICE_INFO": decode_system_devices,
    "SYSTEM_INFO2": decode_system2,
    "LIBRARY_INFO": decode_libraries,
    "BUDGET_INFO": decode_budgets,
    "EVENT_LOG_INFO": decode_event_log,
    "CALLBACK_INFO": decode_callbacks,
    "TIMER_INFO": decode_timers,
    "APP_LIST_INFO": decode_app_list,
    "EXTNL_PROC_INFO": decode_external_processes,
    "DEVICE_INFO": decode_device,
    "GPU_ACT_INFO": decode_gpu_activity,
}


@dataclass(frozen=True)
class DecodedNote:
    note: Note
    status: str
    decoder: Optional[str]
    data: Optional[dict]
    error: Optional[str]

    def summary(self) -> dict:
        result = self.note.summary()
        result.update(
            {
                "status": self.status,
                "decoder": self.decoder,
                "data": self.data,
                "error": self.error,
            }
        )
        return result


def decode_note(note: Note, core: CoreDump, execution: Optional[ExecutionContext] = None) -> DecodedNote:
    def status(value: dict) -> str:
        return "decoded" if note.complete and value.get("complete", True) else "partial"

    try:
        if note.name in ("TTY_INFO", "TTY_INFO2"):
            value = TtyInfo.parse(note.description).summary()
            return DecodedNote(note, status(value), "TtyInfo", value, None)
        if note.name == "SUMMARY_INFO":
            value = SummaryInfo.parse(note.description).summary(core)
            return DecodedNote(note, status(value), "SummaryInfo", value, None)
        if note.name in KERNEL_PARSERS:
            value = KERNEL_PARSERS[note.name](note.description).summary()
            return DecodedNote(note, status(value), "KernelObjectTable", value, None)
        if note.name in ("PROCESS_INFO", "MODULE_INFO", "THREAD_INFO", "THREAD_REG_INFO", "STACK_INFO"):
            execution = execution or ExecutionContext.parse(core)
            values = {
                "PROCESS_INFO": execution.process.summary() if execution.process else None,
                "MODULE_INFO": execution.modules.summary() if execution.modules else None,
                "THREAD_INFO": execution.threads.summary() if execution.threads else None,
                "THREAD_REG_INFO": execution.registers.summary() if execution.registers else None,
                "STACK_INFO": execution.stacks.summary() if execution.stacks else None,
            }
            value = values[note.name]
            if value is None:
                error = next((item["error"] for item in execution.errors if item["note"] == note.name), "decoder unavailable")
                return DecodedNote(note, "error", "ExecutionContext", None, error)
            return DecodedNote(note, status(value), "ExecutionContext", value, None)
        decoder = DECODERS.get(note.name)
        if decoder is None:
            return DecodedNote(note, "inventory", None, decode_blob(note.description), None)
        value = decode_memory_blocks(note.description, core) if note.name == "MEM_BLK_INFO" else decoder(note.description)
        return DecodedNote(note, status(value), decoder.__name__, value, None)
    except (ParseError, BoundsError, struct.error, ValueError) as exc:
        return DecodedNote(note, "error", getattr(DECODERS.get(note.name), "__name__", None), None, str(exc))


def supporting_context(core: CoreDump, execution: Optional[ExecutionContext] = None) -> dict:
    execution = execution or ExecutionContext.parse(core)
    decoded = [decode_note(note, core, execution) for note in core.notes]
    by_name: dict[str, list[dict]] = {}
    for item in decoded:
        by_name.setdefault(item.note.name, []).append(item.summary())
    return {
        "decoded": [item.summary() for item in decoded],
        "by_name": by_name,
        "coverage": {
            "note_count": len(decoded),
            "decoded_count": sum(item.status in ("decoded", "partial") for item in decoded),
            "partial_count": sum(item.status == "partial" for item in decoded),
            "inventory_count": sum(item.status == "inventory" for item in decoded),
            "error_count": sum(item.status == "error" for item in decoded),
            "inventory_names": sorted({item.note.name for item in decoded if item.status == "inventory"}),
            "error_names": sorted({item.note.name for item in decoded if item.status == "error"}),
        },
    }


def latest_decoded(context: dict, name: str) -> Optional[dict]:
    values = context.get("by_name", {}).get(name, [])
    if not values:
        return None
    return values[-1].get("data")
