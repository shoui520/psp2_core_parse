from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from .binary import c_string, u32, words
from .core import CoreDump, ParseError


@dataclass(frozen=True)
class KernelWaiter:
    process_id: Optional[int]
    thread_uid: int
    role: str = "waiter"

    def summary(self) -> dict:
        return {
            "process_id": self.process_id,
            "thread_uid": self.thread_uid,
            "role": self.role,
        }


@dataclass(frozen=True)
class KernelObject:
    index: int
    kind: str
    note_name: str
    uid: int
    process_id: Optional[int]
    name: str
    attributes: int
    state: dict[str, object]
    waiters: tuple[KernelWaiter, ...]
    record_size: int
    raw_words: tuple[int, ...]
    complete: bool = True

    @property
    def owner_thread_uid(self) -> Optional[int]:
        value = self.state.get("current_owner_id")
        return value if value not in (None, 0, 0xFFFFFFFF) else None

    @property
    def waiting_thread_count(self) -> int:
        if self.kind == "message-pipe":
            return self.state.get("send_wait_threads", 0) + self.state.get("receive_wait_threads", 0)
        return self.state.get("wait_threads", len(self.waiters))

    def summary(self) -> dict:
        return {
            "index": self.index,
            "kind": self.kind,
            "note_name": self.note_name,
            "uid": self.uid,
            "process_id": self.process_id,
            "name": self.name,
            "attributes": self.attributes,
            "state": self.state,
            "owner_thread_uid": self.owner_thread_uid,
            "waiting_thread_count": self.waiting_thread_count,
            "waiters": [item.summary() for item in self.waiters],
            "record_size": self.record_size,
            "complete": self.complete,
            "raw_words": list(self.raw_words),
            "raw_sha256": hashlib.sha256(struct.pack(f"<{len(self.raw_words)}I", *self.raw_words)).hexdigest(),
        }


@dataclass(frozen=True)
class KernelObjectTable:
    note_name: str
    format_version: int
    declared_count: int
    objects: tuple[KernelObject, ...]
    trailing: bytes
    complete: bool
    error: Optional[str] = None

    def summary(self) -> dict:
        return {
            "note_name": self.note_name,
            "format_version": self.format_version,
            "declared_count": self.declared_count,
            "decoded_count": len(self.objects),
            "complete": self.complete,
            "error": self.error,
            "trailing_size": len(self.trailing),
            "trailing_nonzero_bytes": sum(value != 0 for value in self.trailing),
            "trailing_sha256": hashlib.sha256(self.trailing).hexdigest(),
            "objects": [item.summary() for item in self.objects],
        }


def _header(data: bytes, note_name: str) -> tuple[int, int]:
    if len(data) < 8:
        raise ParseError(f"{note_name} is shorter than its two-word header")
    return struct.unpack_from("<2I", data)


def _waiters(data: bytes, offset: int, count: int, *, roles: tuple[str, ...] = ()) -> tuple[KernelWaiter, ...]:
    available = min(count, max(0, (len(data) - offset) // 8))
    return tuple(
        KernelWaiter(
            *struct.unpack_from("<2I", data, offset + index * 8),
            roles[index] if index < len(roles) else "waiter",
        )
        for index in range(available)
    )


def _parse_fixed_waiter_table(
    data: bytes,
    note_name: str,
    kind: str,
    base_size: int,
    waiter_offset: int,
    object_decoder: Callable[[bytes, int, tuple[KernelWaiter, ...]], KernelObject],
) -> KernelObjectTable:
    version, count = _header(data, note_name)
    offset = 8
    objects: list[KernelObject] = []
    error = None
    for index in range(count):
        if offset + base_size > len(data):
            error = f"object {index} fixed prefix is truncated"
            break
        wait_count = u32(data, offset + waiter_offset)
        available = min(wait_count, max(0, (len(data) - offset - base_size) // 8))
        waiters = _waiters(data, offset + base_size, wait_count)
        raw_size = base_size + available * 8
        raw = data[offset : offset + raw_size]
        item = object_decoder(raw, index, waiters)
        if available != wait_count:
            item = KernelObject(**{**item.__dict__, "complete": False})
            objects.append(item)
            error = f"object {index} declares {wait_count} waiters but {available} are available"
            offset += raw_size
            break
        objects.append(item)
        offset += base_size + wait_count * 8
    return KernelObjectTable(
        note_name,
        version,
        count,
        tuple(objects),
        data[min(offset, len(data)):],
        error is None and len(objects) == count,
        error,
    )


def _base_object(
    raw: bytes,
    index: int,
    waiters: tuple[KernelWaiter, ...],
    *,
    kind: str,
    note_name: str,
    uid_offset: int = 4,
    process_offset: Optional[int] = 8,
    name_offset: int = 0x0C,
    attributes_offset: int = 0x2C,
    state: dict[str, object],
) -> KernelObject:
    return KernelObject(
        index=index,
        kind=kind,
        note_name=note_name,
        uid=u32(raw, uid_offset),
        process_id=u32(raw, process_offset) if process_offset is not None else None,
        name=c_string(raw, name_offset, 0x20),
        attributes=u32(raw, attributes_offset),
        state={"capture_status": u32(raw, 0), **state},
        waiters=waiters,
        record_size=len(raw),
        raw_words=tuple(words(raw)),
    )


def parse_semaphores(data: bytes) -> KernelObjectTable:
    def decode(raw: bytes, index: int, waiters: tuple[KernelWaiter, ...]) -> KernelObject:
        return _base_object(raw, index, waiters, kind="semaphore", note_name="SEMAPHORE_INFO", state={
            "producer_word": u32(raw, 0x30), "initial_count": u32(raw, 0x34),
            "current_count": u32(raw, 0x38), "maximum_count": u32(raw, 0x3C),
            "wait_threads": u32(raw, 0x40),
        })
    return _parse_fixed_waiter_table(data, "SEMAPHORE_INFO", "semaphore", 0x44, 0x40, decode)


def parse_event_flags(data: bytes) -> KernelObjectTable:
    def decode(raw: bytes, index: int, waiters: tuple[KernelWaiter, ...]) -> KernelObject:
        return _base_object(raw, index, waiters, kind="event-flag", note_name="EVENTFLAG_INFO", state={
            "producer_word": u32(raw, 0x30), "initial_pattern": u32(raw, 0x34),
            "current_pattern": u32(raw, 0x38), "wait_threads": u32(raw, 0x3C),
        })
    return _parse_fixed_waiter_table(data, "EVENTFLAG_INFO", "event-flag", 0x40, 0x3C, decode)


def parse_mutexes(data: bytes) -> KernelObjectTable:
    # FUN_810085d4 writes 0x44 fixed bytes, the waiter pairs, and then the
    # final word produced by FUN_810045f8.  The footer is not part of the
    # fixed prefix and therefore moves with the waiter count.
    note_name = "MUTEX_INFO"
    version, count = _header(data, note_name)
    offset = 8
    objects: list[KernelObject] = []
    error = None
    for index in range(count):
        if offset + 0x44 > len(data):
            error = f"object {index} fixed prefix is truncated"
            break
        wait_count = u32(data, offset + 0x40)
        suffix_offset = offset + 0x44
        expected_end = suffix_offset + wait_count * 8 + 4
        complete = expected_end <= len(data)
        available = wait_count if complete else min(wait_count, max(0, (len(data) - suffix_offset) // 8))
        waiter_end = suffix_offset + available * 8
        footer_size = 4 if complete else 0
        raw = data[offset : waiter_end + footer_size]
        waiters = _waiters(raw, 0x44, available)
        state = {
            "capture_status": u32(raw, 0),
            "producer_word_0x30": u32(raw, 0x30),
            "initial_count": u32(raw, 0x34),
            "current_count": u32(raw, 0x38),
            "current_owner_id": u32(raw, 0x3C),
            "wait_threads": wait_count,
        }
        if complete:
            state["footer_word"] = u32(raw, 0x44 + wait_count * 8)
        objects.append(KernelObject(
            index, "mutex", note_name, u32(raw, 4), u32(raw, 8), c_string(raw, 0x0C, 0x20),
            u32(raw, 0x2C), state, waiters, len(raw), tuple(words(raw)), complete,
        ))
        offset += len(raw)
        if not complete:
            error = f"object {index} waiter array or footer is truncated"
            break
    return KernelObjectTable(
        note_name, version, count, tuple(objects), data[min(offset, len(data)):],
        error is None and len(objects) == count, error,
    )


def parse_lwmutexes(data: bytes) -> KernelObjectTable:
    # Unlike every other waiter list emitted by this producer, FUN_810087b0
    # deliberately writes only the second word of each kernel waiter pair.
    note_name = "LWMUTEX_INFO"
    version, count = _header(data, note_name)
    offset = 8
    objects: list[KernelObject] = []
    error = None
    for index in range(count):
        if offset + 0x40 > len(data):
            error = f"object {index} fixed prefix is truncated"
            break
        wait_count = u32(data, offset + 0x3C)
        available = min(wait_count, max(0, (len(data) - offset - 0x40) // 4))
        raw_size = 0x40 + available * 4
        raw = data[offset : offset + raw_size]
        waiters = tuple(KernelWaiter(None, u32(raw, 0x40 + item * 4)) for item in range(available))
        item = _base_object(
            raw, index, waiters, kind="lightweight-mutex", note_name=note_name,
            process_offset=None, name_offset=8, attributes_offset=0x28,
            state={"work_address": u32(raw, 0x2C), "initial_count": u32(raw, 0x30),
                   "current_count": u32(raw, 0x34), "current_owner_id": u32(raw, 0x38),
                   "wait_threads": wait_count},
        )
        if available != wait_count:
            item = KernelObject(**{**item.__dict__, "complete": False})
        objects.append(item)
        offset += raw_size
        if available != wait_count:
            error = f"object {index} declares {wait_count} waiters but {available} are available"
            break
    return KernelObjectTable(note_name, version, count, tuple(objects), data[min(offset, len(data)):], error is None and len(objects) == count, error)


def parse_condition_variables(data: bytes) -> KernelObjectTable:
    def decode(raw: bytes, index: int, waiters: tuple[KernelWaiter, ...]) -> KernelObject:
        return _base_object(raw, index, waiters, kind="condition-variable", note_name="CONDVAR_INFO", state={
            "producer_word": u32(raw, 0x30), "associated_mutex_uid": u32(raw, 0x34),
            "wait_threads": u32(raw, 0x38),
        })
    return _parse_fixed_waiter_table(data, "CONDVAR_INFO", "condition-variable", 0x3C, 0x38, decode)


def parse_lwcondition_variables(data: bytes) -> KernelObjectTable:
    note_name = "LWCONDVAR_INFO"
    version, count = _header(data, note_name)
    offset = 8
    objects: list[KernelObject] = []
    error = None
    for index in range(count):
        if offset + 0x38 > len(data):
            error = f"object {index} fixed prefix is truncated"
            break
        wait_count = u32(data, offset + 0x34)
        available = min(wait_count, max(0, (len(data) - offset - 0x38) // 8))
        has_footer = offset + 0x38 + wait_count * 8 + 8 <= len(data)
        raw_size = 0x38 + available * 8 + (8 if has_footer else 0)
        raw = data[offset : offset + raw_size]
        waiters = _waiters(raw, 0x38, wait_count)
        footer = 0x38 + wait_count * 8
        state = {
            "capture_status": u32(raw, 0), "work_address": u32(raw, 0x2C),
            "associated_lwmutex_uid": u32(raw, 0x30), "wait_threads": wait_count,
        }
        if has_footer:
            state.update({"producer_word_0": u32(raw, footer), "producer_word_1": u32(raw, footer + 4)})
        objects.append(KernelObject(
            index, "lightweight-condition-variable", note_name, u32(raw, 4), None,
            c_string(raw, 8, 0x20), u32(raw, 0x28), state, waiters, len(raw), tuple(words(raw)),
            available == wait_count and has_footer,
        ))
        offset += raw_size
        if available != wait_count or not has_footer:
            error = f"object {index} waiter array or footer is truncated"
            break
    return KernelObjectTable(note_name, version, count, tuple(objects), data[min(offset, len(data)):], error is None and len(objects) == count, error)


def parse_message_pipes(data: bytes) -> KernelObjectTable:
    note_name = "MESG_PIPE_INFO"
    version, count = _header(data, note_name)
    offset = 8
    objects: list[KernelObject] = []
    error = None
    for index in range(count):
        if offset + 4 > len(data):
            error = f"object {index} record size is truncated"
            break
        producer_size = u32(data, offset)
        if producer_size < 0x50 or producer_size % 8:
            error = f"object {index} has invalid producer size 0x{producer_size:x}"
            break
        fixed = data[offset : min(len(data), offset + 0x44)]
        if len(fixed) < 0x44:
            error = f"object {index} fixed prefix is truncated"
            break
        send_count, receive_count = u32(fixed, 0x3C), u32(fixed, 0x40)
        total = send_count + receive_count
        serialized_count = min(total, 0x140)
        expected_producer_size = 0x50 + total * 8
        expected_end = offset + 0x44 + serialized_count * 8 + 0x0C
        complete = expected_end <= len(data) and producer_size == expected_producer_size
        suffix_available = max(0, len(data) - offset - 0x44)
        available = serialized_count if expected_end <= len(data) else min(serialized_count, suffix_available // 8)
        waiter_end = offset + 0x44 + available * 8
        footer_size = 0x0C if expected_end <= len(data) else 0
        raw = data[offset : waiter_end + footer_size]
        roles = tuple("sender" if item < min(send_count, serialized_count) else "receiver" for item in range(available))
        waiters = _waiters(raw, 0x44, available, roles=roles)
        state = {
            "producer_size": producer_size,
            "expected_producer_size": expected_producer_size,
            "producer_word_0x30": u32(raw, 0x30),
            "buffer_size": u32(raw, 0x34),
            "free_size": u32(raw, 0x38),
            "send_wait_threads": send_count,
            "receive_wait_threads": receive_count,
            "serialized_waiter_count": serialized_count,
        }
        if footer_size:
            state["footer_words"] = list(struct.unpack_from("<3I", raw, 0x44 + serialized_count * 8))
        objects.append(KernelObject(
            index, "message-pipe", note_name, u32(raw, 4), u32(raw, 8), c_string(raw, 0x0C, 0x20),
            u32(raw, 0x2C), state, waiters, len(raw), tuple(words(raw)), complete,
        ))
        offset += len(raw)
        if not complete:
            error = (
                f"object {index} body/footer is truncated or producer size does not match "
                f"the waiter counts (0x{producer_size:x} != 0x{expected_producer_size:x})"
            )
            break
    return KernelObjectTable(note_name, version, count, tuple(objects), data[min(offset, len(data)):], error is None and len(objects) == count, error)


PARSERS: dict[str, Callable[[bytes], KernelObjectTable]] = {
    "SEMAPHORE_INFO": parse_semaphores,
    "EVENTFLAG_INFO": parse_event_flags,
    "MUTEX_INFO": parse_mutexes,
    "LWMUTEX_INFO": parse_lwmutexes,
    "CONDVAR_INFO": parse_condition_variables,
    "LWCONDVAR_INFO": parse_lwcondition_variables,
    "MESG_PIPE_INFO": parse_message_pipes,
}


@dataclass(frozen=True)
class KernelObjectRegistry:
    tables: tuple[KernelObjectTable, ...]
    errors: tuple[dict, ...]

    @classmethod
    def parse(cls, core: CoreDump) -> "KernelObjectRegistry":
        tables = []
        errors = []
        for note_name, parser in PARSERS.items():
            note = core.note(note_name)
            if note is None:
                continue
            try:
                tables.append(parser(note.description))
            except (ParseError, struct.error, ValueError) as exc:
                errors.append({"note": note_name, "error": str(exc)})
        return cls(tuple(tables), tuple(errors))

    @property
    def objects(self) -> tuple[KernelObject, ...]:
        return tuple(item for table in self.tables for item in table.objects)

    def resolve(self, uid: int) -> Optional[KernelObject]:
        matches = tuple(item for item in self.objects if item.uid == uid)
        return matches[0] if len(matches) == 1 else None

    def waiting_objects(self, thread_uid: int) -> tuple[KernelObject, ...]:
        return tuple(item for item in self.objects if any(waiter.thread_uid == thread_uid for waiter in item.waiters))

    def wait_graph(self) -> dict:
        edges = []
        for item in self.objects:
            for waiter in item.waiters:
                edges.append({
                    "from_thread_uid": waiter.thread_uid,
                    "object_uid": item.uid,
                    "object_kind": item.kind,
                    "object_name": item.name,
                    "role": waiter.role,
                    "to_owner_thread_uid": item.owner_thread_uid,
                })
        adjacency: dict[int, set[int]] = {}
        for edge in edges:
            owner = edge["to_owner_thread_uid"]
            if owner is not None:
                adjacency.setdefault(edge["from_thread_uid"], set()).add(owner)
        cycles: set[tuple[int, ...]] = set()

        def visit(start: int, current: int, path: tuple[int, ...]) -> None:
            if len(path) > len(adjacency) + 1:
                return
            for target in adjacency.get(current, ()):
                if target == start:
                    cycle = path
                    rotations = [cycle[index:] + cycle[:index] for index in range(len(cycle))]
                    cycles.add(min(rotations))
                elif target not in path:
                    visit(start, target, path + (target,))

        for node in adjacency:
            visit(node, node, (node,))
        return {
            "edge_count": len(edges),
            "edges": edges,
            "cycle_count": len(cycles),
            "cycles": [list(cycle) for cycle in sorted(cycles)],
        }

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for item in self.objects:
            counts[item.kind] = counts.get(item.kind, 0) + 1
        active = tuple(item for item in self.objects if item.waiting_thread_count or item.owner_thread_uid is not None)
        return {
            "table_count": len(self.tables),
            "object_count": len(self.objects),
            "object_counts": counts,
            "active_object_count": len(active),
            "active_objects": [item.summary() for item in active],
            "wait_graph": self.wait_graph(),
            "tables": [table.summary() for table in self.tables],
            "errors": list(self.errors),
        }
