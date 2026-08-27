import struct

from psp2_core_parse.kernel import parse_lwmutexes, parse_message_pipes, parse_mutexes


def lwmutex(uid, name, waiters=()):
    raw = bytearray(0x40)
    struct.pack_into("<I", raw, 4, uid)
    raw[8:8 + len(name)] = name.encode()
    struct.pack_into("<6I", raw, 0x28, 2, 0xE0001000, 0, 1, 0x40010001, len(waiters))
    return bytes(raw) + struct.pack(f"<{len(waiters)}I", *waiters)


def test_lwmutex_waiters_are_single_thread_uid_words():
    payload = struct.pack("<2I", 1, 2)
    payload += lwmutex(0x40010010, "active", (0x40010020, 0x40010030))
    payload += lwmutex(0x40010011, "next")
    table = parse_lwmutexes(payload)
    assert table.complete
    assert len(table.objects) == 2
    assert [item.thread_uid for item in table.objects[0].waiters] == [0x40010020, 0x40010030]
    assert all(item.process_id is None for item in table.objects[0].waiters)
    assert table.objects[1].name == "next"


def mutex(uid, name, waiters=(), footer=0):
    raw = bytearray(0x44)
    struct.pack_into("<2I", raw, 4, uid, 0x12345)
    raw[0x0C:0x0C + len(name)] = name.encode()
    struct.pack_into("<I", raw, 0x40, len(waiters))
    pairs = b"".join(struct.pack("<2I", pid, thread) for pid, thread in waiters)
    return bytes(raw) + pairs + struct.pack("<I", footer)


def test_mutex_waiters_precede_the_moving_footer():
    payload = struct.pack("<2I", 9, 2)
    payload += mutex(0x40010010, "active", ((0x12345, 0x40010020),), 0xAABBCCDD)
    payload += mutex(0x40010011, "next", (), 0x11223344)
    table = parse_mutexes(payload)
    assert table.complete
    assert table.objects[0].waiters[0].thread_uid == 0x40010020
    assert table.objects[0].state["footer_word"] == 0xAABBCCDD
    assert table.objects[1].name == "next"
    assert table.objects[1].state["footer_word"] == 0x11223344


def message_pipe(uid, name, senders=(), receivers=(), footer=(0, 0, 0)):
    waiters = tuple(senders) + tuple(receivers)
    raw = bytearray(0x44)
    struct.pack_into("<I", raw, 0, 0x50 + len(waiters) * 8)
    struct.pack_into("<2I", raw, 4, uid, 0x12345)
    raw[0x0C:0x0C + len(name)] = name.encode()
    struct.pack_into("<2I", raw, 0x3C, len(senders), len(receivers))
    pairs = b"".join(struct.pack("<2I", pid, thread) for pid, thread in waiters)
    return bytes(raw) + pairs + struct.pack("<3I", *footer)


def test_message_pipe_waiters_precede_the_moving_footer():
    payload = struct.pack("<2I", 17, 2)
    payload += message_pipe(
        0x40010030, "pipe", ((0x12345, 0x40010031),),
        ((0x12345, 0x40010032),), (1, 2, 3),
    )
    payload += message_pipe(0x40010040, "next", footer=(4, 5, 6))
    table = parse_message_pipes(payload)
    assert table.complete
    assert [item.role for item in table.objects[0].waiters] == ["sender", "receiver"]
    assert table.objects[0].state["footer_words"] == [1, 2, 3]
    assert table.objects[1].name == "next"
