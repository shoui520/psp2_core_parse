import struct

from psp2_core_parse.execution import ProcessInfo
from psp2_core_parse.support import (
    decode_app_list,
    decode_device,
    decode_event_log,
    decode_external_processes,
    decode_files,
    decode_libraries,
    decode_metadata,
    decode_timers,
)


def padded(value: bytes) -> bytes:
    return value + b"\0" * ((-len(value)) & 3)


def test_file_and_metadata_variable_records_preserve_payload_boundaries():
    fixed = bytearray(0x48)
    struct.pack_into("<I", fixed, 4, 0x40010005)
    struct.pack_into("<I", fixed, 0x10, 0x12345)
    file_data = struct.pack("<2I", 5, 1) + fixed
    file_data += struct.pack("<I", 2) + padded(b"a\0")
    file_data += struct.pack("<I", 3) + padded(b"xy\0")
    files = decode_files(file_data)
    assert files["complete"]
    assert files["trailing_size"] == 0
    assert files["records"][0]["strings"] == ["a", "xy"]

    metadata_data = struct.pack("<4I", 2, 1, 0x40010005, 3) + padded(b"abc") + b"\0" * 12
    metadata = decode_metadata(metadata_data)
    assert metadata["complete"]
    assert metadata["entries"][0]["payload_size"] == 3
    assert metadata["trailing_size"] == 12
    assert metadata["trailing_nonzero_bytes"] == 0


def test_event_log_uses_sce_kernel_debug_event_log_union_layouts():
    process = bytearray(0x5C)
    struct.pack_into("<2I", process, 0, 0x5C, 10)
    process[8:0x12] = b"NPXS19999\0"
    struct.pack_into("<3I", process, 0x14, 0x12711, 0x10005, 0x10215)
    struct.pack_into("<Q", process, 0x30, 0x123456789)
    struct.pack_into("<I", process, 0x3C, 0x1C)
    struct.pack_into("<4I", process, 0x40, 0, 0x11A2D, 4, 10)
    process[0x50:0x55] = b"main\0"

    network_word = bytearray(0x44)
    struct.pack_into("<2I", network_word, 0, 0x44, 10)
    network_word[8:0x12] = b"NPXS19999\0"
    struct.pack_into("<I", network_word, 0x3C, 4)
    struct.pack_into("<I", network_word, 0x40, 0x80412113)

    addresses = bytearray(0x94)
    struct.pack_into("<2I", addresses, 0, 0x94, 10)
    addresses[8:0x12] = b"NPXS19999\0"
    struct.pack_into("<I", addresses, 0x3C, 0x54)
    for index, value in enumerate((b"10.0.0.1\0", b"10.0.0.2\0", b"\0", b"\0", b"\0")):
        addresses[0x44 + index * 0x10:0x44 + index * 0x10 + len(value)] = value

    raw = struct.pack("<3I", 9, 0, 3) + process + network_word + addresses + bytes(0x40)
    event_log = decode_event_log(raw)
    assert event_log["complete"]
    assert [item["item"]["kind"] for item in event_log["records"]] == [
        "process", "network-word", "network-addresses",
    ]
    assert event_log["records"][0]["flags"] == 0x12711
    assert event_log["records"][0]["item"]["process_id"] == 0x11A2D
    assert event_log["records"][2]["item"]["addresses"][:2] == ["10.0.0.1", "10.0.0.2"]
    assert event_log["trailing_size"] == 0x40


def test_app_external_library_timer_and_device_exact_layouts():
    app = bytearray(0x4C)
    struct.pack_into("<I", app, 0x0C, 0x23456)
    app[0x14:0x1E] = b"TEST00001\0"
    struct.pack_into("<I", app, 0x48, 9)
    apps = decode_app_list(struct.pack("<2I", 6, 1) + app + padded(b"app0:test"))
    assert apps["complete"]
    assert apps["records"][0]["title_id"] == "TEST00001"
    assert apps["records"][0]["path"] == "app0:test"
    assert len(apps["records"][0]["producer_words_0x34"]) == 5

    external = bytearray(0x5C)
    struct.pack_into("<3I", external, 4, 0x23456, 0x40010009, 7)
    external[0x10:0x18] = b"Process\0"
    struct.pack_into("<I", external, 0x38, 0xAAAAAAAA)
    struct.pack_into("<I", external, 0x40, 0x11111)
    struct.pack_into("<I", external, 0x58, 9)
    external_data = struct.pack("<2I", 6, 1) + external + padded(b"app0:test") + struct.pack("<4I", 1, 2, 3, 4)
    processes = decode_external_processes(external_data)
    assert processes["complete"]
    assert processes["records"][0]["path"] == "app0:test"
    assert processes["records"][0]["parent_process_id"] == 0x11111
    assert processes["records"][0]["producer_words_0x30"][2] == 0xAAAAAAAA
    assert len(processes["records"][0]["producer_words_0x44"]) == 5
    assert processes["records"][0]["footer_words"] == [1, 2, 3, 4]

    library = bytearray(0x24)
    struct.pack_into("<9I", library, 0, 0, 0x40010011, 0x40010001, 1, 0, 1, 1, 0, 1)
    library_data = struct.pack("<2I", 6, 1) + library
    library_data += struct.pack("<5I", 0x11111111, 0x81000101, 0x22222222, 0x81000201, 9)
    library_data += struct.pack("<I", 4) + b"Test"
    libraries = decode_libraries(library_data)
    assert libraries["complete"]
    assert libraries["records"][0]["name"] == "Test"
    assert [item["class"] for item in libraries["records"][0]["entries"]] == ["primary", "secondary"]

    timer = bytearray(0x78)
    struct.pack_into("<I", timer, 0, len(timer))
    struct.pack_into("<2I", timer, 4, 0x40010021, 0x23456)
    timer[0x0C:0x12] = b"Timer\0"
    struct.pack_into("<I", timer, 0x60, 1)
    struct.pack_into("<2I", timer, 0x64, 0x23456, 0x40010023)
    struct.pack_into("<3I", timer, 0x6C, 4, 5, 6)
    timers = decode_timers(struct.pack("<2I", 17, 1) + timer)
    assert timers["complete"]
    assert timers["records"][0]["waiters"][0]["thread_uid"] == 0x40010023
    assert timers["records"][0]["footer_words"] == [4, 5, 6]

    capped_waiters = tuple((0x23456, 0x40011000 + index) for index in range(0x140))
    capped = bytearray(0x64)
    struct.pack_into("<I", capped, 0, 0x70 + 0x141 * 8)
    struct.pack_into("<2I", capped, 4, 0x40010031, 0x23456)
    struct.pack_into("<I", capped, 0x60, 0x141)
    capped += b"".join(struct.pack("<2I", *waiter) for waiter in capped_waiters)
    capped += struct.pack("<3I", 7, 8, 9)
    capped_timers = decode_timers(struct.pack("<2I", 17, 1) + capped)
    assert capped_timers["complete"]
    assert capped_timers["records"][0]["declared_waiter_count"] == 0x141
    assert capped_timers["records"][0]["serialized_waiter_count"] == 0x140
    assert capped_timers["records"][0]["footer_words"] == [7, 8, 9]

    fixed = bytes(0x3C)
    device_data = struct.pack("<I", 6) + fixed + struct.pack("<3I", 1, 0x123, 1) + struct.pack("<I", 0x456)
    device = decode_device(device_data)
    assert device["complete"]
    assert [item["values"] for item in device["id_lists"]] == [[0x123], [0x456]]


def test_process_tail_is_separated_from_path():
    fixed = bytearray(0x5C)
    struct.pack_into("<4I", fixed, 0, 1, 0, 0x23456, 7)
    fixed[0x10:0x18] = b"Process\0"
    struct.pack_into("<I", fixed, 0x40, 0x12345)
    struct.pack_into("<I", fixed, 0x58, 9)
    raw = fixed + padded(b"app0:test") + struct.pack("<4IQ", 1, 2, 3, 4, 0x1122334455667788)
    process = ProcessInfo.parse(raw)
    assert process.complete
    assert process.path == "app0:test"
    assert process.parent_process_id == 0x12345
    assert process.footer_words == (1, 2, 3, 4)
    assert process.accounting_value == 0x1122334455667788
