import struct

from psp2_core_parse.execution import ThreadRegisterInfo


def test_partial_register_prefix_is_salvaged_without_exception():
    payload = struct.pack("<3I", 1, 1, 0x178) + b"\0" * 49
    value = ThreadRegisterInfo.parse(payload)
    assert value.records == ()
    assert len(value.partial_records) == 1
    assert value.partial_records[0].summary()["available_gpr_count"] == 11
    assert not value.complete


def test_late_partial_register_prefix_does_not_invent_unwritten_fault_words():
    raw = bytearray(0x160)
    struct.pack_into("<2I", raw, 0, 0x178, 0x40010001)
    struct.pack_into("<16I", raw, 8, *range(16))
    struct.pack_into("<3I", raw, 0x48, 0x600001D3, 0x1234, 0x5678)
    value = ThreadRegisterInfo.parse(struct.pack("<2I", 1, 1) + raw)
    assert value.records == ()
    partial = value.partial_records[0].summary()
    assert partial["available_gpr_count"] == 16
    assert partial["available_vfp_d_count"] == 32
    assert partial["cpsr"] == 0x600001D3
    assert partial["producer_system_words_prefix"] == [0, 0, 0]
    assert partial["ifsr"] is None
    assert partial["dfar"] is None
