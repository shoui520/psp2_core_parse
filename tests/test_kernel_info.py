import json
import struct

import pytest

pytest.importorskip("cryptography")

from psp2_core_parse import read_dump
from psp2_core_parse.analysis import analyze
from psp2_core_parse.cli import main
from psp2_core_parse.kernel_info import KernelInfo
from test_core import make_core
from test_kerndump import make_blob
from test_spsp2dmp import KERNEL_DATA_IV, KERNEL_KEK, KERNEL_KEY_IV, encrypt, make_container, write_dump


KEY = bytes(range(0x80, 0xA0))
FIRMWARE = 0x03650000
DRAM_BASE = 0x40200000
PAGES = (0x70001000, 0x81234000)


def psp2_note(kind, description):
    return (
        struct.pack("<3I", 5, len(description), kind) + b"PSP2\0\0\0\0"
        + description + b"\0" * ((-len(description)) & 3)
    )


def crash_header(kind, cpu=1):
    header = struct.pack("<8I", 0x50, FIRMWARE, 0, cpu, kind, 0x4000406A, 0x40000000, 0x40050000)
    return header + bytes(range(16)) + encrypt(KEY, KERNEL_KEK, KERNEL_KEY_IV)


def tty(text):
    return text.encode().rjust(0x1000, b"\0")


def bus_error_record():
    ocp = bytearray(320)
    # BET0 sees DMAC5 in the first status; BEBT names the Main Xbar.
    struct.pack_into("<8I", ocp, 0, 320, 0x20, 0, 0x1, 0, 0, 0, 18)
    struct.pack_into("<2I", ocp, 32 + 5 * 16, 0x1F000040, 0x00C0FFEE)
    bus = struct.pack("<4I5Q", 120, 1, 1, 0xEC000000, 1, 0, 0, 0, 0)
    initiator = struct.pack("<2I3Q", 32, 0xEC040000, 0x1, 0x123456789A, 0x40300000)
    target = struct.pack("<2I3Q", 32, 0xEC050400, 0x1000, 0, 0)
    si = struct.pack("<2I", 8, 1) + bus + initiator + target
    grab = struct.pack("<21I", 84, 4, 0x11, 0x50000000, 0x22, 0x33, *([0] * 15))
    regbus = struct.pack("<11I", 44, *([0] * 10))
    vip = struct.pack("<13I", 52, *([0] * 12))
    blocks = bytes(ocp) + si + grab + regbus + vip
    header = struct.pack("<7I", 28, 28 + len(blocks), len(ocp), len(si), len(grab), len(regbus), len(vip))
    return header + blocks


def make_crashdump_elf(kind=0, *, full=True, text=None):
    """An ARM core as SceCrashDump's crashdumpWriteCore lays it out."""
    notes = psp2_note(0x1000, crash_header(kind))
    if full:
        notes += psp2_note(0x1001, struct.pack(f"<{len(PAGES)}I", *PAGES))
    if text is None:
        text = {
            0: "boot\n*** Kernel Data Abort Exception at CPU1 <0x12345678:0x9abc>\nStopped\n",
            1: "boot\n*** Kernel Panic at <1:0x1234567823456789:0x34567890:0x81000101>\nStopped\n",
            2: "boot\n[ Bus error occured on target device ]\n",
        }[kind]
    notes += psp2_note(0x1100, tty(text))
    if kind == 0:
        notes += psp2_note(0x1200, make_blob(0x38, 3))
    elif kind == 1:
        notes += psp2_note(0x1201, make_blob(0x40, 1))
    else:
        notes += psp2_note(0x1202, bus_error_record())

    dram = bytes(range(256)) * 32
    pages = b"".join(bytes([index + 1]) * 0x1000 for index in range(len(PAGES)))
    loads = [(DRAM_BASE, dram), (0, pages)] if full else []
    header_size = 52 + 32 * (1 + len(loads))
    offset = (len(notes) + 0xFFF + header_size) & ~0xFFF
    headers = [struct.pack("<8I", 4, header_size, 0, 0, len(notes), 0, 0, 0)]
    for address, data in loads:
        headers.append(struct.pack("<8I", 1, offset, 0, address, len(data), len(data), 4, 0x1000))
        offset += len(data)

    elf = bytearray(52)
    elf[:16] = b"\x7fELF\x01\x01\x01" + bytes(9)
    struct.pack_into("<HHIIIIIHHHHHH", elf, 16, 4, 40, 1, 0, 52, 0, 0x05000000, 52, 32, len(headers), 0, 0, 0)
    elf += b"".join(headers) + notes
    plain = bytearray(elf)
    for address, data in loads:
        start = (len(elf) + 0xFFF) & ~0xFFF if address else len(elf)
        elf += bytes(start - len(elf)) + encrypt(data, KEY, KERNEL_DATA_IV)
        plain += bytes(start - len(plain)) + data
    return bytes(elf), bytes(plain), dram, pages


def kernel_info_note(elf):
    return struct.pack("<QI", 8, len(elf)) + elf


def write_kernel_dump(tmp_path, elf):
    image = make_core(note_name=b"KERNEL_INFO\0", note_type=0x3000, description=kernel_info_note(elf))
    return write_dump(tmp_path, make_container(image))


def test_exception_crash_core_is_decoded(tmp_path):
    elf, plain, dram, pages = make_crashdump_elf(0)
    info = KernelInfo.parse(kernel_info_note(elf), strict=True)
    assert info.complete and info.image == plain
    assert info.crash["kind_name"] == "kernel exception" and info.crash["cpu"] == 1
    assert info.crash["firmware"] == "3.65" and info.crash["ttbr0"] == 0x4000406A
    assert info.crash["session_id"] == bytes(range(16)).hex()
    assert [note["name"] for note in info.notes] == ["CRASH_INFO", "PAGE_LIST", "KERNEL_TTY", "EXCEPTION_DUMP"]
    assert all(note["status"] == "decoded" for note in info.notes)
    assert info.pages == list(PAGES)
    assert info.tty["fault_kind"] == "Data Abort Exception"

    dump = info.dump
    assert dump["kind"] == "exception" and dump["header"]["process_id"] == 0x10001
    assert dump["exception_context"]["registers"]["dfar"] == 0xDEADBEEF
    assert dump["kernel_backtrace"][0]["pc"] == 0x81000101
    assert dump["saved_thread_registers"]["pc"] == 0x81000301

    assert [segment["role"] for segment in info.segments] == ["dram", "pages"]
    assert info.read_physical(DRAM_BASE + 0x10, 4) == dram[0x10:0x14]
    assert info.read_physical(PAGES[1] + 0xFFE, 2) == pages[0x1FFE:0x2000]
    assert info.read_physical(PAGES[1] + 0xFFF, 2) is None

    analysis = info.analysis()
    assert analysis["classification"] == "KERNEL_DATA_ABORT"
    assert analysis["fault"]["address"] == 0xDEADBEEF and analysis["fault"]["status"]["write"]
    assert analysis["location"]["notation"] == "0xaabbccdd+0x100"
    assert "fw=03650000" in analysis["failure_bucket"]["canonical"]


def test_panic_is_classified_from_the_kernel_tty():
    elf, *_ = make_crashdump_elf(1)
    analysis = KernelInfo.parse(kernel_info_note(elf), strict=True).analysis()
    assert analysis["classification"] == "KERNEL_PANIC"
    assert "12345678:23456789:34567890" in analysis["failure_bucket"]["canonical"]
    assert "Kernel TTY: *** Kernel Panic at" in analysis["verdict"]

    elf, *_ = make_crashdump_elf(1, text="no report\n")
    info = KernelInfo.parse(kernel_info_note(elf))
    assert info.analysis()["classification"] == "KERNEL_ASSERTION_OR_PANIC"
    assert info.dump["header"]["caller"] == 0x10045


def test_bus_error_record_names_targets_and_agents():
    elf, *_ = make_crashdump_elf(2)
    info = KernelInfo.parse(kernel_info_note(elf), strict=True)
    bus = info.bus_error
    assert bus["complete"] and bus["block_sizes"]["vip"] == 52
    assert bus["ocp"]["target_errors"] == [
        {"target": "DMAC5", "log": "first", "address": 0x1F000040, "attribute": 0x00C0FFEE},
    ]
    assert bus["ocp"]["buses_in_error"] == ["Main Xbar"]
    # The target's only status bit is one the handler ignores.
    assert [agent["agent"] for agent in bus["si"]["buses"][0]["agent_errors"]] == ["SSX_MainXB_IA_ARM0"]
    assert bus["grab"]["write_address"] == 0x50000000
    analysis = info.analysis()
    assert analysis["classification"] == "KERNEL_BUS_ERROR"
    assert "ocp:DMAC5" in analysis["failure_bucket"]["components"]


def test_retail_crash_core_has_notes_but_no_memory():
    elf, plain, *_ = make_crashdump_elf(0, full=False)
    info = KernelInfo.parse(kernel_info_note(elf), strict=True)
    assert info.image == plain and info.segments == [] and info.pages == []
    assert info.read_physical(DRAM_BASE, 4) is None
    assert info.analysis()["classification"] == "KERNEL_DATA_ABORT"


def test_truncated_crash_core_is_salvaged():
    elf, *_ = make_crashdump_elf(0)
    info = KernelInfo.parse(kernel_info_note(elf[:0x400]))
    assert not info.complete
    assert info.crash["kind"] == 0
    assert any(note["status"] == "partial" for note in info.notes)
    assert info.segments == [] or any(segment["available_size"] < segment["size"] for segment in info.segments)


def test_kernel_coredump_commands(tmp_path, capsys):
    elf, _, dram, _ = make_crashdump_elf(0)
    path = write_kernel_dump(tmp_path, elf)

    result = analyze(read_dump(path, strict=True))
    assert result["classification"] == "KERNEL_DATA_ABORT"
    assert result["kernel_info"]["crash"]["cpu"] == 1

    assert main(["analyze", str(path)]) == 0
    text = capsys.readouterr().out
    assert "KERNEL_DATA_ABORT" in text and "KERNEL_CRASH_DUMP:" in text
    assert "KERNEL_EXCEPTION_DUMP:" in text and "*** Kernel Data Abort Exception" in text

    assert main(["notes", str(path), "KERNEL_INFO", "--json"]) == 0
    notes = json.loads(capsys.readouterr().out)
    note = notes[0] if isinstance(notes, list) else notes
    assert note["decoder"] == "KernelInfo" and note["status"] == "decoded"

    assert main(["kernel", str(path)]) == 0
    text = capsys.readouterr().out
    assert text.startswith("Kernel data abort recorded by SceCrashDump on CPU 1 at 0xaabbccdd+0x100.")
    assert "KERNEL_PHYSICAL_MEMORY:" in text and "2 mapped pages" in text

    assert main(["kernel", str(path), "--physical", hex(DRAM_BASE), "--size", "16"]) == 0
    assert capsys.readouterr().out.startswith(f"{DRAM_BASE:08x}  00 01 02 03")
    assert main(["kernel", str(path), "--physical", "0x10000000"]) == 2
    assert "was not captured" in capsys.readouterr().err


def test_kernel_command_requires_kernel_info(tmp_path, capsys):
    path = write_dump(tmp_path, make_container())
    assert main(["kernel", str(path)]) == 2
    assert "NPXS19998" in capsys.readouterr().err
