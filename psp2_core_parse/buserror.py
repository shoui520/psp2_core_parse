# Copyright (c) 2026 psp2_core_parse contributors
# SPDX-License-Identifier: MIT

"""SceKernelBusError's record of a bus error (the sysroot shared memory at +0x6000).

A header of block sizes, then the OCP target error logs, the SI bus agents, the
GRAB and register-bus bridges and (in newer records) the VIP protection logs,
laid out as SceKernelBusError's ES3 handler fills and prints them.
"""

from __future__ import annotations

import struct
from typing import Optional


# The OCP targets by index: the first 15 report in BET0, the rest in BET1.
OCP_TARGETS = (
    ("DMAC0", 0x00000001), ("DMAC1", 0x00000002), ("DMAC2", 0x00000004), ("DMAC3", 0x00000008),
    ("DMAC4", 0x00000010), ("DMAC5", 0x00000020), ("DMAC6", 0x00000040), ("SPM32", 0x00000800),
    ("SPM128", 0x00001000), ("DDRIF0", 0x00004000), ("DDRIF1", 0x00008000), ("CompatRAM", 0x00020000),
    ("Pervasive", 0x00100000), ("Pervasive2", 0x00200000), ("DebugPA", 0x00400000),
    ("TIMER", 0x00000008), ("SDIO1", 0x00004000), ("SDIO0", 0x00008000),
)

# The system buses by their BEBT bit.
SYSTEM_BUSES = (
    ("Main Xbar", 0x00000001), ("Center Xbar", 0x00000002), ("Video Xbar", 0x00000004),
    ("IFTU Xbar", 0x00000008), ("VIP Xbar", 0x00000010), ("Debug Bus", 0x00000020),
    ("DMAC Xbar", 0x00000040), ("IO Slave Bus", 0x00000100), ("IO Master Bus", 0x00000200),
    ("Pervasive Bus", 0x00000400), ("Misc IO Bus", 0x00000800), ("North IO Master Bus", 0x00001000),
    ("Audio Bus", 0x00002000), ("North IO Slave Bus", 0x00004000), ("SRC Bus", 0x00008000),
    ("GPU Register Bus", 0x00010000), ("IFTU Register Bus", 0x00020000), ("Camera Slave Bus", 0x01000000),
    ("Camera Master Bus", 0x02000000), ("USB Slave Bus", 0x04000000), ("USB Master Bus", 0x08000000),
    ("SubLCD Slave Bus", 0x10000000), ("SubLCD Master Bus", 0x20000000), ("Camera Register Bus", 0x40000000),
)

# The SSX initiator and target agents by register address.
BUS_PORTS = {
    0xec040000: "SSX_MainXB_IA_ARM0",
    0xec040400: "SSX_MainXB_IA_ARM1",
    0xec048000: "SSX_MainXB_IA_CenterXbar0",
    0xec048400: "SSX_MainXB_IA_CenterXbar1",
    0xec048800: "SSX_MainXB_IA_CenterXbar2",
    0xec048c00: "SSX_MainXB_IA_IoMasterBus",
    0xec049000: "SSX_MainXB_IA_DmacXbar0",
    0xec049400: "SSX_MainXB_IA_DmacXbar1",
    0xec050000: "SSX_MainXB_TA_Spad_32KiB",
    0xec050400: "SSX_MainXB_TA_LPDDR0",
    0xec050800: "SSX_MainXB_TA_ACP",
    0xec058000: "SSX_MainXB_TA_CenterXbar0",
    0xec058400: "SSX_MainXB_TA_CenterXbar1",
    0xec058800: "SSX_MainXB_TA_IoSlaveBus",
    0xec140000: "SSX_CenterXB_IA_GPUXbar",
    0xec148000: "SSX_CenterXB_IA_MainXbar0",
    0xec148400: "SSX_CenterXB_IA_MainXbar1",
    0xec148800: "SSX_CenterXB_IA_VideoXbar0",
    0xec148c00: "SSX_CenterXB_IA_VideoXbar1",
    0xec149000: "SSX_CenterXB_IA_IoMasterBus",
    0xec149400: "SSX_CenterXB_IA_DmacXbar0",
    0xec149800: "SSX_CenterXB_IA_DmacXbar1",
    0xec150000: "SSX_CenterXB_TA_Compati_2MiB",
    0xec150400: "SSX_CenterXB_TA_DevNull",
    0xec150800: "SSX_CenterXB_TA_GpuXbar",
    0xec158000: "SSX_CenterXB_TA_MainXbar0",
    0xec158400: "SSX_CenterXB_TA_MainXbar1",
    0xec158800: "SSX_CenterXB_TA_MainXbar2",
    0xec158c00: "SSX_CenterXB_TA_VideoXbar",
    0xec240000: "SSX_VideoXB_IA_DMAC2",
    0xec240400: "SSX_VideoXB_IA_DMAC3",
    0xec240800: "SSX_VideoXB_IA_Venezia",
    0xec240c00: "SSX_VideoXB_IA_LCDDMAC",
    0xec248000: "SSX_VideoXB_IA_CenterXbar",
    0xec248400: "SSX_VideoXB_IA_IftuXbar0",
    0xec248800: "SSX_VideoXB_IA_IftuXbar1",
    0xec248c00: "SSX_VideoXB_IA_VipXbar0",
    0xec249000: "SSX_VideoXB_IA_VipXbar1",
    0xec249400: "SSX_VideoXB_IA_DebugBus",
    0xec250000: "SSX_VideoXB_TA_Spad_128KiB",
    0xec250400: "SSX_VideoXB_TA_GpuXbar0",
    0xec250800: "SSX_VideoXB_TA_GpuXbar1",
    0xec250c00: "SSX_VideoXB_TA_GpuXbar2",
    0xec258000: "SSX_VideoXB_TA_CenterXbar0",
    0xec258400: "SSX_VideoXB_TA_CenterXbar1",
    0xec258800: "SSX_VideoXB_TA_DebugBus",
    0xec340000: "SSX_IftuXB_IA_IFTU0a",
    0xec340400: "SSX_IftuXB_IA_IFTU0b",
    0xec340800: "SSX_IftuXB_IA_IFTU1a",
    0xec340c00: "SSX_IftuXB_IA_IFTU1b",
    0xec341000: "SSX_IftuXB_IA_IFTU2",
    0xec348000: "SSX_IftuXB_IA_IftuRegBus",
    0xec358000: "SSX_IftuXB_TA_VideoXbar0",
    0xec358400: "SSX_IftuXB_TA_VideoXbar1",
    0xec440000: "SSX_VipXB_IA_VDP0",
    0xec440400: "SSX_VipXB_IA_VDP1",
    0xec440800: "SSX_VipXB_IA_VDP2",
    0xec440c00: "SSX_VipXB_IA_VDP3",
    0xec441000: "SSX_VipXB_IA_VDPMeP",
    0xec441400: "SSX_VipXB_IA_BAPMeP",
    0xec448000: "SSX_VipXB_IA_GpuRegBus",
    0xec450000: "SSX_VipXB_TA_GpuXbar",
    0xec458000: "SSX_VipXB_TA_VideoXbar0",
    0xec458400: "SSX_VipXB_TA_VideoXbar1",
    0xec540000: "SSX_DebugBus_IA_DMAC6",
    0xec540400: "SSX_DebugBus_IA_PA",
    0xec548000: "SSX_DebugBus_IA_VideoXbar",
    0xec550000: "SSX_DebugBus_TA_SDIO0",
    0xec550400: "SSX_DebugBus_TA_SDIO1",
    0xec550800: "SSX_DebugBus_TA_LPDDR1",
    0xec558000: "SSX_DebugBus_TA_VideoXbar",
    0xec640000: "SSX_DmacXB_IA_DMAC0",
    0xec640400: "SSX_DmacXB_IA_DMAC1",
    0xec648000: "SSX_DmacXB_IA_IoSlaveBus",
    0xec658000: "SSX_DmacXB_TA_MainXbar0",
    0xec658400: "SSX_DmacXB_TA_MainXbar1",
    0xec658800: "SSX_DmacXB_TA_CenterXbar0",
    0xec658c00: "SSX_DmacXB_TA_CenterXbar1",
    0xed048000: "SSX_IoSlaveBus_IA_MainXbar",
    0xed058000: "SSX_IoSlaveBus_TA_PervasiveBus",
    0xed058400: "SSX_IoSlaveBus_TA_NorthIoBus",
    0xed058800: "SSX_IoSlaveBus_TA_GpuRegBus",
    0xed058c00: "SSX_IoSlaveBus_TA_MiscIoBus",
    0xed059000: "SSX_IoSlaveBus_TA_CameraSlaveBus0",
    0xed059400: "SSX_IoSlaveBus_TA_CameraSlaveBus1",
    0xed059800: "SSX_IoSlaveBus_TA_CameraSlaveBus2",
    0xed059c00: "SSX_IoSlaveBus_TA_IoMasterBus",
    0xed05a000: "SSX_IoSlaveBus_TA_DmacXbar",
    0xed148000: "SSX_IoMasterBus_IA_NorthIoBus",
    0xed148400: "SSX_IoMasterBus_IA_CameraMasterBus",
    0xed148800: "SSX_IoMasterBus_IA_IoSlaveBus",
    0xed158000: "SSX_IoMasterBus_TA_MainXbar",
    0xed158400: "SSX_IoMasterBus_TA_CenterXbar",
    0xed248000: "SSX_PervasiveBus_IA_IoSlaveBus",
    0xed250000: "SSX_PervasiveBus_TA_DMAC0",
    0xed250800: "SSX_PervasiveBus_TA_Pervasive",
    0xed250c00: "SSX_PervasiveBus_TA_CoreSight",
    0xed251000: "SSX_PervasiveBus_TA_VFPINT",
    0xed348000: "SSX_MiscIoBus_IA_IoSlaveBus",
    0xed350000: "SSX_MiscIoBus_TA_UART0",
    0xed350400: "SSX_MiscIoBus_TA_UART1",
    0xed350800: "SSX_MiscIoBus_TA_UART2",
    0xed350c00: "SSX_MiscIoBus_TA_UART3",
    0xed351000: "SSX_MiscIoBus_TA_UART4",
    0xed351400: "SSX_MiscIoBus_TA_UART5",
    0xed351800: "SSX_MiscIoBus_TA_UART6",
    0xed351c00: "SSX_MiscIoBus_TA_GPIO0",
    0xed352000: "SSX_MiscIoBus_TA_Timer",
    0xed352400: "SSX_MiscIoBus_TA_PWM",
    0xed440000: "SSX_NIoMasterBus_IA_DMAC4",
    0xed440400: "SSX_NIoMasterBus_IA_DMAC5",
    0xed440800: "SSX_NIoMasterBus_IA_HSMMC1",
    0xed440c00: "SSX_NIoMasterBus_IA_HSMMC2",
    0xed441000: "SSX_NIoMasterBus_IA_HSMMC3",
    0xed448000: "SSX_NIoMasterBus_IA_NIoSlaveBus",
    0xed450000: "SSX_NIoMasterBus_TA_KeyRing",
    0xed458000: "SSX_NIoMasterBus_TA_AudioBus",
    0xed458400: "SSX_NIoMasterBus_TA_SrcBus",
    0xed458800: "SSX_NIoMasterBus_TA_IoMasterBus0",
    0xed458c00: "SSX_NIoMasterBus_TA_IoMasterBus1",
    0xed548000: "SSX_AudioBus_IA_NIoMasterBus",
    0xed550000: "SSX_AudioBus_TA_I2S0",
    0xed550400: "SSX_AudioBus_TA_I2S1",
    0xed550800: "SSX_AudioBus_TA_I2S2",
    0xed550c00: "SSX_AudioBus_TA_I2SD0",
    0xed551000: "SSX_AudioBus_TA_I2SD1",
    0xed551400: "SSX_AudioBus_TA_I2S4",
    0xed551c00: "SSX_AudioBus_TA_I2S7",
    0xed552000: "SSX_AudioBus_TA_SPDIF",
    0xed648000: "SSX_NIoSlaveBus_IA_IoSlaveBus",
    0xed650000: "SSX_NIoSlaveBus_TA_DMAC4",
    0xed650400: "SSX_NIoSlaveBus_TA_DMAC5",
    0xed650800: "SSX_NIoSlaveBus_TA_I2C0",
    0xed650c00: "SSX_NIoSlaveBus_TA_I2C1",
    0xed651000: "SSX_NIoSlaveBus_TA_HSMMC1",
    0xed651400: "SSX_NIoSlaveBus_TA_HSMMC2",
    0xed651800: "SSX_NIoSlaveBus_TA_HSMMC3",
    0xed658000: "SSX_NIoSlaveBus_TA_NIoMasterBus",
    0xed748000: "SSX_SrcBus_IA_NIoMasterBus",
    0xed750000: "SSX_SrcBus_TA_SRC0",
    0xed750400: "SSX_SrcBus_TA_SRC1",
    0xed750800: "SSX_SrcBus_TA_SRC2",
    0xed848000: "SSX_GpuRegBus_IA_IoSlaveBus",
    0xed850000: "SSX_GpuRegBus_TA_DMAC2",
    0xed850400: "SSX_GpuRegBus_TA_DMAC3",
    0xed850800: "SSX_GpuRegBus_TA_LCDDMAC",
    0xed850c00: "SSX_GpuRegBus_TA_DMAC6",
    0xed851000: "SSX_GpuRegBus_TA_PA",
    0xed851400: "SSX_GpuRegBus_TA_Pervasive2",
    0xed851800: "SSX_GpuRegBus_TA_SonyRegBus",
    0xed858000: "SSX_GpuRegBus_TA_IftuRegBus",
    0xed858400: "SSX_GpuRegBus_TA_VipXbar",
    0xed948000: "SSX_IftuRegBus_IA_GpuRegBus",
    0xed950000: "SSX_IftuRegBus_TA_IFTU0",
    0xed950400: "SSX_IftuRegBus_TA_IFTU1",
    0xed950800: "SSX_IftuRegBus_TA_IFTU2",
    0xed950c00: "SSX_IftuRegBus_TA_DSI0",
    0xed951000: "SSX_IftuRegBus_TA_DSI1",
    0xed958000: "SSX_IftuRegBus_TA_IftuXbar",
    0xee048000: "SSX_CameraSlaveBus_IA_IoSlaveBus0",
    0xee048400: "SSX_CameraSlaveBus_IA_IoSlaveBus1",
    0xee048800: "SSX_CameraSlaveBus_IA_IoSlaveBus2",
    0xee050000: "SSX_CameraSlaveBus_TA_GPIO1",
    0xee058000: "SSX_CameraSlaveBus_TA_CameraRegBus",
    0xee058400: "SSX_CameraSlaveBus_TA_SlcdSlaveBus0",
    0xee058800: "SSX_CameraSlaveBus_TA_UsbSlaveBus",
    0xee058c00: "SSX_CameraSlaveBus_TA_SlcdSlaveBus1",
    0xee059000: "SSX_CameraSlaveBus_TA_CameraMasterBus",
    0xee140000: "SSX_CameraMasterBus_IA_CameraIf0",
    0xee140400: "SSX_CameraMasterBus_IA_CameraIf1",
    0xee148000: "SSX_CameraMasterBus_IA_SlcdMasterBus",
    0xee148400: "SSX_CameraMasterBus_IA_UsbMasterBus",
    0xee148800: "SSX_CameraMasterBus_IA_CameraSlaveBus",
    0xee158000: "SSX_CameraMasterBus_TA_IoMasterBus0",
    0xee158400: "SSX_CameraMasterBus_TA_IoMasterBus1",
    0xee248000: "SSX_UsbSlaveBus_IA_CameraSlaveBus",
    0xee250000: "SSX_UsbSlaveBus_TA_USB0HOST",
    0xee250400: "SSX_UsbSlaveBus_TA_USB1HOST",
    0xee250800: "SSX_UsbSlaveBus_TA_USB2HOST",
    0xee252c00: "SSX_UsbSlaveBus_TA_USB1DEVICE",
    0xee253000: "SSX_UsbSlaveBus_TA_USB2DEVICE",
    0xee253400: "SSX_UsbSlaveBus_TA_USB0DEVICE",
    0xee258000: "SSX_UsbSlaveBus_TA_UsbMasterBus",
    0xee340400: "SSX_UsbMasterBus_IA_USB1OHCI",
    0xee340800: "SSX_UsbMasterBus_IA_USB1EHCI",
    0xee340c00: "SSX_UsbMasterBus_IA_USB2OHCI",
    0xee341000: "SSX_UsbMasterBus_IA_USB2EHCI",
    0xee341400: "SSX_UsbMasterBus_IA_USB0OHCI",
    0xee341800: "SSX_UsbMasterBus_IA_USB0EHCI",
    0xee343400: "SSX_UsbMasterBus_IA_USB1DEVICE",
    0xee343800: "SSX_UsbMasterBus_IA_USB2DEVICE",
    0xee343c00: "SSX_UsbMasterBus_IA_USB0DEVICE",
    0xee348000: "SSX_UsbMasterBus_IA_UsbSlaveBus",
    0xee358000: "SSX_UsbMasterBus_TA_CameraMasterBus",
    0xee448000: "SSX_SlcdSlaveBus_IA_CameraSlaveBus0",
    0xee448400: "SSX_SlcdSlaveBus_IA_CameraSlaveBus1",
    0xee450000: "SSX_SlcdSlaveBus_TA_HSMMC0",
    0xee450400: "SSX_SlcdSlaveBus_TA_SubLCD",
    0xee450800: "SSX_SlcdSlaveBus_TA_SMSHC",
    0xee450c00: "SSX_SlcdSlaveBus_TA_SPI0",
    0xee451000: "SSX_SlcdSlaveBus_TA_SPI1",
    0xee451400: "SSX_SlcdSlaveBus_TA_SPI2",
    0xee458000: "SSX_SlcdSlaveBus_TA_SlcdMasterBus",
    0xee540000: "SSX_SlcdMasterBus_IA_HSMMC0",
    0xee540400: "SSX_SlcdMasterBus_IA_SubLCD",
    0xee540800: "SSX_SlcdMasterBus_IA_SMSHC",
    0xee548000: "SSX_SlcdMasterBus_IA_SlcdSlaveBus",
    0xee558000: "SSX_SlcdMasterBus_TA_CameraMasterBus",
    0xee648000: "SSX_CameraRegBus_IA_CameraSlaveBus",
    0xee650000: "SSX_CameraRegBus_TA_CameraIf0",
    0xee650400: "SSX_CameraRegBus_TA_CameraIf1",
    0xee650800: "SSX_CameraRegBus_TA_CSI0",
    0xee650c00: "SSX_CameraRegBus_TA_CSI1",
}


def _words(data: bytes, offset: int, count: int) -> Optional[tuple[int, ...]]:
    if offset < 0 or offset + count * 4 > len(data):
        return None
    return struct.unpack_from(f"<{count}I", data, offset)


def _ocp(data: bytes, offset: int) -> Optional[dict]:
    head = _words(data, offset, 8)
    if head is None:
        return None
    first, second = head[1:4], head[4:7]
    combined = [a | b for a, b in zip(first, second)]
    count = head[7]
    errors = []
    for index in range(min(count, len(OCP_TARGETS))):
        name, mask = OCP_TARGETS[index]
        word = 0 if index < 15 else 1
        if not combined[word] & mask:
            continue
        # The first error log, unless only the second status saw this target.
        slot = 0 if first[word] & mask else 1
        log = _words(data, offset + 32 + index * 16 + slot * 8, 2)
        if log is None:
            break
        errors.append({"target": name, "log": "first" if slot == 0 else "second", "address": log[0], "attribute": log[1]})
    return {
        "bet0": combined[0], "bet1": combined[1], "bebt": combined[2],
        "first_status": list(first), "second_status": list(second), "target_count": count,
        "target_errors": errors,
        "buses_in_error": [name for name, mask in SYSTEM_BUSES if combined[2] & mask],
    }


def _si(data: bytes, offset: int, size: int) -> Optional[dict]:
    head = _words(data, offset, 2)
    if head is None:
        return None
    buses = []
    at, end = offset + 8, min(len(data), offset + size)
    for _ in range(head[1]):
        if at + 56 > end:
            break
        _, initiators, targets, address = struct.unpack_from("<4I", data, at)
        flags = list(struct.unpack_from("<5Q", data, at + 16))
        at += 56
        agents = []
        for index in range(initiators + targets):
            if at + 32 > end:
                break
            agent_size, agent_address, status, log, error_address = struct.unpack_from("<2I3Q", data, at)
            target = index >= initiators
            # Targets report only the status bits outside 0x0000f000.
            reported = status & 0xFFFF0FFF if target else status
            if reported:
                agents.append({
                    "agent": BUS_PORTS.get(agent_address, f"0x{agent_address:08x}"), "address": agent_address,
                    "role": "target" if target else "initiator", "status": status,
                    "error_log": log, "error_address": error_address,
                })
            if agent_size < 32:
                break
            at += agent_size
        buses.append({"address": address, "flag_status": flags, "agent_errors": agents})
    return {"bus_count": head[1], "buses": buses}


def _registers(data: bytes, offset: int, names: tuple[str, ...]) -> Optional[dict]:
    values = _words(data, offset, len(names))
    return dict(zip(names, values)) if values is not None else None


def decode_bus_error(data: bytes) -> dict:
    head = _words(data, 0, 6)
    if head is None:
        raise ValueError("bus error record header is truncated")
    header_size, size, ocp_size, si_size, grab_size, regbus_size = head
    vip_size = _words(data, 24, 1)[0] if header_size > 27 and len(data) >= 28 else 0
    ocp = header_size
    si = ocp + ocp_size
    grab = si + si_size
    regbus = grab + grab_size
    vip = regbus + regbus_size
    grab_fields = (
        "size", "status", "write_id", "write_address", "write_attribute", "write_info",
        "read_id", "read_address", "read_attribute", "read_info", "secure_status",
        "secure_write_id", "secure_write_address", "secure_write_attribute", "secure_write_info",
        "secure_read_id", "secure_read_address", "secure_read_attribute", "secure_read_info",
        "auxiliary_0", "auxiliary_1",
    )
    regbus_fields = (
        "size", "status", "error_id", "error_address", "error_attribute", "error_info",
        "secure_status", "secure_error_id", "secure_error_address", "secure_error_attribute", "secure_error_info",
    )
    vip_fields = ("size", *(f"{unit}_{word}" for unit in ("bap", "vdpd", "vdpm", "venezia") for word in ("errv", "errc", "erra")))
    return {
        "header_size": header_size, "size": size,
        "block_sizes": {"ocp": ocp_size, "si": si_size, "grab": grab_size, "regbus": regbus_size, "vip": vip_size},
        "complete": len(data) >= size,
        "ocp": _ocp(data, ocp) if ocp_size else None,
        "si": _si(data, si, si_size) if si_size else None,
        "grab": _registers(data, grab, grab_fields) if grab_size else None,
        "regbus": _registers(data, regbus, regbus_fields) if regbus_size else None,
        "vip": _registers(data, vip, vip_fields) if header_size > 27 and vip_size else None,
    }
