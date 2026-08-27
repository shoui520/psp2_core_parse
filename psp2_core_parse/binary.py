from __future__ import annotations

import struct
from typing import Iterable, Optional


class BoundsError(ValueError):
    pass


def align(value: int, alignment: int = 4) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError("alignment must be a positive power of two")
    return (value + alignment - 1) & ~(alignment - 1)


def require(data: bytes, offset: int, size: int, what: str = "field") -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise BoundsError(
            f"{what} at 0x{offset:x}+0x{size:x} exceeds 0x{len(data):x}-byte record"
        )


def u8(data: bytes, offset: int) -> int:
    require(data, offset, 1, "u8")
    return data[offset]


def u16(data: bytes, offset: int) -> int:
    require(data, offset, 2, "u16")
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    require(data, offset, 4, "u32")
    return struct.unpack_from("<I", data, offset)[0]


def s32(data: bytes, offset: int) -> int:
    require(data, offset, 4, "s32")
    return struct.unpack_from("<i", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    require(data, offset, 8, "u64")
    return struct.unpack_from("<Q", data, offset)[0]


def maybe_u32(data: bytes, offset: int) -> Optional[int]:
    return u32(data, offset) if 0 <= offset <= len(data) - 4 else None


def c_string(data: bytes, offset: int = 0, size: Optional[int] = None) -> str:
    if offset < 0 or offset > len(data):
        raise BoundsError(f"string offset 0x{offset:x} exceeds record")
    end = len(data) if size is None else min(len(data), offset + size)
    raw = data[offset:end].split(b"\0", 1)[0]
    return raw.decode("utf-8", errors="replace")


def words(data: bytes, offset: int = 0, size: Optional[int] = None) -> tuple[int, ...]:
    if offset < 0 or offset > len(data):
        raise BoundsError(f"word offset 0x{offset:x} exceeds record")
    end = len(data) if size is None else min(len(data), offset + size)
    end -= (end - offset) % 4
    if end == offset:
        return ()
    return struct.unpack_from(f"<{(end - offset) // 4}I", data, offset)


def ranges_merge(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if end <= start:
            continue
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(result[-1][1], end))
        else:
            result.append((start, end))
    return result
