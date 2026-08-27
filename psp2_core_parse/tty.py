from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Optional

from .core import ParseError


ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TIMESTAMP = re.compile(r"^\[\s*(\d+(?:\.\d+)?)\]\s?(.*)$")


@dataclass(frozen=True)
class TtyLine:
    index: int
    text: str
    timestamp: Optional[float]
    message: str

    def summary(self) -> dict:
        return {
            "index": self.index,
            "text": self.text,
            "timestamp": self.timestamp,
            "message": self.message,
        }


@dataclass(frozen=True)
class TtyInfo:
    header_words: tuple[int, int, int]
    payload: bytes
    trailing: bytes
    declared_payload_size: int
    complete: bool

    @classmethod
    def parse(cls, data: bytes, *, salvage: bool = True) -> "TtyInfo":
        if len(data) < 12:
            raise ParseError("TTY note is shorter than its three-word header")
        header = struct.unpack_from("<3I", data)
        size = header[2]
        available = min(size, len(data) - 12)
        if not salvage and available != size:
            raise ParseError(f"TTY note declares 0x{size:x} bytes but only 0x{available:x} remain")
        end = 12 + available
        return cls(header, data[12:end], data[end:], size, available == size)

    def text(self, *, preserve_ansi: bool = False) -> str:
        value = self.payload.replace(b"\0", b"").decode("utf-8", errors="replace")
        return value if preserve_ansi else ANSI_CSI.sub("", value)

    def lines(self, *, preserve_ansi: bool = False) -> tuple[TtyLine, ...]:
        result: list[TtyLine] = []
        for index, text in enumerate(self.text(preserve_ansi=preserve_ansi).splitlines()):
            if not text.strip():
                continue
            match = TIMESTAMP.match(text)
            result.append(
                TtyLine(
                    index,
                    text,
                    float(match.group(1)) if match else None,
                    match.group(2) if match else text,
                )
            )
        return tuple(result)

    def summary(self, *, preserve_ansi: bool = False) -> dict:
        lines = self.lines(preserve_ansi=preserve_ansi)
        stamped = [line for line in lines if line.timestamp is not None]
        gaps = []
        regressions = []
        for before, after in zip(stamped, stamped[1:]):
            delta = after.timestamp - before.timestamp
            record = {
                "from_line": before.index,
                "to_line": after.index,
                "delta": delta,
            }
            (regressions if delta < 0 else gaps).append(record)
        first = stamped[0] if stamped else None
        last = stamped[-1] if stamped else None
        return {
            "header_words": list(self.header_words),
            "declared_payload_size": self.declared_payload_size,
            "payload_size": len(self.payload),
            "complete": self.complete,
            "trailing_size": len(self.trailing),
            "trailing_nonzero_bytes": sum(value != 0 for value in self.trailing),
            "trailing_sha256": hashlib.sha256(self.trailing).hexdigest(),
            "payload_sha256": hashlib.sha256(self.payload).hexdigest(),
            "text": self.text(preserve_ansi=preserve_ansi),
            "timeline": {
                "line_count": len(lines),
                "timestamped_line_count": len(stamped),
                "untimestamped_line_count": len(lines) - len(stamped),
                "first_timestamp": first.timestamp if first else None,
                "last_timestamp": last.timestamp if last else None,
                "captured_span": last.timestamp - first.timestamp if first and last else None,
                "timestamp_regressions": regressions,
                "largest_gap": max(gaps, key=lambda item: item["delta"]) if gaps else None,
                "lines": [line.summary() for line in lines],
            },
        }
