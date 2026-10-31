# Copyright (c) 2026 psp2_core_parse contributors
# SPDX-License-Identifier: MIT

"""Standalone SceCoredump CAF files: crash_report.caf and screenshot containers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from .core import ParseError, ParseIssue
from .spsp2dmp import (
    HEADER, MAGIC, decode_crash_report, decode_screenshot, is_gzip, looks_like_crash_report, open_caf,
)


def caf_kind(prefix: bytes) -> Optional[str]:
    """Classify a CAF by its header; None means a coredump container (.spsp2dmp).

    The producer writes header flag 0 only for screenshot containers, and a
    single-section container with flag 1 only for crash_report.caf.
    """
    if len(prefix) < HEADER.size or not prefix.startswith(MAGIC):
        return None
    type_flag, count = HEADER.unpack_from(prefix)[2:4]
    if type_flag == 0:
        return "screenshot"
    if type_flag == 1 and count == 1:
        return "crash-report"
    return None


@dataclass
class CafFile:
    path: Path
    kind: str
    raw_file_size: int
    raw_file_sha256: str
    container: dict
    issues: list[ParseIssue] = field(default_factory=list)
    sections: list[Optional[bytes]] = field(default_factory=list, repr=False)
    crash_report: Optional[dict] = None
    screenshot: Optional[dict] = None
    pixels: list[bytes] = field(default_factory=list, repr=False)

    @classmethod
    def read(cls, path: Union[Path, str], *, strict: bool = False) -> "CafFile":
        path = Path(path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ParseError(f"cannot read {path}: {exc}") from exc
        kind = caf_kind(raw)
        if kind is None:
            raise ParseError(f"{path} is not a crash report or screenshot CAF")
        issues: list[ParseIssue] = []
        probe = is_gzip if kind == "screenshot" else looks_like_crash_report
        container, sections = open_caf(raw, issues, probe=probe)
        result = cls(
            path, kind, len(raw), hashlib.sha256(raw).hexdigest(), container, issues, sections,
        )
        if kind == "screenshot":
            result.screenshot, result.pixels = decode_screenshot(container, sections)
        else:
            if container["decryption_error"]:
                raise ParseError(container["decryption_error"])
            if sections[0] is not None:
                result.crash_report = decode_crash_report(sections[0])
        if strict:
            failures = [issue for issue in issues if issue.severity == "error"]
            if failures:
                raise ParseError("; ".join(issue.message for issue in failures))
        return result

    @property
    def complete(self) -> bool:
        return all(section["available_size"] == section["size"] for section in self.container["sections"])

    def summary(self) -> dict:
        return {
            "format": "caf",
            "kind": self.kind,
            "path": str(self.path),
            "raw_file_size": self.raw_file_size,
            "raw_file_sha256": self.raw_file_sha256,
            "complete": self.complete,
            "container": self.container,
            "crash_report": self.crash_report,
            "screenshot": self.screenshot,
            "issues": [issue.summary() for issue in self.issues],
        }
