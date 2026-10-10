# Copyright (c) 2026 devnoname120
# SPDX-License-Identifier: MIT

from __future__ import annotations

from pathlib import Path
from typing import Union

from .core import CoreDump, ParseError
from .kerndump import KernelDump, looks_like_kernel_dump


def read_dump(path: Union[Path, str], *, strict: bool = False) -> Union[CoreDump, KernelDump]:
    """Read an ELF core or a development-kit kernel dump."""
    path = Path(path)
    try:
        with path.open("rb") as stream:
            prefix = stream.read(0x34)
    except OSError as exc:
        raise ParseError(f"cannot read {path}: {exc}") from exc
    if prefix.startswith((b"\x7fELF", b"\x1f\x8b", b"\0\0FACECS")):
        return CoreDump.read(path, strict=strict)
    if looks_like_kernel_dump(prefix) or path.suffix.lower() == ".psp2kerndmp":
        return KernelDump.read(path, strict=strict)
    return CoreDump.read(path, strict=strict)
