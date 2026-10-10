# Copyright (c) 2026 devnoname120
# SPDX-License-Identifier: MIT

"""Encrypted Vita system dump support, adapted from Princess-of-Sleeping.

Reference: https://github.com/Princess-of-Sleeping/spsp2dmp-parser
Copyright (c) 2022 Princess-of-Sleeping. MIT license; see LICENSE.
"""

from __future__ import annotations

import struct
import warnings
from typing import Optional

from .core import ParseError, ParseIssue


MAGIC = b"\0\0FACECS"
HEADER = struct.Struct("<8s5Q")
SECTION = struct.Struct("<5Q16sQ")
# The reference selects AES-128, despite storing a 32-byte outer key array.
CONTAINER_KEY = bytes.fromhex("c815c36ff2f89564a2f7ae13cb6d47ac")
KERNEL_KEK = bytes.fromhex("845c655b503b54717add4999436b5b5b")
KERNEL_KEY_IV = bytes.fromhex("08090a0c0c0d0e0f0001020304050607")
KERNEL_DATA_IV = bytes.fromhex("0be6477340c4460fdbb9c02db13ce964")


def _decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise ParseError(
            "encrypted dumps require cryptography; install with "
            "python -m pip install 'psp2-core-parse[crypto]' "
            "(or python -m pip install '.[crypto]' from the checkout)"
        ) from exc
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    # Container lengths, not PKCS#7 padding, delimit these encrypted records.
    return decryptor.update(data) + decryptor.finalize()


def decrypt_container(raw: bytes, issues: list[ParseIssue]) -> tuple[bytes, dict]:
    if len(raw) < HEADER.size:
        raise ParseError("SPSP2DMP header is truncated")
    magic, version, hmac_key_id, count, header_size, total_size = HEADER.unpack_from(raw)
    if magic != MAGIC:
        raise ParseError("invalid SPSP2DMP header magic")
    if version != 2:
        raise ParseError(f"unsupported SPSP2DMP version {version}; expected version 2")
    if not count:
        raise ParseError("SPSP2DMP header declares no sections")
    minimum_header_size = HEADER.size + count * (SECTION.size + 0x30) + 0x20
    if header_size < minimum_header_size:
        raise ParseError("SPSP2DMP header is too small for its section and hash tables")
    if header_size > len(raw):
        raise ParseError("SPSP2DMP header is truncated")

    sections = []
    ids = set()
    core_section = None
    for index in range(count):
        metadata_offset = HEADER.size + index * SECTION.size
        section_id, start, length, section_hmac, key_id, iv, _ = SECTION.unpack_from(raw, metadata_offset)
        if section_id in ids:
            raise ParseError(f"duplicate SPSP2DMP section ID {section_id}")
        ids.add(section_id)
        if start < header_size:
            raise ParseError(f"SPSP2DMP section {section_id} overlaps the header")
        encrypted_size = (length + 15) // 16 * 16
        if start + encrypted_size > header_size + total_size:
            raise ParseError(f"SPSP2DMP section {section_id} exceeds the declared total section size")
        available = min(length, max(0, len(raw) - start))
        available_encrypted = min(encrypted_size, max(0, len(raw) - start))
        section = {
            "id": section_id,
            "file_offset": start,
            "size": length,
            "available_size": available,
            "encrypted_size": encrypted_size,
            "available_encrypted_size": available_encrypted,
            "encryption_key_id": key_id,
            "hmac_key_id": section_hmac,
        }
        sections.append(section)
        if available_encrypted < encrypted_size:
            issues.append(ParseIssue(
                "error", "spsp2dmp-truncated-section",
                f"SPSP2DMP section {section_id} is truncated: "
                f"0x{available_encrypted:x} of 0x{encrypted_size:x} encrypted bytes available",
                start + available_encrypted,
            ))
        if section_id == 0:
            core_section = (section, iv)

    previous_end = header_size
    for section in sorted(sections, key=lambda item: item["file_offset"]):
        if section["file_offset"] < previous_end:
            raise ParseError("SPSP2DMP sections overlap")
        previous_end = section["file_offset"] + section["encrypted_size"]
    if core_section is None:
        raise ParseError("SPSP2DMP coredump section 0 is missing")
    section, iv = core_section
    if section["encryption_key_id"] != 2:
        raise ParseError(f"unsupported SPSP2DMP encryption key ID {section['encryption_key_id']}")
    captured_size = section["available_encrypted_size"] // 16 * 16
    if not captured_size:
        raise ParseError("SPSP2DMP coredump section 0 has no complete AES block")
    start = section["file_offset"]
    payload = _decrypt_cbc(raw[start : start + captured_size], CONTAINER_KEY, iv)
    payload = payload[:section["size"]]
    if not payload.startswith(b"\x1f\x8b"):
        raise ParseError("decrypted SPSP2DMP coredump section 0 does not begin with gzip data")

    expected_end = header_size + total_size
    if len(raw) < expected_end and all(
        item["encrypted_size"] == item["available_encrypted_size"] for item in sections
    ):
        issues.append(ParseIssue(
            "error", "spsp2dmp-truncated-container",
            "SPSP2DMP file is truncated before its declared end", len(raw),
        ))
    elif len(raw) > expected_end:
        issues.append(ParseIssue(
            "warning", "spsp2dmp-trailing-data",
            f"SPSP2DMP is followed by 0x{len(raw) - expected_end:x} bytes", expected_end,
        ))
    issues.append(ParseIssue(
        "warning", "spsp2dmp-hmac-unverified",
        "SPSP2DMP HMACs are not verified; successful decryption does not authenticate the dump",
    ))
    return payload, {
        "format": "spsp2dmp",
        "version": version,
        "cipher": "AES-128-CBC",
        "header_size": header_size,
        "hmac_key_id": hmac_key_id,
        "hmac_verified": False,
        "section_count": count,
        "sections": sections,
    }


def decrypt_kernel_info(
    description: bytes, *, strict: bool = False, issues: Optional[list[ParseIssue]] = None,
) -> bytes:
    """Return a decrypted ELF prefix; retain missing ranges in its original headers."""
    def damaged(code: str, message: str, offset: Optional[int] = None) -> None:
        if strict:
            raise ParseError(message)
        issue = ParseIssue("error", code, message, offset)
        if issues is None:
            warnings.warn(message, RuntimeWarning, stacklevel=2)
        else:
            issues.append(issue)

    image = description
    if image[12:16] == b"\x7fELF" or image[:8] == struct.pack("<Q", 8):
        if len(image) < 12:
            raise ParseError("KERNEL_INFO version-8 wrapper is truncated")
        version, size = struct.unpack_from("<QI", image)
        if version != 8:
            raise ParseError(f"unsupported KERNEL_INFO note version {version}")
        if size != len(image) - 12:
            damaged(
                "kernel-info-wrapper-size",
                f"KERNEL_INFO wrapper declares 0x{size:x} ELF bytes but 0x{len(image) - 12:x} "
                "are captured; using the available note bytes",
            )
        image = image[12:]
    elif image[4:8] == b"\x7fELF":
        version = struct.unpack_from("<I", image)[0]
        if version != 1:
            raise ParseError(f"unsupported KERNEL_INFO note version {version}")
        image = image[4:]
    if len(image) < 52 or image[:4] != b"\x7fELF":
        raise ParseError("KERNEL_INFO ELF header is missing or truncated")
    if image[4:7] != b"\x01\x01\x01" or struct.unpack_from("<H", image, 18)[0] != 40:
        raise ParseError("KERNEL_INFO must contain a little-endian ELF32 ARM image")
    header_size, ph_size, ph_count = struct.unpack_from("<3H", image, 40)
    ph_offset = struct.unpack_from("<I", image, 28)[0]
    table_end = ph_offset + ph_count * ph_size
    if header_size < 52 or ph_offset < header_size or ph_size < 32:
        raise ParseError("KERNEL_INFO ELF program-header table is invalid")
    available_count = min(ph_count, max(0, (len(image) - ph_offset) // ph_size))
    if table_end > len(image):
        damaged(
            "kernel-info-truncated-program-headers",
            f"KERNEL_INFO program-header table is truncated: {available_count}/{ph_count} entries available",
            len(image),
        )

    headers = []
    limit = len(image)

    def overlaps_headers(offset: int, size: int) -> bool:
        return offset < header_size or (offset < table_end and offset + size > ph_offset)

    for index in range(available_count):
        values = struct.unpack_from("<8I", image, ph_offset + index * ph_size)
        segment_type, offset, _, _, size, _, _, _ = values
        if not size:
            continue
        if offset + size > len(image):
            damaged(
                "kernel-info-truncated-segment",
                f"KERNEL_INFO segment {index} is truncated or out of bounds: "
                f"0x{min(size, max(0, len(image) - offset)):x}/0x{size:x} bytes captured",
                min(len(image), offset),
            )
        if overlaps_headers(offset, size):
            damaged("kernel-info-header-overlap", f"KERNEL_INFO segment {index} overlaps an ELF header", offset)
            limit = min(limit, max(header_size, offset))
        if segment_type != 4 and size % 16:
            damaged("kernel-info-block-alignment", f"KERNEL_INFO segment {index} is not AES-block aligned", offset)
            limit = min(limit, max(header_size, offset + size // 16 * 16))
        headers.append((segment_type, offset, size))
    previous_end = 0
    for _, offset, size in sorted(headers, key=lambda item: item[1]):
        if offset < previous_end:
            damaged("kernel-info-overlapping-segments", "KERNEL_INFO segments overlap; recovering only the unambiguous prefix", offset)
            limit = min(limit, max(header_size, offset))
        previous_end = max(previous_end, offset + size)

    for segment_type, offset, size in sorted(headers, key=lambda item: item[1]):
        if segment_type != 4 and offset < limit and not overlaps_headers(offset, size):
            available = min(size, limit - offset)
            if available % 16:
                limit = offset + available // 16 * 16

    key_headers = [header for header in headers if header[0] == 4]
    key_available = len(key_headers) == 1 and key_headers[0][2] >= 0x64
    if key_available:
        key_start, key_end = key_headers[0][1] + 0x44, key_headers[0][1] + 0x64
        key_available = not overlaps_headers(key_headers[0][1], key_headers[0][2]) and key_end <= len(image) and not any(
            segment_type != 4 and offset < key_end and offset + size > key_start
            for segment_type, offset, size in headers
        )
    if not key_available:
        damaged(
            "kernel-info-missing-key",
            "KERNEL_INFO requires exactly one PT_NOTE with a complete, unambiguous wrapped key at +0x44; "
            "preserving metadata without exposing encrypted segments as plaintext",
        )
        data_offsets = [offset for segment_type, offset, _ in headers if segment_type != 4]
        if data_offsets:
            limit = min(limit, max(header_size, min(data_offsets)))
        elif ph_offset > len(image):
            limit = min(header_size, len(image))
        return bytes(image[:limit])

    key_offset = key_headers[0][1] + 0x44
    key = _decrypt_cbc(image[key_offset : key_offset + 0x20], KERNEL_KEK, KERNEL_KEY_IV)
    result = bytearray(image[:limit])
    for segment_type, offset, size in headers:
        if segment_type != 4 and offset < limit and not overlaps_headers(offset, size):
            captured_size = min(size, limit - offset) // 16 * 16
            result[offset : offset + captured_size] = _decrypt_cbc(
                image[offset : offset + captured_size], key, KERNEL_DATA_IV,
            )
    return bytes(result)
