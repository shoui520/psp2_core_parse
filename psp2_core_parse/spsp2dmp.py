# Copyright (c) 2026 devnoname120
# SPDX-License-Identifier: MIT

"""Encrypted Vita system dump support, adapted from Princess-of-Sleeping.

Reference: https://github.com/Princess-of-Sleeping/spsp2dmp-parser
Copyright (c) 2022 Princess-of-Sleeping. MIT license; see LICENSE.
"""

from __future__ import annotations

import struct

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


def decrypt_kernel_info(description: bytes) -> bytes:
    """Return a standalone decrypted ELF without modifying the captured note."""
    image = description
    if image[4:8] == b"\x7fELF":
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
    if header_size < 52 or ph_offset < header_size or ph_size < 32 or table_end > len(image):
        raise ParseError("KERNEL_INFO ELF program-header table is invalid or truncated")

    headers = []
    for index in range(ph_count):
        values = struct.unpack_from("<8I", image, ph_offset + index * ph_size)
        segment_type, offset, _, _, size, _, _, _ = values
        if not size:
            continue
        if offset + size > len(image):
            raise ParseError(f"KERNEL_INFO segment {index} is truncated or out of bounds")
        if offset < header_size or (offset < table_end and offset + size > ph_offset):
            raise ParseError(f"KERNEL_INFO segment {index} overlaps an ELF header")
        if segment_type != 4 and size % 16:
            raise ParseError(f"KERNEL_INFO segment {index} is not AES-block aligned")
        headers.append((segment_type, offset, size))
    previous_end = 0
    for _, offset, size in sorted(headers, key=lambda item: item[1]):
        if offset < previous_end:
            raise ParseError("KERNEL_INFO segments overlap")
        previous_end = offset + size

    key_headers = [header for header in headers if header[0] == 4]
    if len(key_headers) != 1 or key_headers[0][2] < 0x64:
        raise ParseError("KERNEL_INFO requires exactly one PT_NOTE with a complete wrapped key at +0x44")
    key_offset = key_headers[0][1] + 0x44
    key = _decrypt_cbc(image[key_offset : key_offset + 0x20], KERNEL_KEK, KERNEL_KEY_IV)
    result = bytearray(image)
    for segment_type, offset, size in headers:
        if segment_type != 4:
            result[offset : offset + size] = _decrypt_cbc(image[offset : offset + size], key, KERNEL_DATA_IV)
    return bytes(result)
