# Copyright (c) 2026 devnoname120
# SPDX-License-Identifier: MIT

"""Encrypted Vita system dump support, adapted from Princess-of-Sleeping.

Reference: https://github.com/Princess-of-Sleeping/spsp2dmp-parser
Copyright (c) 2022 Princess-of-Sleeping. MIT license; see LICENSE.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import warnings
from typing import Optional

from .core import ParseError, ParseIssue, _decompress_gzip


MAGIC = b"\0\0FACECS"
HEADER = struct.Struct("<8s5Q")
SECTION = struct.Struct("<5Q16sQ")
SECTION_HASH = struct.Struct("<8x32s8x")
DIGEST_SIZE = 0x20
# SceCoredump requests HMAC-SHA256 keys by hash key ID and AES-128 keys by
# encryption key ID from SceSblPostSsMgr. Its two CFK1 key tables decrypt with
# EncDec key 02: the External key on retail units, the Internal key otherwise.
KEY_SETS = {
    "retail": {
        "hmac": {
            1: bytes.fromhex("e2a128f52636f29058871f64ad6d99deb35eb7ca6aa660780ac798b111ba7adf"),
            2: bytes.fromhex("96bb82cdc0a1417761138f549c5d2dc3c228a0a1a17f765b08366056e6ae6e00"),
            3: bytes.fromhex("41ca34324c4c2a80e41630db4ce50c2c680bd9903e255161571ba9a5b090e9d4"),
        },
        "cipher": {
            1: bytes.fromhex("53c25972bb6037d92ddd006f212e0add"),
            2: bytes.fromhex("c815c36ff2f89564a2f7ae13cb6d47ac"),
            3: bytes.fromhex("57e740070a2e0f357a21240bf464251d"),
            4: bytes.fromhex("4e953b94fdc1c06bc277b160d7567004"),
            0x10000001: bytes.fromhex("eb24a48394b75420e23ad974e9040923"),
            0x10000002: bytes.fromhex("5b1aa11e9e2db86040986fb424385f3b"),
        },
    },
    "internal": {
        "hmac": {
            1: bytes.fromhex("262e6b31f99382086940b8e8bccd9f9d1c3ceb334224dc8e36f91121b8aae10c"),
            2: bytes.fromhex("a23988a53063a1caf70fc48b5053619d272b39c7595e58fcb960d8a429cfa2e7"),
            3: bytes.fromhex("9a4a3defd7fb4a520be62d06b2315bec458ff543df658c718f222f34b07aba4e"),
        },
        "cipher": {
            1: bytes.fromhex("47190545c1323a598d149af2bd0ef32c"),
            2: bytes.fromhex("3f849e43640c31fb9c29e926311781b7"),
            3: bytes.fromhex("ae2130b1cfed811a830c6772cd219969"),
            4: bytes.fromhex("02fc3aba46a263972f96586c986e8e31"),
            0x10000001: bytes.fromhex("d05fb9c22ff6b9e2623c7cade2f27e28"),
            0x10000002: bytes.fromhex("7c0410f15744757bda45e4bdb55280c7"),
        },
    },
}
# The producer authenticates every container header with hash key ID 1.
HEADER_HMAC_KEY_ID = 1
# SYSTEM_INFO keeps a copy of the OpenPSID encrypted with this key and IV.
OPEN_PSID_KEY_ID = 2
OPEN_PSID_IV = struct.pack("<4I", 0xBF0B9E95, 0xC651A66B, 0x49E8533B, 0xA7056463)
# "CDAP" record in the coredump container's second section.
ACCESS_PARAMETERS = struct.Struct("<4s9I16xI36x")
# SYSTEM_INFO2 frame header: reserved, vblank count, width, height, pixel format.
SCREENSHOT_FRAME = struct.Struct("<5I")
SCREENSHOT_SOURCES = ("process", "shell")
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


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _parse_caf(raw: bytes, label: str) -> dict:
    if len(raw) < HEADER.size:
        raise ParseError(f"{label} header is truncated")
    magic, version, type_flag, count, header_size, total_size = HEADER.unpack_from(raw)
    if magic != MAGIC:
        raise ParseError(f"invalid {label} header magic")
    if version != 2:
        raise ParseError(f"unsupported {label} version {version}; expected version 2")
    if not count:
        raise ParseError(f"{label} header declares no sections")
    hashes_offset = HEADER.size + count * SECTION.size
    digest_offset = hashes_offset + count * SECTION_HASH.size
    if header_size < digest_offset + DIGEST_SIZE:
        raise ParseError(f"{label} header is too small for its section and hash tables")
    if header_size > len(raw):
        raise ParseError(f"{label} header is truncated")

    sections = []
    ids = set()
    for index in range(count):
        metadata_offset = HEADER.size + index * SECTION.size
        section_id, start, length, section_hmac, key_id, iv, _ = SECTION.unpack_from(raw, metadata_offset)
        if section_id in ids:
            raise ParseError(f"duplicate {label} section ID {section_id}")
        ids.add(section_id)
        if start < header_size:
            raise ParseError(f"{label} section {section_id} overlaps the header")
        encrypted_size = (length + 15) // 16 * 16
        if start + encrypted_size > header_size + total_size:
            raise ParseError(f"{label} section {section_id} exceeds the declared total section size")
        sections.append({
            "id": section_id,
            "file_offset": start,
            "size": length,
            "available_size": min(length, max(0, len(raw) - start)),
            "encrypted_size": encrypted_size,
            "available_encrypted_size": min(encrypted_size, max(0, len(raw) - start)),
            "encryption_key_id": key_id,
            "hmac_key_id": section_hmac,
            "iv": iv,
            "digest": SECTION_HASH.unpack_from(raw, hashes_offset + index * SECTION_HASH.size)[0],
        })

    previous_end = header_size
    for section in sorted(sections, key=lambda item: item["file_offset"]):
        if section["file_offset"] < previous_end:
            raise ParseError(f"{label} sections overlap")
        previous_end = section["file_offset"] + section["encrypted_size"]
    return {
        "version": version,
        "type_flag": type_flag,
        "header_size": header_size,
        "total_size": total_size,
        "digest_offset": digest_offset,
        "sections": sections,
    }


def _header_key_set(raw: bytes, caf: dict) -> Optional[str]:
    """Return the key set whose HMAC authenticates the container header."""
    offset = caf["digest_offset"]
    digest = raw[offset : offset + DIGEST_SIZE]
    for name, keys in KEY_SETS.items():
        if hmac.compare_digest(_hmac(keys["hmac"][HEADER_HMAC_KEY_ID], raw[:offset]), digest):
            return name
    return None


def _section_hmac(raw: bytes, section: dict, key_set: str) -> str:
    if section["available_size"] < section["size"]:
        return "truncated"
    key = KEY_SETS[key_set]["hmac"].get(section["hmac_key_id"])
    if key is None:
        return "unknown-key"
    start = section["file_offset"]
    # The producer authenticates the ciphertext.
    digest = _hmac(key, raw[start : start + section["size"]])
    return "verified" if hmac.compare_digest(digest, section["digest"]) else "mismatch"


def _decrypt_section(raw: bytes, section: dict, key_set: str) -> bytes:
    captured_size = section["available_encrypted_size"] // 16 * 16
    start = section["file_offset"]
    key = KEY_SETS[key_set]["cipher"][section["encryption_key_id"]]
    return _decrypt_cbc(raw[start : start + captured_size], key, section["iv"])[:section["size"]]


def _public(section: dict) -> dict:
    return {key: value for key, value in section.items() if key not in ("iv", "digest")}


def _decode_access_parameters(data: bytes) -> dict:
    (_, version, system_version, app_version, stop_reason, pc, _, lr, _,
     pc_fingerprint, lr_fingerprint) = ACCESS_PARAMETERS.unpack_from(data)
    return {
        "format_version": version,
        "system_version": system_version,
        "application_version": app_version,
        "stop_reason": stop_reason,
        "pc": pc,
        "lr": lr,
        "pc_module_fingerprint": pc_fingerprint,
        "lr_module_fingerprint": lr_fingerprint,
    }


def decrypt_container(raw: bytes, issues: list[ParseIssue]) -> tuple[bytes, dict]:
    caf = _parse_caf(raw, "SPSP2DMP")
    sections = caf["sections"]
    for section in sections:
        if section["available_encrypted_size"] < section["encrypted_size"]:
            issues.append(ParseIssue(
                "error", "spsp2dmp-truncated-section",
                f"SPSP2DMP section {section['id']} is truncated: "
                f"0x{section['available_encrypted_size']:x} of 0x{section['encrypted_size']:x} "
                "encrypted bytes available",
                section["file_offset"] + section["available_encrypted_size"],
            ))
    section = next((item for item in sections if item["id"] == 0), None)
    if section is None:
        raise ParseError("SPSP2DMP coredump section 0 is missing")
    if section["encryption_key_id"] not in KEY_SETS["retail"]["cipher"]:
        raise ParseError(f"unsupported SPSP2DMP encryption key ID {section['encryption_key_id']}")
    if section["available_encrypted_size"] < 16:
        raise ParseError("SPSP2DMP coredump section 0 has no complete AES block")

    header_key_set = _header_key_set(raw, caf)
    if header_key_set is None:
        issues.append(ParseIssue(
            "error", "spsp2dmp-hmac-mismatch",
            "SPSP2DMP header HMAC matches neither the retail nor the internal key set; "
            "the header is corrupt or was modified",
            caf["digest_offset"],
        ))
    payload = key_set = None
    for name in [header_key_set] if header_key_set else KEY_SETS:
        candidate = _decrypt_section(raw, section, name)
        if candidate.startswith(b"\x1f\x8b"):
            payload, key_set = candidate, name
            break
    if payload is None:
        raise ParseError("decrypted SPSP2DMP coredump section 0 does not begin with gzip data")

    access_parameters = None
    for item in sections:
        item["hmac"] = _section_hmac(raw, item, key_set)
        if item["hmac"] == "mismatch":
            issues.append(ParseIssue(
                "error", "spsp2dmp-hmac-mismatch",
                f"SPSP2DMP section {item['id']} HMAC does not match its ciphertext; "
                "the section is corrupt or was modified",
                item["file_offset"],
            ))
        elif item["hmac"] == "unknown-key":
            issues.append(ParseIssue(
                "warning", "spsp2dmp-hmac-unverified",
                f"SPSP2DMP section {item['id']} uses unknown hash key ID {item['hmac_key_id']}; "
                "its HMAC is not verified",
                item["file_offset"],
            ))
        if (item["id"] != 0 and item["size"] >= ACCESS_PARAMETERS.size
                and item["available_size"] == item["size"]
                and item["encryption_key_id"] in KEY_SETS[key_set]["cipher"]):
            plaintext = _decrypt_section(raw, item, key_set)
            if plaintext.startswith(b"CDAP"):
                access_parameters = {"section_id": item["id"], **_decode_access_parameters(plaintext)}

    expected_end = caf["header_size"] + caf["total_size"]
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
    return payload, {
        "format": "spsp2dmp",
        "version": caf["version"],
        "cipher": "AES-128-CBC",
        "header_size": caf["header_size"],
        "primary_type_flag": caf["type_flag"],
        "key_set": key_set,
        "header_hmac": "verified" if header_key_set else "mismatch",
        "hmac_verified": header_key_set is not None and all(item["hmac"] == "verified" for item in sections),
        "section_count": len(sections),
        "sections": [_public(item) for item in sections],
        "access_parameters": access_parameters,
    }


def screenshot_frames(data: bytes) -> tuple[dict, list[bytes]]:
    """Decode the SYSTEM_INFO2 screenshot container and return its recovered frame pixels."""
    if len(data) < 4 + HEADER.size:
        raise ParseError("SYSTEM_INFO2 is truncated")
    raw = data[4:]
    header_size, total_size = HEADER.unpack_from(raw)[4:]
    result = {"format_version": struct.unpack_from("<I", data)[0], "raw_size": len(data)}
    if header_size > len(raw):
        return {
            **result, "complete": False, "header_complete": False, "key_set": None,
            "header_hmac": "truncated", "hmac_verified": False, "decrypted": False,
            "decryption_error": None, "frames": [], "container_end": len(data),
        }, []
    caf = _parse_caf(raw, "SYSTEM_INFO2")
    header_key_set = _header_key_set(raw, caf)
    key_set = header_key_set or "retail"
    frames = []
    pixels = []
    decryption_error = None
    for index, section in enumerate(caf["sections"]):
        hmac_status = _section_hmac(raw, section, key_set)
        frame = {
            "index": index,
            "source": SCREENSHOT_SOURCES[index] if index < len(SCREENSHOT_SOURCES) else None,
            "section_id": section["id"],
            "encryption_key_id": section["encryption_key_id"],
            "hmac": hmac_status,
            "section_size": section["size"],
            "available_section_size": section["available_size"],
            "vblank_count": None,
            "width": None,
            "height": None,
            "pixel_format": None,
            "pixel_bytes": 0,
            "expected_pixel_bytes": None,
            "complete": False,
            "pixel_sha256": None,
        }
        frame_pixels = b""
        if (decryption_error is None and section["available_encrypted_size"] >= 16
                and section["encryption_key_id"] in KEY_SETS[key_set]["cipher"]):
            try:
                plaintext = _decrypt_section(raw, section, key_set)
            except ParseError as exc:
                decryption_error = str(exc)
            else:
                body, body_complete = _decompress_gzip(plaintext, [])
                if len(body) >= SCREENSHOT_FRAME.size:
                    _, vblank_count, width, height, pixel_format = SCREENSHOT_FRAME.unpack_from(body)
                    expected = width * height * 4
                    frame_pixels = body[SCREENSHOT_FRAME.size : SCREENSHOT_FRAME.size + expected]
                    frame.update({
                        "vblank_count": vblank_count,
                        "width": width,
                        "height": height,
                        "pixel_format": pixel_format,
                        "pixel_bytes": len(frame_pixels),
                        "expected_pixel_bytes": expected,
                        "complete": body_complete and len(body) == SCREENSHOT_FRAME.size + expected,
                        "pixel_sha256": hashlib.sha256(frame_pixels).hexdigest(),
                    })
        frames.append(frame)
        pixels.append(frame_pixels)
    return {
        **result,
        "complete": all(section["available_size"] == section["size"] for section in caf["sections"]),
        "header_complete": True,
        "container_version": caf["version"],
        "primary_type_flag": caf["type_flag"],
        "header_size": header_size,
        "total_size": total_size,
        "key_set": header_key_set,
        "header_hmac": "verified" if header_key_set else "mismatch",
        "hmac_verified": header_key_set is not None and all(frame["hmac"] == "verified" for frame in frames),
        "decrypted": decryption_error is None and any(frame["width"] is not None for frame in frames),
        "decryption_error": decryption_error,
        "frames": frames,
        "container_end": min(len(data), 4 + header_size + total_size),
    }, pixels


def describe_hmac(info: dict) -> str:
    """Summarize the HMAC verification of a decoded container for reports."""
    if info.get("header_hmac") == "truncated":
        return "unavailable (header truncated)"
    problems = [] if info.get("header_hmac") == "verified" else ["header mismatch"]
    for item in info.get("sections") or info.get("frames") or []:
        if item["hmac"] != "verified":
            problems.append(f"section {item.get('section_id', item.get('id'))} {item['hmac']}")
    if not problems:
        return f"verified ({info['key_set']} keys)"
    prefix = "FAILED" if any("mismatch" in problem for problem in problems) else "incomplete"
    return f"{prefix}: {', '.join(problems)}"


def format_key_id(value: int) -> str:
    return str(value) if value < 10 else f"0x{value:x}"


def decode_open_psid(plaintext: bytes, encrypted: bytes) -> dict:
    """Decrypt SYSTEM_INFO's encrypted OpenPSID copy, verified against the plaintext when present."""
    result = {
        "open_psid": plaintext.hex() if any(plaintext) else None,
        "encrypted_open_psid": encrypted.hex() if any(encrypted) else None,
        "decrypted_open_psid": None,
        "open_psid_key_set": None,
        "open_psid_verified": None,
        "open_psid_decryption_error": None,
    }
    if not any(encrypted):
        return result
    try:
        candidates = {
            name: _decrypt_cbc(encrypted, keys["cipher"][OPEN_PSID_KEY_ID], OPEN_PSID_IV)
            for name, keys in KEY_SETS.items()
        }
    except ParseError as exc:
        result["open_psid_decryption_error"] = str(exc)
        return result
    key_set = "retail"
    if result["open_psid"] is not None:
        match = next((name for name, value in candidates.items() if value == plaintext), None)
        result["open_psid_verified"] = match is not None
        key_set = match or key_set
    result["decrypted_open_psid"] = candidates[key_set].hex()
    result["open_psid_key_set"] = key_set
    return result


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
