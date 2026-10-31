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
from typing import Callable, Optional

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


def _decrypt_section(raw: bytes, section: dict, key_set: str, limit: Optional[int] = None) -> bytes:
    captured_size = section["available_encrypted_size"] // 16 * 16
    if limit is not None:
        captured_size = min(captured_size, limit)
    start = section["file_offset"]
    key = KEY_SETS[key_set]["cipher"][section["encryption_key_id"]]
    return _decrypt_cbc(raw[start : start + captured_size], key, section["iv"])[:section["size"]]


def _public(section: dict) -> dict:
    return {key: value for key, value in section.items() if key not in ("iv", "digest")}


def is_gzip(data: bytes) -> bool:
    return data.startswith(b"\x1f\x8b")


def _open_caf(
    raw: bytes, caf: dict, issues: list[ParseIssue], label: str, code: str,
    probe: Optional[Callable[[bytes], bool]] = None,
) -> tuple[dict, list[Optional[bytes]]]:
    """Verify a parsed CAF's HMACs and decrypt every section with a complete AES block.

    The header HMAC selects the key set. When it matches neither set, the first set
    whose first plaintext block of the lowest section satisfies probe is used.
    """
    sections = caf["sections"]
    for section in sections:
        if section["available_encrypted_size"] < section["encrypted_size"]:
            issues.append(ParseIssue(
                "error", f"{code}-truncated-section",
                f"{label} section {section['id']} is truncated: "
                f"0x{section['available_encrypted_size']:x} of 0x{section['encrypted_size']:x} "
                "encrypted bytes available",
                section["file_offset"] + section["available_encrypted_size"],
            ))
    header_key_set = _header_key_set(raw, caf)
    if header_key_set is None:
        issues.append(ParseIssue(
            "error", f"{code}-hmac-mismatch",
            f"{label} header HMAC matches neither the retail nor the internal key set; "
            "the header is corrupt or was modified",
            caf["digest_offset"],
        ))
    decryptable = [
        section["available_encrypted_size"] >= 16 and section["encryption_key_id"] in KEY_SETS["retail"]["cipher"]
        for section in sections
    ]
    key_set = header_key_set or "retail"
    plaintexts: list[Optional[bytes]] = [None] * len(sections)
    decryption_error = None
    try:
        candidates = [section for section, usable in zip(sections, decryptable) if usable]
        if header_key_set is None and probe is not None and candidates:
            first = min(candidates, key=lambda item: item["id"])
            key_set = next(
                (name for name in KEY_SETS if probe(_decrypt_section(raw, first, name, 16))), key_set,
            )
        plaintexts = [
            _decrypt_section(raw, section, key_set) if usable else None
            for section, usable in zip(sections, decryptable)
        ]
    except ParseError as exc:
        decryption_error = str(exc)

    for section in sections:
        section["hmac"] = _section_hmac(raw, section, key_set)
        if section["hmac"] == "mismatch":
            issues.append(ParseIssue(
                "error", f"{code}-hmac-mismatch",
                f"{label} section {section['id']} HMAC does not match its ciphertext; "
                "the section is corrupt or was modified",
                section["file_offset"],
            ))
        elif section["hmac"] == "unknown-key":
            issues.append(ParseIssue(
                "warning", f"{code}-hmac-unverified",
                f"{label} section {section['id']} uses unknown hash key ID {section['hmac_key_id']}; "
                "its HMAC is not verified",
                section["file_offset"],
            ))

    expected_end = caf["header_size"] + caf["total_size"]
    if len(raw) < expected_end and all(
        section["encrypted_size"] == section["available_encrypted_size"] for section in sections
    ):
        issues.append(ParseIssue(
            "error", f"{code}-truncated-container",
            f"{label} file is truncated before its declared end", len(raw),
        ))
    elif len(raw) > expected_end:
        issues.append(ParseIssue(
            "warning", f"{code}-trailing-data",
            f"{label} is followed by 0x{len(raw) - expected_end:x} bytes", expected_end,
        ))
    return {
        "version": caf["version"],
        "cipher": "AES-128-CBC",
        "header_size": caf["header_size"],
        "total_size": caf["total_size"],
        "primary_type_flag": caf["type_flag"],
        "key_set": key_set,
        "header_hmac": "verified" if header_key_set else "mismatch",
        "hmac_verified": header_key_set is not None and all(section["hmac"] == "verified" for section in sections),
        "decryption_error": decryption_error,
        "section_count": len(sections),
        "sections": [_public(section) for section in sections],
    }, plaintexts


def open_caf(
    raw: bytes, issues: list[ParseIssue], *, label: str = "CAF", code: str = "caf",
    probe: Optional[Callable[[bytes], bool]] = None,
) -> tuple[dict, list[Optional[bytes]]]:
    """Parse a SceCoredump CAF, verify its HMACs, and return its decrypted sections in table order."""
    return _open_caf(raw, _parse_caf(raw, label), issues, label, code, probe)


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
    section = next((item for item in caf["sections"] if item["id"] == 0), None)
    if section is None:
        raise ParseError("SPSP2DMP coredump section 0 is missing")
    if section["encryption_key_id"] not in KEY_SETS["retail"]["cipher"]:
        raise ParseError(f"unsupported SPSP2DMP encryption key ID {section['encryption_key_id']}")
    if section["available_encrypted_size"] < 16:
        raise ParseError("SPSP2DMP coredump section 0 has no complete AES block")
    container, plaintexts = _open_caf(raw, caf, issues, "SPSP2DMP", "spsp2dmp", is_gzip)
    if container["decryption_error"]:
        raise ParseError(container["decryption_error"])
    payload = plaintexts[caf["sections"].index(section)]
    if not is_gzip(payload):
        raise ParseError("decrypted SPSP2DMP coredump section 0 does not begin with gzip data")

    access_parameters = None
    for item, plaintext in zip(container["sections"], plaintexts):
        if (item["id"] != 0 and plaintext is not None and item["available_size"] == item["size"]
                and len(plaintext) >= ACCESS_PARAMETERS.size and plaintext.startswith(b"CDAP")):
            access_parameters = {"section_id": item["id"], **_decode_access_parameters(plaintext)}
    del container["decryption_error"]
    return payload, {"format": "spsp2dmp", **container, "access_parameters": access_parameters}


def decode_screenshot(container: dict, plaintexts: list[Optional[bytes]]) -> tuple[dict, list[bytes]]:
    """Decode an opened screenshot CAF: one gzip frame per section."""
    frames = []
    pixels = []
    for index, (section, plaintext) in enumerate(zip(container["sections"], plaintexts)):
        frame = {
            "index": index,
            "source": SCREENSHOT_SOURCES[index] if index < len(SCREENSHOT_SOURCES) else None,
            "section_id": section["id"],
            "encryption_key_id": section["encryption_key_id"],
            "hmac": section["hmac"],
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
        if plaintext is not None:
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
        "complete": all(section["available_size"] == section["size"] for section in container["sections"]),
        "header_complete": True,
        "container_version": container["version"],
        "primary_type_flag": container["primary_type_flag"],
        "header_size": container["header_size"],
        "total_size": container["total_size"],
        "key_set": container["key_set"],
        "header_hmac": container["header_hmac"],
        "hmac_verified": container["hmac_verified"],
        "decrypted": any(frame["width"] is not None for frame in frames),
        "decryption_error": container["decryption_error"],
        "frames": frames,
    }, pixels


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
    summary, pixels = decode_screenshot(*open_caf(raw, [], label="SYSTEM_INFO2", probe=is_gzip))
    return {
        **result, **summary, "container_end": min(len(data), 4 + header_size + total_size),
    }, pixels


def decode_crash_report(payload: bytes) -> dict:
    """Decode crash_report.caf: the finished dump's path and the title ID, NUL-terminated."""
    path, path_end, rest = payload.partition(b"\0")
    title_id, title_end, padding = rest.partition(b"\0")
    return {
        "corefile_path": path.decode("utf-8", errors="replace"),
        "corefile_path_complete": bool(path_end),
        "corefile_name": path.rsplit(b"/", 1)[-1].decode("utf-8", errors="replace"),
        "title_id": title_id.decode("utf-8", errors="replace") or None,
        "title_id_complete": bool(title_end),
        "padding_nonzero_bytes": sum(value != 0 for value in padding),
    }


def looks_like_crash_report(block: bytes) -> bool:
    head = block.split(b"\0", 1)[0]
    return b":" in head and all(0x20 <= value < 0x7F for value in head)


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
