import builtins
import gzip
import json

import pytest

pytest.importorskip("cryptography")

from psp2_core_parse import CafFile, read_dump
from psp2_core_parse.caf import caf_kind
from psp2_core_parse.cli import main
from psp2_core_parse.core import ParseError
from test_core import make_core
from test_spsp2dmp import (
    KEY_SETS, frame_pixels, make_caf, make_container, make_screenshot, read_png, rgb, write_dump,
)


def crash_report_payload(path=b"ux0:data/psp2core-NPXS10001.spsp2dmp", title_id=b"NPXS10001"):
    # writeCrashReport: NUL-terminated path, the title ID, then 1-16 bytes of padding.
    payload = path + b"\0" + title_id
    return payload + b"\0" * (16 - (len(payload) & 15))


def make_crash_report(*, key_id=2, key_set="retail", payload=None):
    return make_caf([payload or crash_report_payload()], [key_id], key_set=key_set)


@pytest.mark.parametrize("key_set", sorted(KEY_SETS))
@pytest.mark.parametrize("key_id", [1, 2])
def test_crash_report_is_verified_and_decoded(tmp_path, key_set, key_id):
    path = write_dump(tmp_path, make_crash_report(key_id=key_id, key_set=key_set), ".caf")
    report = read_dump(path, strict=True)
    assert isinstance(report, CafFile)
    assert report.kind == "crash-report" and report.complete and not report.issues
    assert report.container["key_set"] == key_set and report.container["hmac_verified"]
    assert report.crash_report == {
        "corefile_path": "ux0:data/psp2core-NPXS10001.spsp2dmp",
        "corefile_path_complete": True,
        "corefile_name": "psp2core-NPXS10001.spsp2dmp",
        "title_id": "NPXS10001",
        "title_id_complete": True,
        "padding_nonzero_bytes": 0,
    }


def test_crash_report_commands(tmp_path, capsys):
    path = write_dump(tmp_path, make_crash_report(), ".caf")
    assert main(["info", str(path)]) == 0
    text = capsys.readouterr().out
    assert "SceCoredump crash report (CAF): complete" in text
    assert "Dump file: ux0:data/psp2core-NPXS10001.spsp2dmp" in text
    assert "Title ID: NPXS10001" in text
    assert "retail key ID 2); HMACs: verified (retail keys)" in text
    assert main(["analyze", str(path)]) == 0
    assert "analyze psp2core-NPXS10001.spsp2dmp instead" in capsys.readouterr().out
    assert main(["validate", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main(["context", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["crash_report"]["title_id"] == "NPXS10001"
    output = tmp_path / "section.bin"
    assert main(["extract", str(path), "--section", "0", "--output", str(output)]) == 0
    assert output.read_bytes() == crash_report_payload()
    capsys.readouterr()


@pytest.mark.parametrize("argv,message", [
    (["threads"], "not available for a crash report CAF"),
    (["system2"], "not available for a crash report CAF"),
    (["extract", "--elf", "--output", "out.bin"], "extract --section"),
    (["extract", "--section", "1", "--output", "out.bin"], "section 1 was not found"),
])
def test_crash_report_rejects_coredump_commands(tmp_path, capsys, argv, message):
    path = write_dump(tmp_path, make_crash_report(), ".caf")
    argv = [item.replace("out.bin", str(tmp_path / "out.bin")) for item in argv]
    assert main([argv[0], str(path), *argv[1:]]) == 2
    assert message in capsys.readouterr().err


def test_modified_crash_report_fails_hmac(tmp_path):
    raw = bytearray(make_crash_report())
    raw[-1] ^= 1
    path = write_dump(tmp_path, raw, ".caf")
    report = CafFile.read(path)
    assert report.container["sections"][0]["hmac"] == "mismatch"
    assert any(issue.code == "caf-hmac-mismatch" for issue in report.issues)
    with pytest.raises(ParseError, match="HMAC"):
        CafFile.read(path, strict=True)


def test_truncated_crash_report_is_salvaged(tmp_path, capsys):
    path = write_dump(tmp_path, make_crash_report()[:-16], ".caf")
    report = CafFile.read(path)
    assert not report.complete
    assert report.container["sections"][0]["hmac"] == "truncated"
    assert report.crash_report["corefile_path"] == "ux0:data/psp2core-NPXS10001.spsp"
    assert report.crash_report["corefile_path_complete"] is False
    with pytest.raises(ParseError, match="truncated"):
        CafFile.read(path, strict=True)
    assert main(["info", str(path)]) == 0
    text = capsys.readouterr().out
    assert "Dump file: ux0:data/psp2core-NPXS10001.spsp (truncated)" in text
    assert "Title ID: unavailable" in text


def test_crash_report_requires_cryptography(tmp_path, monkeypatch):
    path = write_dump(tmp_path, make_crash_report(), ".caf")
    original_import = builtins.__import__

    def without_crypto(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("synthetic missing optional dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_crypto)
    with pytest.raises(ParseError, match="cryptography"):
        read_dump(path)


def test_caf_kind_routes_only_standalone_containers():
    assert caf_kind(make_crash_report()) == "crash-report"
    assert caf_kind(make_screenshot([(1, 8, 8)])[4:]) == "screenshot"
    assert caf_kind(make_container()) is None
    assert caf_kind(b"\x1f\x8b" + bytes(0x40)) is None


def test_screenshot_container_round_trip(tmp_path, capsys):
    description = make_screenshot([(0, 0, 0), (7, 16, 4)])
    image = make_core(note_name=b"SYSTEM_INFO2\0", note_type=0x102D, description=description)
    dump = write_dump(tmp_path, gzip.compress(image, mtime=0), ".psp2dmp")
    container = tmp_path / "display.caf"
    assert main(["system2", str(dump), "--output", str(container)]) == 0
    capsys.readouterr()
    assert container.read_bytes() == description[4:-0x40]

    screenshot = read_dump(container, strict=True)
    assert isinstance(screenshot, CafFile) and screenshot.kind == "screenshot" and not screenshot.issues
    assert [frame["width"] for frame in screenshot.screenshot["frames"]] == [0, 16]
    assert main(["system2", str(container), "--frames", str(tmp_path / "frames")]) == 0
    text = capsys.readouterr().out
    assert "SceCoredump screenshot container (CAF): complete" in text
    assert "Frame 1 (shell): 16x4" in text
    assert read_png(tmp_path / "frames" / "shell.png") == (16, 4, rgb(frame_pixels(16, 4)))
    assert main(["system2", str(container), "--output", str(tmp_path / "again.caf")]) == 2
    assert "already a standalone" in capsys.readouterr().err


def test_extract_section_from_encrypted_coredump(tmp_path, capsys):
    path = write_dump(tmp_path, make_container())
    output = tmp_path / "section1.bin"
    assert main(["extract", str(path), "--section", "1", "--output", str(output)]) == 0
    assert output.read_bytes() == b"synthetic auxiliary data".ljust(0x60, b"\0")
    plain = write_dump(tmp_path, gzip.compress(make_core(), mtime=0), ".psp2dmp")
    assert main(["extract", str(plain), "--section", "0", "--output", str(tmp_path / "plain.bin")]) == 2
    assert "requires an encrypted" in capsys.readouterr().err


def test_triage_reports_crash_reports_as_failures(tmp_path, capsys):
    write_dump(tmp_path, make_container())
    (tmp_path / "crash_report.caf").write_bytes(make_crash_report())
    assert main(["triage", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["analyzed_count"] == 1
    assert result["failures"] == [{"path": str(tmp_path / "crash_report.caf"), "error": "crash report CAF holds no crash data"}]
