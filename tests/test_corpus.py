import json
import os
from collections import Counter
from pathlib import Path

import pytest

from psp2_core_parse.analysis import analyze
from psp2_core_parse.core import CoreDump
from psp2_core_parse.kernel import PARSERS as KERNEL_PARSERS
from psp2_core_parse.report import ANALYSIS_BANNER, render_analysis_report
from psp2_core_parse.support import DECODERS


CORPUS_ENV = "PSP2_CORE_PARSE_CORPUS"
EXECUTION_NOTES = {
    "PROCESS_INFO",
    "MODULE_INFO",
    "THREAD_INFO",
    "THREAD_REG_INFO",
    "STACK_INFO",
}
EXPECTED_CORPUS_NOTE_NAMES = (
    set(DECODERS)
    | set(KERNEL_PARSERS)
    | EXECUTION_NOTES
    | {"TTY_INFO", "TTY_INFO2", "SUMMARY_INFO"}
)
EXPECTED_NOTE_COUNTS = {
    "9\x1a\x01": 1,
    "APP_INFO": 184,
    "APP_LIST_INFO": 140,
    "BUDGET_INFO": 140,
    "BUILD_VER_INFO": 143,
    "CALLBACK_INFO": 7,
    "CONDVAR_INFO": 6,
    "COREFILE_INFO": 186,
    "DEVICE_INFO": 140,
    "EVENTFLAG_INFO": 186,
    "EVENT_LOG_INFO": 173,
    "EXTNL_PROC_INFO": 173,
    "FILE_INFO": 173,
    "GPU_ACT_INFO": 158,
    "HW_INFO": 143,
    "LIBRARY_INFO": 184,
    "LWCONDVAR_INFO": 6,
    "LWMUTEX_INFO": 186,
    "MEM_BLK_INFO": 173,
    "MESG_PIPE_INFO": 186,
    "META_DATA_INFO": 183,
    "MODULE_INFO": 184,
    "MUTEX_INFO": 186,
    "PROCESS_INFO": 185,
    "SEMAPHORE_INFO": 186,
    "STACK_INFO": 184,
    "SUMMARY_INFO": 158,
    "SYSTEM_INFO": 185,
    "SYSTEM_INFO2": 173,
    "SYS_DEVICE_INFO": 140,
    "THREAD_INFO": 186,
    "THREAD_REG_INFO": 186,
    "TIMER_INFO": 6,
    "TTY_INFO": 173,
    "TTY_INFO2": 158,
}
EXPECTED_CLASSIFICATIONS = {
    "DATA_ABORT": 81,
    "UNDEFINED_INSTRUCTION": 71,
    "PREFETCH_ABORT": 29,
    "STACK_OVERFLOW": 4,
    "NO_CRASH_THREAD": 1,
}


def test_exhaustive_corpus_decoder_and_report_coverage():
    configured = os.environ.get(CORPUS_ENV)
    if not configured:
        pytest.skip(f"set {CORPUS_ENV}=corpus to run the exhaustive local-corpus audit")
    corpus = Path(configured)
    paths = sorted(path for path in corpus.iterdir() if path.is_file())
    assert paths, f"no dumps found under {corpus}"
    assert len(paths) == 186

    seen_valid_names = set()
    inventoried_damage = []
    note_counts = Counter()
    status_counts = Counter()
    classification_counts = Counter()
    complete_counts = Counter()
    load_count = 0
    kernel_object_count = 0
    active_kernel_object_count = 0
    waiting_kernel_object_count = 0
    wait_edge_count = 0
    for path in paths:
        core = CoreDump.read(path)
        result = analyze(core, tty_lines=0, stack_candidates=0)
        json.dumps(result)
        complete_counts[core.complete] += 1
        load_count += len(core.loads)
        kernel_object_count += result["kernel_objects"]["object_count"]
        active_kernel_object_count += result["kernel_objects"]["active_object_count"]
        waiting_kernel_object_count += sum(
            item["waiting_thread_count"] > 0 for item in result["kernel_objects"]["active_objects"]
        )
        wait_edge_count += result["kernel_objects"]["wait_graph"]["edge_count"]
        classification_counts[result["classification"]] += 1
        assert not result["decoder_errors"], (path, result["decoder_errors"])
        report = render_analysis_report(result)
        assert report.startswith(ANALYSIS_BANNER), path

        for note in result["supporting_context"]["decoded"]:
            note_counts[note["name"]] += 1
            status_counts[note["status"]] += 1
            assert note["status"] != "error", (path, note["name"], note["error"])
            data = note.get("data") or {}
            assert not data.get("trailing_nonzero_bytes", 0), (
                path, note["name"], "decoder left non-zero bytes outside known records",
            )
            if data.get("complete") is False:
                assert note["status"] == "partial", (path, note["name"], note["status"])
            if note["status"] == "inventory":
                assert not note["complete"], (path, note["name"], "complete note lacks a decoder")
                inventoried_damage.append((path.name, note["name"]))
            else:
                seen_valid_names.add(note["name"])

    assert seen_valid_names == EXPECTED_CORPUS_NOTE_NAMES
    assert inventoried_damage, "the exhaustive corpus is expected to retain at least one damaged note-name fragment"
    assert note_counts == EXPECTED_NOTE_COUNTS
    assert status_counts == {"decoded": 5143, "partial": 17, "inventory": 1}
    assert classification_counts == EXPECTED_CLASSIFICATIONS
    assert complete_counts == {True: 158, False: 28}
    assert load_count == 8543
    assert kernel_object_count == 36911
    assert active_kernel_object_count == 1093
    assert waiting_kernel_object_count == 1001
    assert wait_edge_count == 1003
