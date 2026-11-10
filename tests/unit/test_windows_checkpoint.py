"""Unit tests for Windows checkpoint persistence and log reset detection."""

import pytest
from collectors.windows.checkpoint import WindowsCheckpoint


def test_windows_checkpoint_save_and_reload(tmp_path):
    ckpt_file = tmp_path / "checkpoint_win.json"
    ckpt = WindowsCheckpoint(str(ckpt_file))

    assert ckpt.get_last_record_number() == 0
    assert ckpt.get_bookmark_xml() is None

    ckpt.update_record(
        record_number=500100,
        bookmark_xml="<Bookmark>...</Bookmark>",
        event_timestamp="2026-10-14T20:00:00Z",
    )

    # Reload with fresh instance
    reloaded = WindowsCheckpoint(str(ckpt_file))
    assert reloaded.get_last_record_number() == 500100
    assert reloaded.get_bookmark_xml() == "<Bookmark>...</Bookmark>"
    assert reloaded.data["last_event_timestamp"] == "2026-10-14T20:00:00Z"


def test_windows_checkpoint_detect_log_cleared_or_reset(tmp_path):
    ckpt_file = tmp_path / "checkpoint_win_reset.json"
    ckpt = WindowsCheckpoint(str(ckpt_file))

    ckpt.update_record(record_number=1000)

    # Active log with records 500 to 2000 -> No reset
    assert not ckpt.check_log_reset(current_oldest_record=500, current_newest_record=2000)

    # Security log was cleared, now records are 1 to 50 -> Reset detected!
    assert ckpt.check_log_reset(current_oldest_record=1, current_newest_record=50)

    # Reset checkpoint explicitly
    ckpt.reset_checkpoint(starting_record=0)
    assert ckpt.get_last_record_number() == 0
