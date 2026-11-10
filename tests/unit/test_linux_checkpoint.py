"""Unit tests for Linux checkpoint persistence, rotation, and truncation detection."""

import os
import pytest
from collectors.linux.checkpoint import LinuxCheckpoint


def test_checkpoint_save_and_reload(tmp_path):
    ckpt_file = tmp_path / "checkpoint.json"
    ckpt = LinuxCheckpoint(str(ckpt_file))

    assert ckpt.get_offset() == 0
    assert ckpt.get_inode() is None

    ckpt.update_file_position(
        file_path="/var/log/auth.log",
        inode=12345,
        offset=1024,
        file_size=2048,
        last_line_hash="hashabc",
    )

    # Reload from disk with new instance
    reloaded = LinuxCheckpoint(str(ckpt_file))
    assert reloaded.get_offset() == 1024
    assert reloaded.get_inode() == 12345
    assert reloaded.data["file_size"] == 2048


def test_checkpoint_journal_cursor(tmp_path):
    ckpt_file = tmp_path / "checkpoint_journal.json"
    ckpt = LinuxCheckpoint(str(ckpt_file))

    assert ckpt.get_journal_cursor() is None
    ckpt.update_journal_cursor("cursor_token_12345")

    reloaded = LinuxCheckpoint(str(ckpt_file))
    assert reloaded.get_journal_cursor() == "cursor_token_12345"


def test_checkpoint_detect_rotation_inode_changed(tmp_path):
    ckpt_file = tmp_path / "checkpoint_rot.json"
    ckpt = LinuxCheckpoint(str(ckpt_file))

    ckpt.update_file_position("/var/log/auth.log", inode=100, offset=500, file_size=500)

    # Same inode, larger size -> No rotation
    assert not ckpt.is_rotated_or_truncated(current_inode=100, current_size=800)

    # Inode changed -> Rotation occurred!
    assert ckpt.is_rotated_or_truncated(current_inode=200, current_size=100)


def test_checkpoint_detect_truncation_size_decreased(tmp_path):
    ckpt_file = tmp_path / "checkpoint_trunc.json"
    ckpt = LinuxCheckpoint(str(ckpt_file))

    ckpt.update_file_position("/var/log/auth.log", inode=100, offset=2000, file_size=2000)

    # Current size smaller than offset (e.g. log truncated in-place)
    assert ckpt.is_rotated_or_truncated(current_inode=100, current_size=50)


def test_checkpoint_corrupt_file_recovery(tmp_path):
    """Verify that a corrupted checkpoint file falls back safely without crashing."""
    ckpt_file = tmp_path / "corrupt.json"
    with open(ckpt_file, "w", encoding="utf-8") as f:
        f.write("{NOT_VALID_JSON")

    ckpt = LinuxCheckpoint(str(ckpt_file))
    assert ckpt.get_offset() == 0
    assert ckpt.get_inode() is None
