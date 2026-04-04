import json
import os

from app.storage.secure_storage import read_json, write_json_atomic


def test_write_and_read_json_roundtrip(tmp_path):
    path = tmp_path / "state.json"
    payload = {"name": "OpenCircuit", "count": 2}

    write_json_atomic(str(path), payload)
    loaded = read_json(str(path), default={})

    assert loaded == payload


def test_read_json_returns_default_for_invalid_json(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not-valid-json", encoding="utf-8")

    loaded = read_json(str(path), default={"ok": False})

    assert loaded == {"ok": False}


def test_write_json_atomic_rejects_symlink_target(tmp_path):
    real_target = tmp_path / "real.json"
    real_target.write_text(json.dumps({"seed": True}), encoding="utf-8")

    symlink_path = tmp_path / "linked.json"
    symlink_path.symlink_to(real_target)

    try:
        write_json_atomic(str(symlink_path), {"value": 1})
        assert False, "expected symlink rejection"
    except OSError as exc:
        assert "symlink" in str(exc).lower()


def test_write_json_atomic_rejects_symlink_parent_directory(tmp_path):
    real_dir = tmp_path / "real-dir"
    real_dir.mkdir()

    linked_dir = tmp_path / "linked-dir"
    linked_dir.symlink_to(real_dir)

    file_path = linked_dir / "state.json"
    try:
        write_json_atomic(str(file_path), {"value": 1})
        assert False, "expected parent symlink rejection"
    except OSError as exc:
        assert "symlink" in str(exc).lower()


def test_write_json_atomic_sets_restrictive_permissions(tmp_path):
    path = tmp_path / "perm.json"
    write_json_atomic(str(path), {"secure": True})

    mode = os.stat(path).st_mode & 0o777
    assert mode == 0o600
