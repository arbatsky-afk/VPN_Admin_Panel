from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from monitor.path_security import ManagedPathGuard


def atomic_write_json(
    path: Path,
    value: Any,
    guard: ManagedPathGuard | None = None,
) -> None:
    guard = guard or ManagedPathGuard(path.parent)
    path = guard.validate(path, kind="file")
    guard.ensure_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        guard.confirm_open_file(temporary_path, descriptor)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        guard.validate(path.parent, kind="directory", allow_missing=False)
        guard.validate(path, kind="file")
        os.replace(temporary_path, path)
        guard.validate(path, kind="file", allow_missing=False)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            guard.validate(temporary_path, kind="file")
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
