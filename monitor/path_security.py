from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


class UnsafeManagedPathError(OSError):
    pass


@dataclass(frozen=True, slots=True)
class ManagedPathGuard:
    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", _absolute(self.root))

    def validate(
        self,
        path: Path,
        *,
        kind: str,
        allow_missing: bool = True,
    ) -> Path:
        candidate = _absolute(path)
        try:
            candidate.relative_to(self.root)
        except ValueError as error:
            raise UnsafeManagedPathError("Managed path escapes its allowed root.") from error

        components = _components(candidate)
        root_components = set(_components(self.root))
        for component in components:
            try:
                status = component.lstat()
            except FileNotFoundError:
                if not allow_missing:
                    raise UnsafeManagedPathError("Managed path does not exist.") from None
                continue
            except OSError as error:
                raise UnsafeManagedPathError("Managed path could not be inspected.") from error

            if _is_link_or_reparse(status):
                raise UnsafeManagedPathError("Managed path contains a symlink or reparse point.")

            is_final = component == candidate
            if not is_final or component in root_components:
                if not stat.S_ISDIR(status.st_mode):
                    raise UnsafeManagedPathError("Managed path parent is not a directory.")
            elif kind == "directory" and not stat.S_ISDIR(status.st_mode):
                raise UnsafeManagedPathError("Managed directory has an invalid file type.")
            elif kind == "file" and not stat.S_ISREG(status.st_mode):
                raise UnsafeManagedPathError("Managed file has an invalid file type.")
        return candidate

    def ensure_directory(self, directory: Path) -> Path:
        candidate = self.validate(directory, kind="directory")
        relative = candidate.relative_to(self.root)
        components = [self.root]
        current = self.root
        for part in relative.parts:
            current /= part
            components.append(current)
        for component in components:
            if component.exists():
                self.validate(component, kind="directory", allow_missing=False)
                continue
            self.validate(candidate, kind="directory")
            try:
                component.mkdir(mode=0o700)
            except FileExistsError:
                pass
            self.validate(component, kind="directory", allow_missing=False)
        return candidate

    def create_directory(self, directory: Path) -> Path:
        candidate = self.validate(directory, kind="directory")
        self.validate(candidate, kind="directory")
        candidate.mkdir(mode=0o700)
        return self.validate(candidate, kind="directory", allow_missing=False)

    def confirm_open_file(self, path: Path, descriptor: int) -> Path:
        candidate = self.validate(path, kind="file", allow_missing=False)
        try:
            path_status = candidate.lstat()
            descriptor_status = os.fstat(descriptor)
        except OSError as error:
            raise UnsafeManagedPathError("Managed file identity could not be verified.") from error
        if not stat.S_ISREG(descriptor_status.st_mode) or (
            path_status.st_dev,
            path_status.st_ino,
        ) != (
            descriptor_status.st_dev,
            descriptor_status.st_ino,
        ):
            raise UnsafeManagedPathError("Managed file identity changed while opening it.")
        return candidate

    def open_file(self, path: Path, flags: int, mode: int = 0o600) -> int:
        candidate = self.validate(path, kind="file")
        self.validate(candidate.parent, kind="directory", allow_missing=False)
        descriptor = os.open(candidate, flags | getattr(os, "O_NOFOLLOW", 0), mode)
        try:
            self.confirm_open_file(candidate, descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _components(path: Path) -> tuple[Path, ...]:
    current = Path(path.anchor)
    components: list[Path] = [current]
    for part in path.parts[1:]:
        current /= part
        components.append(current)
    return tuple(components)


def _is_link_or_reparse(status: os.stat_result) -> bool:
    if stat.S_ISLNK(status.st_mode):
        return True
    attributes = getattr(status, "st_file_attributes", 0)
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_attribute)
