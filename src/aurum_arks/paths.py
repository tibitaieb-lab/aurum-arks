"""Résolution bornée sans liens. Contrôle ponctuel, pas protection TOCTOU."""
from pathlib import Path, PureWindowsPath
import stat

from .serialization import ContractError


def reject_links(path):
    path = Path(path)
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ContractError("PATH_LINK_REFUSED")


def confined(root, relative):
    root = Path(root)
    if not root.is_absolute() or not isinstance(relative, str) or not relative:
        raise ContractError("PATH_INVALID")
    win = PureWindowsPath(relative)
    parts = relative.replace("\\", "/").split("/")
    if (win.is_absolute() or win.drive or win.root
            or any(p in ("", ".", "..") or p.endswith((".", " ")) for p in parts)
            or any(c in relative for c in ':\x00*?<>|"')
            or any(PureWindowsPath(p).is_reserved() for p in parts)):
        raise ContractError("PATH_INVALID")
    candidate = root.joinpath(*parts)
    reject_links(candidate)
    resolved_root = root.resolve(strict=True)
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(resolved_root):
        raise ContractError("PATH_OUTSIDE_ROOT")
    return resolved


class FixtureStore:
    """Liste d'admission fournie par le harness, aucune découverte récursive."""

    def __init__(self, root, source_files):
        self.root = Path(root)
        self.files = dict(source_files)

    def read(self, source_id):
        if source_id not in self.files:
            raise ContractError("SOURCE_NOT_ADMITTED")
        path = confined(self.root, self.files[source_id])
        if path.suffix != ".txt":
            raise ContractError("UNSUPPORTED_SOURCE_TYPE")
        try:
            if path.stat().st_size > 65536:
                raise ContractError("SOURCE_SIZE_LIMIT")
            with path.open("rb") as stream:
                data = stream.read(65537)
        except OSError:
            raise ContractError("SOURCE_UNAVAILABLE") from None
        if len(data) > 65536:
            raise ContractError("SOURCE_SIZE_LIMIT")
        return data
