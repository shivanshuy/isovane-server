"""Resolve a local folder, archive upload, or shallow-clone a git repo for Analyze."""

from __future__ import annotations

import io
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

_GIT_URL = re.compile(
    r"^(?:https?://|git@|ssh://).+\.git$|^https?://(?:github\.com|gitlab\.com|bitbucket\.org)/[\w.-]+/[\w.-]+/?$",
    re.I,
)

_MAX_ARCHIVE_BYTES = 80 * 1024 * 1024  # 80 MB compressed
_SKIP_DIR_NAMES = {".git", "node_modules", ".venv", "dist", "build", "__pycache__"}


def looks_like_git_url(value: str) -> bool:
    raw = (value or "").strip()
    if not raw:
        return False
    if raw.startswith(("http://", "https://", "git@", "ssh://")):
        return True
    return bool(_GIT_URL.match(raw))


def resolve_source(folder: str | None = None, repo: str | None = None) -> tuple[Path, str | None]:
    """Return (path_to_scan, temp_dir_to_cleanup_or_None)."""
    if repo and looks_like_git_url(repo):
        return _clone(repo.strip())
    target = (folder or repo or "").strip()
    if not target:
        raise ValueError("Provide a local folder path or a git repository URL.")
    path = Path(target).expanduser()
    if not path.exists() or not path.is_dir():
        raise ValueError(f"Folder not found: {path}")
    return path.resolve(), None


def _clone(url: str) -> tuple[Path, str]:
    temp = tempfile.mkdtemp(prefix="isovane-repo-")
    dest = Path(temp) / "src"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dest)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError as exc:
        shutil.rmtree(temp, ignore_errors=True)
        raise ValueError("git is not installed on this machine.") from exc
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(temp, ignore_errors=True)
        raise ValueError("git clone timed out.") from exc
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(temp, ignore_errors=True)
        detail = (exc.stderr or exc.stdout or "").strip() or "clone failed"
        raise ValueError(f"git clone failed: {detail}") from exc
    return dest, temp


def cleanup_temp(temp_dir: str | None) -> None:
    if temp_dir:
        shutil.rmtree(temp_dir, ignore_errors=True)


def extract_archive(data: bytes, filename: str) -> tuple[Path, str]:
    """Unpack a zip/tar archive to a temp dir. Returns (scan_root, temp_dir)."""
    if len(data) > _MAX_ARCHIVE_BYTES:
        raise ValueError(
            f"Archive too large ({len(data)} bytes). Max is {_MAX_ARCHIVE_BYTES} bytes compressed."
        )
    name = (filename or "upload.zip").lower()
    temp = tempfile.mkdtemp(prefix="isovane-archive-")
    dest = Path(temp) / "src"
    dest.mkdir(parents=True, exist_ok=True)
    try:
        if name.endswith(".zip"):
            _extract_zip(data, dest)
        elif name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")):
            _extract_tar(data, dest, name)
        else:
            raise ValueError("Unsupported archive. Use .zip, .tar.gz, or .tgz.")
    except ValueError:
        shutil.rmtree(temp, ignore_errors=True)
        raise
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(temp, ignore_errors=True)
        raise ValueError(f"Could not extract archive: {exc}") from exc

    root = _unwrap_single_root(dest)
    if not any(root.rglob("*")):
        shutil.rmtree(temp, ignore_errors=True)
        raise ValueError("Archive is empty after extract.")
    return root, temp


def _safe_join(root: Path, member: str) -> Path:
    target = (root / member).resolve()
    if not str(target).startswith(str(root.resolve())):
        raise ValueError(f"Archive path escapes extract root: {member}")
    return target


def _extract_zip(data: bytes, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            raw = info.filename.replace("\\", "/")
            if not raw or raw.endswith("/"):
                continue
            parts = Path(raw).parts
            if any(part in _SKIP_DIR_NAMES for part in parts):
                continue
            if raw.startswith("/") or ".." in parts:
                raise ValueError(f"Unsafe archive entry: {raw}")
            target = _safe_join(dest, raw)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out)


def _extract_tar(data: bytes, dest: Path, name: str) -> None:
    mode = "r:*"
    if name.endswith((".tar.gz", ".tgz")):
        mode = "r:gz"
    elif name.endswith((".tar.bz2", ".tbz2")):
        mode = "r:bz2"
    with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            raw = member.name.replace("\\", "/")
            parts = Path(raw).parts
            if any(part in _SKIP_DIR_NAMES for part in parts):
                continue
            if raw.startswith("/") or ".." in parts:
                raise ValueError(f"Unsafe archive entry: {raw}")
            target = _safe_join(dest, raw)
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            with extracted, target.open("wb") as out:
                shutil.copyfileobj(extracted, out)


def _unwrap_single_root(dest: Path) -> Path:
    children = [p for p in dest.iterdir() if p.name not in {".", ".."}]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest
