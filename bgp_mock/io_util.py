"""Small file helpers shared by every writer."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path


def load_json(path: Path):
    """Load a JSON object or list. YAML is accepted when PyYAML is installed."""
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise ValueError(
                "YAML input needs PyYAML (pip install pyyaml). "
                "JSON input works with the standard library."
            ) from exc
        return yaml.safe_load(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON ({exc})") from exc


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class _HashWriter:
    """File wrapper that hashes bytes as gzip writes them."""

    def __init__(self, raw):
        self.raw = raw
        self.md5 = hashlib.md5()
        self.size = 0

    def write(self, data: bytes) -> int:
        self.raw.write(data)
        self.md5.update(data)
        self.size += len(data)
        return len(data)

    def flush(self) -> None:
        self.raw.flush()


def _prepare_dest(path: Path, force: bool) -> Path:
    path = Path(path)
    if path.exists() and not force:
        raise FileExistsError(
            f"refusing to overwrite {path}. Pass --force or set \"force\": true."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_gz(path: Path, text: str, force: bool = False) -> dict:
    """Write one gzip text file. Refuse to replace an existing file unless force."""
    return write_gz_lines(path, _lines_of(text), force=force)


def _lines_of(text: str):
    for line in text.splitlines():
        yield line


def write_gz_lines(path: Path, lines, force: bool = False) -> dict:
    """Stream lines into a gzip file. Each line is written with a single newline."""
    path = _prepare_dest(path, force)
    tmp = path.with_name(path.name + ".tmp")
    if tmp.exists():
        tmp.unlink()
    count = 0
    try:
        with tmp.open("wb") as raw:
            hasher = _HashWriter(raw)
            with gzip.GzipFile(fileobj=hasher, mode="wb", compresslevel=6, mtime=0) as handle:
                for line in lines:
                    handle.write((line + "\n").encode("utf-8"))
                    count += 1
            digest = hasher.md5.hexdigest()
            size = hasher.size
        tmp.replace(path)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise
    return {
        "path": str(path),
        "bytes": size,
        "lines": count,
        "md5": digest,
    }


def read_text(path: Path) -> str:
    """Read a plain or gzip text file."""
    path = Path(path)
    if str(path).endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    return path.read_text(encoding="utf-8", errors="replace")


def open_text(path: Path):
    """Stream a plain or gzip text file."""
    path = Path(path)
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("rt", encoding="utf-8", errors="replace")


def resolve_path(base: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (base / path).resolve()
