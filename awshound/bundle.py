import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable

from .manifest import Manifest


def json_serial(obj):
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_manifest(manifest: Manifest, output_dir: Path) -> Path:
    ensure_dir(output_dir)
    out = output_dir / "manifest.json"
    out.write_text(manifest.to_json(), encoding="utf-8")
    return out


def write_jsonl(records: Iterable[Dict[str, Any]], path: Path) -> Path:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, default=json_serial))
            f.write("\n")
    return path
