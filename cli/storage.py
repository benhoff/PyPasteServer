import json
from pathlib import Path
from typing import Any, Dict, Optional


def save_json_data(data: Dict[str, Any], filepath: Path) -> None:
    """Persist a dictionary as JSON to filepath."""
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=4)
        print(f"Data saved to {filepath}")
    except IOError as exc:
        raise IOError(f"Failed to write data to file: {exc}") from exc


def load_json_data(filepath: Path) -> Optional[Dict[str, Any]]:
    """Return JSON content as a dictionary if filepath is readable, else None."""
    try:
        with open(filepath, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (IOError, json.JSONDecodeError):
        return None
