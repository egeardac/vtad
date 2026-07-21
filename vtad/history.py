import json
import os
from datetime import datetime

from .paths import data_path

HISTORY_FILE = data_path("analysis_history.json")


def load_history() -> list[dict]:
    if not os.path.isfile(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def add_history_entry(result: dict) -> int:
    """Kaydı geçmişe ekler ve kalıcı rapor numarasını döndürür."""
    entries = load_history()
    next_id = max((entry.get("id", 0) for entry in entries), default=0) + 1

    entry = dict(result)
    entry["id"] = next_id
    entry["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entries.append(entry)
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(entries, f, ensure_ascii=False, indent=2)
    except OSError:
        pass
    return next_id


def get_history_entry(entry_id: int) -> dict | None:
    for entry in load_history():
        if entry.get("id") == entry_id:
            return entry
    return None
