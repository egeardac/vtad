import json
import os
from datetime import datetime

from .paths import data_path

WATCHLIST_FILE = data_path("watchlist.json")


def load_watchlist() -> list[dict]:
    if not os.path.isfile(WATCHLIST_FILE):
        return []
    try:
        with open(WATCHLIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save(entries: list[dict]) -> None:
    try:
        with open(WATCHLIST_FILE, "w", encoding="utf-8") as f:
            json.dump(entries, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def add_to_watchlist(target: str) -> bool:
    """Hedefi izleme listesine ekler. Zaten varsa False döner."""
    target = target.strip().lower()
    entries = load_watchlist()
    if any(entry["target"] == target for entry in entries):
        return False

    entries.append({
        "target": target,
        "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_verdict": None,
        "last_checked": None,
    })
    _save(entries)
    return True


def remove_from_watchlist(target: str) -> bool:
    """Hedefi listeden çıkarır. Listede yoksa False döner."""
    target = target.strip().lower()
    entries = load_watchlist()
    remaining = [entry for entry in entries if entry["target"] != target]
    if len(remaining) == len(entries):
        return False
    _save(remaining)
    return True


def update_watch_result(target: str, verdict_kind: str, verdict_text: str) -> str | None:
    """Tarama sonrası son sonucu günceller; önceki verdict_kind'ı döndürür
    (değişiklik tespiti için)."""
    target = target.strip().lower()
    entries = load_watchlist()
    previous = None
    for entry in entries:
        if entry["target"] == target:
            previous = entry.get("last_verdict")
            entry["last_verdict"] = verdict_kind
            entry["last_verdict_text"] = verdict_text
            entry["last_checked"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            break
    _save(entries)
    return previous
