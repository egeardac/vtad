import json
import os
import time

from .paths import data_path

CACHE_FILE = data_path("result_cache.json")
CACHE_TTL_SECONDS = 3600  # 1 saat


def _load() -> dict:
    if not os.path.isfile(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(cache: dict) -> None:
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
    except OSError:
        pass


def get_cached_result(target: str) -> tuple[dict, int] | None:
    """Süresi geçmemiş bir önbellek kaydı varsa (sonuç, kaç saniye önce
    kaydedildiği) ikilisini döndürür; yoksa None."""
    entry = _load().get(target.lower())
    if not entry:
        return None

    age = int(time.time() - entry.get("cached_at", 0))
    if age > CACHE_TTL_SECONDS:
        return None

    return entry["result"], age


def store_result(target: str, result: dict) -> None:
    cache = _load()
    now = time.time()

    # Süresi dolmuş kayıtları da bu vesileyle temizle.
    cache = {
        key: value for key, value in cache.items()
        if now - value.get("cached_at", 0) <= CACHE_TTL_SECONDS
    }

    cache[target.lower()] = {"cached_at": now, "result": result}
    _save(cache)
