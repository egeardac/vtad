import json
import os
import threading
import time
from datetime import datetime
from typing import Callable


class QuotaExceededError(Exception):
    pass


class QuotaTracker:
    """Bir API'nin günlük/aylık istek kotasını yerel bir durum dosyasında
    izler (script'in ayrı ayrı çalıştırılan oturumları arasında da geçerli
    olması için) ve istekleri "burst_limit kadar hemen, sonra pencere dolana
    kadar bekle" mantığıyla gruplar (ör. 4 istek hemen, 5. istekte pencerenin
    kalanı kadar bekle, sonraki 4 istek yine hemen...)."""

    def __init__(
        self,
        state_file: str,
        daily_limit: int,
        monthly_limit: int | None = None,
        burst_limit: int | None = None,
        burst_window_seconds: float = 60.0,
        on_wait: Callable[[int], None] | None = None,
    ):
        self.state_file = state_file
        self.daily_limit = daily_limit
        self.monthly_limit = monthly_limit
        self.burst_limit = burst_limit
        self.burst_window_seconds = burst_window_seconds
        self.on_wait = on_wait
        self._window_start: float | None = None
        self._window_count = 0
        self._lock = threading.Lock()

    def _load(self) -> dict:
        if not os.path.isfile(self.state_file):
            return {}
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self, state: dict) -> None:
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state, f)
        except OSError:
            pass

    def _current_state(self) -> dict:
        state = self._load()
        today = datetime.now().strftime("%Y-%m-%d")
        month = today[:7]

        if state.get("date") != today:
            state["date"] = today
            state["daily_count"] = 0
        if state.get("month") != month:
            state["month"] = month
            state["monthly_count"] = 0

        state.setdefault("daily_count", 0)
        state.setdefault("monthly_count", 0)
        return state

    def check_and_reserve(self, api_name: str) -> None:
        """Kota dolmuşsa QuotaExceededError fırlatır; değilse gerekirse
        burst penceresi dolana kadar bekler ve isteği kullanılmış olarak
        işaretler."""
        with self._lock:
            state = self._current_state()

            if state["daily_count"] >= self.daily_limit:
                raise QuotaExceededError(
                    f"{api_name} günlük istek kotası doldu ({self.daily_limit} istek/gün). "
                    "Yarın tekrar deneyin."
                )
            if self.monthly_limit is not None and state["monthly_count"] >= self.monthly_limit:
                raise QuotaExceededError(
                    f"{api_name} aylık istek kotası doldu ({self.monthly_limit} istek/ay)."
                )

            if self.burst_limit:
                now = time.monotonic()

                # Pencere hiç başlamamışsa ya da süresi dolmuşsa yeni pencere aç.
                if self._window_start is None or (now - self._window_start) >= self.burst_window_seconds:
                    self._window_start = now
                    self._window_count = 0

                # Bu pencerede burst_limit kadar istek zaten yapıldıysa,
                # pencere tamamen dolana kadar saniye saniye geri sayarak bekle.
                if self._window_count >= self.burst_limit:
                    wait = self.burst_window_seconds - (now - self._window_start)
                    if wait > 0:
                        remaining = int(wait) + 1
                        while remaining > 0:
                            if self.on_wait:
                                self.on_wait(remaining)
                            time.sleep(1.0)
                            remaining -= 1
                        if self.on_wait:
                            self.on_wait(0)
                    self._window_start = time.monotonic()
                    self._window_count = 0

                self._window_count += 1

            state["daily_count"] += 1
            state["monthly_count"] += 1
            self._save(state)
