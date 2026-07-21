import requests

from .paths import data_path
from .quota_tracker import QuotaExceededError, QuotaTracker
from .utils import print_wait

BASE_URL = "https://www.virustotal.com/api/v3"

# Ücretsiz VirusTotal planı: 4 istek/dakika, 500 istek/gün, 15.500 istek/ay
VT_STATE_FILE = data_path(".vt_quota_state.json")
VT_REQUESTS_PER_MINUTE = 4
VT_DAILY_LIMIT = 500
VT_MONTHLY_LIMIT = 15_500


def _on_wait(remaining_seconds: int) -> None:
    print_wait(
        remaining_seconds,
        f"VirusTotal'ın dakikada {VT_REQUESTS_PER_MINUTE} istek limitine ulaşıldı,",
    )


class VirusTotalError(Exception):
    pass


class VirusTotalClient:
    def __init__(self, api_key: str, state_file: str = VT_STATE_FILE):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}
        self.quota = QuotaTracker(
            state_file,
            daily_limit=VT_DAILY_LIMIT,
            monthly_limit=VT_MONTHLY_LIMIT,
            burst_limit=VT_REQUESTS_PER_MINUTE,
            burst_window_seconds=60.0,
            on_wait=_on_wait,
        )

    def _get(self, url: str) -> dict:
        try:
            self.quota.check_and_reserve("VirusTotal")
        except QuotaExceededError as exc:
            raise VirusTotalError(str(exc)) from exc

        try:
            response = requests.get(url, headers=self.headers, timeout=15)
        except requests.RequestException as exc:
            raise VirusTotalError(f"VirusTotal'a bağlanılamadı: {exc}") from exc

        if response.status_code == 401:
            raise VirusTotalError("VirusTotal API anahtarı geçersiz (401 Unauthorized).")
        if response.status_code == 404:
            return {}
        if response.status_code == 429:
            raise VirusTotalError("VirusTotal API istek limiti aşıldı (429 Too Many Requests).")
        if not response.ok:
            raise VirusTotalError(
                f"VirusTotal isteği başarısız oldu: HTTP {response.status_code} - {response.text[:200]}"
            )

        return response.json()

    def check_ip(self, ip: str) -> dict:
        return self._parse(self._get(f"{BASE_URL}/ip_addresses/{ip}"))

    def check_domain(self, domain: str) -> dict:
        return self._parse(self._get(f"{BASE_URL}/domains/{domain}"))

    @staticmethod
    def _parse(raw: dict) -> dict:
        if not raw:
            return {
                "found": False,
                "stats": {},
                "malicious_engines": [],
                "suspicious_engines": [],
                "reputation": None,
            }

        attributes = raw.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})

        malicious_engines = [
            engine for engine, result in results.items()
            if result.get("category") == "malicious"
        ]
        suspicious_engines = [
            engine for engine, result in results.items()
            if result.get("category") == "suspicious"
        ]

        # DNS kayıtlarını tipe göre grupla (sadece domain yanıtlarında bulunur)
        dns_records: dict[str, list[str]] = {}
        for record in attributes.get("last_dns_records") or []:
            record_type = record.get("type")
            value = record.get("value")
            if record_type and value:
                dns_records.setdefault(record_type, []).append(str(value))

        return {
            "found": True,
            "stats": stats,
            "malicious_engines": malicious_engines,
            "suspicious_engines": suspicious_engines,
            "reputation": attributes.get("reputation"),
            "total_votes": attributes.get("total_votes") or {},
            "tags": attributes.get("tags") or [],
            "last_analysis_date": attributes.get("last_analysis_date"),
            # IP hedeflerinde dolu gelen alanlar
            "country": attributes.get("country"),
            "continent": attributes.get("continent"),
            "asn": attributes.get("asn"),
            "as_owner": attributes.get("as_owner"),
            "network": attributes.get("network"),
            "rir": attributes.get("regional_internet_registry"),
            # Domain hedeflerinde dolu gelen alanlar
            "categories": attributes.get("categories") or {},
            "popularity_ranks": attributes.get("popularity_ranks") or {},
            "registrar": attributes.get("registrar"),
            "creation_date": attributes.get("creation_date"),
            "expiration_date": attributes.get("expiration_date"),
            "tld": attributes.get("tld"),
            "dns_records": dns_records,
        }
