import requests

from .paths import data_path
from .quota_tracker import QuotaExceededError, QuotaTracker

BASE_URL = "https://api.abuseipdb.com/api/v2/check"

# Ücretsiz AbuseIPDB planı: 1.000 IP check/gün
ABUSEIPDB_STATE_FILE = data_path(".abuseipdb_quota_state.json")
ABUSEIPDB_DAILY_LIMIT = 1_000

CATEGORY_NAMES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class AbuseIPDBError(Exception):
    pass


class AbuseIPDBClient:
    def __init__(self, api_key: str, state_file: str = ABUSEIPDB_STATE_FILE):
        self.api_key = api_key
        self.headers = {"Key": api_key, "Accept": "application/json"}
        self.quota = QuotaTracker(state_file, daily_limit=ABUSEIPDB_DAILY_LIMIT)

    def check_ip(self, ip: str) -> dict:
        try:
            self.quota.check_and_reserve("AbuseIPDB")
        except QuotaExceededError as exc:
            raise AbuseIPDBError(str(exc)) from exc

        try:
            response = requests.get(
                BASE_URL,
                headers=self.headers,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                timeout=15,
            )
        except requests.RequestException as exc:
            raise AbuseIPDBError(f"AbuseIPDB'ye bağlanılamadı: {exc}") from exc

        if response.status_code == 401:
            raise AbuseIPDBError("AbuseIPDB API anahtarı geçersiz (401 Unauthorized).")
        if response.status_code == 429:
            raise AbuseIPDBError("AbuseIPDB API istek limiti aşıldı (429 Too Many Requests).")
        if not response.ok:
            raise AbuseIPDBError(
                f"AbuseIPDB isteği başarısız oldu: HTTP {response.status_code} - {response.text[:200]}"
            )

        return self._parse(response.json())

    @staticmethod
    def _parse(raw: dict) -> dict:
        data = raw.get("data", {})
        reports = data.get("reports", [])

        category_counts: dict[str, int] = {}
        for report in reports:
            for cat_id in report.get("categories", []):
                name = CATEGORY_NAMES.get(cat_id, f"Kategori {cat_id}")
                category_counts[name] = category_counts.get(name, 0) + 1

        top_categories = sorted(category_counts.items(), key=lambda item: item[1], reverse=True)

        return {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "hostnames": data.get("hostnames") or [],
            "is_whitelisted": data.get("isWhitelisted"),
            "is_tor": data.get("isTor"),
            "ip_version": data.get("ipVersion"),
            "num_distinct_users": data.get("numDistinctUsers"),
            "last_reported_at": data.get("lastReportedAt"),
            "top_categories": top_categories[:5],
        }
