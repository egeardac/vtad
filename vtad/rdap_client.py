from datetime import datetime, timezone

import requests

# rdapapi.io - WHOIS'in modern, JSON-native karşılığı olan RDAP protokolü üzerinden
# domain kayıt bilgisi sağlar. Ücretsiz rdap.org'a göre çok daha zengin veri döndürür
# (registrar abuse iletişimi, tarih detayları, nameserver'lar, DNSSEC, kişi kayıtları).
DOMAIN_URL = "https://rdapapi.io/api/v1/domain/{domain}?follow=true"


class RDAPClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"Authorization": f"Bearer {api_key}"}

    @staticmethod
    def _calculate_age_days(registered: str | None) -> int | None:
        if not registered:
            return None
        try:
            created = datetime.fromisoformat(registered.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - created).days
        except ValueError:
            return None

    def get_domain(self, domain: str) -> dict:
        empty = {"found": False, "error": None}
        try:
            response = requests.get(DOMAIN_URL.format(domain=domain), headers=self.headers, timeout=20)
        except requests.RequestException as exc:
            return {**empty, "error": f"RDAP sorgusu başarısız: {exc}"}

        if response.status_code == 401:
            return {**empty, "error": "RDAP API anahtarı geçersiz (401 Unauthorized)."}
        if response.status_code == 404:
            return {**empty, "error": "Bu domain için RDAP kaydı bulunamadı."}
        if response.status_code == 429:
            return {**empty, "error": "RDAP API istek limiti aşıldı (429 Too Many Requests)."}
        if not response.ok:
            return {**empty, "error": f"RDAP isteği başarısız: HTTP {response.status_code}"}

        try:
            data = response.json()
        except ValueError:
            return {**empty, "error": "RDAP yanıtı işlenemedi."}

        return self._parse(data)

    @classmethod
    def _parse(cls, data: dict) -> dict:
        registrar = data.get("registrar") or {}
        dates = data.get("dates") or {}
        entities = data.get("entities") or {}
        registrant = entities.get("registrant") or {}

        registered = dates.get("registered")

        return {
            "found": True,
            "error": None,
            "domain": data.get("domain"),
            "handle": data.get("handle"),
            "status": data.get("status") or [],
            "dnssec": data.get("dnssec"),
            "nameservers": data.get("nameservers") or [],
            # Registrar bilgisi
            "registrar": registrar.get("name"),
            "registrar_iana_id": registrar.get("iana_id"),
            "registrar_abuse_email": registrar.get("abuse_email"),
            "registrar_abuse_phone": registrar.get("abuse_phone"),
            "registrar_url": registrar.get("url"),
            # Tarihler
            "creation_date": registered,
            "expiration_date": dates.get("expires"),
            "updated_date": dates.get("updated"),
            "age_days": cls._calculate_age_days(registered),
            # Kayıt sahibi (registrant) bilgisi
            "registrant_name": registrant.get("name"),
            "registrant_org": registrant.get("organization"),
            "registrant_email": registrant.get("email"),
            "registrant_country": registrant.get("country_code"),
            # İletişim kayıtlarının tamamı (registrant / administrative / technical)
            "entities": entities,
        }
