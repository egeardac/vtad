import requests

BASE_URL = "https://api.platform.censys.io/v3/global/asset/host/{ip}"


class CensysError(Exception):
    pass


class CensysClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}

    def check_ip(self, ip: str) -> dict:
        try:
            response = requests.get(BASE_URL.format(ip=ip), headers=self.headers, timeout=15)
        except requests.RequestException as exc:
            raise CensysError(f"Censys'e bağlanılamadı: {exc}") from exc

        if response.status_code == 401:
            raise CensysError("Censys API anahtarı geçersiz (401 Unauthorized).")
        if response.status_code == 404:
            return self._empty(found=False)
        if response.status_code == 429:
            raise CensysError("Censys API istek limiti aşıldı (429 Too Many Requests).")
        if not response.ok:
            raise CensysError(
                f"Censys isteği başarısız oldu: HTTP {response.status_code} - {response.text[:200]}"
            )

        try:
            resource = response.json().get("result", {}).get("resource", {})
        except ValueError as exc:
            raise CensysError("Censys yanıtı işlenemedi.") from exc

        return self._parse(resource)

    @staticmethod
    def _empty(found: bool) -> dict:
        return {
            "found": found,
            "services": [],
            "asn": None,
            "as_name": None,
            "as_country": None,
            "bgp_prefix": None,
            "country": None,
            "city": None,
            "province": None,
            "continent": None,
            "postal_code": None,
            "timezone": None,
            "coordinates": None,
            "whois_org": None,
            "whois_network": None,
        }

    @classmethod
    def _parse(cls, resource: dict) -> dict:
        if not resource:
            return cls._empty(found=False)

        services = []
        for service in resource.get("services", []):
            software = [
                s.get("product") for s in (service.get("software") or []) if s.get("product")
            ]
            services.append({
                "port": service.get("port"),
                "protocol": service.get("protocol") or "?",
                "transport": service.get("transport_protocol") or "",
                "software": software,
            })

        autonomous_system = resource.get("autonomous_system", {})
        location = resource.get("location", {})
        coordinates = location.get("coordinates") or {}
        whois = resource.get("whois", {})
        whois_org = (whois.get("organization") or {}).get("name")
        whois_network = (whois.get("network") or {}).get("name")

        coords = None
        if coordinates.get("latitude") is not None and coordinates.get("longitude") is not None:
            coords = f"{coordinates['latitude']}, {coordinates['longitude']}"

        return {
            "found": True,
            "services": services,
            "asn": autonomous_system.get("asn"),
            "as_name": autonomous_system.get("name"),
            "as_country": autonomous_system.get("country_code"),
            "bgp_prefix": autonomous_system.get("bgp_prefix"),
            "country": location.get("country"),
            "city": location.get("city"),
            "province": location.get("province"),
            "continent": location.get("continent"),
            "postal_code": location.get("postal_code"),
            "timezone": location.get("timezone"),
            "coordinates": coords,
            "whois_org": whois_org,
            "whois_network": whois_network,
        }


def format_services(services: list[dict]) -> str:
    return ", ".join(
        f"{s['port']}/{s['protocol']}" + (f" ({s['transport']})" if s["transport"] not in ("tcp", "") else "")
        for s in services
    )


def format_service_detail(service: dict) -> str:
    transport = f" ({service['transport']})" if service["transport"] else ""
    line = f"Port {service['port']}: {service['protocol']}{transport}"
    if service.get("software"):
        line += f" — {', '.join(service['software'])}"
    return line
