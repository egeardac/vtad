import argparse
import os
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

from colorama import Fore, Style
from colorama import init as colorama_init
from dotenv import load_dotenv

from .abuseipdb_client import AbuseIPDBClient, AbuseIPDBError
from .cache import get_cached_result, store_result
from .censys_client import CensysClient, CensysError, format_service_detail, format_services
from .excel_io import read_targets_from_excel, write_results_to_excel
from .history import add_history_entry, get_history_entry, load_history
from .paths import data_path
from .utils import (
    is_ip,
    print_bad,
    print_header,
    print_info,
    print_ok,
    print_warn,
    resolve_domain_to_ip,
)
from .rdap_client import RDAPClient
from .vt_client import VirusTotalClient, VirusTotalError
from .watchlist import (
    add_to_watchlist,
    load_watchlist,
    remove_from_watchlist,
    update_watch_result,
)

VERDICT_PRINTERS = {"bad": print_bad, "warn": print_warn, "ok": print_ok}


class Clients:
    """Tarama için gereken API istemcilerini bir arada tutar."""

    def __init__(self, vt_key: str, abuse_key: str, censys_key: str | None, rdap_key: str | None):
        self.vt = VirusTotalClient(vt_key)
        self.abuse = AbuseIPDBClient(abuse_key)
        self.censys = CensysClient(censys_key) if censys_key else None
        self.rdap = RDAPClient(rdap_key) if rdap_key else None


ENV_FILE = data_path(".env")


def load_clients() -> Clients:
    # Önce standart konum (~/.vtad/.env), sonra (varsa) çalışma dizinindeki .env
    # ek/override olarak denenir - ikisi de bulunursa ~/.vtad/.env öncelikli olur.
    load_dotenv(ENV_FILE)
    load_dotenv()

    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    censys_key = os.getenv("CENSYS_API_KEY")
    rdap_key = os.getenv("RDAP_API_KEY")

    if not vt_key or not abuse_key:
        print_bad(
            f"API anahtarları bulunamadı. '{ENV_FILE}' dosyasını oluşturup "
            "VIRUSTOTAL_API_KEY ve ABUSEIPDB_API_KEY değerlerini girin "
            "(.env.example dosyasını referans alabilirsiniz). CENSYS_API_KEY ve "
            "RDAP_API_KEY isteğe bağlıdır."
        )
        sys.exit(1)

    return Clients(vt_key, abuse_key, censys_key, rdap_key)


def determine_verdict(vt_result: dict, abuse_result: dict | None) -> tuple[str, str]:
    vt_malicious = vt_result["stats"].get("malicious", 0) if vt_result["found"] else 0
    vt_suspicious = vt_result["stats"].get("suspicious", 0) if vt_result["found"] else 0
    abuse_score = abuse_result["abuse_score"] if abuse_result else 0

    if vt_malicious >= 1 or abuse_score >= 25:
        return "bad", "GÜVENİLİR DEĞİL"
    if vt_suspicious >= 1 or 1 <= abuse_score < 25:
        return "warn", "ŞÜPHELİ / DİKKAT"
    return "ok", "GÜVENİLİR"


def analyze_target(target: str, clients: Clients) -> dict:
    target_is_ip = is_ip(target)

    vt_result = {"found": False, "stats": {}, "malicious_engines": [], "suspicious_engines": [], "reputation": None}
    vt_error = None
    try:
        vt_result = clients.vt.check_ip(target) if target_is_ip else clients.vt.check_domain(target)
    except VirusTotalError as exc:
        vt_error = str(exc)

    resolved_ip = None
    ip_for_lookup = target
    abuse_result = None
    abuse_error = None
    rdap_result = None
    censys_result = None
    censys_error = None

    if not target_is_ip:
        resolved_ip = resolve_domain_to_ip(target)
        ip_for_lookup = resolved_ip
        if resolved_ip is None:
            abuse_error = "Domain bir IP adresine çözülemediği için IP tabanlı kontroller atlandı."

        if clients.rdap:
            rdap_result = clients.rdap.get_domain(target)

    if ip_for_lookup:
        try:
            abuse_result = clients.abuse.check_ip(ip_for_lookup)
        except AbuseIPDBError as exc:
            abuse_error = str(exc)

        if clients.censys:
            try:
                censys_result = clients.censys.check_ip(ip_for_lookup)
            except CensysError as exc:
                censys_error = str(exc)

    verdict_kind, verdict_text = determine_verdict(vt_result, abuse_result)

    return {
        "target": target,
        "is_ip": target_is_ip,
        "resolved_ip": resolved_ip,
        "vt_result": vt_result,
        "vt_error": vt_error,
        "abuse_result": abuse_result,
        "abuse_error": abuse_error,
        "rdap_result": rdap_result,
        "censys_result": censys_result,
        "censys_error": censys_error,
        "verdict_kind": verdict_kind,
        "verdict_text": verdict_text,
    }


def analyze_with_cache(target: str, clients: Clients, no_cache: bool = False) -> tuple[dict, int | None]:
    """Hedefi (gerekirse önbellekten) analiz eder.
    (sonuç, önbellek_yaşı_saniye | None) döndürür. Yeni taramalar geçmişe
    kaydedilir; önbellekten gelenler tekrar kaydedilmez."""
    if not no_cache:
        cached = get_cached_result(target)
        if cached:
            return cached[0], cached[1]

    result = analyze_target(target, clients)
    result["report_id"] = add_history_entry(result)
    store_result(target, result)
    return result, None


# ---------------------------------------------------------------------------
# Raporlama
# ---------------------------------------------------------------------------

def _compact_vt_line(result: dict) -> None:
    vt = result.get("vt_result") or {}
    if result.get("vt_error"):
        print_bad(f"  VirusTotal : {result['vt_error']}")
        return
    if not vt.get("found"):
        print("  VirusTotal : kayıt bulunamadı (henüz analiz edilmemiş olabilir)")
        return

    stats = vt.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = malicious + suspicious + stats.get("harmless", 0) + stats.get("undetected", 0)

    line = f"  VirusTotal : {malicious} zararlı, {suspicious} şüpheli / {total} motor"
    engines = vt.get("malicious_engines", [])
    if engines:
        shown = ", ".join(engines[:3])
        if len(engines) > 3:
            shown += f" (+{len(engines) - 3})"
        line += f" — {shown}"

    if malicious:
        print_bad(line)
    elif suspicious:
        print_warn(line)
    else:
        print(line)


def _compact_abuse_line(result: dict) -> None:
    abuse = result.get("abuse_result")
    if abuse:
        score = abuse["abuse_score"]
        line = f"  AbuseIPDB  : skor {score}/100, {abuse['total_reports']} rapor"
        details = [d for d in (abuse.get("country_code"), abuse.get("isp")) if d]
        if details:
            line += f" — {', '.join(details)}"
        if score >= 25:
            print_bad(line)
        elif score >= 1:
            print_warn(line)
        else:
            print(line)
    elif result.get("abuse_error"):
        print_warn(f"  AbuseIPDB  : {result['abuse_error']}")


def _compact_rdap_line(result: dict) -> None:
    rdap = result.get("rdap_result")
    if not rdap:
        return
    if rdap.get("error"):
        print(f"  RDAP       : {rdap['error']}")
        return

    parts = []
    age_days = rdap.get("age_days")
    if age_days is not None:
        created = (rdap.get("creation_date") or "")[:10]
        parts.append(f"{age_days} günlük domain ({created})")
    if rdap.get("registrar"):
        parts.append(rdap["registrar"])
    owner = rdap.get("registrant_org") or rdap.get("registrant_name")
    if owner:
        parts.append(f"sahip: {owner}")

    line = f"  RDAP       : {' — '.join(parts) if parts else 'bilgi yok'}"
    if age_days is not None and age_days < 30:
        print_warn(line + "  [ÇOK YENİ KAYIT]")
    else:
        print(line)


def _compact_censys_line(result: dict) -> None:
    censys = result.get("censys_result")
    if censys:
        if not censys.get("found"):
            print("  Censys     : kayıt bulunamadı")
            return
        services = censys.get("services", [])
        line = f"  Censys     : {len(services)} açık servis"
        if services:
            line += f": {format_services(services[:6])}"
            if len(services) > 6:
                line += f" (+{len(services) - 6})"
        if censys.get("as_name"):
            line += f" — AS{censys.get('asn')} {censys['as_name']}"
        print(line)
    elif result.get("censys_error"):
        print_warn(f"  Censys     : {result['censys_error']}")


def _compact_location_line(result: dict) -> None:
    """Konum ve ağ bilgisini kaynaklardan birleştirip tek satırda gösterir."""
    censys = result.get("censys_result") or {}
    abuse = result.get("abuse_result") or {}
    vt = result.get("vt_result") or {}

    # Şehir/ülke: önce Censys (daha detaylı), yoksa AbuseIPDB ülke bilgisi
    place_parts = [p for p in (censys.get("city"), censys.get("province"), censys.get("country")) if p]
    if not place_parts:
        place_parts = [p for p in (abuse.get("country_name") or abuse.get("country_code"),) if p]
    place = ", ".join(place_parts)

    # ASN / operatör: Censys ya da VT
    asn = censys.get("asn") or vt.get("asn")
    as_name = censys.get("as_name") or vt.get("as_owner") or abuse.get("isp")
    net = f"AS{asn} {as_name}" if asn and as_name else (as_name or "")

    segments = [s for s in (place, net) if s]
    if censys.get("coordinates"):
        segments.append(f"({censys['coordinates']})")
    if segments:
        print(f"  Konum/Ağ   : {' — '.join(segments)}")


def print_compact_report(result: dict, cache_age: int | None = None) -> None:
    target_type = "IP adresi" if result["is_ip"] else "domain"
    target_line = f"Hedef: {result['target']} ({target_type}"
    if result.get("resolved_ip"):
        target_line += f" -> {result['resolved_ip']}"
    target_line += ")"
    print_info(target_line)
    if cache_age is not None:
        print_info(f"(önbellekten — {max(cache_age // 60, 0)} dk önce taranmıştı)")

    report_no = f"  (rapor #{result['report_id']})" if result.get("report_id") else ""
    VERDICT_PRINTERS[result["verdict_kind"]](f"\nSONUÇ: {result['verdict_text']}{report_no}")

    _compact_vt_line(result)
    _compact_abuse_line(result)
    _compact_rdap_line(result)
    _compact_censys_line(result)
    _compact_location_line(result)


def print_full_report(result: dict, cache_age: int | None = None) -> None:
    print_compact_report(result, cache_age)

    vt = result.get("vt_result") or {}
    if vt.get("found"):
        print_header("VirusTotal Detayı")
        stats = vt["stats"]
        print(f"Zararlı: {stats.get('malicious', 0)}  Şüpheli: {stats.get('suspicious', 0)}  "
              f"Zararsız: {stats.get('harmless', 0)}  Tespitsiz: {stats.get('undetected', 0)}")
        if vt.get("malicious_engines"):
            print_bad(f"Zararlı diyen motorlar: {', '.join(vt['malicious_engines'])}")
        if vt.get("suspicious_engines"):
            print_warn(f"Şüpheli diyen motorlar: {', '.join(vt['suspicious_engines'])}")
        if vt.get("reputation") is not None:
            print(f"Reputation skoru: {vt['reputation']}")
        votes = vt.get("total_votes") or {}
        if votes:
            print(f"Topluluk oyları: {votes.get('harmless', 0)} zararsız / {votes.get('malicious', 0)} zararlı")
        if vt.get("tags"):
            print(f"Etiketler: {', '.join(vt['tags'])}")
        if vt.get("asn"):
            print(f"ASN: {vt['asn']} ({vt.get('as_owner') or '?'})  Ağ: {vt.get('network') or '?'}")
        if vt.get("country"):
            print(f"Ülke (VT): {vt['country']}")
        if vt.get("categories"):
            cats = sorted(set(vt["categories"].values()))
            print(f"Kategoriler: {', '.join(cats)}")
        if vt.get("popularity_ranks"):
            ranks = ", ".join(f"{src}: {info.get('rank')}" for src, info in list(vt["popularity_ranks"].items())[:4])
            print(f"Popülerlik sıralaması: {ranks}")
        if vt.get("dns_records"):
            print("DNS kayıtları:")
            for rtype, values in vt["dns_records"].items():
                print(f"  - {rtype}: {', '.join(values[:5])}" + (f" (+{len(values) - 5})" if len(values) > 5 else ""))

    abuse = result.get("abuse_result")
    if abuse:
        print_header("AbuseIPDB Detayı")
        print(f"Kötüye kullanım güven skoru: {abuse['abuse_score']}/100")
        print(f"Toplam rapor sayısı: {abuse['total_reports']}"
              + (f" ({abuse['num_distinct_users']} farklı kullanıcı)" if abuse.get("num_distinct_users") else ""))
        location = ", ".join(p for p in (abuse.get("country_name"), abuse.get("country_code")) if p)
        if location:
            print(f"Ülke: {location}")
        if abuse.get("isp"):
            print(f"ISP: {abuse['isp']}")
        if abuse.get("usage_type"):
            print(f"Kullanım tipi: {abuse['usage_type']}")
        if abuse.get("domain"):
            print(f"Domain: {abuse['domain']}")
        if abuse.get("hostnames"):
            print(f"Hostname'ler: {', '.join(abuse['hostnames'])}")
        flags = []
        if abuse.get("is_tor"):
            flags.append("Tor çıkış düğümü")
        if abuse.get("is_whitelisted"):
            flags.append("beyaz listede")
        if flags:
            print(f"Notlar: {', '.join(flags)}")
        if abuse.get("last_reported_at"):
            print(f"Son bildirim: {abuse['last_reported_at']}")
        if abuse.get("top_categories"):
            print_warn("En çok bildirilen kategoriler:")
            for name, count in abuse["top_categories"]:
                print(f"  - {name}: {count} rapor")

    rdap = result.get("rdap_result")
    if rdap and rdap.get("found"):
        print_header("RDAP (Kayıt) Detayı")
        if rdap.get("registrar"):
            print(f"Registrar: {rdap['registrar']}"
                  + (f" (IANA #{rdap['registrar_iana_id']})" if rdap.get("registrar_iana_id") else ""))
        if rdap.get("registrar_abuse_email"):
            print(f"Registrar abuse iletişim: {rdap['registrar_abuse_email']}"
                  + (f" / {rdap['registrar_abuse_phone']}" if rdap.get("registrar_abuse_phone") else ""))
        if rdap.get("creation_date"):
            print(f"Kayıt tarihi: {rdap['creation_date']}")
        if rdap.get("age_days") is not None:
            print(f"Domain yaşı: {rdap['age_days']} gün")
        if rdap.get("expiration_date"):
            print(f"Son geçerlilik: {rdap['expiration_date']}")
        if rdap.get("updated_date"):
            print(f"Son güncelleme: {rdap['updated_date']}")
        if rdap.get("status"):
            print(f"Durum: {', '.join(rdap['status'])}")
        if rdap.get("dnssec") is not None:
            print(f"DNSSEC: {'etkin' if rdap['dnssec'] else 'devre dışı'}")
        if rdap.get("nameservers"):
            print(f"Nameserver'lar: {', '.join(rdap['nameservers'])}")

        # Kayıt sahibi / iletişim kayıtları
        owner_bits = [b for b in (rdap.get("registrant_name"), rdap.get("registrant_org")) if b]
        if owner_bits:
            print(f"Kayıt sahibi: {' / '.join(owner_bits)}")
        if rdap.get("registrant_email"):
            print(f"Kayıt sahibi e-posta: {rdap['registrant_email']}")
        if rdap.get("registrant_country"):
            print(f"Kayıt sahibi ülke: {rdap['registrant_country']}")

        for role_key, role_label in (("administrative", "Yönetici"), ("technical", "Teknik")):
            contact = (rdap.get("entities") or {}).get(role_key) or {}
            bits = [b for b in (contact.get("name"), contact.get("organization"),
                                contact.get("email"), contact.get("phone")) if b]
            if bits:
                print(f"{role_label} iletişim: {' / '.join(bits)}")

    censys = result.get("censys_result")
    if censys and censys.get("found"):
        print_header("Censys Detayı")
        services = censys.get("services", [])
        print(f"Açık servis sayısı: {len(services)}")
        for service in services:
            print(f"  - {format_service_detail(service)}")
        if censys.get("asn"):
            net = f"  Prefix: {censys['bgp_prefix']}" if censys.get("bgp_prefix") else ""
            print(f"ASN: {censys['asn']} ({censys.get('as_name') or '?'}){net}")
        location = ", ".join(p for p in (censys.get("city"), censys.get("province"),
                                         censys.get("country"), censys.get("continent")) if p)
        if location:
            print(f"Konum: {location}")
        if censys.get("postal_code"):
            print(f"Posta kodu: {censys['postal_code']}")
        if censys.get("timezone"):
            print(f"Saat dilimi: {censys['timezone']}")
        if censys.get("coordinates"):
            print(f"Koordinatlar: {censys['coordinates']}")
        if censys.get("whois_org"):
            print(f"Kayıtlı organizasyon: {censys['whois_org']}")


# ---------------------------------------------------------------------------
# Komutlar
# ---------------------------------------------------------------------------

def run_single(target: str, clients: Clients, full: bool, no_cache: bool) -> None:
    target = target.strip()
    result, cache_age = analyze_with_cache(target, clients, no_cache)

    if full:
        print_full_report(result, cache_age)
    else:
        print_compact_report(result, cache_age)
        print_info("\nDetaylı inceleme için --full ekleyin ya da: vtad --history "
                   f"{result.get('report_id', 'N')}")


def default_output_path(input_path: str) -> str:
    base, _ext = os.path.splitext(input_path)
    return f"{base}_sonuclar.xlsx"


def run_bulk(input_path: str, output_path: str | None, delay: float, clients: Clients, no_cache: bool) -> None:
    if not os.path.isfile(input_path):
        print_bad(f"Dosya bulunamadı: {input_path}")
        sys.exit(1)

    print_info(f"'{input_path}' dosyasından hedefler okunuyor...")
    try:
        targets = read_targets_from_excel(input_path)
    except Exception as exc:
        print_bad(f"Excel dosyası okunamadı: {exc}")
        sys.exit(1)

    if not targets:
        print_warn("Excel dosyasında kontrol edilecek IP/domain bulunamadı.")
        sys.exit(1)

    print_info(f"{len(targets)} hedef bulundu. Kontrol başlıyor "
               f"(API limitleri nedeniyle gerektiğinde otomatik bekleme yapılacak)...")

    results = []
    for idx, target in enumerate(targets, start=1):
        print_info(f"[{idx}/{len(targets)}] {target} kontrol ediliyor...")
        result, cache_age = analyze_with_cache(target, clients, no_cache)
        results.append(result)
        cache_note = " (önbellekten)" if cache_age is not None else ""
        VERDICT_PRINTERS[result["verdict_kind"]](f"  -> {result['verdict_text']}{cache_note}")

        if idx < len(targets) and delay > 0:
            time.sleep(delay)

    output_path = output_path or default_output_path(input_path)
    write_results_to_excel(output_path, results)

    bad_count = sum(1 for r in results if r["verdict_kind"] == "bad")
    warn_count = sum(1 for r in results if r["verdict_kind"] == "warn")
    ok_count = sum(1 for r in results if r["verdict_kind"] == "ok")

    print_header("Toplu Kontrol Özeti")
    print(f"Toplam hedef: {len(results)}")
    print_bad(f"Güvenilir değil: {bad_count}")
    print_warn(f"Şüpheli: {warn_count}")
    print_ok(f"Güvenilir: {ok_count}")
    print_info(f"Sonuçlar kaydedildi: {output_path}")


def run_history(arg: str) -> None:
    if arg == "list":
        entries = load_history()
        if not entries:
            print_info("Geçmişte kayıtlı analiz yok.")
            return

        print_header("Analiz Geçmişi")
        print(f"{'No':>4}  {'Tarih':<19}  {'Hedef':<30}  Sonuç")
        print("-" * 75)
        for entry in entries:
            no = entry.get("id", "-")
            timestamp = entry.get("timestamp", "")
            target = entry.get("target", "")[:30]
            verdict = entry.get("verdict_text", "")
            printer = VERDICT_PRINTERS.get(entry.get("verdict_kind"), print)
            printer(f"{no:>4}  {timestamp:<19}  {target:<30}  {verdict}")
        print_info(f"\nToplam {len(entries)} kayıt. Detay için: vtad --history <No>")
        return

    try:
        entry_id = int(arg)
    except ValueError:
        print_bad(f"Geçersiz rapor numarası: {arg}")
        sys.exit(1)

    entry = get_history_entry(entry_id)
    if entry is None:
        print_bad(f"#{entry_id} numaralı rapor bulunamadı. Listeyi görmek için: vtad --history")
        sys.exit(1)

    print_info(f"Rapor #{entry_id} — {entry.get('timestamp', '')}")
    print()
    print_full_report(entry)


def run_watch_add(target: str) -> None:
    if add_to_watchlist(target):
        print_ok(f"'{target}' izleme listesine eklendi.")
    else:
        print_warn(f"'{target}' zaten izleme listesinde.")


def run_watch_remove(target: str) -> None:
    if remove_from_watchlist(target):
        print_ok(f"'{target}' izleme listesinden çıkarıldı.")
    else:
        print_warn(f"'{target}' izleme listesinde bulunamadı.")


def run_watch_list() -> None:
    entries = load_watchlist()
    if not entries:
        print_info("İzleme listesi boş. Eklemek için: vtad --watch-add <hedef>")
        return

    print_header("İzleme Listesi")
    print(f"{'Hedef':<30}  {'Eklenme':<19}  {'Son Kontrol':<19}  Son Sonuç")
    print("-" * 90)
    for entry in entries:
        verdict_text = entry.get("last_verdict_text") or "henüz taranmadı"
        printer = VERDICT_PRINTERS.get(entry.get("last_verdict"), print)
        printer(f"{entry['target']:<30}  {entry.get('added_at', ''):<19}  "
                f"{entry.get('last_checked') or '-':<19}  {verdict_text}")


def run_watch_run(clients: Clients) -> None:
    entries = load_watchlist()
    if not entries:
        print_info("İzleme listesi boş. Eklemek için: vtad --watch-add <hedef>")
        return

    print_info(f"İzleme listesi taranıyor ({len(entries)} hedef)...")
    changes = 0

    for idx, entry in enumerate(entries, start=1):
        target = entry["target"]
        print_info(f"[{idx}/{len(entries)}] {target} kontrol ediliyor...")

        # İzleme güncel veri gerektirdiği için önbellek atlanır.
        result = analyze_target(target, clients)
        result["report_id"] = add_history_entry(result)
        store_result(target, result)

        previous = update_watch_result(target, result["verdict_kind"], result["verdict_text"])
        printer = VERDICT_PRINTERS[result["verdict_kind"]]

        if previous is not None and previous != result["verdict_kind"]:
            changes += 1
            printer(f"  -> {result['verdict_text']}  [DEĞİŞİKLİK! önceki sonuç farklıydı]")
        else:
            printer(f"  -> {result['verdict_text']}")

    print_header("İzleme Taraması Özeti")
    if changes:
        print_warn(f"{changes} hedefin sonucu bir önceki taramaya göre DEĞİŞTİ!")
    else:
        print_ok("Değişiklik yok; tüm hedefler önceki taramayla aynı durumda.")


# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vtad",
        description="Bir IP adresi ya da domain'in güvenilirliğini VirusTotal, AbuseIPDB, "
        "Censys ve RDAP (kayıt) verileriyle kontrol eder.",
        epilog="Örnekler:\n"
        "  vtad 8.8.8.8                  Tek hedef tara (kompakt özet)\n"
        "  vtad example.com --full        Tek hedef tara (tüm detaylar)\n"
        "  vtad --excel hedefler.xlsx     Excel'deki hedefleri toplu tara\n"
        "  vtad --history                 Geçmiş analizleri listele\n"
        "  vtad --history 5              5 numaralı raporun detayını göster\n"
        "  vtad --watch-add example.com   Hedefi izleme listesine ekle\n"
        "  vtad --watch-run               İzleme listesini tara, değişiklikleri göster\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="Kontrol edilecek IP adresi veya domain")
    parser.add_argument("--full", "-f", action="store_true",
                        help="Kompakt özet yerine tüm detayları göster")
    parser.add_argument("--no-cache", action="store_true",
                        help="Önbelleği atla, her zaman güncel tarama yap (önbellek süresi: 1 saat)")
    parser.add_argument("--excel", "-e", metavar="DOSYA",
                        help="A sütununda IP/domain listesi bulunan .xlsx dosyasını toplu tara")
    parser.add_argument("--output", "-o", metavar="DOSYA",
                        help="Toplu modda sonuç dosyası (varsayılan: <girdi>_sonuclar.xlsx)")
    parser.add_argument("--delay", "-d", type=float, default=0.0,
                        help="Toplu modda hedefler arasında ek bekleme saniyesi (limitler zaten otomatik)")
    parser.add_argument("--history", nargs="?", const="list", metavar="NO",
                        help="Geçmiş analizleri listele; numara verilirse o raporun detayını göster")
    parser.add_argument("--watch-add", metavar="HEDEF", help="Hedefi izleme listesine ekle")
    parser.add_argument("--watch-remove", metavar="HEDEF", help="Hedefi izleme listesinden çıkar")
    parser.add_argument("--watch-list", action="store_true", help="İzleme listesini göster")
    parser.add_argument("--watch-run", action="store_true",
                        help="İzleme listesindeki tüm hedefleri tara ve değişiklikleri raporla")
    return parser


BANNER = r"""
█   █ █████  ███  ████     ███ ████     ████   ███  █   █  ███  ███ █   █     ███  █   █ █████  ███  █   █ █████ ████
█   █   █   █   █ █   █     █  █   █    █   █ █   █ ██ ██ █   █  █  ██  █    █     █   █ █     █     █  █  █     █   █
█   █   █   █████ █   █     █  ████     █   █ █   █ █ █ █ █████  █  █ █ █    █     █████ ████  █     ███   ████  ████
 █ █    █   █   █ █   █     █  █        █   █ █   █ █   █ █   █  █  █  ██    █     █   █ █     █     █  █  █     █  █
  █     █   █   █ ████     ███ █        ████   ███  █   █ █   █ ███ █   █     ███  █   █ █████  ███  █   █ █████ █   █
"""


def print_banner() -> None:
    print(f"{Fore.CYAN}{Style.BRIGHT}{BANNER}{Style.RESET_ALL}")


def main() -> None:
    colorama_init()
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    # API anahtarı gerektirmeyen komutlar
    if args.history is not None:
        run_history(args.history)
        return
    if args.watch_add:
        run_watch_add(args.watch_add)
        return
    if args.watch_remove:
        run_watch_remove(args.watch_remove)
        return
    if args.watch_list:
        run_watch_list()
        return

    if args.target and args.excel:
        parser.error("'target' ve --excel aynı anda kullanılamaz")

    if not args.target and not args.excel and not args.watch_run:
        parser.print_help()
        return

    clients = load_clients()

    if args.watch_run:
        run_watch_run(clients)
    elif args.excel:
        run_bulk(args.excel, args.output, args.delay, clients, args.no_cache)
    else:
        run_single(args.target, clients, args.full, args.no_cache)


if __name__ == "__main__":
    main()
