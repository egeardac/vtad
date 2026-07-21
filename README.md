# VTAD Threat Intelligence

Bir IP adresi veya domain'in güvenilirliğini VirusTotal, AbuseIPDB, Censys ve RDAP
verileriyle kontrol eden komut satırı aracı. Tüm kaynakların sonucu tek bir kompakt
raporda birleştirilir; istenirse `--full` ile tüm detaylar görüntülenir.

## Kurulum

Paket olarak kurup her yerden `vtad` komutuyla çalıştırmak için:

```
pip install -e .
```

(`-e` = editable/geliştirme kurulumu; kod değiştikçe yeniden kurmanıza gerek kalmaz.
Sadece kullanmak isteyip kodu değiştirmeyecekseniz `pip install .` de yeterlidir.)

Kurulum sonrası `vtad` komutu PATH'e eklenir ve **hangi klasörden çalıştırırsanız
çalıştırın** aynı şekilde çalışır. Paketi kurmak istemiyorsanız, proje kök dizininde
`pip install -r requirements.txt` yapıp `python main.py ...` şeklinde de
çalıştırabilirsiniz (eski kullanım şekli, geriye dönük uyumluluk için korunuyor).

### API anahtarları

İlk çalıştırmada anahtar yoksa program size tam olarak nereye yazmanız gerektiğini
söyler: **`~/.vtad/.env`** (kullanıcı ana dizininizdeki `.vtad` klasörü). Proje
dizinindeki `.env.example` dosyasını oraya kopyalayıp düzenleyin:

```
mkdir %USERPROFILE%\.vtad
copy .env.example %USERPROFILE%\.vtad\.env
```

- `VIRUSTOTAL_API_KEY` (zorunlu): https://www.virustotal.com/ (ücretsiz hesap → Profil → API Key)
- `ABUSEIPDB_API_KEY` (zorunlu): https://www.abuseipdb.com/ (ücretsiz hesap → Account → API)
- `CENSYS_API_KEY` (isteğe bağlı): https://platform.censys.io/ (Personal Access Token);
  yoksa Censys kontrolü atlanır.
- `RDAP_API_KEY` (isteğe bağlı): https://rdapapi.io/ (Bearer token); domainler için kayıt
  (registrar, kayıt sahibi, nameserver vb.) bilgisi sağlar, yoksa RDAP adımı atlanır.

## Veri konumu

Tüm kalıcı veriler (`.env`, kota sayaçları, geçmiş, önbellek, izleme listesi)
**`~/.vtad/`** klasöründe tutulur — programın kendi kod dizininde değil. Bu sayede:
- `vtad` komutunu hangi klasörden çalıştırırsanız çalıştırın, aynı geçmiş/önbellek/
  ayarlar kullanılır.
- Paket pip ile (site-packages içine) kurulsa bile veri yazma sorunu yaşanmaz.

## Kullanım

Tüm komutları görmek için:

```
vtad --help
```

### Tek hedef tarama

```
vtad 8.8.8.8
vtad example.com
```

Çıktı, tüm kaynakların önemli bulgularını tek listede toplar:

```
Hedef: wicar.org (domain -> 199.34.228.69)

SONUÇ: GÜVENİLİR DEĞİL  (rapor #10)
  VirusTotal : 1 zararlı, 1 şüpheli / 91 motor — Chong Lua Dao
  AbuseIPDB  : skor 0/100, 0 rapor — US, Weebly, Inc.
  RDAP       : 5004 günlük domain (2012-11-07) — PDR Ltd. — sahip: Patrick Webster
  Censys     : 13 açık servis: 80/HTTP, 443/HTTP ... — AS27647 WEEBLY
```

Kompakt çıktıda ayrıca birleşik bir **Konum/Ağ** satırı bulunur (şehir, ülke,
koordinatlar, ASN/operatör — Censys ve AbuseIPDB verilerinden birleştirilir).

`--full` ile her kaynağın tüm detayları açılır:

```
vtad wicar.org --full
```

- **VirusTotal**: motor listeleri, topluluk oyları, etiketler, ASN/ağ, domain
  kategorileri, popülerlik sıralaması (Alexa/Cisco vb.), DNS kayıtları (A/MX/NS/TXT...)
- **AbuseIPDB**: skor, rapor sayısı, farklı kullanıcı sayısı, ülke, ISP, kullanım tipi,
  domain, hostname'ler, Tor/beyaz liste durumu, son bildirim tarihi, kategori dökümü
- **RDAP** (kayıt): registrar + abuse iletişim (IANA ID, e-posta, telefon),
  kayıt/son geçerlilik/güncelleme tarihleri, domain yaşı, durum kodları, DNSSEC,
  nameserver'lar, kayıt sahibi/yönetici/teknik iletişim kayıtları (ad, org, e-posta,
  telefon, ülke)
- **Censys**: tüm açık portlar + çalışan yazılım, ASN/prefix, tam konum (şehir, il,
  ülke, posta kodu, saat dilimi, koordinatlar), kayıtlı organizasyon

Domain girildiğinde: VirusTotal domain analizi + DNS ile IP'ye çözümleme + o IP için
AbuseIPDB ve Censys kontrolü + RDAP kayıt sorgusu yapılır.

### Önbellek (cache)

Her tarama sonucu 1 saat boyunca `~/.vtad/result_cache.json` içinde saklanır. Aynı
hedef bu süre içinde tekrar sorgulanırsa API'ye gidilmez, önceki sonuç anında
gösterilir ("önbellekten" notuyla). Güncel tarama zorlamak için:

```
vtad 8.8.8.8 --no-cache
```

### Geçmiş

Her tarama otomatik olarak `~/.vtad/analysis_history.json` dosyasına kalıcı bir
rapor numarasıyla kaydedilir.

```
vtad --history        # tüm geçmişi numaralı liste halinde göster
vtad --history 5      # 5 numaralı raporun tüm detaylarını göster
```

### İzleme listesi (watchlist)

Düzenli takip etmek istediğiniz hedefleri listeye ekleyin; `--watch-run` her
çalıştırıldığında hepsi güncel olarak taranır (önbellek atlanır) ve bir önceki
taramaya göre **sonucu değişen** hedefler vurgulanır (örn. daha önce güvenilirken
zararlı çıkmaya başlayan bir domain).

```
vtad --watch-add example.com
vtad --watch-remove example.com
vtad --watch-list
vtad --watch-run
```

### Excel'den toplu tarama

Bir `.xlsx` dosyasının **A sütununa** hedefleri alt alta yazın (ilk satırdaki başlık
otomatik atlanır):

```
vtad --excel hedefler.xlsx
vtad --excel hedefler.xlsx --output sonuc.xlsx
```

Sonuçlar (girdi dosyasıyla aynı klasöre, `~/.vtad/` içine değil); VirusTotal/AbuseIPDB/
RDAP/Censys sütunları, konum bilgisi (ülke, şehir, ASN/operatör, koordinatlar) ve
renkli sonuç hücresiyle `<girdi>_sonuclar.xlsx` dosyasına yazılır. Önbellekteki güncel
sonuçlar API'ye gidilmeden kullanılır (`--no-cache` ile kapatılabilir).

## API Kota/Hız Limitleri (Ücretsiz Planlar)

| API | Limit | Uygulanan davranış |
|---|---|---|
| VirusTotal | 4 istek/dakika | İlk 4 istek hemen gönderilir; 5. istekte dakikalık pencere dolana kadar geri sayımla beklenir |
| VirusTotal | 500 istek/gün, 15.500 istek/ay | Limit dolunca istek gönderilmez, hata gösterilir |
| AbuseIPDB | 1.000 IP check/gün | Limit dolunca istek gönderilmez, hata gösterilir |

Sayaçlar `~/.vtad/.vt_quota_state.json` / `~/.vtad/.abuseipdb_quota_state.json`
dosyalarında tutulur ve gün/ay değişince otomatik sıfırlanır. Önbellek sayesinde
tekrarlanan sorgular kotadan hiç harcamaz.

## Değerlendirme Mantığı

- VirusTotal'da ≥1 motor "malicious" **veya** AbuseIPDB skoru ≥ 25: **GÜVENİLİR DEĞİL**
- VirusTotal'da ≥1 motor "suspicious" **veya** AbuseIPDB skoru 1-24: **ŞÜPHELİ / DİKKAT**
- Aksi halde: **GÜVENİLİR**

RDAP ve Censys verileri bilgilendirme amaçlıdır, karara etki etmez; ancak 30 günden
yeni kayıtlı domainlerde raporda `[ÇOK YENİ KAYIT]` uyarısı gösterilir.

## Proje yapısı

```
vtad/                  # asıl paket - "vtad" komutu buradan çalışır
  main.py               # CLI, argüman ayrıştırma, raporlama
  paths.py               # ~/.vtad/ veri dizini yönetimi
  vt_client.py            # VirusTotal API istemcisi
  abuseipdb_client.py      # AbuseIPDB API istemcisi
  censys_client.py         # Censys API istemcisi
  rdap_client.py            # RDAP (domain kayıt) istemcisi
  quota_tracker.py           # hız limiti / günlük-aylık kota takibi
  cache.py                    # sonuç önbelleği
  history.py                   # analiz geçmişi
  watchlist.py                  # izleme listesi
  excel_io.py                    # excel okuma/yazma
  utils.py                        # IP/domain tespiti, renkli çıktı
pyproject.toml           # paket tanımı, "vtad" komutu buradan kaydedilir
main.py                   # eski "python main.py" alışkanlığı için köprü dosya
```
