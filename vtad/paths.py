import os

DATA_DIR = os.path.join(os.path.expanduser("~"), ".vtad")


def ensure_data_dir() -> str:
    os.makedirs(DATA_DIR, exist_ok=True)
    return DATA_DIR


def data_path(filename: str) -> str:
    """~/.vtad/ altında bir dosyanın tam yolunu döndürür (dizini gerekirse oluşturur).
    Paket pip ile kurulduğunda (site-packages) durum dosyaları oraya yazılamayabilir;
    bu yüzden tüm kalıcı veriler (kota, geçmiş, önbellek, izleme listesi, .env)
    kullanıcının ana dizinindeki ~/.vtad/ klasöründe tutulur."""
    ensure_data_dir()
    return os.path.join(DATA_DIR, filename)
