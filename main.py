# Geriye dönük uyumluluk köprüsü.
#
# Paket artık vtad/ altında ve pip ile kurulup `vtad` komutuyla çalışacak
# şekilde yapılandırıldı (bkz. pyproject.toml). Bu dosya, eskisi gibi
# `python main.py ...` yazmaya alışkın olanlar için bırakıldı - bağımlılıklar
# kurulu olduğu sürece (pip install -r requirements.txt) bu proje kök
# dizininden çalıştırılabilir, ayrıca paket kurulumu gerekmez.
from vtad.main import main

if __name__ == "__main__":
    main()
