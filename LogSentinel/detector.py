"""
Deterministik (kural tabanlı) saldırı tespit katmanı.

Amaç: Ham logları doğrudan LLM'e yollamadan önce, hızlı/ucuz/deterministik
bir ön-filtre ile bilinen saldırı imzalarını ve istatistiksel anomalileri
(brute-force, istek yoğunluğu) yakalamak. LLM bu katmandan sonra yalnızca
belirsiz/karmaşık durumları YORUMLAR — tek başına KARAR VERİCİ değildir.

Harici bağımlılık yoktur (yalnızca stdlib), böylece izole test edilebilir.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import unquote

# Apache "combined" access log formatı:
# 172.17.0.1 - - [10/Nov/2026:12:00:00 +0000] "POST /login.php HTTP/1.1" 401 512 "-" "python-requests/2.31"
LOG_DESENI = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<tarih>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"[^"]*"\s+"(?P<agent>[^"]*)")?'
)

# Saldırı imzaları (URL-decode edilmiş istek hedefi üzerinde aranır)
IMZALAR: dict[str, list[re.Pattern]] = {
    "SQL Injection": [
        re.compile(r"('|\")\s*(or|and)\s+('|\")?\d+('|\")?\s*=\s*('|\")?\d+", re.I),
        re.compile(r"\bunion\b.{0,40}\bselect\b", re.I),
        re.compile(r"(--|#|;)\s*$"),
        re.compile(r"\b(select|insert|update|delete|drop)\b.{0,30}\b(from|into|table)\b", re.I),
    ],
    "LFI / Path Traversal": [
        re.compile(r"(\.\./|\.\.\\){1,}"),
        re.compile(r"/etc/passwd|/etc/shadow|/proc/self/environ", re.I),
        re.compile(r"php://(filter|input)|data://|expect://", re.I),
    ],
    "XSS": [
        re.compile(r"<\s*script", re.I),
        re.compile(r"on(error|load|mouseover)\s*=", re.I),
        re.compile(r"javascript\s*:", re.I),
    ],
}

# Brute-force / yoğunluk eşikleri (saniye / adet)
VARSAYILAN_ESIKLER = {
    "brute_force_pencere_sn": 60,
    "brute_force_esik": 8,       # 60 sn'de 8+ başarısız giriş
    "yogunluk_pencere_sn": 10,
    "yogunluk_esik": 50,         # 10 sn'de 50+ istek
}

# Giriş (login/auth) uç noktaları ve "başarısız" sayılan statüler
GIRIS_YOLU = re.compile(r"(login|auth|signin|giris)", re.I)
BASARISIZ_STATU = {"401", "403", "400"}


@dataclass
class LogSatiri:
    ip: str
    method: str
    path: str
    status: str
    agent: str = ""


@dataclass
class Bulgu:
    ip: str
    saldiri_turu: str
    siddet: str          # "DUSUK" | "ORTA" | "YUKSEK"
    kanit: str
    sayi: int = 1

    def ozet(self) -> str:
        return f"[{self.siddet}] {self.ip} -> {self.saldiri_turu} ({self.sayi}x): {self.kanit}"


@dataclass
class AnalizSonucu:
    bulgular: list[Bulgu] = field(default_factory=list)
    toplam_satir: int = 0
    parse_edilemeyen: int = 0

    @property
    def temiz_mi(self) -> bool:
        return len(self.bulgular) == 0

    def rapor(self) -> str:
        if self.temiz_mi:
            return f"TEMIZ — {self.toplam_satir} satır analiz edildi, şüpheli aktivite yok."
        satirlar = [f"{len(self.bulgular)} bulgu ({self.toplam_satir} satır analiz edildi):"]
        for b in sorted(self.bulgular, key=lambda x: x.sayi, reverse=True):
            satirlar.append("  " + b.ozet())
        return "\n".join(satirlar)


def satirlari_parse_et(log_metni: str) -> tuple[list[LogSatiri], int]:
    """Ham log metnini yapılandırılmış satırlara çevirir. (satirlar, parse_edilemeyen_sayisi)"""
    kayitlar: list[LogSatiri] = []
    parse_edilemeyen = 0
    for ham in log_metni.splitlines():
        ham = ham.strip()
        if not ham:
            continue
        m = LOG_DESENI.search(ham)
        if not m:
            parse_edilemeyen += 1
            continue
        kayitlar.append(
            LogSatiri(
                ip=m.group("ip"),
                method=m.group("method"),
                path=m.group("path"),
                status=m.group("status"),
                agent=(m.group("agent") or ""),
            )
        )
    return kayitlar, parse_edilemeyen


def imza_tespit(kayitlar: list[LogSatiri]) -> list[Bulgu]:
    """İmza tabanlı tespit: her istek hedefinde bilinen payload'ları arar."""
    # (ip, tur) -> (sayi, ilk_kanit)
    birikim: dict[tuple[str, str], list] = defaultdict(lambda: [0, ""])
    for k in kayitlar:
        hedef = unquote(k.path)
        for tur, desenler in IMZALAR.items():
            if any(d.search(hedef) for d in desenler):
                anahtar = (k.ip, tur)
                birikim[anahtar][0] += 1
                if not birikim[anahtar][1]:
                    birikim[anahtar][1] = hedef[:120]
    bulgular = []
    for (ip, tur), (sayi, kanit) in birikim.items():
        siddet = "YUKSEK" if sayi >= 5 else ("ORTA" if sayi >= 2 else "DUSUK")
        bulgular.append(Bulgu(ip=ip, saldiri_turu=tur, siddet=siddet, kanit=kanit, sayi=sayi))
    return bulgular


def davranis_tespit(kayitlar: list[LogSatiri], esikler: dict = None) -> list[Bulgu]:
    """İstatistiksel tespit: brute-force ve anormal istek yoğunluğu (sayac tabanlı)."""
    esikler = esikler or VARSAYILAN_ESIKLER
    bulgular = []

    istek_sayisi: dict[str, int] = defaultdict(int)
    basarisiz_giris: dict[str, int] = defaultdict(int)
    for k in kayitlar:
        istek_sayisi[k.ip] += 1
        if GIRIS_YOLU.search(k.path) and k.status in BASARISIZ_STATU:
            basarisiz_giris[k.ip] += 1

    for ip, sayi in basarisiz_giris.items():
        if sayi >= esikler["brute_force_esik"]:
            bulgular.append(Bulgu(
                ip=ip, saldiri_turu="Brute Force",
                siddet="YUKSEK" if sayi >= esikler["brute_force_esik"] * 2 else "ORTA",
                kanit=f"{sayi} başarısız giriş denemesi", sayi=sayi,
            ))

    for ip, sayi in istek_sayisi.items():
        if sayi >= esikler["yogunluk_esik"]:
            bulgular.append(Bulgu(
                ip=ip, saldiri_turu="Anormal İstek Yoğunluğu",
                siddet="YUKSEK" if sayi >= esikler["yogunluk_esik"] * 2 else "ORTA",
                kanit=f"{sayi} istek", sayi=sayi,
            ))
    return bulgular


def analiz_et(log_metni: str, esikler: dict = None) -> AnalizSonucu:
    """Ana giriş noktası: ham logu alır, tüm kuralları uygular, AnalizSonucu döner."""
    kayitlar, parse_edilemeyen = satirlari_parse_et(log_metni)
    bulgular = imza_tespit(kayitlar) + davranis_tespit(kayitlar, esikler)
    return AnalizSonucu(
        bulgular=bulgular,
        toplam_satir=len(kayitlar),
        parse_edilemeyen=parse_edilemeyen,
    )
