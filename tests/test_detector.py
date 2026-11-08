"""detector.py için birim testleri. Harici bağımlılık gerektirmez."""
import sys
from pathlib import Path

# LogSentinel dizinini import yoluna ekle
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "LogSentinel"))

import detector  # noqa: E402
from detector import analiz_et, satirlari_parse_et, LogSatiri  # noqa: E402


def log_satiri(ip="1.2.3.4", method="GET", path="/index.php", status="200", agent="curl/8"):
    return (f'{ip} - - [10/Nov/2026:12:00:00 +0000] '
            f'"{method} {path} HTTP/1.1" {status} 512 "-" "{agent}"')


# ---------- Parser ----------
def test_parser_dogru_alanlari_cikarir():
    kayitlar, hata = satirlari_parse_et(log_satiri(ip="9.9.9.9", method="POST", path="/login.php", status="401"))
    assert hata == 0 and len(kayitlar) == 1
    k = kayitlar[0]
    assert (k.ip, k.method, k.path, k.status) == ("9.9.9.9", "POST", "/login.php", "401")


def test_parser_bozuk_satiri_sayar():
    kayitlar, hata = satirlari_parse_et("bu bir log satiri degil\n" + log_satiri())
    assert len(kayitlar) == 1 and hata == 1


def test_bos_girdi():
    assert analiz_et("").temiz_mi


# ---------- İmza tespiti ----------
def test_sqli_tespit():
    # Gerçek access log'da sorgu URL-encode'dur (boşluk -> %20)
    log = log_satiri(path="/search.php?q=%27%20OR%20%271%27=%271", status="200")
    s = analiz_et(log)
    assert any(b.saldiri_turu == "SQL Injection" for b in s.bulgular)


def test_sqli_union_select():
    log = log_satiri(path="/p.php?id=1%20UNION%20SELECT%20user,pass%20FROM%20users")
    assert any(b.saldiri_turu == "SQL Injection" for b in analiz_et(log).bulgular)


def test_lfi_tespit():
    log = log_satiri(path="/page.php?file=../../../../etc/passwd")
    assert any("LFI" in b.saldiri_turu for b in analiz_et(log).bulgular)


def test_lfi_url_encoded():
    # %2e%2e%2f == ../  (URL-decode sonrası yakalanmalı)
    log = log_satiri(path="/p.php?f=%2e%2e%2f%2e%2e%2fetc/passwd")
    assert any("LFI" in b.saldiri_turu for b in analiz_et(log).bulgular)


def test_xss_tespit():
    log = log_satiri(path="/comment.php?c=<script>alert(1)</script>")
    assert any(b.saldiri_turu == "XSS" for b in analiz_et(log).bulgular)


def test_temiz_trafik_bulgu_uretmez():
    loglar = "\n".join(log_satiri(path=f"/urun/{i}", status="200") for i in range(5))
    assert analiz_et(loglar).temiz_mi


# ---------- Davranışsal tespit ----------
def test_brute_force_esigi():
    loglar = "\n".join(log_satiri(ip="5.5.5.5", method="POST", path="/auth.php", status="401")
                       for _ in range(10))
    s = analiz_et(loglar)
    assert any(b.saldiri_turu == "Brute Force" and b.ip == "5.5.5.5" for b in s.bulgular)


def test_brute_force_esik_altinda_tetiklenmez():
    loglar = "\n".join(log_satiri(ip="5.5.5.5", method="POST", path="/auth.php", status="401")
                       for _ in range(3))
    assert not any(b.saldiri_turu == "Brute Force" for b in analiz_et(loglar).bulgular)


def test_basarili_girisler_brute_force_sayilmaz():
    loglar = "\n".join(log_satiri(ip="5.5.5.5", method="POST", path="/auth.php", status="200")
                       for _ in range(10))
    assert not any(b.saldiri_turu == "Brute Force" for b in analiz_et(loglar).bulgular)


def test_anormal_yogunluk():
    loglar = "\n".join(log_satiri(ip="7.7.7.7", path=f"/x/{i}", status="200") for i in range(60))
    assert any(b.saldiri_turu == "Anormal İstek Yoğunluğu" for b in analiz_et(loglar).bulgular)


def test_siddet_siniflamasi():
    loglar = "\n".join(log_satiri(ip="8.8.8.8", method="POST", path="/login", status="401")
                       for _ in range(20))
    bf = [b for b in analiz_et(loglar).bulgular if b.saldiri_turu == "Brute Force"]
    assert bf and bf[0].siddet == "YUKSEK"


def test_farkli_ipler_ayri_raporlanir():
    loglar = (log_satiri(ip="1.1.1.1", path="/p?q=<script>a</script>") + "\n" +
              log_satiri(ip="2.2.2.2", path="/p?f=../../etc/passwd"))
    s = analiz_et(loglar)
    ipler = {b.ip for b in s.bulgular}
    assert {"1.1.1.1", "2.2.2.2"} <= ipler
