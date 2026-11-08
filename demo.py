"""
Hızlı demo: Docker/n8n olmadan, tek komutla deterministik tespit motorunu
gerçek saldırı loglarıyla çalıştırır.

    python demo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "LogSentinel"))
from detector import analiz_et


def L(ip, method, path, status):
    return (f'{ip} - - [08/Nov/2026:14:22:01 +0000] '
            f'"{method} {path} HTTP/1.1" {status} 512 "-" "python-requests/2.31"')


def ornek_loglar():
    loglar = []
    # Normal trafik (gürültü) — yanlış alarm üretilmemeli
    for i in range(6):
        loglar.append(L("10.0.0.5", "GET", f"/frontend/pages/urun_{i}.php", "200"))
    # Brute force (aynı IP, çok sayıda başarısız giriş)
    for _ in range(12):
        loglar.append(L("45.33.12.7", "POST", "/backend/api/auth.php?action=login", "401"))
    # SQL Injection (URL-encoded)
    loglar.append(L("88.12.9.3", "GET", "/frontend/pages/search.php?q=%27%20OR%20%271%27=%271", "200"))
    loglar.append(L("88.12.9.3", "GET", "/frontend/pages/search.php?q=1%20UNION%20SELECT%20username,password%20FROM%20users", "200"))
    # LFI / Path Traversal
    loglar.append(L("88.12.9.3", "GET", "/frontend/pages/view.php?file=../../../../etc/passwd", "200"))
    # XSS
    loglar.append(L("200.1.2.3", "GET", "/frontend/pages/comment.php?c=%3Cscript%3Ealert(1)%3C/script%3E", "200"))
    # Anormal istek yoğunluğu (tek IP, kısa sürede çok istek)
    for i in range(55):
        loglar.append(L("111.222.111.222", "GET", f"/frontend/pages/login.php?x={i}", "200"))
    return "\n".join(loglar)


def main():
    # Windows konsolunda Türkçe karakterler için
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ham = ornek_loglar()
    satir_sayisi = len(ham.splitlines())
    print("=" * 62)
    print(f"  LogSentinel — Deterministik Tespit Motoru Demosu")
    print(f"  Girdi: {satir_sayisi} satırlık karışık access log (saldırı + normal)")
    print("=" * 62)
    sonuc = analiz_et(ham)
    print(sonuc.rapor())
    print("=" * 62)
    print(f"  {len(sonuc.bulgular)} bulgu | {sonuc.toplam_satir} satır analiz edildi | "
          f"{sonuc.parse_edilemeyen} parse edilemeyen")


if __name__ == "__main__":
    main()
