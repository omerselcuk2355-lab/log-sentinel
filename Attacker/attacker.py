"""
Saldırı Simülatörü — SADECE kendi yerel test ortamınız içindir.

Tespit sisteminin (LogSentinel) her saldırı türünü yakalayıp yakalamadığını
denemek için kontrollü trafik üretir. Payload'lar GET sorgu dizesine de
konur; böylece web sunucusunun access log'unda görünür ve deterministik
kural katmanı tarafından yakalanabilir.

Kullanım:
  python attacker.py --mode all
  python attacker.py --mode brute --rate 20 --duration 15
  python attacker.py --mode burst          # anormal istek yoğunluğu
"""
import argparse
import random
import sys
import time

try:
    import requests
except ImportError:
    sys.exit("Bu betik 'requests' paketini gerektirir:  pip install requests")

VARSAYILAN_HEDEF = "http://localhost:8080"

BRUTE_KULLANICILAR = ["admin", "administrator", "root", "test", "user"]
BRUTE_SIFRELER = ["123456", "password", "admin123", "1234", "qwerty"]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "admin' --",
    "1 UNION SELECT username, password FROM users",
    "'; DROP TABLE users; --",
]
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "/proc/self/environ",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
]


def brute_force(s, hedef):
    u = random.choice(BRUTE_KULLANICILAR)
    p = random.choice(BRUTE_SIFRELER)
    s.post(f"{hedef}/backend/api/auth.php?action=login",
           data={"username": u, "password": p}, timeout=2)
    print(f"[BRUTE] {u}:{p}")


def sqli(s, hedef):
    pl = random.choice(SQLI_PAYLOADS)
    s.get(f"{hedef}/frontend/pages/search.php", params={"q": pl}, timeout=2)
    print(f"[SQLI ] {pl}")


def lfi(s, hedef):
    pl = random.choice(LFI_PAYLOADS)
    s.get(f"{hedef}/frontend/pages/view.php", params={"file": pl}, timeout=2)
    print(f"[LFI  ] {pl}")


def xss(s, hedef):
    pl = random.choice(XSS_PAYLOADS)
    s.get(f"{hedef}/frontend/pages/comment.php", params={"c": pl}, timeout=2)
    print(f"[XSS  ] {pl}")


def burst(s, hedef):
    # Kısa sürede çok sayıda istek -> "anormal istek yoğunluğu"
    for _ in range(15):
        s.get(f"{hedef}/frontend/pages/login.php", timeout=2)
    print("[BURST] 15 istek gönderildi")


MODLAR = {"brute": brute_force, "sqli": sqli, "lfi": lfi, "xss": xss, "burst": burst}


def main():
    ap = argparse.ArgumentParser(description="LogSentinel saldırı simülatörü (yalnızca yerel test).")
    ap.add_argument("--mode", default="all",
                    choices=[*MODLAR.keys(), "all"], help="Saldırı türü")
    ap.add_argument("--target", default=VARSAYILAN_HEDEF, help="Hedef URL")
    ap.add_argument("--rate", type=float, default=5, help="Saniyedeki istek sayısı")
    ap.add_argument("--duration", type=int, default=0, help="Saniye (0 = süresiz)")
    args = ap.parse_args()

    eylemler = list(MODLAR.values()) if args.mode == "all" else [MODLAR[args.mode]]
    bekleme = 1.0 / args.rate if args.rate > 0 else 0
    baslangic = time.time()

    print(f"⚔️  Simülatör başladı | mod={args.mode} | hedef={args.target} | rate={args.rate}/sn")
    print("-" * 55)
    s = requests.Session()
    try:
        while True:
            try:
                random.choice(eylemler)(s, args.target)
            except requests.RequestException as e:
                print(f"⚠️  Bağlantı hatası: {e}")
            if args.duration and (time.time() - baslangic) >= args.duration:
                print("✅ Süre doldu, simülatör durdu.")
                break
            time.sleep(bekleme)
    except KeyboardInterrupt:
        print("\n⏹️  Kullanıcı tarafından durduruldu.")


if __name__ == "__main__":
    main()
