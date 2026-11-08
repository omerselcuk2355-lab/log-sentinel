import os
import ipaddress
import logging
import sqlite3
import smtplib
import subprocess
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

import psutil
from mcp.server.fastmcp import FastMCP

from detector import analiz_et

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- YOLLAR (G6: cwd'den bagimsiz, mutlak) ---
BASE_DIR = Path(__file__).resolve().parent
DB_YOLU = BASE_DIR / "guvenlik_loglari.db"
BLACKLIST_YOLU = BASE_DIR / "blacklist.txt"
AUDIT_LOG_YOLU = BASE_DIR / "logsentinel_audit.log"

# --- KRİTİK AYARLAR (gizli bilgiler .env'den okunur) ---
GONDEREN_MAIL = os.getenv("GONDEREN_MAIL", "")
MAIL_SIFRESI = os.getenv("MAIL_SIFRESI", "")
ALICI_MAIL = os.getenv("ALICI_MAIL", "")

HEDEF_KONTEYNER = os.getenv("HEDEF_KONTEYNER", "bilet_satin_alma")
HTACCESS_YOLU = "/var/www/html/.htaccess"
DOCKER_TIMEOUT = 15  # saniye

# --- WHITELIST (G5: asla engellenmeyecek IP'ler) ---
# .env'de IP_WHITELIST="1.2.3.4,5.6.7.8" seklinde genisletilebilir.
_wl_env = os.getenv("IP_WHITELIST", "")
WHITELIST = {"127.0.0.1", "::1"} | {x.strip() for x in _wl_env.split(",") if x.strip()}

# --- LOGLAMA (G4: audit trail — dosya + konsol) ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    handlers=[
        logging.FileHandler(AUDIT_LOG_YOLU, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("LogSentinel")

# 1. Sunucu Tanımı
mcp = FastMCP("SiberGuvenlikLogSistemi")


# ----------------- YARDIMCILAR -----------------
def _ip_gecerli_mi(ip_adresi: str) -> bool:
    """Girdinin gercek bir IPv4/IPv6 adresi oldugunu dogrular (G1: enjeksiyon savunmasi)."""
    try:
        ipaddress.ip_address(ip_adresi)
        return True
    except ValueError:
        return False


def _docker_calistir(args: list) -> subprocess.CompletedProcess:
    """docker komutlarini guvenli (shell'siz) ve timeout'lu calistirir."""
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        timeout=DOCKER_TIMEOUT,
    )


def _veritabanini_baslat():
    try:
        conn = sqlite3.connect(DB_YOLU)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS saldiri_kayitlari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_adresi TEXT NOT NULL,
                saldiri_turu TEXT,
                tarih TEXT,
                detay TEXT
            )
            """
        )
        # G4/O4: sik sorgulanan kolonlara index
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ip ON saldiri_kayitlari(ip_adresi)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tur ON saldiri_kayitlari(saldiri_turu)")
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Veritabani baslatma hatasi: %s", e)


_veritabanini_baslat()


# ----------------- ARAÇ 1: LOG OKUMA -----------------
@mcp.tool()
def docker_loglarini_getir(konteyner_adi: str = None, satir_sayisi: int = 100) -> str:
    """Saldırı tespiti için Docker loglarını getirir."""
    konteyner_adi = konteyner_adi or HEDEF_KONTEYNER
    try:
        satir = max(1, min(int(satir_sayisi), 5000))  # makul sinir
    except (TypeError, ValueError):
        satir = 100
    try:
        sonuc = _docker_calistir(["logs", "--tail", str(satir), konteyner_adi])
        if sonuc.returncode != 0:
            return f"HATA: {sonuc.stderr.strip() or 'Docker logu alinamadi'}"
        return sonuc.stdout
    except FileNotFoundError:
        return "KRİTİK HATA: 'docker' komutu bulunamadi (Docker kurulu/erisilebilir mi?)."
    except subprocess.TimeoutExpired:
        return "HATA: Docker log komutu zaman asimina ugradi."
    except Exception as h:
        return f"KRİTİK HATA: {h}"


# ----------------- ARAÇ 1.5: KURAL TABANLI ANALİZ (deterministik) -----------------
@mcp.tool()
def loglari_kurallarla_analiz_et(konteyner_adi: str = None, satir_sayisi: int = 300) -> str:
    """Docker loglarını deterministik kural motoruyla analiz eder.

    LLM'den ÖNCE çalışır: brute-force, SQL Injection, LFI ve anormal istek
    yoğunluğunu imza + sayaç tabanlı yakalar. Yapılandırılmış bir bulgu
    raporu döner; LLM bu raporu yorumlar (tek başına karar vermez).
    """
    ham = docker_loglarini_getir(konteyner_adi, satir_sayisi)
    if ham.startswith(("HATA", "KRİTİK HATA")):
        return ham
    sonuc = analiz_et(ham)
    logger.info("Kural analizi: %d satir, %d bulgu", sonuc.toplam_satir, len(sonuc.bulgular))
    return sonuc.rapor()


# ----------------- ARAÇ 2: SALDIRGAN ENGELLEME -----------------
@mcp.tool()
def saldirgan_ip_engelle(ip_adresi: str, sebep: str = "Siber Saldiri") -> str:
    """IP'yi doğrulayıp .htaccess ile engeller ve audit log'a işler."""
    # G1: girdi dogrulama — enjeksiyonu kaynaginda kes
    if not _ip_gecerli_mi(ip_adresi):
        logger.warning("Gecersiz IP ile engelleme denemesi reddedildi: %r", ip_adresi)
        return f"HATA: '{ip_adresi}' geçerli bir IP adresi değil. İşlem reddedildi."

    # G5: whitelist korumasi — kendini kilitlemeyi onle
    if ip_adresi in WHITELIST:
        logger.warning("Whitelist'teki IP engellenmek istendi, reddedildi: %s", ip_adresi)
        return f"REDDEDİLDİ: {ip_adresi} güvenli listede (whitelist), engellenemez."

    tarih = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    deny_satiri = f"Deny from {ip_adresi}"
    try:
        # G3: idempotent — zaten engelliyse tekrar ekleme
        kontrol = _docker_calistir(
            ["exec", HEDEF_KONTEYNER, "sh", "-c", f"grep -Fxq '{deny_satiri}' {HTACCESS_YOLU}"]
        )
        if kontrol.returncode == 0:
            logger.info("IP zaten engelli: %s", ip_adresi)
            return f"BİLGİ: {ip_adresi} zaten engelli (tekrar eklenmedi)."

        # .htaccess'e kural ekle (ip_adresi dogrulanmis bir IP oldugu icin guvenli)
        ekle = _docker_calistir(
            ["exec", HEDEF_KONTEYNER, "sh", "-c", f"echo '{deny_satiri}' >> {HTACCESS_YOLU}"]
        )
        if ekle.returncode != 0:
            # G2: gercek hata raporu — yaniltici "BASARILI" dondurme
            return f"HATA: Engelleme uygulanamadı: {ekle.stderr.strip() or 'docker exec basarisiz'}"

        # Z11: blacklist.txt = append-only audit kaydi
        with open(BLACKLIST_YOLU, "a", encoding="utf-8") as f:
            f.write(f"[{tarih}] ENGEL | {ip_adresi} | SEBEP: {sebep}\n")
        logger.info("IP engellendi: %s | sebep: %s", ip_adresi, sebep)
        return f"BAŞARILI: {ip_adresi} engellendi ve erişimi kesildi."
    except FileNotFoundError:
        return "KRİTİK HATA: 'docker' komutu bulunamadi."
    except subprocess.TimeoutExpired:
        return "HATA: Docker komutu zaman asimina ugradi."
    except Exception as e:
        logger.error("Engelleme hatasi (%s): %s", ip_adresi, e)
        return f"HATA: {e}"


# ----------------- ARAÇ 3: ENGEL KALDIRMA -----------------
@mcp.tool()
def saldirgan_ip_engelini_kaldir(ip_adresi: str) -> str:
    """IP üzerindeki engeli kaldırır."""
    if not _ip_gecerli_mi(ip_adresi):
        return f"HATA: '{ip_adresi}' geçerli bir IP adresi değil. İşlem reddedildi."

    tarih = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        # Z4: tam satir eslesmesi (substring degil) — sadece ilgili kurali sil
        sil = _docker_calistir(
            ["exec", HEDEF_KONTEYNER, "sh", "-c",
             f"sed -i '\\#^Deny from {ip_adresi}$#d' {HTACCESS_YOLU}"]
        )
        if sil.returncode != 0:
            return f"HATA: Engel kaldirilamadi: {sil.stderr.strip() or 'docker exec basarisiz'}"

        with open(BLACKLIST_YOLU, "a", encoding="utf-8") as f:
            f.write(f"[{tarih}] KALDIR | {ip_adresi}\n")
        logger.info("IP engeli kaldirildi: %s", ip_adresi)
        return f"BAŞARILI: {ip_adresi} engeli kaldırıldı."
    except FileNotFoundError:
        return "KRİTİK HATA: 'docker' komutu bulunamadi."
    except subprocess.TimeoutExpired:
        return "HATA: Docker komutu zaman asimina ugradi."
    except Exception as e:
        logger.error("Engel kaldirma hatasi (%s): %s", ip_adresi, e)
        return f"HATA: {e}"


# ----------------- ARAÇ 4: VERİTABANI KAYDI -----------------
@mcp.tool()
def veritabanina_saldiri_kaydet(ip_adresi: str, saldiri_turu: str, detay: str) -> str:
    """Saldırıyı SQLite veritabanına kaydeder."""
    try:
        conn = sqlite3.connect(DB_YOLU)
        cur = conn.cursor()
        tarih = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            "INSERT INTO saldiri_kayitlari (ip_adresi, saldiri_turu, tarih, detay) VALUES (?, ?, ?, ?)",
            (ip_adresi, saldiri_turu, tarih, detay),
        )
        conn.commit()
        conn.close()
        logger.info("DB kayit: %s | %s", ip_adresi, saldiri_turu)
        return f"KAYIT BAŞARILI: {ip_adresi} veritabanına işlendi."
    except Exception as e:
        logger.error("DB kayit hatasi: %s", e)
        return f"VERİTABANI HATASI: {e}"


# ----------------- ARAÇ 5: YÖNETİCİYE MAİL -----------------
@mcp.tool()
def yoneticiye_mail_gonder(konu: str, mesaj_detayi: str) -> str:
    """Kritik durumlarda yöneticiye detaylı mail gönderir."""
    if not (GONDEREN_MAIL and MAIL_SIFRESI and ALICI_MAIL):
        return "YAPILANDIRMA HATASI: Mail bilgileri .env dosyasinda eksik."
    try:
        msg = MIMEMultipart()
        msg["From"] = GONDEREN_MAIL
        msg["To"] = ALICI_MAIL
        msg["Subject"] = f"🚨 SOC UYARISI: {konu}"
        msg.attach(MIMEText(mesaj_detayi, "plain"))

        # Z9: timeout eklendi — ag sorununda asili kalmasin
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.starttls()
            server.login(GONDEREN_MAIL, MAIL_SIFRESI)
            server.sendmail(GONDEREN_MAIL, ALICI_MAIL, msg.as_string())
        logger.info("Uyari maili gonderildi: %s", konu)
        return "BAŞARILI: Yöneticiye uyarı maili gönderildi."
    except Exception as e:
        logger.error("Mail hatasi: %s", e)
        return f"MAIL HATASI: {e}"


# ----------------- ARAÇ 6: SİSTEM KAYNAKLARI -----------------
@mcp.tool()
def sunucu_durumunu_kontrol_et() -> str:
    """Sunucunun CPU ve RAM kullanımını kontrol eder."""
    try:
        cpu = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory().percent
        return f"Sistem Durumu: CPU: %{cpu} | RAM: %{ram}"
    except Exception as e:
        return f"SİSTEM OKUMA HATASI: {e}"


if __name__ == "__main__":
    # Tek giris noktasi baslat.py'dir (SSE). Dogrudan calistirma icin de SSE kullanilir.
    logger.info("LogSentinel MCP sunucusu baslatiliyor (SSE, :8000)...")
    mcp.settings.host = "0.0.0.0"
    mcp.settings.port = 8000
    mcp.run(transport="sse")
