import sys
import subprocess
import os
import sqlite3
import smtplib
import psutil
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from mcp.server.fastmcp import FastMCP

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- KRİTİK AYARLAR ---
# Gizli bilgiler koda yazılmaz; .env dosyasından okunur.
# Örnek için .env.example dosyasına bakın. Gmail için "Uygulama Şifresi" gerekir.
GONDEREN_MAIL = os.getenv("GONDEREN_MAIL", "")
MAIL_SIFRESI = os.getenv("MAIL_SIFRESI", "")
ALICI_MAIL = os.getenv("ALICI_MAIL", "")

# 1. Sunucu Tanımı
mcp = FastMCP("SiberGuvenlikLogSistemi")

# --- VERİTABANI KURULUMU ---
def veritabanini_baslat():
    try:
        conn = sqlite3.connect('guvenlik_loglari.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS saldiri_kayitlari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_adresi TEXT NOT NULL,
                saldiri_turu TEXT,
                tarih TEXT,
                detay TEXT
            )
        ''')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Veritabanı başlatma hatası: {e}")

veritabanini_baslat()

# --- ARAÇ 1: LOG OKUMA ---
@mcp.tool()
def docker_loglarini_getir(konteyner_adi: str = "bilet_satin_alma", satir_sayisi: int = 100) -> str:
    """Saldırı tespiti için Docker loglarını getirir."""
    try:
        komut = ["docker", "logs", "--tail", str(satir_sayisi), konteyner_adi]
        sonuc = subprocess.run(komut, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        if sonuc.returncode != 0: return f"HATA: {sonuc.stderr}"
        return sonuc.stdout
    except Exception as h: return f"KRİTİK HATA: {str(h)}"

# --- ARAÇ 2: GERÇEK SALDIRGAN ENGELLEME ---
@mcp.tool()
def saldirgan_ip_engelle(ip_adresi: str, sebep: str = "Siber Saldiri") -> str:
    """IP'yi hem .htaccess ile engeller hem de blacklist'e ekler."""
    dosya_adi = "blacklist.txt"
    tarih = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    konteyner = "bilet_satin_alma"
    try:
        # Dosyaya yaz
        with open(dosya_adi, "a", encoding="utf-8") as f:
            f.write(f"[{tarih}] ENGEL: {ip_adresi} | SEBEP: {sebep}\n")
        # Docker içine kural enjekte et
        bash_komutu = f"echo 'Deny from {ip_adresi}' >> /var/www/html/.htaccess"
        subprocess.run(["docker", "exec", konteyner, "sh", "-c", bash_komutu], check=False)
        return f"BAŞARILI: {ip_adresi} engellendi ve erişimi kesildi."
    except Exception as e: return f"HATA: {str(e)}"

# --- ARAÇ 3: ENGEL KALDIRMA ---
@mcp.tool()
def saldirgan_ip_engelini_kaldir(ip_adresi: str) -> str:
    """IP üzerindeki engeli kaldırır."""
    dosya_adi = "blacklist.txt"
    konteyner = "bilet_satin_alma"
    try:
        if os.path.exists(dosya_adi):
            with open(dosya_adi, "r", encoding="utf-8") as f:
                satirlar = f.readlines()
            with open(dosya_adi, "w", encoding="utf-8") as f:
                f.writelines([s for s in satirlar if ip_adresi not in s])
        bash_komutu = f"sed -i '/Deny from {ip_adresi}/d' /var/www/html/.htaccess"
        subprocess.run(["docker", "exec", konteyner, "sh", "-c", bash_komutu], check=False)
        return f"BAŞARILI: {ip_adresi} engeli kaldırıldı."
    except Exception as e: return f"HATA: {str(e)}"

# --- ARAÇ 4: VERİTABANI KAYDI ---
@mcp.tool()
def veritabanina_saldiri_kaydet(ip_adresi: str, saldiri_turu: str, detay: str) -> str:
    """Saldırıyı SQLite veritabanına kaydeder."""
    try:
        conn = sqlite3.connect('guvenlik_loglari.db')
        cursor = conn.cursor()
        tarih = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('INSERT INTO saldiri_kayitlari (ip_adresi, saldiri_turu, tarih, detay) VALUES (?, ?, ?, ?)', (ip_adresi, saldiri_turu, tarih, detay))
        conn.commit()
        conn.close()
        return f"KAYIT BAŞARILI: {ip_adresi} veritabanına işlendi."
    except Exception as e: return f"VERİTABANI HATASI: {str(e)}"

# --- ARAÇ 5: YENİ - YÖNETİCİYE MAİL GÖNDER (SMTP) ---
@mcp.tool()
def yoneticiye_mail_gonder(konu: str, mesaj_detayi: str) -> str:
    """Kritik durumlarda yöneticiye detaylı mail gönderir."""
    try:
        msg = MIMEMultipart()
        msg['From'] = GONDEREN_MAIL
        msg['To'] = ALICI_MAIL
        msg['Subject'] = f"🚨 SOC UYARISI: {konu}"
        
        msg.attach(MIMEText(mesaj_detayi, 'plain'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(GONDEREN_MAIL, MAIL_SIFRESI)
        server.sendmail(GONDEREN_MAIL, ALICI_MAIL, msg.as_string())
        server.quit()
        return "BAŞARILI: Yöneticiye uyarı maili gönderildi."
    except Exception as e: return f"MAIL HATASI: {str(e)}"

# --- ARAÇ 6: YENİ - SİSTEM KAYNAKLARI KONTROLÜ ---
@mcp.tool()
def sunucu_durumunu_kontrol_et() -> str:
    """Sunucunun CPU ve RAM kullanımını kontrol eder."""
    try:
        cpu = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory().percent
        return f"Sistem Durumu: CPU: %{cpu} | RAM: %{ram}"
    except Exception as e: return f"SİSTEM OKUMA HATASI: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="127.0.0.1", port=8000)