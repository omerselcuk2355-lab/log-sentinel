# 🛡️ LLM Destekli Log İzleme ve Saldırı Tespit Sistemi

Bir otobüs bileti satış uygulamasının **Docker konteyner loglarını** sürekli izleyen, bir **dil modeli (LLM)** ile analiz eden ve şüpheli davranışlara karşı **otomatik savunma** üreten bir SOC (Güvenlik Operasyon Merkezi) otomasyonudur.

Loglar dil modeline (**Google Gemini**), bu proje için geliştirilen özel bir **MCP (Model Context Protocol) sunucusu** aracılığıyla aktarılır. İş akışı (orkestrasyon) **n8n** üzerinde çalışır ve uyarılar **Telegram** üzerinden iletilir.

Sistem; **brute force** giriş denemeleri, **SQL Injection / LFI** istekleri ve **anormal istek yoğunluğu** gibi şüpheli davranışları tespit ederek otomatik uyarı ve engelleme üretir.

**Teknolojiler:** n8n · LLM (Google Gemini) · MCP · Docker · Telegram · Python · SQLite

---

## 🧭 Mimari

```
┌──────────────────┐     Docker logs      ┌─────────────────────┐
│  Bilet Satış     │ ───────────────────► │  LogSentinel        │
│  Uygulaması      │                      │  (MCP Sunucusu /sse)│
│  (Docker)        │                      │  • log okuma        │
└──────────────────┘                      │  • IP engelle       │
         ▲                                 │  • DB kaydet        │
         │ engelleme (.htaccess)           │  • mail/uyarı       │
         │                                 └──────────┬──────────┘
         │                                            │ MCP (SSE)
         │   ┌─────────────┐   ┌─────────────┐ ┌──────▼──────────┐
         └── │  Zamanlayıcı │─► │  n8n AI     │◄┤  Google Gemini  │
             │  + Telegram │   │  Agent      │ │  (LLM)          │
             └─────────────┘   └──────┬──────┘ └─────────────────┘
                                      │ sonuç/uyarı
                                ┌─────▼──────┐
                                │  Telegram  │
                                └────────────┘
```

**Akış:** İki tetikleyici vardır — (1) **Schedule Trigger** belirli aralıklarla otomatik kontrol başlatır, (2) **Telegram Trigger** yönetici komutlarını karşılar. AI Agent (Google Gemini), **MCP Client (SSE)** üzerinden LogSentinel araçlarını çağırır → Docker loglarını ve sistem durumunu çeker → saldırıyı analiz eder → tespit halinde SQLite'a kaydeder, IP'yi engeller ve sonucu **Telegram** üzerinden raporlar. Otomatik kontrolde engelleme otonom yapılır; Telegram üzerinden konuşurken önce onay istenir. **Simple Memory** ile geçmiş olaylar (ör. daha önce engellenen IP'ler) hatırlanır.

---

## 📂 Proje Yapısı

```
MCP/
├── LogSentinel/            # MCP sunucusu (savunma tarafı)
│   ├── server.py           # 6 MCP aracı tanımlı
│   └── baslat.py           # Sunucuyu 0.0.0.0:8000'de başlatır
├── Attacker/
│   └── attacker.py         # Test için saldırı simülatörü (brute force + SQLi)
├── n8n/
│   └── log_izleme_workflow.json   # n8n'e import edilecek örnek iş akışı
├── .env.example            # Ortam değişkenleri şablonu
├── requirements.txt
└── README.md
```

---

## 🧰 MCP Araçları (`LogSentinel/server.py`)

| Araç | Görevi |
|------|--------|
| `docker_loglarini_getir` | Hedef konteynerin son loglarını çeker |
| `veritabanina_saldiri_kaydet` | Tespit edilen saldırıyı SQLite'a yazar |
| `saldirgan_ip_engelle` | IP'yi blacklist + `.htaccess` ile engeller |
| `saldirgan_ip_engelini_kaldir` | IP engelini kaldırır |
| `yoneticiye_mail_gonder` | Kritik durumda yöneticiye SMTP ile mail atar |
| `sunucu_durumunu_kontrol_et` | CPU / RAM kullanımını raporlar |

---

## 🚀 Kurulum ve Çalıştırma

### 1. Bağımlılıklar
```bash
pip install -r requirements.txt
```

### 2. Ortam değişkenleri
`.env.example` dosyasını `.env` olarak kopyalayın ve kendi bilgilerinizle doldurun:
```bash
cp .env.example .env
```
> ⚠️ Mail özelliği için Gmail **Uygulama Şifresi** gerekir (normal şifre değil):
> https://myaccount.google.com/apppasswords

### 3. MCP sunucusunu başlatın
```bash
cd LogSentinel
python baslat.py
# MCP Sunucusu: http://localhost:8000/sse
```

### 4. n8n iş akışını yükleyin
1. n8n arayüzünde **Import from File** ile `n8n/log_izleme_workflow.json` dosyasını içe aktarın.
2. **MCP Client** node'unun endpoint'inin `http://127.0.0.1:8000/sse` (transport: SSE) olduğundan emin olun.
3. Kendi **Credentials** bilgilerinizi n8n üzerinden ekleyin (anahtarlar workflow JSON'ında tutulmaz):
   - **Google Gemini (PaLM) API** — LLM için
   - **Telegram API** (bot token) — tetikleyici ve mesaj gönderme için
4. Workflow'u **aktif** edin ve Telegram botunuza mesaj atarak ya da zamanlayıcıyı bekleyerek test edin.

### 5. (Opsiyonel) Saldırıyı simüle edin
Sistemi test etmek için saldırı simülatörünü çalıştırın:
```bash
python Attacker/attacker.py
```
Birkaç saniye içinde n8n akışı logları çeker, LLM saldırıyı tespit eder ve savunma araçları devreye girer.

---

## 🔐 Güvenlik Notu

- Gizli bilgiler (mail şifresi, API anahtarı) **koda yazılmaz**; `.env` ve n8n Credentials üzerinden okunur.
- `.env`, `*.db` ve `blacklist.txt` dosyaları `.gitignore` ile repoya dâhil edilmez.
- `Attacker/attacker.py` yalnızca **kendi yerel test ortamınızda** kullanılmak içindir.
