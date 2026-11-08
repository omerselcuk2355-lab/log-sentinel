# 🛡️ LLM Destekli Log İzleme ve Saldırı Tespit Sistemi

Bir otobüs bileti satış uygulamasının **Docker konteyner loglarını** sürekli izleyen, bir **dil modeli (LLM)** ile analiz eden ve şüpheli davranışlara karşı **otomatik savunma** üreten bir SOC (Güvenlik Operasyon Merkezi) otomasyonudur.

Loglar dil modeline (**Google Gemini**), bu proje için geliştirilen özel bir **MCP (Model Context Protocol) sunucusu** aracılığıyla aktarılır. İş akışı (orkestrasyon) **n8n** üzerinde çalışır ve uyarılar **Telegram** üzerinden iletilir.

Sistem; **brute force** giriş denemeleri, **SQL Injection / LFI** istekleri ve **anormal istek yoğunluğu** gibi şüpheli davranışları tespit ederek otomatik uyarı ve engelleme üretir.

> **Tasarım kararı — Hibrit tespit (defense in depth):** Tespit yalnızca LLM'e bırakılmaz. Önce **deterministik bir kural katmanı** (`detector.py`) imza (SQLi/LFI/XSS) ve sayaç (brute-force/yoğunluk) tabanlı hızlı/ucuz tespit yapar; LLM bu yapılandırılmış bulguları **yorumlar ve aksiyon alır**, tek başına karar verici değildir. Bu; maliyeti, gecikmeyi, non-determinizmi ve halüsinasyon riskini azaltır.

**Teknolojiler:** n8n · LLM (Google Gemini) · MCP · Docker · Telegram · Python · SQLite · pytest

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
│   ├── server.py           # MCP araçları (log, analiz, engelle, DB, mail, sistem)
│   ├── detector.py         # Deterministik kural tabanlı tespit motoru
│   └── baslat.py           # Sunucuyu 0.0.0.0:8000'de (SSE) başlatır
├── Attacker/
│   └── attacker.py         # Saldırı simülatörü (brute/sqli/lfi/xss/burst modları)
├── tests/
│   └── test_detector.py    # Tespit motoru birim testleri (pytest)
├── n8n/
│   └── log_izleme_workflow.json   # n8n iş akışı (14 node)
├── .env.example            # Ortam değişkenleri şablonu
├── requirements.txt
└── README.md
```

---

## 🧰 MCP Araçları (`LogSentinel/server.py`)

| Araç | Görevi |
|------|--------|
| `docker_loglarini_getir` | Hedef konteynerin son loglarını çeker |
| `loglari_kurallarla_analiz_et` | Logları deterministik kural motoruyla analiz edip yapılandırılmış bulgu raporu döner |
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
Sistemi test etmek için saldırı simülatörünü çalıştırın (yalnızca kendi yerel ortamınızda):
```bash
python Attacker/attacker.py --mode all           # tüm saldırı türleri
python Attacker/attacker.py --mode brute --rate 20   # brute force
python Attacker/attacker.py --mode burst          # anormal istek yoğunluğu
```
Birkaç saniye içinde n8n akışı logları çeker, deterministik katman + LLM saldırıyı tespit eder ve savunma araçları devreye girer.

---

## 🧪 Testler

Deterministik tespit katmanı (`detector.py`) birim testlerle doğrulanır:
```bash
pytest -q
```
Testler parser, SQLi/LFI/XSS imzaları ve brute-force/yoğunluk eşiklerini kapsar; harici servis veya Docker gerektirmez.

---

## 🔐 Güvenlik Notu

- Gizli bilgiler (mail şifresi, API anahtarı) **koda yazılmaz**; `.env` ve n8n Credentials üzerinden okunur.
- `.env`, `*.db` ve `blacklist.txt` dosyaları `.gitignore` ile repoya dâhil edilmez.
- `Attacker/attacker.py` yalnızca **kendi yerel test ortamınızda** kullanılmak içindir.
