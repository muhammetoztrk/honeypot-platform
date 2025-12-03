# 🧪 Honeypot Platform - Test Senaryoları

Bu doküman, Honeypot Platform'un tüm özelliklerini test etmek için kapsamlı test senaryolarını içerir.

## 📋 Test Kategorileri

1. [Kurulum ve Setup](#1-kurulum-ve-setup)
2. [Authentication](#2-authentication)
3. [Dashboard](#3-dashboard)
4. [Node Yönetimi](#4-node-yönetimi)
5. [Honeypot Yönetimi](#5-honeypot-yönetimi)
6. [Event ve IOC](#6-event-ve-ioc)
7. [Alert Sistemi](#7-alert-sistemi)
8. [Threat Intelligence](#8-threat-intelligence)
9. [Reports](#9-reports)
10. [Settings](#10-settings)
11. [Advanced Features](#11-advanced-features)
12. [API Testleri](#12-api-testleri)
13. [Security Testleri](#13-security-testleri)
14. [Performance Testleri](#14-performance-testleri)

---

## 1. Kurulum ve Setup

### 1.1 Docker Compose Başlatma
- [ ] `docker-compose up -d` komutu çalıştırılır
- [ ] Tüm servisler başarıyla başlar (postgres, backend, frontend)
- [ ] `docker-compose ps` ile tüm container'ların "Up" durumunda olduğu doğrulanır
- [ ] Backend health check: `curl http://localhost:8000/health` başarılı yanıt döner

**Beklenen Sonuç:** Tüm servisler çalışır durumda

### 1.2 Setup Wizard - Adım 1: Database Configuration
- [ ] `http://localhost:3000` adresine gidilir
- [ ] Otomatik olarak Setup Wizard açılır
- [ ] Database bağlantı durumu kontrol edilir
- [ ] "✓ Database Connected" mesajı görünür
- [ ] Database version ve table count bilgileri görüntülenir
- [ ] "Next" butonuna tıklanır

**Beklenen Sonuç:** Database bağlantısı başarılı, Adım 2'ye geçilir

### 1.3 Setup Wizard - Adım 2: Admin Account
- [ ] Email alanına geçerli bir email girilir (örn: admin@example.com)
- [ ] Password alanına en az 8 karakter şifre girilir
- [ ] Confirm Password alanına aynı şifre girilir
- [ ] Şifreler eşleşmezse hata mesajı görünür
- [ ] Şifre 8 karakterden kısa ise hata mesajı görünür
- [ ] Tüm alanlar doğru doldurulduğunda "Next" butonu aktif olur
- [ ] "Next" butonuna tıklanır

**Beklenen Sonuç:** Admin hesabı bilgileri doğrulanır, Adım 3'e geçilir

### 1.4 Setup Wizard - Adım 3: Organization & SMTP
- [ ] Organization Name alanı görünür (varsayılan: "Default Organization")
- [ ] Organization Name değiştirilebilir
- [ ] SMTP ayarları opsiyonel olarak girilebilir
- [ ] SMTP alanları boş bırakılabilir
- [ ] "Complete Setup" butonuna tıklanır
- [ ] "Setup Complete!" mesajı görünür
- [ ] 2 saniye sonra otomatik olarak login sayfasına yönlendirilir

**Beklenen Sonuç:** Setup tamamlanır, login sayfasına yönlendirilir

---

## 2. Authentication

### 2.1 Login
- [ ] Login sayfası açılır
- [ ] Setup sırasında oluşturulan email ve şifre ile giriş yapılır
- [ ] Geçersiz email/şifre ile giriş denemesi yapılır → Hata mesajı görünür
- [ ] Boş alanlarla giriş denemesi yapılır → Validation hatası görünür
- [ ] Başarılı giriş sonrası Dashboard'a yönlendirilir

**Beklenen Sonuç:** Sadece doğru bilgilerle giriş yapılabilir

### 2.2 Logout
- [ ] Sağ üstteki kullanıcı menüsünden "Logout" seçilir
- [ ] Login sayfasına yönlendirilir
- [ ] Token geçersiz hale gelir (tekrar giriş gerekir)

**Beklenen Sonuç:** Başarıyla çıkış yapılır

### 2.3 Token Expiry
- [ ] Login yapılır
- [ ] Token süresi dolana kadar beklenir (24 saat)
- [ ] Token süresi dolduğunda API istekleri 401 döner
- [ ] Otomatik olarak login sayfasına yönlendirilir

**Beklenen Sonuç:** Token süresi dolduğunda yeniden giriş gerekir

---

## 3. Dashboard

### 3.1 Dashboard Yükleme
- [ ] Login sonrası Dashboard açılır
- [ ] Tüm metrikler görüntülenir:
  - [ ] Total Nodes
  - [ ] Total Honeypots
  - [ ] Active Sessions
  - [ ] Total IOCs
- [ ] Metrikler doğru sayıları gösterir

**Beklenen Sonuç:** Dashboard başarıyla yüklenir, tüm metrikler görünür

### 3.2 Real-time Updates
- [ ] Dashboard açıkken yeni bir event oluşturulur
- [ ] WebSocket üzerinden gerçek zamanlı güncelleme gelir
- [ ] Metrikler otomatik güncellenir
- [ ] Recent Events listesi güncellenir

**Beklenen Sonuç:** Gerçek zamanlı güncellemeler çalışır

### 3.3 Event Trends Chart
- [ ] "Event Trends (Last 24 Hours)" grafiği görünür
- [ ] Grafik doğru verileri gösterir
- [ ] Grafik interaktif çalışır (hover, zoom)

**Beklenen Sonuç:** Grafik başarıyla render edilir

### 3.4 Top Attackers Panel
- [ ] "Top Attackers" paneli görünür
- [ ] En çok saldırı yapan IP'ler listelenir
- [ ] Risk skorları görüntülenir
- [ ] IP'lere tıklanarak detay sayfasına gidilir

**Beklenen Sonuç:** Top attackers doğru listelenir

---

## 4. Node Yönetimi

### 4.1 Node Listesi
- [ ] Nodes sayfasına gidilir
- [ ] Mevcut node'lar listelenir (varsayılan: "Default Node")
- [ ] Her node için şu bilgiler görünür:
  - [ ] Node adı
  - [ ] API Key (maskelenmiş)
  - [ ] Durum (online/offline)
  - [ ] Oluşturulma tarihi

**Beklenen Sonuç:** Tüm node'lar listelenir

### 4.2 Yeni Node Oluşturma
- [ ] "Create Node" butonuna tıklanır
- [ ] Node adı girilir (örn: "Production Node")
- [ ] "Create" butonuna tıklanır
- [ ] Yeni node listede görünür
- [ ] API Key otomatik oluşturulur

**Beklenen Sonuç:** Yeni node başarıyla oluşturulur

### 4.3 Node Silme
- [ ] Bir node seçilir
- [ ] "Delete" butonuna tıklanır
- [ ] Onay mesajı görünür
- [ ] Onaylandığında node silinir
- [ ] Node'a bağlı honeypot'lar varsa uyarı verilir

**Beklenen Sonuç:** Node başarıyla silinir (veya uyarı verilir)

### 4.4 API Key Görüntüleme
- [ ] Node'un API Key'i görüntülenir
- [ ] "Show" butonuna tıklanarak tam key görüntülenir
- [ ] "Copy" butonu ile key kopyalanır

**Beklenen Sonuç:** API Key doğru görüntülenir ve kopyalanır

---

## 5. Honeypot Yönetimi

### 5.1 Honeypot Listesi
- [ ] Honeypots sayfasına gidilir
- [ ] Mevcut honeypot'lar listelenir
- [ ] Her honeypot için şu bilgiler görünür:
  - [ ] Honeypot adı
  - [ ] Template türü
  - [ ] Port
  - [ ] Durum (running/stopped)
  - [ ] Node

**Beklenen Sonuç:** Tüm honeypot'lar listelenir

### 5.2 Yeni Honeypot Oluşturma
- [ ] "Create Honeypot" butonuna tıklanır
- [ ] Form açılır:
  - [ ] Name: Honeypot adı girilir
  - [ ] Template: Template seçilir (SSH, Web, Database, vb.)
  - [ ] Node: Node seçilir
  - [ ] Port: Port numarası girilir (template'e göre varsayılan port önerilir)
  - [ ] Listen IP: IP adresi girilir (varsayılan: 0.0.0.0)
- [ ] "Create" butonuna tıklanır
- [ ] Yeni honeypot listede görünür (durum: stopped)

**Beklenen Sonuç:** Yeni honeypot başarıyla oluşturulur

### 5.3 Honeypot Başlatma
- [ ] Bir honeypot seçilir (durum: stopped)
- [ ] "Start" butonuna tıklanır
- [ ] Honeypot başlatılır
- [ ] Durum "running" olarak güncellenir
- [ ] Port dinlemeye başlar

**Beklenen Sonuç:** Honeypot başarıyla başlatılır

### 5.4 Honeypot Durdurma
- [ ] Çalışan bir honeypot seçilir (durum: running)
- [ ] "Stop" butonuna tıklanır
- [ ] Honeypot durdurulur
- [ ] Durum "stopped" olarak güncellenir
- [ ] Port dinlemeyi durdurur

**Beklenen Sonuç:** Honeypot başarıyla durdurulur

### 5.5 Honeypot Silme
- [ ] Bir honeypot seçilir
- [ ] "Delete" butonuna tıklanır
- [ ] Onay mesajı görünür
- [ ] Onaylandığında honeypot silinir
- [ ] Çalışan honeypot silinirse önce durdurulur

**Beklenen Sonuç:** Honeypot başarıyla silinir

### 5.6 Template Seçimi
- [ ] Honeypot oluştururken template seçilir
- [ ] Template'e göre varsayılan port önerilir:
  - [ ] SSH → 2222
  - [ ] Web → 8080
  - [ ] Database → 3306
  - [ ] vb.
- [ ] Template değiştirildiğinde port önerisi güncellenir

**Beklenen Sonuç:** Template seçimi doğru çalışır

---

## 6. Event ve IOC

### 6.1 SSH Honeypot Testi
- [ ] SSH honeypot oluşturulur ve başlatılır (port: 2222)
- [ ] Terminal'den bağlantı yapılır: `ssh -p 2222 test@localhost`
- [ ] Bağlantı başarılı olur
- [ ] Komutlar çalıştırılır (örn: `ls`, `pwd`, `whoami`)
- [ ] Events sayfasında yeni event'ler görünür
- [ ] Event detayları doğru kaydedilir:
  - [ ] IP adresi
  - [ ] Event type (ssh_login, ssh_command, vb.)
  - [ ] Timestamp
  - [ ] Details

**Beklenen Sonuç:** SSH honeypot çalışır, event'ler kaydedilir

### 6.2 Web Honeypot Testi
- [ ] Web honeypot oluşturulur ve başlatılır (port: 8080)
- [ ] Tarayıcıdan `http://localhost:8080` adresine gidilir
- [ ] Login sayfası görünür
- [ ] Farklı path'ler test edilir:
  - [ ] `/login` → Login sayfası
  - [ ] `/admin` → Admin paneli
  - [ ] `/wp-admin` → WordPress admin
  - [ ] `/phpmyadmin` → phpMyAdmin
- [ ] Events sayfasında yeni event'ler görünür
- [ ] Event detayları doğru kaydedilir

**Beklenen Sonuç:** Web honeypot çalışır, event'ler kaydedilir

### 6.3 Database Honeypot Testi
- [ ] Database honeypot oluşturulur ve başlatılır (port: 3306)
- [ ] MySQL client ile bağlantı yapılır: `mysql -h localhost -P 3306 -u root -p`
- [ ] Bağlantı denemesi yapılır
- [ ] Events sayfasında yeni event görünür
- [ ] Event detayları doğru kaydedilir

**Beklenen Sonuç:** Database honeypot çalışır, event'ler kaydedilir

### 6.4 Events Listesi
- [ ] Events sayfasına gidilir
- [ ] Tüm event'ler listelenir
- [ ] Her event için şu bilgiler görünür:
  - [ ] Timestamp
  - [ ] IP Address
  - [ ] Event Type
  - [ ] Honeypot
  - [ ] Details
- [ ] Sayfalama çalışır
- [ ] Sıralama çalışır (timestamp, IP, type)

**Beklenen Sonuç:** Tüm event'ler doğru listelenir

### 6.5 Events Filtreleme
- [ ] Events sayfasında filtreleme yapılır:
  - [ ] IP adresine göre filtreleme
  - [ ] Event type'a göre filtreleme
  - [ ] Date range'e göre filtreleme
- [ ] Filtreleme sonuçları doğru görüntülenir
- [ ] Filtreler temizlenebilir

**Beklenen Sonuç:** Filtreleme doğru çalışır

### 6.6 Events Export
- [ ] Events sayfasında "Export CSV" butonuna tıklanır
- [ ] CSV dosyası indirilir
- [ ] CSV dosyası doğru formatta olur
- [ ] "Export JSON" butonuna tıklanır
- [ ] JSON dosyası indirilir
- [ ] JSON dosyası doğru formatta olur

**Beklenen Sonuç:** Export işlemleri başarılı

### 6.7 IOC Extraction
- [ ] Event'ler oluşturulur
- [ ] IOC Extractor otomatik çalışır
- [ ] IOCs sayfasına gidilir
- [ ] Extracted IOC'ler görünür:
  - [ ] IP Addresses
  - [ ] URLs
  - [ ] Hashes
  - [ ] Credentials
- [ ] Her IOC için risk skoru görünür

**Beklenen Sonuç:** IOC'ler otomatik extract edilir

### 6.8 IOC Listesi
- [ ] IOCs sayfasına gidilir
- [ ] Tüm IOC'ler listelenir
- [ ] Her IOC için şu bilgiler görünür:
  - [ ] Value
  - [ ] Type
  - [ ] Risk Score
  - [ ] First Seen
  - [ ] Last Seen
- [ ] Risk skoruna göre sıralama yapılabilir

**Beklenen Sonuç:** Tüm IOC'ler doğru listelenir

### 6.9 IOC Filtreleme
- [ ] IOCs sayfasında filtreleme yapılır:
  - [ ] Value'a göre arama
  - [ ] Type'a göre filtreleme
  - [ ] Min risk score'a göre filtreleme
- [ ] Filtreleme sonuçları doğru görüntülenir

**Beklenen Sonuç:** IOC filtreleme doğru çalışır

### 6.10 IOC Enrichment
- [ ] Bir IOC seçilir
- [ ] "Enrich" butonuna tıklanır
- [ ] Threat intelligence bilgileri yüklenir
- [ ] Enrichment sonuçları görüntülenir:
  - [ ] Reputation score
  - [ ] Threat intelligence data
  - [ ] Historical data

**Beklenen Sonuç:** IOC enrichment başarılı

### 6.11 IOC Export
- [ ] IOCs sayfasında "Export CSV" butonuna tıklanır
- [ ] CSV dosyası indirilir
- [ ] "Export JSON" butonuna tıklanır
- [ ] JSON dosyası indirilir

**Beklenen Sonuç:** IOC export başarılı

---

## 7. Alert Sistemi

### 7.1 Alert Oluşturma
- [ ] Yüksek riskli bir event oluşturulur
- [ ] Alert otomatik oluşturulur
- [ ] Alerts sayfasına gidilir
- [ ] Yeni alert görünür
- [ ] Alert detayları doğru:
  - [ ] Severity (high/medium/low)
  - [ ] Message
  - [ ] Timestamp
  - [ ] Related Event

**Beklenen Sonuç:** Alert otomatik oluşturulur

### 7.2 Alert Listesi
- [ ] Alerts sayfasına gidilir
- [ ] Tüm alert'ler listelenir
- [ ] Unread alert'ler vurgulanır
- [ ] Alert'ler severity'ye göre renklendirilir

**Beklenen Sonuç:** Alert'ler doğru listelenir

### 7.3 Alert Okundu İşaretleme
- [ ] Bir alert seçilir
- [ ] Alert detayları görüntülenir
- [ ] Alert otomatik olarak "read" olarak işaretlenir
- [ ] Unread count güncellenir

**Beklenen Sonuç:** Alert okundu olarak işaretlenir

### 7.4 Alert Rules
- [ ] Alert Rules sayfasına gidilir
- [ ] Mevcut alert rule'lar listelenir
- [ ] Yeni alert rule oluşturulur:
  - [ ] Rule name
  - [ ] Condition (event type, IOC type, risk score, vb.)
  - [ ] Action (create alert, send email, block IP, vb.)
- [ ] Rule kaydedilir
- [ ] Rule aktif olur

**Beklenen Sonuç:** Alert rule başarıyla oluşturulur

---

## 8. Threat Intelligence

### 8.1 Threat Map
- [ ] Threat Map sayfasına gidilir
- [ ] Dünya haritası görüntülenir
- [ ] Saldırı kaynakları haritada gösterilir
- [ ] IP'ler üzerine gelindiğinde detaylar görünür
- [ ] Ülkelere göre saldırı sayıları görünür

**Beklenen Sonuç:** Threat map doğru çalışır

### 8.2 IOC Enrichment (Threat Intel)
- [ ] Bir IOC seçilir
- [ ] "Enrich" butonuna tıklanır
- [ ] Threat intelligence feed'lerinden bilgi çekilir:
  - [ ] AbuseIPDB
  - [ ] VirusTotal
  - [ ] OTX
  - [ ] MISP
- [ ] Enrichment sonuçları görüntülenir

**Beklenen Sonuç:** Threat intelligence enrichment başarılı

### 8.3 Threat Intel Feeds
- [ ] Threat Intel sayfasına gidilir
- [ ] Mevcut feed'ler listelenir
- [ ] Yeni feed eklenir:
  - [ ] Feed name
  - [ ] Feed type
  - [ ] API key
- [ ] Feed test edilir
- [ ] Feed aktif olur

**Beklenen Sonuç:** Threat intel feed başarıyla eklenir

---

## 9. Reports

### 9.1 HTML Report
- [ ] Reports sayfasına gidilir
- [ ] Date range seçilir
- [ ] "Generate HTML Report" butonuna tıklanır
- [ ] HTML report oluşturulur
- [ ] Report içeriği doğru:
  - [ ] Summary statistics
  - [ ] Event list
  - [ ] IOC list
  - [ ] Charts

**Beklenen Sonuç:** HTML report başarıyla oluşturulur

### 9.2 JSON Report
- [ ] Reports sayfasında "Generate JSON Report" butonuna tıklanır
- [ ] JSON report oluşturulur
- [ ] JSON dosyası indirilir
- [ ] JSON formatı doğru

**Beklenen Sonuç:** JSON report başarıyla oluşturulur

### 9.3 PDF Report
- [ ] Reports sayfasında "Generate PDF Report" butonuna tıklanır
- [ ] PDF report oluşturulur
- [ ] PDF dosyası indirilir
- [ ] PDF içeriği doğru:
  - [ ] Cover page
  - [ ] Executive summary
  - [ ] Detailed analysis
  - [ ] Charts and graphs
  - [ ] Recommendations

**Beklenen Sonuç:** PDF report başarıyla oluşturulur

### 9.4 Scheduled Reports
- [ ] Reports sayfasında "Scheduled Reports" bölümüne gidilir
- [ ] Yeni scheduled report oluşturulur:
  - [ ] Report name
  - [ ] Report type (HTML/JSON/PDF)
  - [ ] Schedule (daily/weekly/monthly)
  - [ ] Email recipients
- [ ] Scheduled report kaydedilir
- [ ] Report zamanında otomatik oluşturulur ve gönderilir

**Beklenen Sonuç:** Scheduled report başarıyla oluşturulur

---

## 10. Settings

### 10.1 SMTP Settings
- [ ] Settings sayfasına gidilir
- [ ] SMTP ayarları yapılandırılır:
  - [ ] SMTP Host
  - [ ] SMTP Port
  - [ ] SMTP Username
  - [ ] SMTP Password
- [ ] "Test Connection" butonuna tıklanır
- [ ] Bağlantı test edilir
- [ ] Ayarlar kaydedilir

**Beklenen Sonuç:** SMTP ayarları başarıyla yapılandırılır

### 10.2 Email Notifications
- [ ] SMTP ayarları yapılandırılır
- [ ] Yüksek riskli bir alert oluşturulur
- [ ] Email gönderilir
- [ ] Email içeriği doğru:
  - [ ] Alert detayları
  - [ ] Event bilgileri
  - [ ] IOC bilgileri

**Beklenen Sonuç:** Email bildirimleri çalışır

---

## 11. Advanced Features

### 11.1 MITRE ATT&CK Mapping
- [ ] MITRE ATT&CK sayfasına gidilir
- [ ] Event'ler MITRE tekniklerine map edilir
- [ ] MITRE matrix görüntülenir
- [ ] Her teknik için event sayıları görünür

**Beklenen Sonuç:** MITRE mapping doğru çalışır

### 11.2 Playbooks
- [ ] Playbooks sayfasına gidilir
- [ ] Yeni playbook oluşturulur:
  - [ ] Playbook name
  - [ ] Trigger condition
  - [ ] Actions (block IP, send email, create incident, vb.)
- [ ] Playbook kaydedilir
- [ ] Playbook test edilir

**Beklenen Sonuç:** Playbook başarıyla oluşturulur ve çalışır

### 11.3 Campaigns
- [ ] Campaigns sayfasına gidilir
- [ ] Yeni campaign oluşturulur:
  - [ ] Campaign name
  - [ ] Description
  - [ ] Honeypots (campaign'e dahil edilecek honeypot'lar)
- [ ] Campaign kaydedilir
- [ ] Campaign statistics görüntülenir

**Beklenen Sonuç:** Campaign başarıyla oluşturulur

### 11.4 Attack Replay
- [ ] Attack Replay sayfasına gidilir
- [ ] Bir session seçilir
- [ ] "Replay" butonuna tıklanır
- [ ] Session replay görüntülenir
- [ ] Timeline görüntülenir
- [ ] Event'ler sırayla gösterilir

**Beklenen Sonuç:** Attack replay doğru çalışır

### 11.5 Behavioral Analysis
- [ ] Behavioral Analysis sayfasına gidilir
- [ ] Anomali tespiti yapılır:
  - [ ] Brute force attacks
  - [ ] Port scanning
  - [ ] Credential stuffing
- [ ] Anomali'ler listelenir
- [ ] Anomali detayları görüntülenir

**Beklenen Sonuç:** Behavioral analysis doğru çalışır

### 11.6 ML Anomaly Detection
- [ ] ML Anomaly sayfasına gidilir
- [ ] ML model çalıştırılır
- [ ] Anomali'ler tespit edilir
- [ ] Anomali skorları görüntülenir
- [ ] Anomali detayları görüntülenir

**Beklenen Sonuç:** ML anomaly detection çalışır

### 11.7 SIEM Integration
- [ ] SIEM Integration sayfasına gidilir
- [ ] Yeni SIEM entegrasyonu eklenir:
  - [ ] SIEM type (Splunk, QRadar, Elasticsearch, vb.)
  - [ ] Connection details
  - [ ] Authentication
- [ ] Entegrasyon test edilir
- [ ] Event'ler SIEM'e gönderilir

**Beklenen Sonuç:** SIEM entegrasyonu başarılı

### 11.8 Geo-Blocking
- [ ] Geo-Blocking sayfasına gidilir
- [ ] Yeni geo-block rule oluşturulur:
  - [ ] Rule name
  - [ ] Countries (block edilecek ülkeler)
  - [ ] Action (block/allow/alert)
- [ ] Rule kaydedilir
- [ ] Rule aktif olur

**Beklenen Sonuç:** Geo-blocking doğru çalışır

### 11.9 Rate Limiting
- [ ] Rate Limiting sayfasına gidilir
- [ ] Yeni rate limit rule oluşturulur:
  - [ ] Rule name
  - [ ] Limit type (IP, event type, honeypot)
  - [ ] Rate limit (örn: 10 requests/minute)
- [ ] Rule kaydedilir
- [ ] Rate limit test edilir

**Beklenen Sonuç:** Rate limiting doğru çalışır

### 11.10 Honeytokens
- [ ] Honeytokens sayfasına gidilir
- [ ] Yeni honeytoken oluşturulur:
  - [ ] Token name
  - [ ] Token type (credential, API key, file, URL)
  - [ ] Token value
- [ ] Token kaydedilir
- [ ] Token kullanıldığında alert oluşturulur

**Beklenen Sonuç:** Honeytoken başarıyla oluşturulur

### 11.11 YARA Rules
- [ ] YARA Rules sayfasına gidilir
- [ ] Yeni YARA rule oluşturulur:
  - [ ] Rule name
  - [ ] Rule content
- [ ] Rule kaydedilir
- [ ] Rule event'lerde match edilir

**Beklenen Sonuç:** YARA rules doğru çalışır

### 11.12 Compliance
- [ ] Compliance sayfasına gidilir
- [ ] Compliance report'ları görüntülenir:
  - [ ] GDPR
  - [ ] HIPAA
  - [ ] PCI-DSS
  - [ ] ISO 27001
- [ ] Report'lar generate edilir

**Beklenen Sonuç:** Compliance report'ları oluşturulur

---

## 12. API Testleri

### 12.1 Authentication API
- [ ] `POST /api/v1/auth/login` endpoint'i test edilir
- [ ] Geçerli credentials ile token alınır
- [ ] Geçersiz credentials ile 401 döner
- [ ] Token ile authenticated request yapılır

**Beklenen Sonuç:** Authentication API doğru çalışır

### 12.2 Nodes API
- [ ] `GET /api/v1/nodes` - Node listesi alınır
- [ ] `POST /api/v1/nodes` - Yeni node oluşturulur
- [ ] `GET /api/v1/nodes/{id}` - Node detayı alınır
- [ ] `DELETE /api/v1/nodes/{id}` - Node silinir

**Beklenen Sonuç:** Nodes API doğru çalışır

### 12.3 Honeypots API
- [ ] `GET /api/v1/honeypots` - Honeypot listesi alınır
- [ ] `POST /api/v1/honeypots` - Yeni honeypot oluşturulur
- [ ] `POST /api/v1/honeypots/{id}/start` - Honeypot başlatılır
- [ ] `POST /api/v1/honeypots/{id}/stop` - Honeypot durdurulur
- [ ] `DELETE /api/v1/honeypots/{id}` - Honeypot silinir

**Beklenen Sonuç:** Honeypots API doğru çalışır

### 12.4 Events API
- [ ] `GET /api/v1/events` - Event listesi alınır
- [ ] `GET /api/v1/events?ip=1.2.3.4` - IP'ye göre filtreleme
- [ ] `GET /api/v1/events?type=ssh_login` - Type'a göre filtreleme
- [ ] Export endpoints test edilir

**Beklenen Sonuç:** Events API doğru çalışır

### 12.5 IOCs API
- [ ] `GET /api/v1/iocs` - IOC listesi alınır
- [ ] `GET /api/v1/iocs/{id}/enrich` - IOC enrichment
- [ ] Export endpoints test edilir

**Beklenen Sonuç:** IOCs API doğru çalışır

### 12.6 Health Check API
- [ ] `GET /health` - Health check yapılır
- [ ] Response doğru format:
  - [ ] Status (healthy/unhealthy)
  - [ ] Database status
  - [ ] System resources
  - [ ] Honeypot services

**Beklenen Sonuç:** Health check doğru çalışır

### 12.7 WebSocket API
- [ ] WebSocket bağlantısı kurulur: `ws://localhost:8000/api/v1/ws`
- [ ] Real-time event'ler alınır
- [ ] Alert'ler real-time gelir
- [ ] Bağlantı kapatılır

**Beklenen Sonuç:** WebSocket doğru çalışır

---

## 13. Security Testleri

### 13.1 Authentication Security
- [ ] Geçersiz token ile request yapılır → 401 döner
- [ ] Expired token ile request yapılır → 401 döner
- [ ] Token olmadan request yapılır → 401 döner
- [ ] SQL injection denemesi yapılır → Güvenli

**Beklenen Sonuç:** Authentication güvenli

### 13.2 Input Validation
- [ ] XSS denemesi yapılır → Güvenli
- [ ] SQL injection denemesi yapılır → Güvenli
- [ ] Command injection denemesi yapılır → Güvenli
- [ ] Path traversal denemesi yapılır → Güvenli

**Beklenen Sonuç:** Input validation güvenli

### 13.3 Rate Limiting
- [ ] Rate limit aşılır → 429 döner
- [ ] Rate limit süresi dolduğunda tekrar deneme yapılır → Başarılı

**Beklenen Sonuç:** Rate limiting çalışır

### 13.4 IP Blocking
- [ ] Bir IP block edilir
- [ ] Block edilen IP'den request yapılır → Block edilir
- [ ] IP unblock edilir → Tekrar erişilebilir

**Beklenen Sonuç:** IP blocking çalışır

### 13.5 CORS
- [ ] Farklı origin'den request yapılır
- [ ] CORS header'ları doğru set edilir
- [ ] Sadece izin verilen origin'ler erişebilir

**Beklenen Sonuç:** CORS doğru yapılandırılmış

---

## 14. Performance Testleri

### 14.1 Load Test
- [ ] 100 eşzamanlı kullanıcı ile test yapılır
- [ ] Response time'lar ölçülür
- [ ] Error rate kontrol edilir
- [ ] Memory usage kontrol edilir

**Beklenen Sonuç:** Sistem yük altında stabil çalışır

### 14.2 Database Performance
- [ ] Büyük miktarda event oluşturulur (10,000+)
- [ ] Query performance ölçülür
- [ ] Index'lerin çalıştığı doğrulanır
- [ ] Pagination performansı kontrol edilir

**Beklenen Sonuç:** Database performansı yeterli

### 14.3 Real-time Performance
- [ ] 1000+ eşzamanlı WebSocket bağlantısı
- [ ] Real-time update performansı ölçülür
- [ ] Memory leak kontrol edilir

**Beklenen Sonuç:** Real-time performans yeterli

---

## 📊 Test Sonuçları

Test sonuçlarını buraya kaydedin:

### Test Tarihi: _______________
### Test Edilen Versiyon: _______________
### Test Edilen Kişi: _______________

### Genel Sonuç:
- [ ] ✅ Tüm testler başarılı
- [ ] ⚠️ Bazı testler başarısız (detaylar aşağıda)
- [ ] ❌ Çok sayıda test başarısız

### Başarısız Testler:
1. _________________________
2. _________________________
3. _________________________

### Notlar:
_________________________________________________
_________________________________________________
_________________________________________________

---

## 🔄 Test Checklist

Her test kategorisini tamamladıktan sonra işaretleyin:

- [ ] 1. Kurulum ve Setup
- [ ] 2. Authentication
- [ ] 3. Dashboard
- [ ] 4. Node Yönetimi
- [ ] 5. Honeypot Yönetimi
- [ ] 6. Event ve IOC
- [ ] 7. Alert Sistemi
- [ ] 8. Threat Intelligence
- [ ] 9. Reports
- [ ] 10. Settings
- [ ] 11. Advanced Features
- [ ] 12. API Testleri
- [ ] 13. Security Testleri
- [ ] 14. Performance Testleri

---

**Test Senaryoları v1.0**  
*Son Güncelleme: 2024*

