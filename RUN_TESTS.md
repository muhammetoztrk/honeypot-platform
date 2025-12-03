# 🧪 Test Suite - Çalıştırma Kılavuzu

## Otomatik Testler

Proje için kapsamlı otomatik test suite'i hazırlandı. Tüm test senaryoları otomatik olarak çalıştırılabilir.

## Test Dosyaları

- `backend/tests/test_setup.py` - Setup wizard testleri
- `backend/tests/test_auth.py` - Authentication testleri
- `backend/tests/test_health.py` - Health check testleri
- `backend/tests/test_nodes.py` - Node yönetimi testleri
- `backend/tests/test_honeypots.py` - Honeypot yönetimi testleri
- `backend/tests/test_events.py` - Event testleri
- `backend/tests/test_iocs.py` - IOC testleri
- `backend/tests/test_alerts.py` - Alert sistemi testleri
- `backend/tests/test_security.py` - Security testleri
- `backend/tests/test_api_comprehensive.py` - Kapsamlı API testleri
- `backend/tests/test_integration.py` - Integration testleri

## Testleri Çalıştırma

### Tüm Testleri Çalıştır

```bash
cd backend
pytest tests/ -v
```

### Belirli Bir Test Dosyasını Çalıştır

```bash
cd backend
pytest tests/test_auth.py -v
```

### Belirli Bir Test Fonksiyonunu Çalıştır

```bash
cd backend
pytest tests/test_auth.py::test_login -v
```

### Coverage ile Çalıştır

```bash
cd backend
pytest tests/ -v --cov=app --cov-report=html
```

Coverage raporu `htmlcov/index.html` dosyasında oluşturulur.

### Docker İçinde Test Çalıştırma

```bash
docker-compose exec backend pytest tests/ -v
```

## Test Sonuçları

Testler başarıyla geçtiğinde:
```
========================= test session starts =========================
tests/test_auth.py::test_login PASSED
tests/test_nodes.py::test_create_node PASSED
...
========================= X passed in Y.YYs =========================
```

## Test Kapsamı

- ✅ Setup wizard (database, admin user, organization)
- ✅ Authentication (login, logout, token)
- ✅ Node management (CRUD operations)
- ✅ Honeypot management (CRUD, start/stop)
- ✅ Event creation and listing
- ✅ IOC extraction and management
- ✅ Alert creation and management
- ✅ Security features (authentication, input validation)
- ✅ API endpoints
- ✅ Integration workflows

## Notlar

- Testler in-memory SQLite database kullanır (hızlı ve izole)
- Her test bağımsız çalışır (fixture'lar her test için yeni database oluşturur)
- Authentication gerektiren testler `authenticated_client` fixture'ını kullanır

## Sorun Giderme

### Import Errors
```bash
cd backend
pip install -r requirements.txt
```

### Database Errors
Testler otomatik olarak in-memory database oluşturur, ekstra yapılandırma gerekmez.

### Authentication Errors
`conftest.py` dosyasındaki fixture'lar otomatik olarak test kullanıcısı oluşturur.

