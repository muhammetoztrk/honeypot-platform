# GitHub'a Yükleme Kılavuzu

## Repository Bilgileri

- **Repository URL**: https://github.com/muhammetoztrk/honeypot-platform
- **Clone URL**: https://github.com/muhammetoztrk/honeypot-platform.git

## 1. GitHub Repository Oluşturma

1. GitHub'a giriş yapın: https://github.com
2. Sağ üstteki **"+"** butonuna tıklayın → **"New repository"**
3. Repository bilgilerini doldurun:
   - **Repository name**: `honeypot-platform`
   - **Description**: "Enterprise-grade honeypot management platform with advanced threat detection"
   - **Visibility**: ✅ **Public** (herkese açık)
   - **Initialize repository**: ❌ Boş bırakın (README, .gitignore, license eklemeyin)
4. **"Create repository"** butonuna tıklayın

## 2. Projeyi GitHub'a Yükleme

### İlk Kez Yükleme

```bash
# Proje dizinine gidin
cd C:\Users\muhammeto\Desktop\site

# Git repository'sini başlatın
git init

# Tüm dosyaları ekleyin
git add .

# İlk commit'i yapın
git commit -m "Initial commit: Enterprise honeypot platform"

# GitHub repository'nizi ekleyin
git remote add origin https://github.com/muhammetoztrk/honeypot-platform.git

# Main branch'e geçin
git branch -M main

# GitHub'a yükleyin
git push -u origin main
```

### Sonraki Güncellemeler

```bash
# Değişiklikleri ekleyin
git add .

# Commit yapın
git commit -m "Description of changes"

# GitHub'a yükleyin
git push
```

## 3. README.md'yi Özelleştirme

`README.md` dosyasını açın ve şu bilgileri güncelleyin:

- **Author**: Kendi adınızı ve GitHub/LinkedIn linklerinizi ekleyin
- **Repository URL**: GitHub repository URL'inizi ekleyin
- **Screenshots**: Platform ekran görüntüleri ekleyin (opsiyonel)

## 4. GitHub Repository Ayarları

### Topics (Etiketler) Ekleyin

Repository sayfasında **"Add topics"** butonuna tıklayın ve şunları ekleyin:
- `honeypot`
- `cybersecurity`
- `threat-detection`
- `fastapi`
- `react`
- `docker`
- `postgresql`
- `security`
- `threat-intelligence`
- `siem`

### Repository Açıklaması

Repository açıklamasına şunu ekleyin:
```
Enterprise-grade honeypot management platform with 100+ templates, real-time monitoring, threat intelligence, and SIEM integration. Built with FastAPI, React, and PostgreSQL.
```

### About Section

Repository sayfasında **"⚙️"** (Settings) → **"General"** → **"Features"** bölümünden:
- ✅ **Issues** - AÇIK (Bug bildirimi ve feature request'ler için)
- ✅ **Discussions** - AÇIK (Topluluk tartışmaları ve soru-cevap için)
- ✅ **Wiki** - AÇIK (Detaylı dokümantasyon ve örnekler için)
- ✅ **Projects** - AÇIK (Proje yönetimi ve roadmap için)

## 5. GitHub Actions (Opsiyonel)

CI/CD pipeline eklemek için `.github/workflows/` klasörü oluşturabilirsiniz.

## 6. Security Policy

Güvenlik açıklarını bildirmek için `SECURITY.md` dosyası ekleyebilirsiniz.

## 7. Contributing Guidelines

Katkıda bulunmak isteyenler için `CONTRIBUTING.md` dosyası ekleyebilirsiniz.

## Önemli Notlar

⚠️ **Güvenlik:**
- `.gitignore` dosyası hassas bilgileri (şifreler, API key'ler) hariç tutar
- `docker-compose.yml` içindeki şifreleri production'da mutlaka değiştirin
- GitHub'a yüklemeden önce `.env` dosyalarının olmadığından emin olun

✅ **Best Practices:**
- Her commit'te anlamlı mesajlar yazın
- Düzenli olarak güncelleme yapın
- Issues ve Pull Requests'lere yanıt verin
- Dokümantasyonu güncel tutun

