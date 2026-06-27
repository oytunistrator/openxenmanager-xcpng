# OpenXenManager-XCPNG Arch Linux Package

## 📦 Kurulum (Build & Install)

### Yöntem 1: Otomatik Build (Tavsiye Edilen)
```bash
cd openxenmanager-xcpng/arch
chmod +x build-arch.sh
./build-arch.sh
# Eğer install etmek isterseniz:
./build-arch.sh -i
```

### Yöntem 2: Manuel Build
```bash
cd openxenmanager-xcpng/arch
makepkg -C -S -i --noconfirm
```

### Yöntem 3: Sadece Package Oluştur (Install Etmeden)
```bash
cd openxenmanager-xcpng/arch
makepkg -C -S --noconfirm
sudo pacman -U openxenmanager-*.pkg.tar.xz
```

## 📋 Gereksinimler (Dependencies)

Bu paket aşağıdaki bağımlılıkları gerektirir:
- `python-gobject` (PyGObject/GTK3 arayüzü için)
- `gtk3` (GTK3 runtime)
- `python-configobj` (konfigürasyon dosyası okuma için)
- `gtk-vnc` (VNC konsol desteği için)

### Bağımlılıkları Kurmak İçin:
```bash
sudo pacman -S python-gobject gtk3 python-configobj gtk-vnc
```

## 📁 Dosya Yapısı

```
arch/
├── PKGBUILD              # Arch build dosyası
├── .SRCINFO              # AUR metadata (opsiyonel)
├── openxenmanager.install  # Post-install hooks
├── files/
│   ├── openxenmanager.desktop
│   └── openxenmanager.png
├── openxenmanager-0.1.0.dev1-1.tar.gz  # Kaynak arşivi
├── build-arch.sh         # Otomatik build scripti
└── README.md             # Bu dosya
```

## 🔧 Geliştirici Notları

### Yerel Repository'den Build
Eğer GitHub release tag'i yoksa:
1. `git archive HEAD | gzip > openxenmanager-0.1.0.dev1-1.tar.gz` ile tarball oluşturun
2. PKGBUILD'de source array'ye tarball adını ekleyin
3. Build yapın

### Paket İçeriği
Paket şu dosyaları kurar:
- `/usr/bin/openxenmanager` - Ana uygulama
- `/usr/lib/python3.14/site-packages/OXM/` - Python modülleri
- `/usr/lib/python3.14/site-packages/pygtk_chart/` - Chart kütüphanesi
- `/usr/share/applications/openxenmanager.desktop` - Desktop entry
- `/usr/share/icons/hicolor/256x256/apps/openxenmanager.png` - Uygulama ikonu
- `/usr/share/doc/openxenmanager/README.md` - Dokümantasyon

### İkon Cache Güncelleme
Paket kurulduktan sonra ikon cache otomatik güncellenir. Manuel güncellemek için:
```bash
gtk-update-icon-cache /usr/share/icons/hicolor
```

## 🚀 Kullanım

Build sonrası uygulamayı çalıştırın:
```bash
openxenmanager
```

veya:
```bash
python openxenmanager
```

## 📝 Notlar

- Bu paket yerel repository'den build edilir (GitHub release tag'ı gerektirmez)
- GTK3 ve Python 3.10+ gerektirir
- XCP-NG/XenServer 8.x ile uyumludur
- VNC konsol desteği için `gtk-vnc` paketi kurulu olmalıdır
