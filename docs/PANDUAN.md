# Panduan Keystone

Panduan ini untuk engineer yang baru pertama kali memakai Keystone. Ringkasan dalam bahasa Inggris ada di [README.md](../README.md).

Keystone adalah aplikasi web lokal. Ia berjalan di laptop Anda sendiri, jadi konfigurasi pelanggan tidak keluar dari mesin Anda. Versi saat ini: 1.11.0.

## 1. Yang dibutuhkan

- Windows, macOS, atau Linux.
- Python 3.11 atau lebih baru. Di Windows, pasang dari [python.org](https://www.python.org/downloads/) dan biarkan opsi "py launcher" tetap tercentang, karena skrip setup menjalankan Python dengan `py -3`.
- Koneksi internet saat setup (sekali saja) untuk mengunduh paket di `requirements-lock.txt`.
- Opsional: `dnsmasq`, hanya jika Anda memakai DHCP bawaan ZTP Provisioning (`apt install dnsmasq` atau `brew install dnsmasq`).

## 2. Pasang dan jalankan

1. Unduh repository (tombol hijau Code, lalu Download ZIP) dan ekstrak, atau clone:

   ```bash
   git clone https://github.com/Crawling-Bil/Keystone.git
   cd Keystone
   ```

2. Jalankan setup satu kali. Setup membuat folder `.venv`, memasang paket, lalu menjalankan `verify_install.py`.

   Windows: klik dua kali `setup_windows.bat`. Tunggu sampai jendela berhenti dan meminta Anda menekan tombol.

   macOS atau Linux:

   ```bash
   ./setup_mac_linux.sh
   ```

   Jika `python3` Anda lebih lama dari 3.11: `PYTHON_BIN=python3.12 ./setup_mac_linux.sh`.

3. Jalankan Keystone.

   Windows: klik dua kali `start_windows.bat`.

   macOS atau Linux:

   ```bash
   ./start_mac_linux.sh
   ```

   Browser terbuka di `http://127.0.0.1:8002`. Jika tidak, buka alamat itu sendiri (di Windows, `open_nes.bat` membukanya).

4. Login. Saat pertama kali dijalankan, Keystone membuat password, menampilkannya di jendela terminal dengan judul "Keystone login password", dan menyimpannya di `data/.auth_password`. Untuk memakai password sendiri, set `NES_AUTH_PASSWORD` sebelum start.

5. Hentikan dengan Ctrl+C di jendela terminalnya, atau jalankan `stop_windows.bat` / `./stop_mac_linux.sh`.

Jika antivirus atau kebijakan perusahaan memblokir skrip, jalankan langkahnya manual dari folder Keystone. Windows:

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.venv\Scripts\python.exe verify_install.py
.venv\Scripts\python.exe run.py
```

Di macOS atau Linux ganti `.venv\Scripts\python.exe` dengan `.venv/bin/python` dan `py -3` dengan `python3`.

## 3. Memilih tool

| Kebutuhan | Tool | File yang diunggah |
| --- | --- | --- |
| Menilai switch (VLAN, STP, port-channel, PoE, vPC/M-LAG) | Switch Analyzer | Konfigurasi dan output `show` / `display` |
| Menilai router (routing, BGP/OSPF, VPN, SD-WAN) | Router Analyzer | Capture Cisco IOS, IOS-XE, atau SD-WAN |
| Menilai firewall (policy, NAT, VPN) | Firewall Analyzer | FortiGate, FortiSwitch, Palo Alto, MikroTik |
| Menilai load balancer F5 | Load Balancer Analyzer | `.ucs`, `bigip.conf`, atau output `tmsh` |
| Menilai wireless controller | Wireless Analyzer | Konfigurasi WLC Huawei atau Cisco 9800 |
| Memindahkan konfigurasi switch ke vendor lain | Convert, Switch | Konfigurasi switch Cisco, Huawei, atau Aruba |
| Memindahkan firewall MikroTik ke Palo Alto | Convert, Firewall | Konfigurasi MikroTik |
| Upgrade firmware, push config, onboarding switch baru | Lifecycle Manager, Config Push, ZTP | Kredensial perangkat, firmware, draft config |
| Backup konfigurasi (hanya baca) | Config Backup | Kredensial perangkat |

Halaman Convert untuk Wireless, Router, dan Load Balancer belum punya converter. Halamannya menjelaskan apa yang dibutuhkan dan mengarahkan ke analyzer yang sesuai.

## 4. Analisa pertama (sekitar lima menit)

1. Buka **Switch Analyzer**, pilih tab **Collect Backup**.
2. Unduh daftar perintah untuk platform Anda: Cisco Catalyst, Cisco Nexus, Aruba Switch, Aruba CX, Huawei S/L/E-series, atau Huawei H-series. Atau tekan **Copy commands** dan tempel ke sesi SSH atau console.
3. Simpan seluruh output terminal sebagai satu file `.txt`.
4. Buka tab **Single Device**, jatuhkan filenya, biarkan Vendor di Auto Detect, tekan **Analyze Switch**.
5. Baca **Overview**, **Findings**, dan **Health**. Tekan **Export to Excel (.xlsx)** untuk laporan.

Analyzer lain bekerja dengan cara yang sama dan punya daftar perintah sendiri: router Cisco IOS-XE dan SD-WAN, FortiGate, MikroTik, Palo Alto, F5 BIG-IP (LTM dan DNS).

Tab **Coverage** di Switch Analyzer menunjukkan perintah mana yang ditemukan di capture Anda dan mana yang tidak. Jika hasil terlihat kurang lengkap, kumpulkan ulang dengan daftar perintah lengkap.

Jika file Anda milik tool lain (misalnya capture router di halaman Switch), Keystone tidak memaksanya lewat parser yang salah. Halaman akan menyebut analyzer yang tepat.

## 5. Konversi konfigurasi switch

1. Buka **Convert**, lalu **Switch**.
2. Pilih file konfigurasi atau tempel isinya. Source Vendor boleh tetap Auto Detect.
3. Pilih Target Vendor. Pilih Target Model jika Anda tahu modelnya: Keystone lalu memeriksa setiap port yang dipakai terhadap model sebenarnya dan memberi tahu jika port target tidak cukup.
4. Untuk stack Huawei, isi **Stack member** dan **Units in the stack**. Konversi setiap switch lama sebagai file sendiri.
5. Pilih Standard Config Profile jika perlu, lalu tekan **Convert Configuration**.
6. Baca tiga tampilan hasil:
   - **Configuration**: teks sumber dan hasil berdampingan. Unduh dengan **Download CFG**.
   - **Interface map**: setiap port sumber, port tujuannya, dan alasannya. Sebuah banner menyatakan apakah model target cukup.
   - **Pre-flight**: apa yang terkonversi bersih, apa yang butuh keputusan, apa yang tidak terkonversi, plus pemeriksaan struktur seperti rule ACL ganda dan port-channel kosong.
7. Cari `REVIEW-` di hasil. Setiap baris itu adalah keputusan atau padanan yang tidak ada, dan harus diputuskan manusia sebelum konfigurasi masuk ke perangkat.

Beberapa file atau satu ZIP bisa dikonversi sekaligus lewat **batch conversion**. Aturan converter ada di [modules/configuration-studio.md](modules/configuration-studio.md).

## 6. Tool yang mengubah perangkat

Lifecycle Manager, Config Push, dan ZTP Provisioning menulis ke perangkat asli. Run sungguhan hanya mendukung Huawei VRP; vendor lain berjalan di demo mode. Upgrade firmware dan Config Push menjalankan pre-check dan mengambil backup konfigurasi di sekitar job. Latihan dulu dengan Demo Mode. Config Backup dan Live Logs hanya membaca. Baca [modules/lifecycle-manager.md](modules/lifecycle-manager.md) sebelum job sungguhan pertama.

## 7. Pengaturan

Set sebagai environment variable sebelum menjalankan Keystone.

| Variabel | Default | Arti |
| --- | --- | --- |
| `NES_PORT` | `8002` | Port yang dipakai |
| `NES_HOST` | `127.0.0.1` | Alamat yang didengarkan. Selain localhost juga butuh `NES_ALLOW_REMOTE=1` |
| `NES_ALLOW_REMOTE` | tidak diset | Isi `1` agar mesin lain bisa terhubung. Hanya di jaringan terisolasi yang tepercaya: login hanya satu password bersama |
| `NES_AUTH_PASSWORD` | dibuat otomatis | Password login Anda sendiri |
| `NES_DISABLE_AUTH` | tidak diset | Isi `1` untuk mematikan login, hanya untuk pengembangan lokal |
| `NES_OPEN_BROWSER` | `1` | Isi `0` agar browser tidak terbuka otomatis |
| `NES_SECRET_KEY` | dibuat otomatis | Kunci penandatangan sesi |

Di Windows, buka Command Prompt di folder Keystone, jalankan misalnya `set NES_PORT=8010`, lalu `start_windows.bat`. Variabel yang diset dengan cara ini hanya berlaku untuk jendela itu.

## 8. Masalah umum

| Yang terlihat | Yang dilakukan |
| --- | --- |
| `py` is not recognized (Windows) | Pasang Python 3.11 atau lebih baru dari python.org dengan py launcher, lalu jalankan `setup_windows.bat` lagi |
| "Python 3 was not found" (macOS/Linux) | Pasang Python 3.11 atau lebih baru, atau jalankan `PYTHON_BIN=python3.12 ./setup_mac_linux.sh` |
| Setup berhenti saat memasang paket | Periksa internet dan proxy (pip membaca `HTTPS_PROXY`), lalu jalankan setup lagi |
| `start_windows.bat` meminta setup dulu | Folder `.venv` tidak ada. Jalankan `setup_windows.bat` |
| Port 8002 sudah dipakai | Jalankan `stop_windows.bat` / `./stop_mac_linux.sh`, atau pakai port lain dengan `NES_PORT=8010` |
| Lupa password | Buka `data/.auth_password`. Atau set `NES_AUTH_PASSWORD` lalu restart |
| "Too many attempts" saat login | Lima kali salah mengunci login 60 detik. Tunggu, lalu coba lagi |
| Browser tidak terbuka | Buka `http://127.0.0.1:8002` sendiri |
| "Refusing to bind to" | `NES_HOST` diisi alamat non-lokal. Isi `NES_ALLOW_REMOTE=1` hanya jika Anda menerima risikonya |
| Analyzer bilang file tidak dikenali | Pakai analyzer yang sesuai, atau kumpulkan ulang output dengan daftar perintah di tab Collect Backup |
| DHCP bawaan ZTP tidak jalan | Pasang `dnsmasq` dan jalankan Keystone dengan hak administrator atau root; DHCP memakai port istimewa |
| Setup selesai tapi ada yang gagal | Jalankan `.venv/bin/python verify_install.py` (Windows: `.venv\Scripts\python.exe verify_install.py`) dan baca hasilnya |

## 9. Data Anda

- File unggahan, ekspor, log, dan setting yang dibuat otomatis tersimpan di `data/`, `uploads/`, `exports/`, dan `logs/` di dalam folder Keystone. Folder itu sengaja diabaikan oleh git.
- Jangan pernah commit capture pelanggan atau kredensial asli. Test memakai file sintetis saja.
- Keystone tidak mengirim konfigurasi ke layanan eksternal.

## 10. Dokumen lain

- [PRD.md](PRD.md): scope, vendor yang didukung, roadmap
- [modules/configuration-studio.md](modules/configuration-studio.md): cara kerja Convert, Nexus, stack, katalog hardware
- [modules/lifecycle-manager.md](modules/lifecycle-manager.md): upgrade, push, backup, ZTP
- [../CHANGELOG.md](../CHANGELOG.md)
