# Panduan Keystone

Panduan ini untuk engineer yang baru pertama kali memakai Keystone. Ringkasan dalam bahasa Inggris ada di [README.md](../README.md).

Keystone adalah aplikasi web lokal. Ia berjalan di komputer Anda sendiri, jadi konfigurasi pelanggan tidak keluar dari mesin Anda. Tidak ada akun dan tidak ada login: unduh, jalankan, dan browser terbuka. Versi saat ini: 1.11.0.

## 1. Mulai cepat (3 langkah)

**Windows**

1. Pasang Python 3.12 atau 3.13 dari [python.org](https://www.python.org/downloads/windows/) (sekali saja).
2. Di halaman GitHub Keystone, tekan tombol hijau **Code**, lalu **Download ZIP** ([langkah dari GitHub](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives)). Klik kanan file ZIP, pilih **Extract All**, lalu buka folder `Keystone` hasil ekstrak.
3. Klik dua kali **`start_windows.bat`**.

**macOS atau Linux**

1. Pasang Python 3.11 atau lebih baru jika belum ada (macOS: `brew install python@3.12`; Debian atau Ubuntu: `sudo apt install python3 python3-venv python3-pip`).
2. Unduh dan ekstrak repository, atau jalankan `git clone https://github.com/Crawling-Bil/Keystone.git`.
3. Di terminal, di dalam folder Keystone, jalankan `bash start_mac_linux.sh`.

Saat dijalankan pertama kali, Keystone memasang semua yang dibutuhkan sendiri. Ini memakan 2 sampai 5 menit dan butuh internet; biarkan jendelanya terbuka. Setelah itu browser terbuka di `http://127.0.0.1:8002`, dan start berikutnya hanya beberapa detik. Biarkan jendela hitam tetap terbuka selama Anda bekerja. Tutup jendela itu (atau tekan Ctrl+C) untuk menghentikan Keystone.

Windows kadang menampilkan "Windows protected your PC" untuk file `.bat` hasil unduhan. Tekan **More info**, lalu **Run anyway**. Isi skripnya teks biasa; buka dengan Notepad jika Anda ingin membacanya dulu.

### Apakah aman tanpa login?

Keystone hanya mendengarkan di komputer Anda sendiri (`127.0.0.1`), jadi mesin lain di jaringan tidak bisa menjangkaunya. Keystone juga menolak permintaan yang dikirim website lain lewat browser Anda. Siapa pun yang sedang login di komputer Anda bisa memakainya, sama seperti program lain di komputer itu. Jangan buka ke jaringan (lihat `NES_ALLOW_REMOTE` di bagian Pengaturan) kecuali jaringannya tepercaya dan terisolasi, karena tool Operate bisa mengirim firmware dan konfigurasi ke perangkat asli.

## 2. Yang dibutuhkan

- Windows, macOS, atau Linux.
- Python 3.11 atau lebih baru. Python 3.12 dipakai oleh test otomatis dan 3.13 juga dicoba; pilih salah satunya jika ada pilihan. Cara kerja installer Python dan perintah `py` di Windows: [Python on Windows](https://docs.python.org/3/using/windows.html).
- Koneksi internet hanya pada start pertama, untuk mengunduh paket yang tercantum di `requirements-lock.txt`.
- Browser yang masih baru.
- Opsional: `dnsmasq`, hanya jika Anda memakai DHCP bawaan ZTP Provisioning (`apt install dnsmasq` atau `brew install dnsmasq`).

## 3. Menjalankan dan menghentikan

| | Windows | macOS atau Linux |
| --- | --- | --- |
| Jalankan | klik dua kali `start_windows.bat` | `bash start_mac_linux.sh` |
| Hentikan | tutup jendelanya, atau klik dua kali `stop_windows.bat` | Ctrl+C, atau `bash stop_mac_linux.sh` |
| Buka halaman lagi | klik dua kali `open_nes.bat`, atau buka `http://127.0.0.1:8002` | buka `http://127.0.0.1:8002` |
| Pasang ulang atau perbaiki | klik dua kali `setup_windows.bat` | `bash setup_mac_linux.sh` |
| Periksa instalasi | `.venv\Scripts\python.exe verify_install.py` | `.venv/bin/python verify_install.py` |

Jika Keystone dijalankan saat ia sudah berjalan, ia hanya membuka browser lagi dan tidak error.

Jika antivirus atau kebijakan perusahaan memblokir skrip, jalankan langkahnya manual dari folder Keystone. Windows:

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.venv\Scripts\python.exe run.py
```

Di macOS atau Linux ganti `.venv\Scripts\python.exe` dengan `.venv/bin/python` dan `py -3` dengan `python3`.

## 4. Memperbarui ke versi baru

Dengan git: `git pull`, lalu jalankan file setup sekali (`setup_windows.bat` atau `bash setup_mac_linux.sh`) kalau-kalau daftar paket berubah. Dengan ZIP: unduh ZIP baru, ekstrak ke folder baru, dan salin folder `data` lama ke dalamnya jika Anda ingin riwayat aktivitas tetap ada. Lalu jalankan file setup sekali.

## 5. Memilih tool

| Kebutuhan | Tool | File yang diunggah |
| --- | --- | --- |
| Menilai switch (VLAN, STP, port-channel, PoE, vPC/M-LAG) | Switch Analyzer | Konfigurasi dan output `show` / `display` |
| Menilai router (routing, BGP/OSPF, VPN, SD-WAN) | Router Analyzer | Capture Cisco IOS, IOS-XE, atau SD-WAN |
| Menilai firewall (policy, NAT, VPN) | Firewall Analyzer | FortiGate, FortiSwitch, Palo Alto, MikroTik |
| Menilai load balancer F5 | Load Balancer Analyzer | `.ucs`, `bigip.conf`, atau output `tmsh` |
| Membuat diagram topologi (draw.io) | Topology Builder | Capture per perangkat (atau ZIP) berisi `show cdp neighbors detail` / `show lldp neighbors detail`, opsional tabel MAC / ARP; hasil: tampilan fisik, vPC, dan Logical IP, tetangga dari ARP / MAC / description saat CDP/LLDP tidak ada, pengelompokan per site, nama topologi untuk nama file, kecepatan link, paket dokumentasi (ZIP / laporan HTML), gabung dengan hasil sebelumnya |
| Menilai wireless controller | Wireless Analyzer | Konfigurasi WLC Huawei atau Cisco 9800 |
| Memindahkan konfigurasi switch ke vendor lain | Convert, Switch | Konfigurasi switch Cisco, Huawei, atau Aruba |
| Memindahkan firewall MikroTik ke Palo Alto (sekali klik atau Guided Conversion langkah demi langkah) | Convert, Firewall | Konfigurasi MikroTik |
| Upgrade firmware, push config, onboarding switch baru | Device Operations, ZTP | Kredensial perangkat, firmware, draft config |
| Backup konfigurasi (hanya baca) | Config Backup | Kredensial perangkat |
| Menyusun struktur LLD project | LLD Index | Data project dan goals, inventory perangkat (template Excel), config opsional |
| Membuat dokumen LLD, Work Plan, Work Report | Document Generator | Index dari LLD Index (satu klik) atau file Excel index |

Halaman Convert untuk Wireless, Router, dan Load Balancer belum punya converter. Halamannya menjelaskan apa yang dibutuhkan dan mengarahkan ke analyzer yang sesuai.

## 6. Analisa pertama (sekitar lima menit)

1. Buka **Switch Analyzer**, pilih tab **Collect Backup**.
2. Unduh daftar perintah untuk platform Anda: Cisco Catalyst, Cisco Nexus, Aruba Switch, Aruba CX, Huawei S/L/E-series, atau Huawei H-series. Atau tekan **Copy commands** dan tempel ke sesi SSH atau console.
3. Simpan seluruh output terminal sebagai satu file `.txt`.
4. Buka tab **Single Device**, jatuhkan filenya, biarkan Vendor di Auto Detect, tekan **Analyze Switch**.
5. Baca **Overview**, **Findings**, dan **Health**. Tekan **Export to Excel (.xlsx)** untuk laporan.

Analyzer lain bekerja dengan cara yang sama dan punya daftar perintah sendiri: router Cisco IOS-XE dan SD-WAN, FortiGate, MikroTik, Palo Alto, F5 BIG-IP (LTM dan DNS).

Tab **Coverage** di Switch Analyzer menunjukkan perintah mana yang ditemukan di capture Anda dan mana yang tidak. Jika hasil terlihat kurang lengkap, kumpulkan ulang dengan daftar perintah lengkap.

Jika file Anda milik tool lain (misalnya capture router di halaman Switch), Keystone tidak memaksanya lewat parser yang salah. Halaman akan menyebut analyzer yang tepat.

## 7. Konversi konfigurasi switch

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

## 7b. Membuat diagram topologi

1. Buka **Analyze**, lalu **Topology Builder**. Pilih atau tarik satu capture per perangkat (atau satu ZIP). Semakin banyak perangkat, semakin banyak link yang terkonfirmasi dari kedua ujung.
2. Opsional: isi **Topology name**. Semua file unduhan lalu diberi nama itu (`Lab-DC-topology.drawio`, `Lab-DC-links.csv`, ...); kosong berarti nama biasa. File draw.io menampilkan nama dan `Topology Created at Date YYYY:MM:DD - Time HH:MM:SS` di atas diagram.
3. Atur opsi (nilai awal dalam kurung):
   - **Exclude IP phones, PCs and servers** (aktif): hanya perangkat jaringan yang digambar. Selama aktif, opsi phone/host disembunyikan.
   - **Collapse phones and hosts into one node per switch** (aktif) dan **Collapse access points into one node per switch** (aktif: satu kotak per switch; matikan agar setiap access point tampil dengan hostname, model, dan IP sendiri untuk diagram yang lebih detail).
   - **Show port names on the lines** (aktif), **Infer neighbors where CDP/LLDP is silent** (aktif; urutan kepercayaan: ARP, lalu MAC address, lalu port description), **Add routed /30 and /31 links** (aktif), **Leave out-of-band management links out of the picture** (aktif), **Draw end hosts learned from MAC tables** (mati).
   - **Grouping**: satu diagram, atau kelompok berdasarkan satu, dua, atau tiga kata pertama hostname (`JKT`, `JKT-A02`, `JKT-GD1-LT1`). Grup dengan link terbanyak ke grup lain digambar di tengah, grup lain di sekelilingnya, masing-masing dalam kotak hitam.
   - **Diagram file contains**: tampilan fisik dan vPC, fisik saja, vPC saja, atau **Logical IP view** (perangkat yang berbagi subnet, interface dan alamat di tiap ujung, serta tabel semua alamat interface per perangkat).
   - **Style lines by**: kecepatan rating (default) atau status link.
4. Tekan **Build topology**, lihat pratinjau (zoom, geser, buka di tab baru), dan baca findings. Unduh **pack** (ZIP) untuk semuanya, atau file satuan.
5. Untuk melanjutkan nanti, pilih `topology.json` di **Add to a previous run** dan `topology.drawio` yang sudah Anda geser di **Keep my layout**.
6. Penempatan perangkat: satu level dibaca dari kiri ke kanan urut nama (A-Z, lalu 0-9). Semua yang terhubung ke satu perangkat (switch, access point, IP phone, PC) dikelompokkan tepat di bawah perangkat itu, jadi 3 AP di bawah switch A tidak bercampur dengan 2 AP di bawah switch B. Perangkat yang hanya uplink (router, firewall) ditempatkan di atas perangkat yang dilayaninya, berdampingan (router A, B, C).

Pack berisi `run-settings.txt`: opsi yang Anda pilih, waktu pembuatan, dan nama topologi. Kirimkan bersama pertanyaan atau laporan masalah. Penjelasan lengkap, termasuk ID finding (TOPO-001 ...), ada di [modules/topology.md](modules/topology.md).

## 7c. Membuat dokumen LLD

1. Buka **Document**, lalu **LLD Index**. Isi customer, nama project, kode, nama penulis, dan goals project. Nyalakan **Replacement project** kalau ada perangkat lama yang diganti.
2. Pilih teknologi (Switch, Wireless, Firewall, ...).
3. Isi perangkat: **Download template**, isi di Excel (Site, Hostname, Model, Role, Status, Mgmt IP, SN, Config, Rack, Rack Size, U, U Height), lalu **Import CSV / XLSX**, atau ketik langsung. Status: New, Existing (dicabut), atau Keep (tetap).
4. Opsional: masukkan running config (satu per perangkat, atau satu ZIP). Tabel VLAN, interface, routing, dan policy diisi dari situ; tanpa config tabelnya tetap TBD.
5. Klik **Build LLD index**. Hasil build tersimpan: lain kali pilih di **Continue a project**, ubah yang perlu, lalu build lagi tanpa upload config ulang.
6. Klik **Open in Document Generator**. Project terbuka lengkap dengan babnya. Build ulang nanti memperbarui project yang sama, gambar dan editan tetap.
7. Di Document Generator: drop, paste, atau pilih gambar topology dan rack (SVG dari Topology Builder bisa; tombol **Pictures** menaruh banyak gambar sekaligus sesuai nama file), lengkapi yang ada di daftar **Review**, dan atur logo customer, versi, serta **Approvers** di **Settings**.
8. Klik **Generate & Download**. Buka di Word dan biarkan Word memperbarui field (daftar isi, caption).

Pertama kali pakai, buka **Document Generator** lalu klik **Import from the old Document Generator** untuk memindahkan project dari aplikasi Document Generator yang lama. Detail: [modules/lld-index.md](modules/lld-index.md) dan [modules/lld-generator.md](modules/lld-generator.md).

## 8. Tool yang mengubah perangkat

Device Operations dan ZTP Provisioning menulis ke perangkat asli. Run sungguhan hanya mendukung Huawei VRP; vendor lain berjalan di demo mode. Upgrade firmware dan Config Push menjalankan pre-check dan mengambil backup konfigurasi di sekitar job. Latihan dulu dengan Demo Mode. Tab Backup dan Live Logs hanya membaca. Baca [modules/lifecycle-manager.md](modules/lifecycle-manager.md) sebelum job sungguhan pertama.

## 9. Pengaturan (opsional)

Anda tidak perlu mengubah apa pun di sini. Set sebagai environment variable sebelum menjalankan Keystone.

| Variabel | Default | Arti |
| --- | --- | --- |
| `NES_PORT` | `8002` | Port yang dipakai |
| `NES_HOST` | `127.0.0.1` | Alamat yang didengarkan. Selain localhost juga butuh `NES_ALLOW_REMOTE=1` |
| `NES_ALLOW_REMOTE` | tidak diset | Isi `1` agar mesin lain bisa terhubung. Tidak ada login, jadi hanya di jaringan terisolasi yang tepercaya |
| `NES_ALLOWED_HOSTS` | tidak diset | Nama host tambahan yang boleh dijawab Keystone, dipisah koma |
| `NES_OPEN_BROWSER` | `1` | Isi `0` agar browser tidak terbuka otomatis |
| `NES_SECRET_KEY` | dibuat otomatis | Kunci penandatangan cookie |

Di Windows, buka Command Prompt di folder Keystone, jalankan misalnya `set NES_PORT=8010`, lalu `start_windows.bat`. Variabel yang diset dengan cara ini hanya berlaku untuk jendela itu. Di macOS atau Linux: `NES_PORT=8010 bash start_mac_linux.sh`.

## 10. Masalah umum

| Yang terlihat | Yang dilakukan |
| --- | --- |
| "Python 3.11 or newer was not found" | Pasang Python dari [python.org](https://www.python.org/downloads/), lalu klik dua kali `setup_windows.bat` lagi (macOS atau Linux: `bash setup_mac_linux.sh`). Untuk memilih satu Python: `PYTHON_BIN=python3.12 bash setup_mac_linux.sh` |
| "Windows protected your PC" | Tekan **More info**, lalu **Run anyway** |
| Setup berhenti saat memasang paket | Periksa internet dan proxy perusahaan (pip membaca `HTTPS_PROXY`), lalu jalankan file setup lagi |
| Antivirus menghapus atau memblokir skrip | Izinkan folder Keystone, atau pakai perintah manual di bagian Menjalankan dan menghentikan |
| "Could not create the private Python folder" (Debian atau Ubuntu) | `sudo apt install python3-venv python3-pip`, lalu jalankan setup lagi |
| `bash: ... No such file` atau error `\r` aneh di macOS/Linux | Skrip memakai akhir baris Windows. Jalankan `sed -i 's/\r$//' *.sh` (macOS: `sed -i '' 's/\r$//' *.sh`) di folder Keystone |
| "Port 8002 is already used by another program" | Port dipakai program lain. Jalankan Keystone di port lain dengan `NES_PORT=8010` (lihat Pengaturan) |
| "Keystone is already running" | Memang sudah berjalan. Browser dibuka lagi; pakai tab itu |
| Browser tidak terbuka | Buka `http://127.0.0.1:8002` sendiri |
| "Keystone only answers on this computer's own addresses" | Anda membukanya dengan nama atau alamat lain. Pakai `http://127.0.0.1:8002` atau `http://localhost:8002` |
| "Refusing to listen on ..." | `NES_HOST` diisi alamat non-lokal. Hapus, atau isi juga `NES_ALLOW_REMOTE=1` jika Anda menerima risikonya |
| "Keystone refused a request that another website started" | Halaman selain Keystone mencoba mengirim permintaan. Tutup tab itu dan pakai tab Keystone |
| Analyzer bilang file tidak dikenali | Pakai analyzer yang sesuai, atau kumpulkan ulang output dengan daftar perintah di tab Collect Backup |
| Hasil terlihat kurang lengkap | Kumpulkan dengan daftar perintah lengkap untuk platformnya. Tab Coverage di Switch Analyzer menunjukkan perintah mana yang ditemukan |
| DHCP bawaan ZTP tidak jalan | Pasang `dnsmasq` dan jalankan Keystone dengan hak administrator atau root; DHCP memakai port istimewa |
| Setup selesai tapi ada yang gagal | Jalankan pemeriksaan di bagian Menjalankan dan menghentikan dan baca hasilnya |

## 11. Data Anda

- File unggahan, ekspor, log, dan setting yang dibuat otomatis tersimpan di `data/`, `uploads/`, `exports/`, dan `logs/` di dalam folder Keystone. Folder itu sengaja diabaikan oleh git.
- Jangan pernah commit capture pelanggan atau kredensial asli. Test memakai file sintetis saja.
- Pekerjaan LLD tersimpan di `data/nes.db` (project LLD Index dan LLD Generator, approvers) dan `data/lld_generator/` (template, gambar, file Word hasil generate; file hasil generate yang lebih dari 7 hari dihapus). Backup folder `data` untuk menyimpannya.
- Keystone tidak mengirim konfigurasi ke layanan eksternal.

## 12. Dokumen lain

- [PRD.md](PRD.md): scope, vendor yang didukung, roadmap
- [modules/configuration-studio.md](modules/configuration-studio.md): cara kerja Convert, Nexus, stack, katalog hardware
- [modules/lifecycle-manager.md](modules/lifecycle-manager.md): upgrade, push, backup, ZTP
- [modules/lld-index.md](modules/lld-index.md) dan [modules/lld-generator.md](modules/lld-generator.md): LLD Index dan LLD Generator
- [../CHANGELOG.md](../CHANGELOG.md)
