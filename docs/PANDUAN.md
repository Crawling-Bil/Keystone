# Panduan Keystone

Panduan ini untuk engineer yang baru pertama kali memakai Keystone. Ringkasan dalam bahasa Inggris ada di [README.md](../README.md).

Keystone adalah aplikasi web lokal. Ia berjalan di komputer Anda sendiri, jadi konfigurasi pelanggan tidak keluar dari mesin Anda. Tidak ada akun dan tidak ada login: unduh, jalankan, dan browser terbuka. Versi saat ini: 1.11.0.

**Isi panduan**

1. [Mulai cepat](#1-mulai-cepat-3-langkah): pasang dan jalankan dalam tiga langkah
2. [Yang dibutuhkan](#2-yang-dibutuhkan)
3. [Menjalankan dan menghentikan](#3-menjalankan-dan-menghentikan)
4. [Memperbarui ke versi baru](#4-memperbarui-ke-versi-baru): `git clone` lewat perintah (4a), GitHub Desktop (4b), cara pemilik repository menerbitkan pembaruan (4c), dan ZIP (4d)
5. [Memilih tool](#5-memilih-tool), lalu [analisa pertama](#6-analisa-pertama-sekitar-lima-menit)
6. Panduan per tool: [konversi switch](#7-konversi-konfigurasi-switch), [diagram topologi](#7b-membuat-diagram-topologi), [dokumen LLD](#7c-membuat-dokumen-lld), [konversi firewall](#7d-mengonversi-firewall-fortigate-dan-pan-os), [tool yang mengubah perangkat](#8-tool-yang-mengubah-perangkat)
7. [Pengaturan](#9-pengaturan-opsional), [masalah umum](#10-masalah-umum), [data Anda](#11-data-anda), [dokumen lain](#12-dokumen-lain)

## 1. Mulai cepat (3 langkah)

**Windows**

1. Pasang Python dari [python.org](https://www.python.org/downloads/windows/) (sekali saja). Versi terbaru boleh dipakai: Keystone butuh Python 3.11 atau lebih baru, dan test otomatisnya lulus di 3.12, 3.13 dan 3.15. Di layar pertama installer, centang **Add python.exe to PATH** dan biarkan **py launcher** terpasang.
2. Di halaman GitHub Keystone, tekan tombol hijau **Code**, lalu **Download ZIP** ([langkah dari GitHub](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives)). Klik kanan file ZIP, pilih **Extract All**, lalu buka folder `Keystone` hasil ekstrak. Ingin mendapat pembaruan tanpa mengunduh ulang? Pakai `git clone` sebagai ganti ZIP: lihat [bagian 4](#4-memperbarui-ke-versi-baru) (ada versi perintah dan versi GitHub Desktop dengan tombol).
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
- Python 3.11 atau lebih baru; versi terbaru dari python.org boleh dipakai. Test otomatis berjalan di Python 3.12, 3.13 dan 3.15 dan semuanya lulus; jika ada pilihan, 3.12 atau 3.13 paling aman. Pada rilis Python yang baru beberapa minggu, beberapa paket (misalnya PyYAML) mungkin belum punya paket jadi, sehingga pip membangunnya di komputer Anda: lebih lambat tetapi tetap jalan tanpa compiler C. Setup selalu memilih Python 3.11 atau lebih baru yang paling baru ditemukan. Cara kerja installer Python dan perintah `py` di Windows: [Python on Windows](https://docs.python.org/3/using/windows.html).
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

Cara termudah: ambil Keystone dengan **`git clone`** sekali, lalu setiap ada versi baru cukup **`git pull`**. Tidak perlu mengunduh ZIP dan menyalin folder lagi, dan data Anda tidak tersentuh.

### 4a. Ikuti Keystone dengan git clone lewat perintah

**Langkah 1. Pasang Git (sekali saja).**

- Windows: unduh dari [git-scm.com/download/win](https://git-scm.com/download/win) dan jalankan installer. Pilihan bawaan sudah cukup. Di jaringan kantor dengan inspeksi SSL, pada layar *HTTPS transport backend* pilih **Use the native Windows Secure Channel library** supaya Git memakai sertifikat Windows.
- macOS: `brew install git` (atau `xcode-select --install`). Debian atau Ubuntu: `sudo apt install git`.
- Periksa di terminal baru: `git --version`. Panduan resmi: [Installing Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).

**Langkah 2. Ambil Keystone (sekali saja).** Buka PowerShell (Windows) atau Terminal, masuk ke folder tempat Anda ingin menyimpannya, lalu jalankan:

```powershell
cd D:\Tools
git clone https://github.com/Crawling-Bil/Keystone.git
cd Keystone
```

Hasilnya folder `Keystone` berisi seluruh isi proyek dan riwayatnya. Pilih lokasi yang pendek dan tidak di dalam OneDrive atau folder yang disinkronkan, karena folder `.venv` dan `data` berubah terus. Jika GitHub meminta masuk, login dengan akun GitHub Anda di jendela browser yang terbuka (Git Credential Manager ikut terpasang bersama Git for Windows); repository yang privat hanya bisa diambil oleh akun yang diberi akses. Dokumentasi: [Cloning a repository](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository).

Lebih suka tombol daripada perintah? Pakai GitHub Desktop: lihat bagian 4b di bawah.

**Langkah 3. Jalankan.** Klik dua kali `start_windows.bat` (macOS atau Linux: `bash start_mac_linux.sh`). Start pertama memasang paket sendiri, seperti di bagian 1.

**Langkah 4. Setiap ada versi baru.**

1. Hentikan Keystone (tutup jendela hitamnya, atau `stop_windows.bat`).
2. Di folder Keystone jalankan:

   ```powershell
   git pull --ff-only
   ```

   `--ff-only` hanya menerima pembaruan yang bersih. Jika ada masalah ia berhenti dan tidak menggabungkan apa pun secara diam-diam ([git pull](https://git-scm.com/docs/git-pull)).
3. Klik dua kali `setup_windows.bat` (macOS atau Linux: `bash setup_mac_linux.sh`) sekali, kalau-kalau daftar paket berubah. Jika paketnya sudah lengkap, ia selesai dalam hitungan detik.
4. Jalankan Keystone seperti biasa, lalu tekan **Ctrl+F5** di browser supaya halaman dan JavaScript yang lama tidak dipakai lagi.

Ingin tahu apa yang berubah? Buka `CHANGELOG.md` (entri terbaru ada di atas), atau jalankan `git log --oneline -10` untuk sepuluh perubahan terakhir. Ingin tahu versi yang terpasang? `git log -1 --format="%h %ad %s" --date=short`.

**Yang aman.** Folder `data/`, `uploads/`, `exports/`, `logs/` dan `.venv/` diabaikan oleh git (lihat `.gitignore` dan bagian 11), jadi `git pull` tidak menimpa riwayat analisa, unggahan, hasil ekspor, atau instalasi Python Anda.

**Aturan sederhana supaya `git pull` selalu mulus:**

- Jangan mengubah file di dalam folder hasil clone. Jika Anda butuh salinan untuk percobaan, salin foldernya ke tempat lain.
- Tetap di cabang `main`. Periksa dengan `git branch --show-current`; jika hasilnya lain, jalankan `git switch main` ([git switch](https://git-scm.com/docs/git-switch)).
- Jangan menyalin folder `.venv` ke komputer lain. Di komputer baru, cukup `git clone` lalu jalankan start.

**Kalau `git pull` menolak:**

| Pesan atau gejala | Artinya dan yang dilakukan |
| --- | --- |
| `Your local changes to the following files would be overwritten by merge` | Ada file yang Anda ubah. Simpan dulu dengan `git stash` lalu `git pull --ff-only` ([git stash](https://git-scm.com/docs/git-stash)). Jika perubahan itu tidak dibutuhkan, buang dengan `git restore .` (semua perubahan di file yang dilacak git hilang, jadi pastikan benar-benar tidak dibutuhkan) ([git restore](https://git-scm.com/docs/git-restore)) |
| `Not possible to fast-forward, aborting` | Cabang lokal punya commit yang tidak ada di GitHub, biasanya karena Anda commit sendiri. Salin pekerjaan itu ke tempat lain, lalu `git fetch origin` dan `git reset --hard origin/main` (membuang semua commit dan perubahan lokal) |
| `detected dubious ownership in repository` | Folder dibuat oleh akun Windows lain. Jalankan `git config --global --add safe.directory D:/Tools/Keystone` dengan path folder Anda ([safe.directory](https://git-scm.com/docs/git-config#Documentation/git-config.txt-safedirectory)) |
| `Could not resolve host: github.com` atau `unable to access` | Tidak ada internet, atau proxy kantor memblokir. Dengan proxy: `git config --global http.proxy http://alamat-proxy:port` ([http.proxy](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpproxy)). Tanpa internet Anda tetap bisa memakai versi yang terpasang; pull cukup diulang nanti |
| `SSL certificate problem` | Inspeksi SSL di jaringan kantor. Jalankan `git config --global http.sslBackend schannel` supaya Git memakai sertifikat Windows; jangan mematikan verifikasi SSL |
| `Authentication failed` atau `Repository not found` | Akun GitHub Anda belum punya akses ke repository, atau login lama kedaluwarsa. Minta akses ke pemilik repository, lalu login ulang ([credential helper](https://docs.github.com/en/get-started/getting-started-with-git/caching-your-github-credentials-in-git)) |

**Kembali ke versi sebelumnya.** Jika versi baru bermasalah di pekerjaan Anda, lihat daftarnya dengan `git log --oneline -20`, lalu `git switch --detach <kode-commit>` untuk mencoba versi itu. Untuk kembali ke versi terbaru: `git switch main`, lalu `git pull --ff-only`. Laporkan masalahnya ke pemilik repository supaya diperbaiki.

### 4b. Ikuti Keystone dengan GitHub Desktop (tombol, tanpa perintah)

GitHub Desktop adalah aplikasi gratis dari GitHub untuk Windows dan macOS. Ia sudah membawa Git sendiri, jadi Anda **tidak perlu** memasang Git terpisah. Hasilnya sama persis dengan `git clone` dan `git pull` di bagian 4a; Anda memakai tombol sebagai ganti perintah.

**Langkah 1. Pasang GitHub Desktop (sekali saja).**

1. Buka [desktop.github.com](https://desktop.github.com/) dan tekan **Download for Windows** (atau macOS). Dokumentasi resmi: [Installing GitHub Desktop](https://docs.github.com/en/desktop/installing-and-authenticating-to-github-desktop/installing-github-desktop).
2. Klik dua kali file installer (`GitHubDesktopSetup-x64.exe`). Tidak ada pertanyaan; aplikasi terpasang dan terbuka sendiri. Di komputer kantor yang membatasi pemasangan program, minta bantuan IT; aplikasi ini terpasang untuk satu pengguna dan tidak butuh hak administrator.
3. Layar pertama meminta masuk. Tekan **Sign in to GitHub.com**; browser terbuka, login dengan akun GitHub Anda, lalu **Authorize desktop**. Jika Keystone berstatus publik Anda juga bisa memakai **Skip this step**, tetapi repository yang privat butuh login dengan akun yang diberi akses. Panduan resmi: [Authenticating to GitHub in GitHub Desktop](https://docs.github.com/en/desktop/installing-and-authenticating-to-github-desktop/authenticating-to-github-in-github-desktop).
4. Layar berikutnya menanyakan nama dan email untuk commit. Isi bebas; Anda tidak akan membuat commit, hanya mengikuti pembaruan. Tekan **Finish**.

**Langkah 2. Ambil Keystone (sekali saja).**

1. Di menu pilih **File > Clone repository...** (di jendela awal: **Clone a repository from the Internet**).
2. Buka tab **URL**, tempel `https://github.com/Crawling-Bil/Keystone.git`. (Tab **GitHub.com** juga bisa: pilih `Crawling-Bil/Keystone` dari daftar jika terlihat.)
3. Di **Local path** pilih folder tujuan, misalnya `D:\Tools\Keystone`. Pilih lokasi yang pendek dan di luar OneDrive.
4. Tekan **Clone**. Tunggu sampai selesai. Jika GitHub Desktop menanyakan *How are you planning to use this fork*, pilih **For my own purposes**.

Dokumentasi resmi: [Cloning a repository from GitHub to GitHub Desktop](https://docs.github.com/en/desktop/adding-and-cloning-repositories/cloning-a-repository-from-github-to-github-desktop).

**Langkah 3. Jalankan Keystone.** Di GitHub Desktop pilih **Repository > Show in Explorer** (macOS: **Show in Finder**) untuk membuka folder Keystone, lalu klik dua kali `start_windows.bat`. Start pertama memasang paket sendiri (butuh internet, 2 sampai 5 menit).

**Langkah 4. Setiap ada versi baru.**

1. Hentikan Keystone (tutup jendela hitamnya, atau `stop_windows.bat`).
2. Buka GitHub Desktop. Pastikan **Current repository** di kiri atas bertuliskan `Keystone` dan **Current branch** bertuliskan `main`. Jika branch lain, klik **Current branch**, lalu pilih `main`.
3. Tekan tombol **Fetch origin** di bilah atas. GitHub Desktop memeriksa apakah ada versi baru, tanpa mengubah file Anda.
4. Jika ada pembaruan, tombolnya berubah menjadi **Pull origin** dan menampilkan jumlah commit baru (misalnya panah turun dengan angka 3). Tekan **Pull origin**. Selesai dalam hitungan detik.
5. Lihat apa yang berubah di tab **History**: setiap baris adalah satu perubahan, klik satu untuk melihat file yang berubah. Ringkasan yang mudah dibaca ada di `CHANGELOG.md` (entri terbaru di atas).
6. Klik dua kali `setup_windows.bat` sekali (jika paketnya sudah lengkap, selesai dalam hitungan detik), jalankan Keystone, lalu tekan **Ctrl+F5** di browser.

Jika setelah **Fetch origin** tombolnya tetap **Fetch origin** (bukan **Pull origin**), berarti Anda sudah memakai versi terbaru.

**Masalah yang sering muncul di GitHub Desktop:**

| Gejala | Yang dilakukan |
| --- | --- |
| Tab **Changes** menampilkan file yang berubah, dan **Pull origin** gagal karena bentrok | Anda mengubah file di folder Keystone. Jika perubahan itu tidak dibutuhkan: di tab **Changes** klik kanan file lalu **Discard changes** (perubahan hilang, tidak bisa dibatalkan). Jika dibutuhkan, salin file itu ke folder lain dulu, lalu discard, lalu pull. Menu **Branch > Stash all changes** juga bisa dipakai. Setelah pull, jangan mengubah file di dalam folder ini lagi |
| Tombol **Pull origin** tidak ada, yang muncul **Push origin** | Ada commit lokal yang tidak ada di GitHub. Jangan tekan Push. Salin pekerjaan Anda dan folder `data` ke tempat lain, hapus folder Keystone lama, lalu ulangi Langkah 2 (clone ulang) dan kembalikan folder `data` |
| *Authentication failed* atau *Repository not found* | Akun Anda belum diberi akses, atau login kedaluwarsa. Minta akses ke pemilik repository, lalu **File > Options > Accounts > Sign out**, **Sign in** lagi (macOS: **GitHub Desktop > Settings > Accounts**) |
| *Can't reach github.com* atau *getaddrinfo failed* | Tidak ada internet atau proxy kantor memblokir. Tanpa internet Anda tetap bisa memakai Keystone yang terpasang; ulangi **Fetch origin** nanti. Pengaturan proxy ada di **File > Options > Advanced** (macOS: **Settings**) atau ikuti tabel di bagian 4a |
| Layar awal menawarkan repository lain | Pilih `Keystone` di **Current repository** di kiri atas |

**Folder `data` aman.** `data/`, `uploads/`, `exports/` dan `logs/` diabaikan oleh git, jadi **Pull origin** tidak menimpa riwayat analisa, unggahan atau hasil ekspor Anda, dan file-file itu tidak muncul di tab **Changes**.

### 4c. Untuk pemilik repository: menerbitkan pembaruan dengan GitHub Desktop

Bagian ini untuk Anda yang mengubah Keystone dan ingin pengguna lain menerimanya lewat `git pull` atau **Pull origin** (bagian 4a dan 4b). Pengguna biasa tidak perlu membacanya. Aturan lengkap proyek ada di [CONTRIBUTING.md](../CONTRIBUTING.md).

Gambaran besarnya: perubahan dikerjakan di **cabang** (branch) sendiri, dikirim ke GitHub dengan **push**, digabung ke cabang `main` lewat **pull request**, dan setelah itu semua pengguna yang memakai clone mendapat versi baru saat mereka melakukan pull.

**Sebelum mulai.** Pastikan folder kerja Anda adalah hasil clone (bukan hasil ZIP), pasang GitHub Desktop dan login (bagian 4b), dan Anda sudah menjadi collaborator di repository `Crawling-Bil/Keystone`. Jangan pernah memasukkan capture pelanggan, hostname atau nama site asli, alamat IP asli, password, atau kunci ke repository; folder `data/`, `uploads/`, `exports/` dan `logs/` sudah diabaikan git, tetapi file yang Anda salin ke tempat lain tidak.

**Langkah 1. Buat cabang dari `main` terbaru.**

1. Di GitHub Desktop pilih **Current branch**, lalu `main`, lalu **Fetch origin** dan, jika muncul, **Pull origin**.
2. Klik **Current branch > New branch**, beri nama pendek yang menjelaskan isinya (misalnya `improve-topology-print`), pilih **Create branch**. Satu topik satu cabang.

**Langkah 2. Ubah dan uji.**

1. Ubah file di folder Keystone dengan editor Anda.
2. Jalankan seluruh test sebelum mengirim. Di folder Keystone (Windows):

   ```powershell
   .venv\Scripts\python.exe -m pip install pytest
   .venv\Scripts\python.exe -m pytest -q
   ```

   Semua test harus lulus. Test yang harus Anda ubah karena perilaku memang sengaja berubah diubah di pull request yang sama, dengan alasannya di deskripsi. Pakai data sintetis saja.
3. Jika perubahannya terlihat oleh pengguna, perbarui dokumen tool di `docs/modules/` dan tambahkan entri di `CHANGELOG.md` (entri terbaru di atas).

**Langkah 3. Commit.**

1. Di tab **Changes** periksa daftar file di kiri. Klik tiap file dan baca perubahannya. Hanya file yang memang Anda maksudkan yang boleh tercentang. Jika ada file aneh (capture, `.venv`, file hasil ekspor), hilangkan centangnya dan beri tahu pemilik repository.
2. Isi **Summary** di kiri bawah dengan satu kalimat (misalnya `Topology: print set A3 per page`), dan **Description** bila perlu.
3. Tekan **Commit to <nama-cabang>**.

**Langkah 4. Push ke GitHub.** Tekan **Publish branch** (kali pertama) atau **Push origin** (kali berikutnya) di bilah atas. Cabang Anda sekarang ada di GitHub, tetapi pengguna lain **belum** menerimanya, karena mereka mengikuti `main`.

**Langkah 5. Buka pull request.**

1. Tekan **Create Pull Request** (muncul setelah push; atau menu **Branch > Create pull request**). Browser terbuka di GitHub.
2. Isi template pull request: apa yang berubah, mengapa, bagaimana diuji, dan centang daftar periksanya.
3. Tunggu pemeriksaan otomatis **tests** selesai hijau. Jika merah, buka detailnya, perbaiki di cabang yang sama, commit dan push lagi; pull request ikut diperbarui.
4. Setelah disetujui, tekan **Merge pull request** di GitHub. Sejak saat ini `main` berisi perubahan Anda.

Jika GitHub menulis *This branch has conflicts that must be resolved*, hampir selalu penyebabnya `CHANGELOG.md` yang juga diubah orang lain. Tekan **Resolve conflicts** di GitHub, simpan **kedua** entri (bagian di antara `<<<<<<<` dan `>>>>>>>` yang sama-sama berisi entri CHANGELOG), hapus penanda `<<<<<<<`, `=======`, `>>>>>>>`, lalu **Mark as resolved** dan **Commit merge**.

**Langkah 6. Rapikan dan sinkronkan.** Di GitHub Desktop pilih `main`, tekan **Fetch origin** lalu **Pull origin** supaya komputer Anda ikut menerima hasil merge. Cabang lama boleh dihapus (**Branch > Delete**). Cabang baru berikutnya selalu dibuat dari `main` yang baru ditarik.

**Setelah merge, pengguna lain melakukan ini:** tutup Keystone, **Fetch origin** lalu **Pull origin** (atau `git pull --ff-only`), jalankan `setup_windows.bat` sekali, start Keystone, dan tekan Ctrl+F5. Tidak ada unduhan manual. Beri tahu tim bahwa ada versi baru, dan arahkan mereka ke entri terbaru di `CHANGELOG.md`. Jika Anda ingin penanda versi yang jelas, buat **Release** di GitHub ([Managing releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)); itu opsional dan tidak mengubah cara pull.

**Tanda bahwa ada yang salah:**

| Gejala | Yang dilakukan |
| --- | --- |
| Tombol **Push origin** ditolak (*rejected*, *non-fast-forward*) | Cabang di GitHub berubah sejak pull terakhir. Tekan **Fetch origin**, lalu **Pull origin**, selesaikan konflik jika ada, lalu push lagi |
| Tidak boleh push ke `main` langsung (*protected branch*) | Memang disengaja: `main` hanya menerima perubahan lewat pull request. Pakai cabang sendiri (Langkah 1) |
| Tab **Changes** menampilkan ratusan file | Ujung baris (CRLF/LF) atau folder yang tidak seharusnya ikut. Jangan commit; periksa `.gitattributes` dan beri tahu pemilik repository |
| Test merah di GitHub padahal hijau di komputer Anda | Cek versi Python (GitHub memakai 3.12, 3.13 dan 3.15 dengan `requirements.txt`, bukan file lock) dan baca log merahnya di tab **Checks** |
| Salah commit (belum di-push) | Di tab **History** klik kanan commit, **Undo commit** |
| Salah commit data pelanggan yang sudah di-push | Jangan hanya menghapus filenya. Beri tahu pemilik repository segera: riwayat git menyimpan file itu, dan data yang pernah bocor harus diganti (password, community, kunci) |

Dokumentasi resmi GitHub Desktop: [Creating a branch](https://docs.github.com/en/desktop/making-changes-in-a-branch/managing-branches-in-github-desktop), [Committing and reviewing changes](https://docs.github.com/en/desktop/making-changes-in-a-branch/committing-and-reviewing-changes-to-your-project-in-github-desktop), [Pushing changes to GitHub](https://docs.github.com/en/desktop/making-changes-in-a-branch/pushing-changes-to-github-from-github-desktop), [Creating an issue or pull request](https://docs.github.com/en/desktop/working-with-your-remote-repository-on-github-or-github-enterprise/creating-an-issue-or-pull-request-from-github-desktop), [Resolving a merge conflict on GitHub](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/addressing-merge-conflicts/resolving-a-merge-conflict-on-github).

### 4d. Dengan ZIP (tanpa git)

Unduh ZIP baru, ekstrak ke folder baru, dan salin folder `data` lama ke dalamnya jika Anda ingin riwayat aktivitas tetap ada. Lalu jalankan file setup sekali. Cara ini harus diulang setiap ada versi baru; untuk memakai Keystone terus-menerus, `git clone` (bagian 4a) atau GitHub Desktop (bagian 4b) lebih praktis.

## 5. Memilih tool

| Kebutuhan | Tool | File yang diunggah |
| --- | --- | --- |
| Menilai switch (VLAN, STP, port-channel, PoE, vPC/M-LAG) | Switch Analyzer | Konfigurasi dan output `show` / `display` |
| Menilai router (routing, BGP/OSPF, VPN, SD-WAN) | Router Analyzer | Capture Cisco IOS, IOS-XE, atau SD-WAN |
| Menilai firewall (policy, NAT, VPN) | Firewall Analyzer | FortiGate, FortiSwitch, Palo Alto (firewall atau Panorama; unggah export Panorama bersama export firewall yang dikelolanya, maksimal 60 file, dan tiap firewall dianalisis bersama template stack dan device group-nya), MikroTik |
| Menilai load balancer F5 | Load Balancer Analyzer | `.ucs`, `bigip.conf`, atau output `tmsh` |
| Membuat diagram topologi (draw.io) | Topology Builder | Capture per perangkat (atau ZIP): switch, router, FortiGate, Palo Alto (firewall yang dikelola Panorama dibaca bersama export Panorama-nya bila keduanya diunggah), F5 BIG-IP (`.ucs` atau `tmsh`), berisi `show cdp neighbors detail` / `show lldp neighbors detail`, opsional tabel MAC / ARP dan fakta routing; hasil: tampilan L3 over L2, L3 logical dan route, Logical IP, fisik, vPC, dan peta F5, tetangga dari ARP / MAC / description saat CDP/LLDP tidak ada, satu halaman per site untuk jaringan besar, overlay SD-WAN, trace jalur, kecepatan link, paket dokumentasi (ZIP / laporan HTML), daftar capture berikutnya, gabung dengan hasil sebelumnya, data demo multi-site (kantor pusat + 6 cabang, 44 capture, lima vendor, dengan tata letak diagram siap pakai; rencana alamat di [modules/topology-demo-multisite.md](modules/topology-demo-multisite.md)), salinan anonim opsional, progress bar saat proses berjalan |
| Menilai wireless controller | Wireless Analyzer | Konfigurasi WLC Huawei atau Cisco 9800 |
| Memindahkan konfigurasi switch ke vendor lain | Convert, Switch | Konfigurasi switch Cisco, Huawei, atau Aruba (Aruba 2540 / ArubaOS-Switch dan AOS-CX), atau capture sesi terminalnya |
| Memindahkan firewall MikroTik ke Palo Alto (sekali klik atau Guided Conversion langkah demi langkah) | Convert, Firewall | Konfigurasi MikroTik |
| Memindahkan firewall FortiGate ke PAN-OS, atau PAN-OS ke FortiGate | Convert, Firewall | `show full-configuration` FortiGate, atau konfigurasi PAN-OS (perintah `set`, XML, atau tampilan kurung kurawal); export Panorama juga bisa, satu device group per konversi |
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

Yang dibawa converter, dan yang ditinggalkan untuk Anda:

- Hanya yang dinyatakan sumber yang ditulis. Port yang PoE-nya tidak disebut sumber tidak mendapat baris PoE (setiap vendor menyalakan PoE secara default); port yang PoE-nya dimatikan sumber tetap dimatikan.
- Speed dan duplex tetap (`speed 100` / `duplex full`, `speed-duplex 100-full`) dan alamat DHCP client (`ip address dhcp`, `ip address dhcp-bootp`, `ip dhcp`, `ip address dhcp-alloc`) ditulis di setiap target. Port dengan speed tetap juga mendapat baris `REVIEW-SPEED`, karena ujung lawannya harus ditetapkan sama, kalau tidak terjadi duplex mismatch. AOS-CX hanya menerima `ip dhcp` di interface management dan VLAN 1, jadi interface lain mendapat baris `REVIEW-DHCP-CLIENT`.
- Capture `show tech-support` atau capture sesi terminal lain hanya dibaca bagian running configuration-nya; capture Aruba 2540 puluhan ribu baris tidak lagi dianggap sebagai konfigurasi. Banner mempertahankan jenis (`motd`, `exec`, `login`) dan isinya.
- Baris yang tidak punya padanan di target tetap terlihat sebagai baris `REVIEW-`, tidak dibuang diam-diam.

Beberapa file atau satu ZIP bisa dikonversi sekaligus lewat **batch conversion**. Aturan converter ada di [modules/configuration-studio.md](modules/configuration-studio.md).

## 7b. Membuat diagram topologi

1. Buka **Analyze**, lalu **Topology Builder**. Pilih atau tarik satu capture per perangkat (atau satu ZIP; untuk F5 BIG-IP arsip `.ucs`, ditambah capture `tmsh` unit yang sama untuk status port dan ARP). Semakin banyak perangkat, semakin banyak link yang terkonfirmasi dari kedua ujung.
2. Opsional: isi **Topology name**. Semua file unduhan lalu diberi nama itu (`Lab-DC-topology.drawio`, `Lab-DC-links.csv`, ...); kosong berarti nama biasa. File draw.io menampilkan nama dan `Topology Created at Date YYYY:MM:DD - Time HH:MM:SS` di atas diagram.
3. Atur opsi (nilai awal dalam kurung):
   - **Exclude IP phones, PCs and servers** (aktif): hanya perangkat jaringan yang digambar. Selama aktif, opsi phone/host disembunyikan.
   - **Collapse phones and hosts into one node per switch** (aktif), **Group end points under the same switch** (aktif, bila end point digambar satu per satu: satu bingkai per switch di sekeliling phone, PC, dan server-nya) dan **Collapse access points into one node per switch** (aktif: satu kotak per switch; matikan agar setiap access point tampil dengan hostname, model, dan IP sendiri, dalam bingkai di bawah switch-nya).
   - **Show port names on the lines** (aktif), **Show the address of routed ports on the lines** (aktif), **Infer neighbors where CDP/LLDP is silent** (aktif; urutan kepercayaan: ARP, lalu MAC address, lalu port description), **Add routed /30 and /31 links** (aktif), **Leave out-of-band management links out of the picture** (aktif), **Draw end hosts learned from MAC tables** (mati).
   - **Grouping**: Automatic (default), satu diagram, kelompok berdasarkan satu, dua, atau tiga kata pertama hostname (`JKT`, `JKT-A02`, `JKT-GD1-LT1`), atau **Sites, smart**. *Sites, smart* membaca keluarga nama hostname yang toleran terhadap perbedaan kecil dan dikoreksi oleh kabel: `HQWANR1` dan `HQ-ACC1` satu site, `LT2` dan `LT02` satu lantai, dan nama yang diawali peran (`SW-JKT-1`, `RTR-JKT-1`, `SW-A02-1`: peran di depan, site atau lantai di belakang) dikelompokkan menurut site-nya, bukan menurut peran. **Automatic** memilih sendiri: satu diagram untuk jaringan kecil (kurang dari 30 perangkat), site smart bila nama menunjukkan site yang jelas, kata pertama atau kedua hostname bila itu yang paling masuk akal; **alasannya ditampilkan di halaman hasil dan ditulis di `run-settings.txt`**, jadi Anda tahu mengapa halaman dibagi begitu. Setiap grup digambar dalam kotak hitam; grup dengan link terbanyak ke grup lain ada di tengah.
   - **Site rules** (opsional): bila pengelompokan otomatis salah, tulis aturan Anda sendiri, satu baris per site: `Nama = awal, awal`. Perangkat yang hostname-nya diawali salah satu `awal` (huruf besar atau kecil tidak berpengaruh) masuk site itu, dan end point di switch yang dipindah ikut. Contoh: `HQ = HQWAN, HQSDWAN, HQ-ACC` dan `DC1 = DCA-, DCB-`. Berlaku untuk semua pengelompokan kecuali satu diagram; maksimal 60 aturan.
   - **Diagram file contains**: semua tampilan dalam satu file (default), **L3 over L2** (link L3 digambar di atas kabel yang membawanya), **L3 - Logical and Route** (link yang dibuktikan tabel routing dan tetangga), **L3 - Logical view** (subnet bersama, alamat interface), **L2 fisik dan vPC**, fisik saja, vPC saja, atau **F5 map** (virtual server, pool, member, node tiap BIG-IP).
   - **Line shape** (lurus dengan satu tekukan di sekitar perangkat, atau melengkung) dan **Style lines by** (kecepatan rating atau status link).
   - **SD-WAN sites on the L3 pages**: hanya site yang Anda capture (default; sisanya satu cloud) atau semua site di tabel BFD, opsional dengan daftar site yang digambar. **Group what repeats on the L3 pages** (aktif) mengubah router next-hop yang tidak di-capture menjadi satu node per VRF, dan pasangan interface VLAN antara dua switch menjadi satu garis; tabel tetap berisi semua baris.
   - **Provider hints** (opsional): satu aturan per baris, misalnya `HQWANR1 Gi0/0/1 = mpls Telkom` atau `203.0.113.0/30 = internet Biznet`, untuk menamai cloud provider di tampilan L3.
   - **Also make an anonymized copy** (mati): paket kedua dengan hostname, nama domain, description, nama VRF dan objek F5, alamat IP, MAC address, dan serial number diganti secara konsisten di semua tempat, plus file kunci. Simpan kunci itu di komputer Anda sendiri.
4. Tekan **Build topology**. Progress bar menampilkan langkahnya (capture 3 dari 7, menggambar halaman 2 dari 5, menulis pack) dan detik yang sudah berjalan; build kedua dari capture yang sama jauh lebih cepat karena hasil pembacaan disimpan. Lalu lihat pratinjau (zoom, geser, buka di tab baru) dan baca findings. Unduh **pack** (ZIP) untuk semuanya, atau file satuan. Untuk dicetak, buka `topology-print-a3.html` di browser lalu cetak ke PDF (kertas A3 landscape, tanpa scaling): satu lembar per halaman diagram, masing-masing sudah diskalakan muat satu lembar. Tab **Capture next** menampilkan perangkat yang capture-nya paling menambah link, dan **Trace a path** menelusuri alamat tujuan hop demi hop lewat tabel routing.
5. Untuk melanjutkan nanti, pilih `topology.json` di **Add to a previous run** dan `topology.drawio` yang sudah Anda geser di **Keep my layout**.
6. Penempatan perangkat: satu level dibaca dari kiri ke kanan urut nama (A-Z, lalu 0-9). Semua yang terhubung ke satu perangkat (switch, access point, IP phone, PC) dikelompokkan tepat di bawah perangkat itu, jadi 3 AP di bawah switch A tidak bercampur dengan 2 AP di bawah switch B. Perangkat yang hanya uplink (router, firewall) ditempatkan di atas perangkat yang dilayaninya, berdampingan (router A, B, C).

Pack berisi `run-settings.txt`: opsi yang Anda pilih, waktu pembuatan, nama topologi, alasan pengelompokan Automatic, aturan site yang dipakai, dan **Layout check** (per halaman: jumlah garis yang bersilangan, garis yang melewati ikon perangkat lain, dan panjang garis, dihitung pada garis seperti yang digambar). Angka itu berguna untuk membandingkan dua build dari capture yang sama. Kirimkan bersama pertanyaan atau laporan masalah. Penjelasan lengkap, termasuk ID finding (TOPO-001 ...), ada di [modules/topology.md](modules/topology.md).

### Mencoba tanpa capture, riwayat, banding, dan runbook

- Belum punya capture? Di **Device captures** ada tombol data contoh (**Data center today**, **After a change window**, **Firewall and F5**). Isinya capture karangan, bukan jaringan nyata. Muat yang pertama, build, lalu muat yang kedua dan build lagi: banner di atas hasil menyebut apa yang berubah.
- Tombol **Topology history** (di samping nama topologi) membuka semua topologi yang pernah dibuat di komputer ini: 20 terbaru selama 30 hari, ditambah yang Anda **pin** (tidak pernah dihapus otomatis). Per run: **Details**, **Open again** (hasilnya terbuka lagi tanpa build ulang), **Download pack**, ganti nama, catatan, hapus. Run yang di-pin terbaru menjadi **baseline**; setiap build berikutnya dibandingkan dengannya.
- Tab **Compare two runs** menunjukkan apa yang berubah antara dua build (perangkat, link, kecepatan, bundle, finding, host). Tab **Cutover runbook** membuat rencana perubahan berurutan yang bisa dicetak dari satu run: dampak per perangkat, pasangan redundan, peta port, pemeriksaan, dan rollback. Detail: [modules/topology.md](modules/topology.md).
- Build 100 capture sekarang selesai sekitar 8 detik (tadinya 26 detik); hasil gambar sama persis.

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

## 7d. Mengonversi firewall FortiGate dan PAN-OS

1. Buka **Convert**, lalu **Firewall**. Pilih file (FortiGate: `show full-configuration` atau backup `.conf`; PAN-OS: perintah `set`, XML dari `show config running`, atau tampilan kurung kurawal). Pilih Source Vendor (atau Auto Detect) dan Target Vendor: **Palo Alto** untuk FortiGate ke PAN-OS, **FortiGate** untuk arah sebaliknya.
2. Untuk export **Panorama** (XML dari *Export named configuration snapshot*), halaman mengenali file-nya dan mengisi daftar pada kolom VDOM / device group. Isi `NamaGroup` (semua rule device group itu) atau `NamaGroup:SERIAL` (hanya rule yang dipush ke firewall itu). Hasilnya bisa ke FortiGate atau diratakan menjadi satu XML PAN-OS biasa. Password hash, pre-shared key, SNMP community dan private key tidak pernah disalin. Detail: `docs/modules/panorama.md`.
3. Pilih layer yang ditulis (interface dan zona, objek, policy, NAT, routing, VPN site-to-site). Untuk backup FortiGate multi-VDOM, isi VDOM yang dibaca; satu VDOM per konversi.
4. Tekan **Convert Configuration**. Tab **Conversion report** mendaftar setiap objek per layer dengan status **converted**, **approximated**, **review**, atau **not converted**, plus dokumentasi vendor yang perlu dibaca. Laporan bisa diunduh sebagai CSV.
5. Rule yang tidak bisa dibawa apa adanya (schedule, user atau group, Internet Service, application control) ditulis **disabled** dengan alasan di description; kotak centang menulisnya enabled. Pre-shared key IPsec tidak pernah dibaca atau ditulis: hasilnya berisi `REPLACE-ME`, isi sendiri di perangkat.
6. Bacalah baris review sebelum konfigurasi masuk ke firewall. Beda mendasar: PAN-OS mencocokkan rule dengan alamat *sebelum* NAT dan zona *sesudah* NAT, sehingga VIP FortiGate menjadi objek alamat ditambah rule destination NAT ([NAT policy overview](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/nat/nat-policy-rules/nat-policy-overview)). Penjelasan lengkap dan referensi: [modules/configuration-studio.md](modules/configuration-studio.md).

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
| Wireless Center tidak lagi menampilkan kunci WPA-PSK; `redact_line` menyembunyikan nilai setelah `cipher` / `irreversible-cipher` | Hasil pemindaian token pada capture nyata; nilai hanya disembunyikan di baris perintah mentah, label seperti `WPA-PSK` tetap tampil |
| Hasil konversi memuat hash password dan community SNMP | Memang disengaja: converter menyalin nilai dari sumber supaya konfigurasi bisa langsung ditempel. Centang **Hide passwords and keys in the output** di halaman Convert Switch sebelum file dibagikan; nilai diganti `<hidden>` di layar, unduhan dan ZIP batch |
| Community SNMP tampil sebagai `<hidden> (N characters)` | Memang disengaja: nama community adalah rahasia bersama dan tidak pernah ditampilkan atau diekspor. Nama bawaan seperti `public` dan `private` tetap terlihat karena itulah temuannya |
| Analyzer bilang file tidak dikenali | Pakai analyzer yang sesuai, atau kumpulkan ulang output dengan daftar perintah di tab Collect Backup |
| Hasil terlihat kurang lengkap | Kumpulkan dengan daftar perintah lengkap untuk platformnya. Tab Coverage di Switch Analyzer menunjukkan perintah mana yang ditemukan |
| DHCP bawaan ZTP tidak jalan | Pasang `dnsmasq` dan jalankan Keystone dengan hak administrator atau root; DHCP memakai port istimewa |
| Setup selesai tapi ada yang gagal | Jalankan pemeriksaan di bagian Menjalankan dan menghentikan dan baca hasilnya |

## 11. Data Anda

- File unggahan, ekspor, log, dan setting yang dibuat otomatis tersimpan di `data/`, `uploads/`, `exports/`, dan `logs/` di dalam folder Keystone. Folder itu sengaja diabaikan oleh git.
- Jangan pernah commit capture pelanggan atau kredensial asli. Test memakai file sintetis saja.
- Pekerjaan LLD tersimpan di `data/nes.db` (project LLD Index dan LLD Generator, approvers) dan `data/lld_generator/` (template, gambar, file Word hasil generate; file hasil generate yang lebih dari 7 hari dihapus). Backup folder `data` untuk menyimpannya.
- Keystone tidak mengirim konfigurasi ke layanan eksternal.
- Nilai rahasia (password, secret, pre-shared key, nama community SNMP, kunci SNMPv3) tidak pernah sampai ke layar, ekspor Excel, log, atau finding; analyzer hanya menyimpan jenis dan kekuatannya. Setiap halaman dan unduhan dikirim dengan header keamanan (Content-Security-Policy yang hanya mengizinkan sumber dari Keystone sendiri, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`).

## 12. Dokumen lain

- [PRD.md](PRD.md): scope, vendor yang didukung, roadmap
- [../CONTRIBUTING.md](../CONTRIBUTING.md): aturan berkontribusi, cara membuka issue dan pull request
- [PRESENTER_SCRIPT.md](PRESENTER_SCRIPT.md): demonstrasi lima menit dengan data contoh (bahasa Inggris)
- [modules/configuration-studio.md](modules/configuration-studio.md): cara kerja Convert, Nexus, stack, katalog hardware
- [modules/lifecycle-manager.md](modules/lifecycle-manager.md): upgrade, push, backup, ZTP
- [modules/lld-index.md](modules/lld-index.md) dan [modules/lld-generator.md](modules/lld-generator.md): LLD Index dan LLD Generator
- [../CHANGELOG.md](../CHANGELOG.md)
