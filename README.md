# MessageBox

MessageBox adalah aplikasi desktop sederhana dan modern untuk melakukan *testing* pengiriman maupun pemantauan (penerimaan) pesan pada protokol **MQTT** dan **AMQP** (RabbitMQ).

Aplikasi ini dibangun menggunakan arsitektur frontend web modern dengan Wails:
- **Backend:** Go (Golang)
- **Frontend:** React, TypeScript, Tailwind CSS, dan DaisyUI
- **Libraries Engine:** `paho.mqtt.golang` dan `rabbitmq/amqp091-go`

---

## 🚀 Instalasi dari Binary (Siap Pakai)

Anda tidak perlu menginstal bahasa pemrograman (Go/NodeJS) jika menggunakan versi rilis *binary* karena aplikasi ini sudah dipaketkan secara mandiri (*standalone*). Silakan unduh versi terbaru langsung dari halaman **Releases** di repositori GitHub ini.

### Untuk Pengguna Windows
1. Unduh (atau pindahkan) berkas `messagebox.exe` dari folder distribusi rilis (direktori `build/bin/`).
2. Klik dua kali pada file `messagebox.exe` untuk menjalankannya.

### Untuk Pengguna Linux
1. Unduh berkas `messagebox` tanpa ekstensi dari direktori `build/bin/`.
2. Buka terminal di lokasi berkas tersebut.
3. Berikan izin eksekusi ganda: 
   ```bash
   chmod +x messagebox
   ```
4. Jalankan aplikasi:
   ```bash
   ./messagebox
   ```

---

## 🛠 Panduan Cara Penggunaan

### 1. Pengaturan Koneksi
Di panel sebelah kiri aplikasi, Anda dapat mengatur detail koneksi menuju *broker*:
- **Protocol:** Pilih **MQTT** atau **AMQP**.
- **Mode TLS:** Centang boks **Use TLS** jika peladen (*server*) Anda memerlukan koneksi aman (`tls://` atau `amqps://`). Secara otomatis *port* akan berganti ke format standar (8883 atau 5671).
- **Kredensial:** Isi parameter Host, Port, Username, dan Password dari peladen broker Anda.
- *(Khusus AMQP)* **Connection URL:** Anda bisa menyunting URL koneksi AMQP yang akan masuk secara otomatis ke *backend*.
- Isi tujuan Topik (MQTT) atau Exchange/Routing/Queue/VHost (AMQP) Anda.
- Klik **Connect**. Status antarmuka akan menjadi hijau (tersambung).

### 2. Menyimpan dan Memuat Profil (Profile Manager)
Jika Anda mempunyai profil *broker* yang sering dihubungi:
- Ketikkan nama profil pilihan Anda pada kotak pilihan (*dropdown*) `Select profile`.
- Klik tombol **Save** untuk menyimpan profil tersebut secara permanen ke komputer Anda.
- Di lain waktu, Anda cukup memilih nama tersebut lalu klik **Load** sehingga paramater Host, Sandi, hingga sandi TLS akan terisi secara otomatis tanpa perlu mengetik ulang. Anda juga bisa menghapusnya dengan klik **Delete**.

### 3. Mengirim Pesan (Sender)
1. Setelah tersambung, lihat panel sisi kanan ("Sender").
2. Pastikan tuas/ *toggle* **Enable** dalam kondisi warna hijau menyala.
3. Ketikkan tulisan *payload* pesan pada kotak teks yang tersedia.
4. Tekan tombol **Enter** di *keyboard* atau klik **Send**.
5. Bukti riwayat pengiriman akan terekam berwarna biru dalam kotak kotak terminal aplikasi Anda.

### 4. Menerima Pesan (Receiver)
1. Pastikan fitur tuas **Enable** dalam kondisi dicentang pada panel kanan ("Receiver").
2. Jika ada pesan yang dikirimkan oleh pihak lain ke alamat MQTT atau antrean RabbitMQ yang Anda targetkan, data masuk akan terekam secara rapi ke *log window* dengan warna teks hijau.
3. Kotak log dibekali fungsionalitas pengguliran (*scroll*) otomatis ke bagian bawah sehingga rekaman pesan tidak memakan layar Anda.

---

## 💻 Pengembangan Mode Live (Development)

Bagi pengembang (*developer*), Anda dapat masuk ke ranah pengembangan *Hot-Reload* dengan Wails.

Buka terminal di lokasi kode map ini dan jalankan:
```bash
wails dev
```
Wails akan mempersiapkan pratinjau React serta peladen Go lokal sehingga jika mengubah kode, Anda tidak perlu mengkompilasi secara manual ulang!

Untuk membentuk hasil akhir yang dapat didistribusikan (*production build*):
```bash
wails build -platform <os>/<arch>
# contoh: wails build -platform windows/amd64
```
