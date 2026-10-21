# Tugas 2 Keamanan Informasi – AES dan Key Distribution Center

Implementasi skenario distribusi kunci dengan KDC (Stallings) yang melibatkan tiga
entitas di tiga perangkat/IP berbeda: **KDC**, **Alice**, dan **Bob**. Setelah langkah
ke-5 selesai, Alice dan Bob bisa saling berkirim pesan yang dienkripsi AES memakai
session key dari KDC.

AES dan protokol KDC ditulis sendiri tanpa library kriptografi. Library yang dipakai
hanya bawaan Python (`socket`, `json`, `threading`, `secrets`, `os`).

## Skenario distribusi kunci

```
(1) A   -> KDC : IDA || IDB || N1
(2) KDC -> A   : E(Ka, [Ks || IDA || IDB || N1 || E(Kb, [Ks || IDA])])
(3) A   -> B   : E(Kb, [Ks || IDA])
(4) B   -> A   : E(Ks, N2)
(5) A   -> B   : E(Ks, f(N2))          f(N2) = N2 + 1
```

- `Ka`, `Kb` : master key Alice dan Bob, hanya diketahui pemiliknya dan KDC
- `Ks`       : session key yang dibuat KDC untuk satu sesi
- `N1`, `N2` : nonce untuk mencegah replay

## Struktur file

| File          | Isi |
|---------------|-----|
| `aes.py`      | AES-128/192/256 manual (S-box, key expansion, 4 transformasi ronde), mode ECB & CBC, padding PKCS#7. Bisa dijalankan sendiri untuk uji enkripsi dan melihat state tiap ronde. |
| `kdc.py`      | Server KDC: menyimpan master key, membuat session key, melayani langkah 1–2. |
| `alice.py`    | Inisiator: menjalankan langkah 1, 3, 5 lalu chat. |
| `bob.py`      | Responder: menangani langkah 3–5 lalu chat. |
| `peserta.py`  | Bagian yang dipakai bersama oleh Alice dan Bob (chat, perintah). |
| `jaringan.py` | Kirim/terima pesan JSON lewat TCP, enkripsi field protokol, nonce. |
| `test_aes.py` | Pengujian AES dengan test vector FIPS-197 dan NIST SP 800-38A. |

## Format data

- Key dan plaintext: ASCII. Panjang key 16/24/32 karakter → AES-128/192/256.
- Ciphertext: hexadecimal. Pada mode CBC, 16 byte pertama adalah IV.
- Semua key dimasukkan saat program berjalan (tidak di-hardcode) dan bisa diubah
  tanpa restart.

## Cara menjalankan

Butuh Python 3.8+ di ketiga perangkat, tidak perlu install apa pun.
Misal IP: KDC `192.168.1.10`, Bob `192.168.1.12`, Alice `192.168.1.11`.

```bash
# perangkat KDC
python kdc.py --port 5000

# perangkat Bob
python bob.py --port 6000

# perangkat Alice
python alice.py --kdc 192.168.1.10:5000 --bob 192.168.1.12:6000
```

Masukkan master key yang sama di KDC dan di masing-masing pengguna. Begitu Alice
jalan, langkah 1–5 otomatis dikerjakan dan log tiap langkah tampil di ketiga terminal.

### Perintah di Alice / Bob

| Perintah         | Fungsi |
|------------------|--------|
| `<teks>`         | kirim pesan terenkripsi |
| `/info`          | lihat session key, master key, mode |
| `/mode ecb\|cbc` | ganti mode AES pesan yang dikirim |
| `/kunci <kunci>` | ganti master key sendiri |
| `/rekey`         | minta session key baru (langkah 1–5 diulang) |
| `/keluar`        | keluar |

### Perintah di KDC

| Perintah                | Fungsi |
|-------------------------|--------|
| `status`                | lihat master key terdaftar dan pengaturan session key |
| `kunci <ID> <kunci>`    | ubah/tambah master key pengguna |
| `hapus <ID>`            | hapus pengguna |
| `sesi auto`             | session key dibuat acak |
| `sesi <kunci>`          | session key berikutnya ditentukan manual |
| `panjang 16\|24\|32`    | panjang session key acak |

## Fitur tambahan

- AES-192 dan AES-256 selain AES-128.
- Mode ECB dan CBC (IV acak per pesan), bisa diganti saat chat.
- Session key acak dibangkitkan dengan PRNG berbasis AES mode counter
  (`Xi = E(Km, [i])`, sesuai materi Random Numbers).
- S-box dibangun dari definisinya (invers di GF(2^8) + transformasi affine),
  bukan tabel yang diketik.
- Rekey kapan saja dari Alice maupun Bob tanpa memutus koneksi.
- Validasi nonce N1 dan N2, serta penolakan jika master key tidak cocok.
- Mode jejak di `aes.py` untuk menampilkan round key dan state setiap ronde.

## Pengujian AES

```bash
python -m unittest test_aes -v
```

## Wireshark

Filter tampilan: `tcp.port == 5000 || tcp.port == 6000`. Pesan dikirim sebagai JSON
per baris sehingga lewat *Follow → TCP Stream* terlihat jelas bahwa yang lewat di
jaringan hanya ID, nonce N1 (memang plaintext di langkah 1), dan ciphertext hex.
