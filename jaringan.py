"""
Fungsi bantu yang dipakai bersama oleh KDC, Alice, dan Bob:
kirim/terima pesan lewat TCP, enkripsi field protokol, dan pembuatan nonce.

Setiap pesan dikirim sebagai satu baris JSON. Sengaja dibuat berbentuk teks
supaya di Wireshark (Follow TCP Stream) isi paketnya mudah dibaca: bagian yang
terenkripsi akan terlihat sebagai string hex.
"""

import json
import secrets
import threading
from datetime import datetime

from aes import AES


def log(sumber, pesan):
    jam = datetime.now().strftime("%H:%M:%S")
    print(f"[{jam}] [{sumber}] {pesan}", flush=True)


def kirim(sock, data):
    baris = json.dumps(data) + "\n"
    sock.sendall(baris.encode("ascii"))


class Penerima:
    """Membaca pesan JSON baris per baris dari socket."""

    def __init__(self, sock):
        self.berkas = sock.makefile("r", encoding="ascii", newline="\n")

    def terima(self):
        baris = self.berkas.readline()
        if not baris:
            return None
        return json.loads(baris)


def buat_nonce():
    return secrets.randbits(32)


def f_nonce(n):
    # fungsi transformasi nonce di langkah 5, cukup ditambah satu
    return (n + 1) % (1 << 32)


def bungkus(kunci, isi):
    # isi berupa dict diubah ke JSON lalu dienkripsi AES-CBC, hasilnya hex
    aes = AES(kunci.encode("ascii"))
    return aes.enkripsi_cbc(json.dumps(isi).encode("ascii")).hex()


def buka(kunci, cipher_hex):
    aes = AES(kunci.encode("ascii"))
    polos = aes.dekripsi_cbc(bytes.fromhex(cipher_hex))
    return json.loads(polos.decode("ascii"))


def parse_alamat(teks, port_bawaan):
    if ":" in teks:
        host, port = teks.rsplit(":", 1)
        return host, int(port)
    return teks, port_bawaan


def jalankan_thread(fungsi, *args):
    t = threading.Thread(target=fungsi, args=args, daemon=True)
    t.start()
    return t


def minta_kunci(label):
    # dipakai saat startup; kunci tidak di-hardcode di program
    while True:
        k = input(f"Masukkan {label} (ASCII 16/24/32 karakter): ")
        if k.isascii() and len(k) in (16, 24, 32):
            return k
        print(f"  Kunci tidak valid ({len(k)} karakter). Coba lagi.")


def kunci_valid(k):
    return k.isascii() and len(k) in (16, 24, 32)
