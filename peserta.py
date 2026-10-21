"""
Bagian yang sama antara Alice dan Bob: menyimpan session key aktif,
mengenkripsi/mendekripsi pesan chat, dan menangani perintah dari keyboard.
"""

import threading

from aes import dekripsi_teks, enkripsi_teks
from jaringan import kirim, kunci_valid, log

BANTUAN = """Perintah:
  <teks>            kirim pesan terenkripsi ke lawan bicara
  /info             tampilkan session key, master key, dan mode
  /mode ecb|cbc     ganti mode AES untuk pesan yang dikirim
  /kunci <kunci>    ganti master key milik sendiri (harus sama dengan di KDC)
  /rekey            minta session key baru lewat KDC (ulang langkah 1-5)
  /bantuan          tampilkan bantuan ini
  /keluar           keluar dari program"""


class Peserta:
    def __init__(self, nama, nama_lawan, master_key):
        self.nama = nama
        self.nama_lawan = nama_lawan
        self.master_key = master_key
        self.ks = None
        self.mode = "cbc"
        self.sock = None
        self.gembok_kirim = threading.Lock()

    def kirim_json(self, data):
        if self.sock is None:
            raise OSError(f"belum terhubung dengan {self.nama_lawan}")
        with self.gembok_kirim:
            kirim(self.sock, data)

    def kirim_pesan(self, teks):
        if self.ks is None:
            log(self.nama, "belum ada session key, tunggu proses distribusi kunci selesai")
            return
        if not teks.isascii():
            log(self.nama, "plaintext harus karakter ASCII")
            return
        cipher = enkripsi_teks(self.ks, teks, self.mode)
        self.kirim_json({"tipe": "pesan", "mode": self.mode, "data": cipher})
        log(self.nama, f"kirim ({self.mode.upper()}) ciphertext: {cipher}")

    def tampilkan_pesan(self, pesan):
        cipher = pesan["data"]
        mode = pesan.get("mode", "cbc")
        print()
        log(self.nama, f"pesan masuk dari {self.nama_lawan} ({mode.upper()})")
        print(f"    ciphertext : {cipher}")
        if self.ks is None:
            print("    (belum punya session key, tidak bisa didekripsi)")
            return
        try:
            print(f"    plaintext  : {dekripsi_teks(self.ks, cipher, mode)}")
        except (ValueError, UnicodeDecodeError) as e:
            print(f"    gagal didekripsi: {e}")

    def info(self):
        print(f"  Nama        : {self.nama}")
        print(f"  Lawan       : {self.nama_lawan}")
        print(f"  Master key  : {self.master_key}")
        if self.ks:
            print(f"  Session key : {self.ks} (AES-{len(self.ks) * 8})")
        else:
            print("  Session key : belum ada")
        print(f"  Mode kirim  : {self.mode.upper()}")

    def rekey(self):
        raise NotImplementedError

    def loop_input(self):
        print(BANTUAN)
        while True:
            try:
                baris = input()
            except (EOFError, KeyboardInterrupt):
                break
            if not baris:
                continue
            try:
                if not baris.startswith("/"):
                    self.kirim_pesan(baris)
                    continue

                perintah, _, sisa = baris.partition(" ")
                if perintah == "/info":
                    self.info()
                elif perintah == "/mode":
                    if sisa.lower() in ("ecb", "cbc"):
                        self.mode = sisa.lower()
                        print(f"  mode sekarang {self.mode.upper()}")
                    else:
                        print("  pilihan mode: ecb atau cbc")
                elif perintah == "/kunci":
                    if kunci_valid(sisa):
                        self.master_key = sisa
                        print(f"  master key diganti menjadi {sisa}")
                        print("  (pastikan KDC juga memakai kunci yang sama, lalu /rekey)")
                    else:
                        print("  kunci harus ASCII 16/24/32 karakter")
                elif perintah == "/rekey":
                    self.rekey()
                elif perintah == "/bantuan":
                    print(BANTUAN)
                elif perintah == "/keluar":
                    break
                else:
                    print("  perintah tidak dikenal, ketik /bantuan")
            except OSError as e:
                log(self.nama, f"koneksi bermasalah: {e}")
        if self.sock:
            self.sock.close()
