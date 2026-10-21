"""
Key Distribution Center (KDC).

KDC menyimpan master key setiap pengguna (Ka untuk Alice, Kb untuk Bob) dan
melayani langkah 1-2 dari skenario distribusi kunci:

  (1) A -> KDC : IDA || IDB || N1
  (2) KDC -> A : E(Ka, [Ks || IDA || IDB || N1 || E(Kb, [Ks || IDA])])

Contoh menjalankan:
  python kdc.py --port 5000
"""

import argparse
import os
import socket
import string
import threading
import time

from aes import AES
from jaringan import (Penerima, bungkus, jalankan_thread, kirim, kunci_valid,
                      log, minta_kunci)

KARAKTER_KUNCI = string.ascii_letters + string.digits


class PembangkitKunci:
    """
    PRNG berbasis block cipher (mode counter) seperti di slide:  Xi = E(Km, [i])
    Km adalah kunci internal KDC yang dibuat acak saat program dijalankan.
    Hasilnya dipetakan ke karakter huruf/angka supaya session key tetap ASCII.
    """

    def __init__(self):
        self.aes = AES(os.urandom(16))
        # counter diawali waktu supaya tiap kali program jalan urutannya beda
        self.counter = time.time_ns()
        self.gembok = threading.Lock()

    def _blok_berikutnya(self):
        with self.gembok:
            self.counter += 1
            nilai = self.counter
        return self.aes.enkripsi_ecb(nilai.to_bytes(16, "big"))[:16]

    def buat(self, panjang):
        hasil = []
        while len(hasil) < panjang:
            for b in self._blok_berikutnya():
                # byte >= 248 dibuang supaya tiap karakter peluangnya sama (248 = 4 * 62)
                if b < 248 and len(hasil) < panjang:
                    hasil.append(KARAKTER_KUNCI[b % len(KARAKTER_KUNCI)])
        return "".join(hasil)


class KDC:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.master_key = {}
        self.sesi_manual = None
        self.panjang_sesi = 16
        self.prng = PembangkitKunci()
        self.gembok = threading.Lock()

    def buat_session_key(self):
        if self.sesi_manual:
            return self.sesi_manual
        return self.prng.buat(self.panjang_sesi)

    def layani(self, conn, alamat):
        sumber = f"{alamat[0]}:{alamat[1]}"
        try:
            penerima = Penerima(conn)
            pesan = penerima.terima()
            if not pesan or pesan.get("langkah") != 1:
                log("KDC", f"pesan tidak dikenal dari {sumber}")
                return

            id_a, id_b, n1 = pesan["id_a"], pesan["id_b"], pesan["n1"]
            log("KDC", f"Langkah 1 diterima dari {sumber}: IDA={id_a}, IDB={id_b}, N1={n1}")

            with self.gembok:
                ka = self.master_key.get(id_a)
                kb = self.master_key.get(id_b)
                ks = self.buat_session_key()

            if ka is None or kb is None:
                tidak_ada = id_a if ka is None else id_b
                log("KDC", f"'{tidak_ada}' belum terdaftar, permintaan ditolak")
                kirim(conn, {"langkah": 2, "error": f"ID {tidak_ada} tidak terdaftar di KDC"})
                return

            tiket = bungkus(kb, {"ks": ks, "id_a": id_a})
            isi = {"ks": ks, "id_a": id_a, "id_b": id_b, "n1": n1, "tiket": tiket}
            data = bungkus(ka, isi)

            log("KDC", f"Session key baru untuk {id_a}<->{id_b}: Ks = {ks}")
            log("KDC", f"Tiket untuk {id_b}  E(Kb, [Ks||IDA]) = {tiket}")
            log("KDC", f"Langkah 2 dikirim ke {id_a}: E(Ka, [...]) = {data[:64]}... ({len(data) // 2} byte)")
            kirim(conn, {"langkah": 2, "data": data})
        except (OSError, ValueError, KeyError) as e:
            log("KDC", f"koneksi {sumber} bermasalah: {e}")
        finally:
            conn.close()

    def jalankan_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen()
        log("KDC", f"mendengarkan di {self.host}:{self.port}")
        while True:
            conn, alamat = server.accept()
            jalankan_thread(self.layani, conn, alamat)

    def cetak_status(self):
        print("  Master key terdaftar:")
        for pid, k in self.master_key.items():
            print(f"    {pid:<10} {k}")
        if self.sesi_manual:
            print(f"  Session key : manual -> {self.sesi_manual}")
        else:
            print(f"  Session key : acak (PRNG), panjang {self.panjang_sesi} karakter")


BANTUAN = """Perintah KDC:
  status                  tampilkan master key dan pengaturan session key
  kunci <ID> <master key> ubah/tambah master key pengguna (contoh: kunci Alice abcdefghijklmnop)
  hapus <ID>              hapus pengguna
  sesi auto               session key dibuat acak oleh KDC
  sesi <kunci>            paksa KDC membagikan session key tertentu (untuk test case)
  panjang <16|24|32>      panjang session key acak (AES-128/192/256)
  bantuan                 tampilkan bantuan ini
  keluar                  matikan KDC"""


def konsol(kdc):
    print(BANTUAN)
    while True:
        try:
            baris = input("KDC> ").strip()
        except EOFError:
            return
        if not baris:
            continue
        perintah, _, sisa = baris.partition(" ")
        perintah = perintah.lower()

        with kdc.gembok:
            if perintah == "status":
                kdc.cetak_status()
            elif perintah == "kunci":
                pid, _, k = sisa.partition(" ")
                if not pid or not kunci_valid(k):
                    print("  format: kunci <ID> <kunci ASCII 16/24/32 karakter>")
                else:
                    kdc.master_key[pid] = k
                    print(f"  master key {pid} diubah menjadi {k}")
            elif perintah == "hapus":
                if kdc.master_key.pop(sisa, None) is None:
                    print("  ID tidak ditemukan")
                else:
                    print(f"  {sisa} dihapus")
            elif perintah == "sesi":
                if sisa == "auto":
                    kdc.sesi_manual = None
                    print("  session key kembali acak")
                elif kunci_valid(sisa):
                    kdc.sesi_manual = sisa
                    print(f"  session key berikutnya: {sisa}")
                else:
                    print("  session key harus ASCII 16/24/32 karakter")
            elif perintah == "panjang":
                if sisa in ("16", "24", "32"):
                    kdc.panjang_sesi = int(sisa)
                    print(f"  panjang session key acak: {sisa} karakter (AES-{int(sisa) * 8})")
                else:
                    print("  pilihan: 16, 24, atau 32")
            elif perintah == "bantuan":
                print(BANTUAN)
            elif perintah == "keluar":
                return
            else:
                print("  perintah tidak dikenal, ketik 'bantuan'")


def main():
    parser = argparse.ArgumentParser(description="Key Distribution Center")
    parser.add_argument("--host", default="0.0.0.0", help="alamat IP untuk listen")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--pengguna", nargs="+", default=["Alice", "Bob"],
                        help="daftar ID yang master key-nya diminta saat startup")
    args = parser.parse_args()

    kdc = KDC(args.host, args.port)
    print("=== Key Distribution Center ===")
    for pid in args.pengguna:
        kdc.master_key[pid] = minta_kunci(f"master key {pid}")

    jalankan_thread(kdc.jalankan_server)
    time.sleep(0.2)
    konsol(kdc)


if __name__ == "__main__":
    main()
