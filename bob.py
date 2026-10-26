"""
Bob: menunggu koneksi dari Alice dan menangani langkah 3-5.

  (3) A -> B : E(Kb, [Ks || IDA])     Bob membuka tiket dengan Kb
  (4) B -> A : E(Ks, N2)              Bob menantang Alice dengan nonce baru
  (5) A -> B : E(Ks, f(N2))           Bob mengecek jawabannya

"""

import argparse
import socket

from jaringan import (Penerima, buat_nonce, buka, bungkus, f_nonce, log,
                      minta_kunci, jalankan_thread)
from peserta import Peserta


class Bob(Peserta):
    def __init__(self, nama, master_key, host, port):
        super().__init__(nama, "-", master_key)
        self.host = host
        self.port = port
        # session key yang belum lolos langkah 5 disimpan sementara di sini
        self.calon = None

    def tolak(self, alasan):
        log(self.nama, f"handshake ditolak: {alasan}")
        self.calon = None
        self.kirim_json({"tipe": "status", "ok": False, "alasan": alasan})

    def langkah_3(self, pesan):
        tiket = pesan["tiket"]
        log(self.nama, f"Langkah 3 <- tiket E(Kb, [Ks||IDA]) = {tiket}")
        try:
            isi = buka(self.master_key, tiket)
        except (ValueError, UnicodeDecodeError):
            self.tolak("tiket tidak bisa dibuka, master key Bob tidak cocok dengan KDC")
            return

        ks, id_a = isi["ks"], isi["id_a"]
        n2 = buat_nonce()
        self.calon = (ks, id_a, n2)
        log(self.nama, f"  tiket valid: IDA={id_a}, Ks={ks}")

        data = bungkus(ks, {"n2": n2})
        log(self.nama, f"Langkah 4 -> {id_a}: N2={n2}, E(Ks, N2) = {data}")
        self.kirim_json({"langkah": 4, "data": data})

    def langkah_5(self, pesan):
        if self.calon is None:
            self.tolak("langkah 5 datang sebelum langkah 3")
            return
        ks, id_a, n2 = self.calon
        log(self.nama, f"Langkah 5 <- E(Ks, f(N2)) = {pesan['data']}")
        try:
            jawaban = buka(ks, pesan["data"])["f_n2"]
        except (ValueError, UnicodeDecodeError, KeyError):
            self.tolak("jawaban langkah 5 tidak bisa didekripsi")
            return

        if jawaban != f_nonce(n2):
            self.tolak(f"f(N2) salah, diharapkan {f_nonce(n2)} tapi diterima {jawaban}")
            return

        # Alice terbukti memegang Ks yang sama, session key resmi dipakai
        self.ks = ks
        self.nama_lawan = id_a
        self.calon = None
        log(self.nama, f"  f(N2) = {jawaban} cocok. Session key aktif: {ks}")
        print(f"  Sekarang bisa chat dengan {id_a}. Ketik /bantuan untuk daftar perintah.")
        self.kirim_json({"tipe": "status", "ok": True})

    def layani(self, conn, alamat):
        log(self.nama, f"koneksi masuk dari {alamat[0]}:{alamat[1]}")
        penerima = Penerima(conn)
        while True:
            try:
                pesan = penerima.terima()
            except (OSError, ValueError):
                pesan = None
            if pesan is None:
                log(self.nama, "koneksi terputus, menunggu koneksi baru")
                if self.sock is conn:
                    self.sock = None
                    self.ks = None
                return
            try:
                langkah = pesan.get("langkah")
                if langkah == 3:
                    self.langkah_3(pesan)
                elif langkah == 5:
                    self.langkah_5(pesan)
                elif pesan.get("tipe") == "pesan":
                    self.tampilkan_pesan(pesan)
            except OSError as e:
                log(self.nama, f"gagal membalas: {e}")

    def jalankan_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen()
        log(self.nama, f"menunggu Alice di {self.host}:{self.port}")
        while True:
            conn, alamat = server.accept()
            # cukup satu lawan bicara; koneksi lama ditutup kalau ada yang baru
            if self.sock is not None:
                self.sock.close()
            self.sock = conn
            self.ks = None
            jalankan_thread(self.layani, conn, alamat)

    def rekey(self):
        # yang menghubungi KDC tetap Alice, Bob hanya memintanya mengulang
        log(self.nama, "meminta Alice mengulang distribusi kunci")
        self.kirim_json({"tipe": "minta_rekey"})


def main():
    parser = argparse.ArgumentParser(description="Bob (responder)")
    parser.add_argument("--host", default="0.0.0.0", help="alamat IP untuk listen")
    parser.add_argument("--port", type=int, default=6000)
    parser.add_argument("--id", default="Bob")
    args = parser.parse_args()

    print(f"=== {args.id} ===")
    kb = minta_kunci(f"master key {args.id} (Kb)")
    bob = Bob(args.id, kb, args.host, args.port)
    jalankan_thread(bob.jalankan_server)
    bob.loop_input()


if __name__ == "__main__":
    main()
