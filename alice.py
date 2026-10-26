"""
Alice: pihak yang memulai distribusi kunci.

  (1) A -> KDC : IDA || IDB || N1
  (2) KDC -> A : E(Ka, [Ks || IDA || IDB || N1 || E(Kb, [Ks || IDA])])
  (3) A -> B   : E(Kb, [Ks || IDA])
  (4) B -> A   : E(Ks, N2)
  (5) A -> B   : E(Ks, f(N2))

Setelah langkah 5, Alice dan Bob saling berkirim pesan dengan AES memakai Ks.

"""

import argparse
import queue
import socket
import threading

from jaringan import (Penerima, buat_nonce, buka, bungkus, f_nonce,
                      jalankan_thread, kirim, log, minta_kunci, parse_alamat)
from peserta import Peserta

BATAS_WAKTU = 15


class Alice(Peserta):
    def __init__(self, nama, nama_lawan, master_key, alamat_kdc, alamat_bob, ip_lokal):
        super().__init__(nama, nama_lawan, master_key)
        self.alamat_kdc = alamat_kdc
        self.alamat_bob = alamat_bob
        self.sumber = (ip_lokal, 0) if ip_lokal else None
        # balasan Bob untuk langkah 4 dan status handshake dititipkan ke antrean ini
        self.antrean_handshake = queue.Queue()
        self.gembok_handshake = threading.Lock()

    def sambung(self, alamat):
        return socket.create_connection(alamat, timeout=BATAS_WAKTU, source_address=self.sumber)

    def sambung_bob(self):
        log(self.nama, f"menghubungi {self.nama_lawan} di {self.alamat_bob[0]}:{self.alamat_bob[1]}")
        self.sock = self.sambung(self.alamat_bob)
        self.sock.settimeout(None)
        jalankan_thread(self.loop_terima)

    def loop_terima(self):
        penerima = Penerima(self.sock)
        while True:
            try:
                pesan = penerima.terima()
            except (OSError, ValueError):
                pesan = None
            if pesan is None:
                log(self.nama, f"koneksi dengan {self.nama_lawan} terputus")
                self.antrean_handshake.put(None)
                return

            tipe = pesan.get("tipe")
            if tipe == "pesan":
                self.tampilkan_pesan(pesan)
            elif tipe == "minta_rekey":
                log(self.nama, f"{self.nama_lawan} meminta session key baru")
                jalankan_thread(self.rekey)
            else:
                self.antrean_handshake.put(pesan)

    def tunggu_bob(self):
        try:
            pesan = self.antrean_handshake.get(timeout=BATAS_WAKTU)
        except queue.Empty:
            raise RuntimeError(f"{self.nama_lawan} tidak membalas")
        if pesan is None:
            raise RuntimeError("koneksi terputus")
        if pesan.get("tipe") == "status" and not pesan.get("ok"):
            raise RuntimeError(f"{self.nama_lawan} menolak: {pesan.get('alasan')}")
        return pesan

    def minta_ke_kdc(self):
        n1 = buat_nonce()
        permintaan = {"langkah": 1, "id_a": self.nama, "id_b": self.nama_lawan, "n1": n1}
        log(self.nama, f"Langkah 1 -> KDC: IDA={self.nama}, IDB={self.nama_lawan}, N1={n1}")

        with self.sambung(self.alamat_kdc) as s:
            kirim(s, permintaan)
            balasan = Penerima(s).terima()

        if not balasan or balasan.get("langkah") != 2:
            raise RuntimeError("balasan KDC tidak valid")
        if "error" in balasan:
            raise RuntimeError(f"KDC: {balasan['error']}")

        log(self.nama, f"Langkah 2 <- KDC: {balasan['data'][:64]}... ({len(balasan['data']) // 2} byte)")
        try:
            isi = buka(self.master_key, balasan["data"])
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError("gagal mendekripsi balasan KDC, master key Alice tidak cocok dengan KDC")

        # pastikan balasan ini memang untuk permintaan barusan (bukan replay)
        if isi["n1"] != n1 or isi["id_b"] != self.nama_lawan or isi["id_a"] != self.nama:
            raise RuntimeError("N1 atau ID tidak cocok, balasan KDC ditolak")
        log(self.nama, f"  N1 cocok, Ks = {isi['ks']}")
        return isi["ks"], isi["tiket"]

    def rekey(self):
        if not self.gembok_handshake.acquire(blocking=False):
            log(self.nama, "distribusi kunci sedang berjalan")
            return False
        try:
            ks_baru, tiket = self.minta_ke_kdc()

            # kosongkan sisa pesan lama di antrean
            while not self.antrean_handshake.empty():
                self.antrean_handshake.get_nowait()

            log(self.nama, f"Langkah 3 -> {self.nama_lawan}: tiket E(Kb, [Ks||IDA]) = {tiket}")
            self.kirim_json({"langkah": 3, "tiket": tiket})

            pesan = self.tunggu_bob()
            if pesan.get("langkah") != 4:
                raise RuntimeError("seharusnya menerima langkah 4")
            log(self.nama, f"Langkah 4 <- {self.nama_lawan}: E(Ks, N2) = {pesan['data']}")
            n2 = buka(ks_baru, pesan["data"])["n2"]

            jawaban = f_nonce(n2)
            data = bungkus(ks_baru, {"f_n2": jawaban})
            log(self.nama, f"  N2 = {n2}, f(N2) = {jawaban}")
            log(self.nama, f"Langkah 5 -> {self.nama_lawan}: E(Ks, f(N2)) = {data}")
            self.kirim_json({"langkah": 5, "data": data})

            status = self.tunggu_bob()
            if status.get("tipe") != "status":
                raise RuntimeError("konfirmasi dari Bob tidak valid")

            self.ks = ks_baru
            log(self.nama, f"distribusi kunci selesai, session key aktif: {self.ks}")
            print(f"  Sekarang bisa chat dengan {self.nama_lawan}. Ketik /bantuan untuk daftar perintah.")
            return True
        except (RuntimeError, OSError, ValueError, KeyError) as e:
            log(self.nama, f"distribusi kunci gagal: {e}")
            return False
        finally:
            self.gembok_handshake.release()


def main():
    parser = argparse.ArgumentParser(description="Alice (inisiator)")
    parser.add_argument("--kdc", required=True, help="alamat KDC, contoh 192.168.1.10:5000")
    parser.add_argument("--bob", required=True, help="alamat Bob, contoh 192.168.1.12:6000")
    parser.add_argument("--ip", help="IP lokal yang dipakai Alice (opsional)")
    parser.add_argument("--id", default="Alice")
    parser.add_argument("--lawan", default="Bob", help="ID Bob yang terdaftar di KDC")
    args = parser.parse_args()

    print(f"=== {args.id} ===")
    ka = minta_kunci(f"master key {args.id} (Ka)")
    alice = Alice(args.id, args.lawan, ka, parse_alamat(args.kdc, 5000),
                  parse_alamat(args.bob, 6000), args.ip)
    try:
        alice.sambung_bob()
    except OSError as e:
        log(args.id, f"tidak bisa terhubung ke {args.lawan}: {e}")
        return
    alice.rekey()
    alice.loop_input()


if __name__ == "__main__":
    main()
