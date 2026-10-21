"""
Implementasi AES (Rijndael) manual tanpa library kriptografi.

Mendukung kunci 128/192/256 bit, mode ECB dan CBC, serta padding PKCS#7.
Kalau file ini dijalankan langsung, akan muncul menu kecil untuk mencoba
enkripsi/dekripsi dan melihat isi state di setiap ronde.
"""

import os


# ---------------------------------------------------------------------------
# Aritmetika GF(2^8) dengan polinomial m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
# ---------------------------------------------------------------------------

def xtime(a):
    # perkalian dengan x (alias 0x02), kalau bit ke-8 keluar dikurangi 0x11B
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gmul(a, b):
    hasil = 0
    while b:
        if b & 1:
            hasil ^= a
        a = xtime(a)
        b >>= 1
    return hasil


def ginv(a):
    # invers perkalian: a^254 = a^-1 karena grupnya berorde 255
    if a == 0:
        return 0
    hasil = 1
    for _ in range(254):
        hasil = gmul(hasil, a)
    return hasil


def _bangun_sbox():
    # S-box tidak saya ketik manual, tapi dibangun dari definisinya:
    # cari invers di GF(2^8), lalu lakukan transformasi affine dengan konstanta 0x63
    sbox = [0] * 256
    for x in range(256):
        b = ginv(x)
        s = b
        for geser in range(1, 5):
            s ^= ((b << geser) | (b >> (8 - geser))) & 0xFF
        sbox[x] = s ^ 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


SBOX, INV_SBOX = _bangun_sbox()

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ---------------------------------------------------------------------------
# Key expansion
# ---------------------------------------------------------------------------

def ekspansi_kunci(kunci):
    nk = len(kunci) // 4
    if len(kunci) not in (16, 24, 32):
        raise ValueError("panjang kunci harus 16, 24, atau 32 byte")
    nr = nk + 6

    # w berisi word 4 byte, totalnya 4 * (nr + 1) word (44/52/60)
    w = [list(kunci[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [SBOX[b] for b in temp]          # SubWord
            temp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            # khusus AES-256 ada SubWord tambahan di tengah
            temp = [SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])

    # dikelompokkan jadi round key 16 byte supaya gampang di-XOR ke state
    round_keys = []
    for r in range(nr + 1):
        rk = []
        for word in w[4 * r:4 * r + 4]:
            rk.extend(word)
        round_keys.append(rk)
    return round_keys


# ---------------------------------------------------------------------------
# Transformasi per ronde
# State disimpan sebagai list 16 byte urut kolom: state[baris + 4*kolom]
# ---------------------------------------------------------------------------

def sub_bytes(s):
    return [SBOX[b] for b in s]


def inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def shift_rows(s):
    # baris ke-r digeser ke kiri sebanyak r byte
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def inv_shift_rows(s):
    return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def _mix_satu_kolom(k, m):
    return [
        gmul(k[0], m[0]) ^ gmul(k[1], m[1]) ^ gmul(k[2], m[2]) ^ gmul(k[3], m[3]),
        gmul(k[0], m[3]) ^ gmul(k[1], m[0]) ^ gmul(k[2], m[1]) ^ gmul(k[3], m[2]),
        gmul(k[0], m[2]) ^ gmul(k[1], m[3]) ^ gmul(k[2], m[0]) ^ gmul(k[3], m[1]),
        gmul(k[0], m[1]) ^ gmul(k[1], m[2]) ^ gmul(k[2], m[3]) ^ gmul(k[3], m[0]),
    ]


def mix_columns(s):
    # tiap kolom dikali matriks [02 03 01 01] yang digeser per baris
    hasil = []
    for c in range(4):
        hasil.extend(_mix_satu_kolom(s[4 * c:4 * c + 4], (2, 3, 1, 1)))
    return hasil


def inv_mix_columns(s):
    hasil = []
    for c in range(4):
        hasil.extend(_mix_satu_kolom(s[4 * c:4 * c + 4], (0x0E, 0x0B, 0x0D, 0x09)))
    return hasil


def add_round_key(s, rk):
    return [a ^ b for a, b in zip(s, rk)]


# ---------------------------------------------------------------------------
# Enkripsi dan dekripsi satu blok 16 byte
# ---------------------------------------------------------------------------

def enkripsi_blok(blok, round_keys, jejak=None):
    nr = len(round_keys) - 1
    s = add_round_key(list(blok), round_keys[0])
    if jejak is not None:
        jejak.append(("ronde 0 (AddRoundKey awal)", s))

    for r in range(1, nr):
        s = sub_bytes(s)
        s = shift_rows(s)
        s = mix_columns(s)
        s = add_round_key(s, round_keys[r])
        if jejak is not None:
            jejak.append((f"ronde {r}", s))

    # ronde terakhir tidak pakai MixColumns
    s = sub_bytes(s)
    s = shift_rows(s)
    s = add_round_key(s, round_keys[nr])
    if jejak is not None:
        jejak.append((f"ronde {nr} (tanpa MixColumns)", s))
    return bytes(s)


def dekripsi_blok(blok, round_keys, jejak=None):
    nr = len(round_keys) - 1
    s = add_round_key(list(blok), round_keys[nr])
    if jejak is not None:
        jejak.append((f"ronde {nr} (AddRoundKey awal)", s))

    for r in range(nr - 1, 0, -1):
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, round_keys[r])
        s = inv_mix_columns(s)
        if jejak is not None:
            jejak.append((f"ronde {r}", s))

    s = inv_shift_rows(s)
    s = inv_sub_bytes(s)
    s = add_round_key(s, round_keys[0])
    if jejak is not None:
        jejak.append(("ronde 0", s))
    return bytes(s)


# ---------------------------------------------------------------------------
# Padding dan mode operasi
# ---------------------------------------------------------------------------

def pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n] * n)


def unpad(data):
    if not data or len(data) % 16 != 0:
        raise ValueError("panjang data tidak kelipatan 16")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n] * n):
        raise ValueError("padding tidak valid (kemungkinan kunci salah)")
    return data[:-n]


class AES:
    def __init__(self, kunci):
        if isinstance(kunci, str):
            kunci = kunci.encode("ascii")
        self.kunci = kunci
        self.round_keys = ekspansi_kunci(kunci)
        self.jumlah_ronde = len(self.round_keys) - 1

    def enkripsi_ecb(self, data):
        data = pad(data)
        return b"".join(enkripsi_blok(data[i:i + 16], self.round_keys)
                        for i in range(0, len(data), 16))

    def dekripsi_ecb(self, data):
        if len(data) % 16 != 0:
            raise ValueError("ciphertext harus kelipatan 16 byte")
        hasil = b"".join(dekripsi_blok(data[i:i + 16], self.round_keys)
                         for i in range(0, len(data), 16))
        return unpad(hasil)

    def enkripsi_cbc(self, data, iv=None):
        # IV ditaruh di depan ciphertext supaya penerima bisa langsung pakai
        if iv is None:
            iv = os.urandom(16)
        data = pad(data)
        sebelumnya = iv
        keluaran = [iv]
        for i in range(0, len(data), 16):
            blok = bytes(a ^ b for a, b in zip(data[i:i + 16], sebelumnya))
            sebelumnya = enkripsi_blok(blok, self.round_keys)
            keluaran.append(sebelumnya)
        return b"".join(keluaran)

    def dekripsi_cbc(self, data):
        if len(data) < 32 or len(data) % 16 != 0:
            raise ValueError("ciphertext CBC minimal 32 byte (IV + 1 blok)")
        sebelumnya = data[:16]
        hasil = []
        for i in range(16, len(data), 16):
            blok = data[i:i + 16]
            polos = dekripsi_blok(blok, self.round_keys)
            hasil.append(bytes(a ^ b for a, b in zip(polos, sebelumnya)))
            sebelumnya = blok
        return unpad(b"".join(hasil))


# ---------------------------------------------------------------------------
# Fungsi bantu dengan format tugas: key & plaintext ASCII, ciphertext hex
# ---------------------------------------------------------------------------

def cek_kunci_ascii(kunci):
    if not kunci.isascii():
        raise ValueError("kunci harus karakter ASCII")
    if len(kunci) not in (16, 24, 32):
        raise ValueError(f"kunci harus 16/24/32 karakter, sekarang {len(kunci)} karakter")
    return kunci.encode("ascii")


def enkripsi_teks(kunci, plaintext, mode="cbc"):
    if not plaintext.isascii():
        raise ValueError("plaintext harus karakter ASCII")
    aes = AES(cek_kunci_ascii(kunci))
    data = plaintext.encode("ascii")
    if mode == "ecb":
        return aes.enkripsi_ecb(data).hex()
    return aes.enkripsi_cbc(data).hex()


def dekripsi_teks(kunci, cipher_hex, mode="cbc"):
    aes = AES(cek_kunci_ascii(kunci))
    data = bytes.fromhex(cipher_hex)
    if mode == "ecb":
        hasil = aes.dekripsi_ecb(data)
    else:
        hasil = aes.dekripsi_cbc(data)
    return hasil.decode("ascii")


# ---------------------------------------------------------------------------
# Menu uji coba mandiri
# ---------------------------------------------------------------------------

def _cetak_state(s):
    # ditampilkan sebagai matriks 4x4 sesuai susunan state di slide
    for r in range(4):
        print("      " + " ".join(f"{s[r + 4 * c]:02x}" for c in range(4)))


def _demo_jejak():
    kunci = input("Kunci (ASCII 16/24/32 karakter): ")
    teks = input("Plaintext (ASCII, maks 16 karakter, sisanya di-padding): ")
    try:
        kb = cek_kunci_ascii(kunci)
        data = teks.encode("ascii")
    except (ValueError, UnicodeEncodeError) as e:
        print("Error:", e)
        return
    if len(data) > 16:
        print("Untuk jejak ronde cukup satu blok saja (maks 16 karakter).")
        return
    blok = data if len(data) == 16 else pad(data)
    aes = AES(kb)
    print(f"\nAES-{len(kb) * 8}, {aes.jumlah_ronde} ronde")
    print("Plaintext blok :", blok.hex())
    for i, rk in enumerate(aes.round_keys):
        print(f"  round key {i:2d}: {bytes(rk).hex()}")
    jejak = []
    hasil = enkripsi_blok(blok, aes.round_keys, jejak)
    for label, s in jejak:
        print(f"  {label}:")
        _cetak_state(s)
    print("Ciphertext     :", hasil.hex())


def main():
    mode = "ecb"
    while True:
        print(f"\n=== Uji AES manual (mode {mode.upper()}) ===")
        print("1. Enkripsi")
        print("2. Dekripsi")
        print("3. Lihat jejak per ronde (1 blok)")
        print("4. Ganti mode ECB/CBC")
        print("0. Keluar")
        pilih = input("> ").strip()
        try:
            if pilih == "1":
                kunci = input("Kunci (ASCII): ")
                teks = input("Plaintext (ASCII): ")
                print("Ciphertext (hex):", enkripsi_teks(kunci, teks, mode))
            elif pilih == "2":
                kunci = input("Kunci (ASCII): ")
                hx = input("Ciphertext (hex): ").strip()
                print("Plaintext:", dekripsi_teks(kunci, hx, mode))
            elif pilih == "3":
                _demo_jejak()
            elif pilih == "4":
                mode = "cbc" if mode == "ecb" else "ecb"
            elif pilih == "0":
                break
        except ValueError as e:
            print("Error:", e)


if __name__ == "__main__":
    main()
