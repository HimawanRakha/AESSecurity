"""
Pengujian AES manual dengan test vector resmi.
Jalankan: python -m unittest test_aes -v
"""

import unittest

from aes import AES, SBOX, INV_SBOX, enkripsi_blok, dekripsi_blok, enkripsi_teks, dekripsi_teks


class TestSBox(unittest.TestCase):
    def test_contoh_di_slide(self):
        # contoh dari slide: {95} diganti {2A}
        self.assertEqual(SBOX[0x95], 0x2A)

    def test_nilai_awal(self):
        self.assertEqual(SBOX[0x00], 0x63)
        self.assertEqual(SBOX[0x53], 0xED)

    def test_invers(self):
        for i in range(256):
            self.assertEqual(INV_SBOX[SBOX[i]], i)


class TestFIPS197(unittest.TestCase):
    # FIPS-197 Appendix C
    PLAIN = bytes.fromhex("00112233445566778899aabbccddeeff")

    def _uji(self, kunci_hex, cipher_hex):
        aes = AES(bytes.fromhex(kunci_hex))
        c = enkripsi_blok(self.PLAIN, aes.round_keys)
        self.assertEqual(c.hex(), cipher_hex)
        self.assertEqual(dekripsi_blok(c, aes.round_keys), self.PLAIN)

    def test_aes128(self):
        self._uji("000102030405060708090a0b0c0d0e0f",
                  "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_aes192(self):
        self._uji("000102030405060708090a0b0c0d0e0f1011121314151617",
                  "dda97ca4864cdfe06eaf70a0ec0d7191")

    def test_aes256(self):
        self._uji("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                  "8ea2b7ca516745bfeafc49904b496089")


class TestKunciASCII(unittest.TestCase):
    def test_contoh_populer(self):
        # contoh yang sering dipakai di tutorial AES dengan kunci & plaintext ASCII
        aes = AES("Thats my Kung Fu")
        c = enkripsi_blok(b"Two One Nine Two", aes.round_keys)
        self.assertEqual(c.hex(), "29c3505f571420f6402299b31a02d73a")


class TestCBC(unittest.TestCase):
    def test_sp800_38a(self):
        # NIST SP 800-38A F.2.1, blok pertama
        aes = AES(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        c = aes.enkripsi_cbc(plain, iv)
        self.assertEqual(c[16:32].hex(), "7649abac8119b246cee98e9b12e9197d")

    def test_bolak_balik(self):
        for mode in ("ecb", "cbc"):
            for kunci in ("kuncirahasia1234", "kuncirahasia12345678abcd", "k" * 32):
                for teks in ("", "a", "halo bob", "x" * 16, "pesan yang lebih panjang dari satu blok"):
                    hx = enkripsi_teks(kunci, teks, mode)
                    self.assertEqual(dekripsi_teks(kunci, hx, mode), teks)

    def test_kunci_salah(self):
        hx = enkripsi_teks("kuncirahasia1234", "rahasia negara", "cbc")
        # biasanya gagal di padding, tapi kalau kebetulan lolos isinya pasti beda
        try:
            hasil = dekripsi_teks("kuncisalah123456", hx, "cbc")
        except (ValueError, UnicodeDecodeError):
            return
        self.assertNotEqual(hasil, "rahasia negara")


if __name__ == "__main__":
    unittest.main()
