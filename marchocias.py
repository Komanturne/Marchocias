import hashlib

F_TABLE = [
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
]

# Inverse F-table for decryption
F_TABLE_INV = [0] * 256
for i in range(256):
    F_TABLE_INV[F_TABLE[i]] = i


class Marchocias:
    BLOCK_SIZE = 8
    KEY_SIZE = 48
    ROUNDS = 64
    TINYROUNDS = 64
    DELTA = 0x9E3779B9

    def __init__(self, key):
        if len(key) != self.KEY_SIZE:
            raise ValueError("Key must be exactly 48 bytes (384 bits)")

        self.master_key = key

        # --- Derive internal working keys ---
        digest = hashlib.sha512(key).digest()

        self.idea_key = digest[0:16]
        self.g_key    = digest[16:32]
        self.tiny_raw = digest[32:48]

        self.subkeys = self._generate_subkeys()
        self.tiny_key = self._derive_tiny_key()

    def _generate_subkeys(self):
        subkeys = []
        key_int = int.from_bytes(self.idea_key, 'big')

        for i in range(self.ROUNDS * 6):
            shift = (112 - (i * 16) % 128)
            subkey = (key_int >> shift) & 0xFFFF

            if i % 6 in [0, 3, 4, 5]:
                subkey |= 1
                if subkey == 0xFFFF:
                    subkey = 1

            subkeys.append(subkey)

            if (i + 1) % 8 == 0:
                key_int = ((key_int << 25) | (key_int >> 103)) & ((1 << 128) - 1)

        return subkeys
    
    def _derive_tiny_key(self):
        return [
            int.from_bytes(self.tiny_raw[0:4], 'big'),
            int.from_bytes(self.tiny_raw[4:8], 'big'),
            int.from_bytes(self.tiny_raw[8:12], 'big'),
            int.from_bytes(self.tiny_raw[12:16], 'big')
        ]

    def _mul_mod(self, a, b):
        if a == 0:
            a = 0x10000
        if b == 0:
            b = 0x10000
        
        result = (a * b) % 0x10001
        
        if result == 0x10000:
            result = 0
        
        return result & 0xFFFF
    
    def _mul_mod_inv(self, a):
        if a == 0:
            a = 0x10000
        
        t, new_t = 0, 1
        r, new_r = 0x10001, a
        
        while new_r != 0:
            quotient = r // new_r
            t, new_t = new_t, t - quotient * new_t
            r, new_r = new_r, r - quotient * new_r
        
        if t < 0:
            t += 0x10001
        
        if t == 0x10000:
            t = 0
        
        return t & 0xFFFF
    
    def _add_mod(self, a, b):
        return (a + b) & 0xFFFF
    
    def _sub_mod(self, a, b):
        return (a - b) & 0xFFFF
    
    def _g_permutation(self, w, k_step, key_offset):
        g1 = (w >> 8) & 0xFF
        g2 = w & 0xFF
        
        for i in range(4):
            key_byte = self.g_key[(k_step * 4 + key_offset + i) % 16]
            f_index = (g1 ^ key_byte) & 0xFF
            g2 ^= F_TABLE[f_index]
            g2 = (g2 + key_byte) & 0xFF
            g1, g2 = g2, g1
        
        return ((g1 << 8) | g2) & 0xFFFF
    
    def _g_permutation_inv(self, w, k_step, key_offset):
        g1 = (w >> 8) & 0xFF
        g2 = w & 0xFF
        
        for i in range(3, -1, -1):
            key_byte = self.g_key[(k_step * 4 + key_offset + i) % 16]
            g1, g2 = g2, g1
            g2 = (g2 - key_byte) & 0xFF
            f_index = (g1 ^ key_byte) & 0xFF
            g2 ^= F_TABLE[f_index]
        
        return ((g1 << 8) | g2) & 0xFFFF
    
    def _ma_structure(self, a, b, k1, k2):
        t1 = self._mul_mod(a, k1)
        t2 = self._add_mod(b, t1)
        t2 = self._mul_mod(t2, k2)
        t1 = self._add_mod(t1, t2)
        return t1, t2
    
    def _ma_structure_inv(self, t1, t2, k1, k2):
        k1_inv = self._mul_mod_inv(k1)
        k2_inv = self._mul_mod_inv(k2)
        
        # t1 = a_mul_k1 + t2, so: a_mul_k1 = t1 - t2
        a_mul_k1 = self._sub_mod(t1, t2)
        a = self._mul_mod(a_mul_k1, k1_inv)
        
        # t2 = (b + a_mul_k1) * k2, so: b + a_mul_k1 = t2 * k2_inv
        b_plus_a_mul_k1 = self._mul_mod(t2, k2_inv)
        b = self._sub_mod(b_plus_a_mul_k1, a_mul_k1)
        
        return a, b
    
    def _hybrid_round(self, w, k_step, is_a_round=True):
        w1, w2, w3, w4 = w
        
        sk_base = k_step * 6
        sk1 = self.subkeys[sk_base]
        sk2 = self.subkeys[sk_base + 1]
        sk3 = self.subkeys[sk_base + 2]
        sk4 = self.subkeys[sk_base + 3]
        sk5 = self.subkeys[sk_base + 4]
        sk6 = self.subkeys[sk_base + 5]
        
        w1 = self._mul_mod(w1, sk1)
        w2 = self._add_mod(w2, sk2)
        w3 = self._add_mod(w3, sk3)
        w4 = self._mul_mod(w4, sk4)
        
        temp1 = w1 ^ w3
        temp2 = w2 ^ w4
        ma1, ma2 = self._ma_structure(temp1, temp2, sk5, sk6)
        
        w1 = w1 ^ ma1
        w2 = w2 ^ ma2
        w3 = w3 ^ ma1
        w4 = w4 ^ ma2
        
        g_w1 = self._g_permutation(w1, k_step, 0)
        
        if is_a_round:
            new_w1 = w4
            new_w2 = g_w1
            new_w3 = w2
            new_w4 = w3 ^ g_w1
        else:
            new_w1 = g_w1
            new_w2 = w4
            new_w3 = w2 ^ g_w1
            new_w4 = w3
        
        return [new_w1, new_w2, new_w3, new_w4]
    
    def _hybrid_round_inv(self, w, k_step, is_a_round=True):
        new_w1, new_w2, new_w3, new_w4 = w
        
        sk_base = k_step * 6
        sk1 = self.subkeys[sk_base]
        sk2 = self.subkeys[sk_base + 1]
        sk3 = self.subkeys[sk_base + 2]
        sk4 = self.subkeys[sk_base + 3]
        sk5 = self.subkeys[sk_base + 4]
        sk6 = self.subkeys[sk_base + 5]
        
        if is_a_round:
            w4 = new_w1
            g_w1 = new_w2
            w2 = new_w3
            w3 = new_w4 ^ g_w1
        else:
            g_w1 = new_w1
            w4 = new_w2
            w2 = new_w3 ^ g_w1  
            w3 = new_w4
        w1 = self._g_permutation_inv(g_w1, k_step, 0)
        
        temp1_input = w1 ^ w3
        temp2_input = w2 ^ w4
        ma1, ma2 = self._ma_structure(temp1_input, temp2_input, sk5, sk6)
        
        w1 = w1 ^ ma1
        w2 = w2 ^ ma2
        w3 = w3 ^ ma1
        w4 = w4 ^ ma2
        sk1_inv = self._mul_mod_inv(sk1)
        sk4_inv = self._mul_mod_inv(sk4)
        
        w1 = self._mul_mod(w1, sk1_inv)
        w2 = self._sub_mod(w2, sk2)
        w3 = self._sub_mod(w3, sk3)
        w4 = self._mul_mod(w4, sk4_inv)
        
        return [w1, w2, w3, w4]
    
    def _tiny_encrypt(self, v):
        v0, v1 = v
        sum_val = 0
        delta = self.DELTA
        
        for _ in range(self.TINYROUNDS):
            sum_val = (sum_val + delta) & 0xFFFFFFFF
            e = (sum_val >> 2) & 3
            v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + self.tiny_key[e]))) & 0xFFFFFFFF
            e = (sum_val >> 2) & 3
            v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + self.tiny_key[(e + 1) & 3]))) & 0xFFFFFFFF
        
        return [v0, v1]
    
    def _tiny_decrypt(self, v):
        v0, v1 = v
        delta = self.DELTA
        sum_val = (delta * self.TINYROUNDS) & 0xFFFFFFFF
        
        for _ in range(self.TINYROUNDS):
            e = (sum_val >> 2) & 3
            v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + self.tiny_key[(e + 1) & 3]))) & 0xFFFFFFFF
            e = (sum_val >> 2) & 3
            v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + self.tiny_key[e]))) & 0xFFFFFFFF
            sum_val = (sum_val - delta) & 0xFFFFFFFF
        
        return [v0, v1]
    
    def encrypt_block(self, plaintext):
        if len(plaintext) != self.BLOCK_SIZE:
            raise ValueError(f"Block must be {self.BLOCK_SIZE} bytes")
        
        v = [
            int.from_bytes(plaintext[0:4], 'big'),
            int.from_bytes(plaintext[4:8], 'big')
        ]

        v = self._tiny_encrypt(v)
        
        w = [
            (v[0] >> 16) & 0xFFFF,
            v[0] & 0xFFFF,
            (v[1] >> 16) & 0xFFFF,
            v[1] & 0xFFFF
        ]
        
        # 64 hybrid rounds
        for k in range(16):
            w = self._hybrid_round(w, k, is_a_round=True)
        for k in range(16, 32):
            w = self._hybrid_round(w, k, is_a_round=False)
        for k in range(32, 48):
            w = self._hybrid_round(w, k, is_a_round=True)
        for k in range(48, 64):
            w = self._hybrid_round(w, k, is_a_round=False)

        v = [
            ((w[0] << 16) | w[1]) & 0xFFFFFFFF,
            ((w[2] << 16) | w[3]) & 0xFFFFFFFF
        ]
        v = self._tiny_encrypt(v)
        
        return v[0].to_bytes(4, 'big') + v[1].to_bytes(4, 'big')
    
    def decrypt_block(self, ciphertext):
        if len(ciphertext) != self.BLOCK_SIZE:
            raise ValueError(f"Block must be {self.BLOCK_SIZE} bytes")
        
        v = [
            int.from_bytes(ciphertext[0:4], 'big'),
            int.from_bytes(ciphertext[4:8], 'big')
        ]
        v = self._tiny_decrypt(v)
        
        # Convert to four 16-bit words
        w = [
            (v[0] >> 16) & 0xFFFF,
            v[0] & 0xFFFF,
            (v[1] >> 16) & 0xFFFF,
            v[1] & 0xFFFF
        ]
        
        # Reverse 64 hybrid rounds
        for k in range(63, 47, -1):
            w = self._hybrid_round_inv(w, k, is_a_round=False)
        for k in range(47, 31, -1):
            w = self._hybrid_round_inv(w, k, is_a_round=True)
        for k in range(31, 15, -1):
            w = self._hybrid_round_inv(w, k, is_a_round=False)
        for k in range(15, -1, -1):
            w = self._hybrid_round_inv(w, k, is_a_round=True)
        
        v = [
            ((w[0] << 16) | w[1]) & 0xFFFFFFFF,
            ((w[2] << 16) | w[3]) & 0xFFFFFFFF
        ]
        v = self._tiny_decrypt(v)
        
        return v[0].to_bytes(4, 'big') + v[1].to_bytes(4, 'big')
    
    def encrypt(self, plaintext):
        padding_length = self.BLOCK_SIZE - (len(plaintext) % self.BLOCK_SIZE)
        padded = plaintext + bytes([padding_length] * padding_length)
        
        ciphertext = b''
        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            ciphertext += self.encrypt_block(block)
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be multiple of block size")
        
        plaintext = b''
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]
            plaintext += self.decrypt_block(block)
        
        padding_length = plaintext[-1]
        if padding_length > self.BLOCK_SIZE or padding_length == 0:
            raise ValueError("Invalid padding")
        
        for i in range(padding_length):
            if plaintext[-(i + 1)] != padding_length:
                raise ValueError("Invalid padding")
        
        return plaintext[:-padding_length]