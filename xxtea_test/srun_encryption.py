#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from regadgets import xxtea_encrypt, xxtea_decrypt, byte2dword, dword2byte, encode_b64, decode_b64

SRUN_BASE64_TABLE = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA="
def xxtea_srun_shift(z, y, sum, k, p, debug = False):
    e = (sum.value >> 2) & 3
    PE = (p & 3) ^ e
    Ly = y.value << 2
    Ry = y.value >> 3
    Lz = z.value << 4
    Rz = z.value >> 5 

    LzRy = Rz ^ Ly
    LyRz = Ry ^ Lz
    SY = sum.value ^ y.value
    K = k[PE].value
    KZ = K ^ z.value
    # Modified XXTEA MX Algorithm.
    result = LzRy + (LyRz ^ SY) + KZ
    return result

def srun_encrypt(msg: bytes, key: bytes) -> str:
    message = byte2dword(msg) + [len(msg)]
    encrypted = dword2byte(xxtea_encrypt(message, key, shift_func=xxtea_srun_shift))
    return encode_b64(encrypted, table=SRUN_BASE64_TABLE)


def srun_decrypt(msg: str, key: bytes) -> bytes:
    message = decode_b64(msg, table=SRUN_BASE64_TABLE)
    message = byte2dword(message)
    decrypted = xxtea_decrypt(message, key, shift_func=xxtea_srun_shift)
    msglen = decrypted[-1]
    return dword2byte(decrypted)[:msglen]

if __name__ == '__main__':
    message = b'hello world'
    key = b'1234567890abcdef'
    encrypted = srun_encrypt(message, key)
    print('encrypted: ', encrypted)
    decrypted = srun_decrypt(encrypted, key)
    print('decrypted: ', decrypted)