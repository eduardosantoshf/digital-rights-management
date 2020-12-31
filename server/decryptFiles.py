import os
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding

files = os.listdir('./catalog/')

iv = b'\xa4y\x15\xc5\x19\xf3\x11\x14IF\xb1\xd6?b\xde\xdf'

key = b'MayTheCodeBeWithYou'
salt = b'IAmTheOneWhoCodes'

hkdf = HKDF(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = salt,
            info = None
        )
key = hkdf.derive(key)

with open("./catalog/" + "0woft9i8rz553vttlnc33yjzcs4li1a3mtt60e8v.mp3", "rb") as f:
    data = f.read()

    cipher = Cipher(
                algorithms.AES(key),
                modes.ECB()
            )
    
    decryptor = cipher.decryptor()

    dd = decryptor.update(data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(dd)
    unpadded_data += unpadder.finalize()

    proc = subprocess.Popen(['ffplay', '-i', '-'], stdin = subprocess.PIPE)

    proc.stdin.write(unpadded_data)