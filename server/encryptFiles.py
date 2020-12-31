import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding

files = os.listdir('./catalog/')

#iv = os.urandom(16)
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

for file in files:
    with open("./catalog/" + file, 'rb') as f:
        data = f.read()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        cipher = Cipher(
                algorithms.AES(key),
                modes.ECB()
            )

        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()

    with open("./catalog/" + file, 'wb') as f:
        f.write(ct)
