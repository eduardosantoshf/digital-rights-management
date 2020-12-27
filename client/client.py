import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives import padding as real_padding
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

with open("client_private_key.pem", "rb") as key_file:
    CLIENT_PRIVATE_KEY  = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

SERVER_URL = 'http://127.0.0.1:8080'
SERVER_PUBLIC_KEY = None

CLIENT_CERTIFICATE = open("client_cert.pem",'rb').read().decode()

CLIENT_CYPHER_SUITES = ['ECDHE_ECDSA_AES256-GCM_SHA384', 'DHE_RSA_AES256_SHA256']
CHOSEN_CYPHER_SUITE = None

s = requests.Session()

def getSessionkeys(cypher_suite, dh_key,client_random,server_random):
    if "SHA384" in cypher_suite:
        hash_type = hashes.SHA384()
        size = 48
    elif "SHA256" in cypher_suite:
        hash_type = hashes.SHA256()
        size = 32

    if "AES256" in cypher_suite:
        hkdf = HKDF(
            algorithm = hash_type,
            length = 64 + size*2,
            salt = client_random+server_random,
            info = None
        )

        key = hkdf.derive(dh_key)

        c_w_mac_k = key[:size]
        s_w_mac_k = key[size:size*2]
        c_w_k = key[size*2:size*2+32]
        s_w_k = key[size*2+32:size*2+64]

    return c_w_mac_k, s_w_mac_k, c_w_k, s_w_k

def make_signature(cypher_suite, data):
    if "SHA384" in cypher_suite:
        signature = CLIENT_PRIVATE_KEY.sign(
            data,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA384()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA384()
        )
    
    elif "SHA256" in cypher_suite:
        signature = CLIENT_PRIVATE_KEY.sign(
            data,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    return signature

def encrypt_comunication(cypher_suite, data):
    if "AES256" in cypher_suite:
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(CLIENT_WRITE_KEY),
            modes.CBC(iv)
        )
        encryptor = cipher.encryptor()

        encrypted_data = encryptor.update(padding_data(data, 128)) + encryptor.finalize()

    return iv + generate_hmac(CLIENT_WRITE_MAC_KEY, cypher_suite, encrypted_data + iv) + encrypted_data

def decrypt_comunication(cypher_suite, data, iv):
    if "AES256" in cypher_suite:
        cipher = Cipher(
            algorithms.AES(CLIENT_WRITE_KEY),
            modes.CBC(CLIENT_IV)
        )
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(data) + decryptor.finalize()

    return decrypted_data

def padding_data(data, bits):
    padder = real_padding.PKCS7(bits).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()

    return padded_data

def generate_hmac(key, cypher_suite, data):
    if "SHA256" in cypher_suite:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
    
    elif "SHA384" in cypher_suite:
        h = hmac.HMAC(key, hashes.SHA384())
        h.update(data)

    return h.finalize()

def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    client_random = os.urandom(28)
    req = s.post(f'{SERVER_URL}/api/protocols', data= {"cypher_suite":CLIENT_CYPHER_SUITES,"client_random":client_random})
    print(client_random)

    # TODO: Secure the session
    req = req.json()
    
    server_random = req['server_random'].encode('latin')

    y = int(req['y'])
    p = int(req['p'])
    g = int(req['g'])

    cert = x509.load_pem_x509_certificate(req['certificate'].encode())
    print(cert.not_valid_before)

    SERVER_PUBLIC_KEY = cert.public_key()
    CHOSEN_CYPHER_SUITE = req['cypher_suite']
    
    if "SHA256" in CHOSEN_CYPHER_SUITE:
        hash_type = hashes.SHA256()
        hash_type2 = hashes.SHA256()
    elif "SHA384" in CHOSEN_CYPHER_SUITE:
        hash_type = hashes.SHA384()
        hash_type2 = hashes.SHA384()

    SERVER_PUBLIC_KEY.verify(
        req['signature'].encode('latin'),
        client_random + server_random + str(y).encode() + str(p).encode() + str(g).encode(),
        padding.PSS(
            mgf = padding.MGF1(hash_type),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hash_type2
    )

    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters()

    peer_public_numbers = dh.DHPublicNumbers(y, pn)
    peer_public_key = peer_public_numbers.public_key()

    # generating client's private and public keys
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    y = public_key.public_numbers().y

    signature = make_signature(CHOSEN_CYPHER_SUITE, client_random + server_random + str(y).encode())
    req = s.post(f'{SERVER_URL}/api/key', data={'certificate': CLIENT_CERTIFICATE , 'DH_PARAMETER':y, 'signature': signature})

    shared_key = private_key.exchange(peer_public_key)

    global CLIENT_WRITE_MAC_KEY
    global CLIENT_WRITE_KEY
    global SERVER_WRITE_MAC_KEY
    global SERVER_WRITE_KEY

    CLIENT_WRITE_MAC_KEY, SERVER_WRITE_MAC_KEY, CLIENT_WRITE_KEY, SERVER_WRITE_KEY = getSessionkeys(CHOSEN_CYPHER_SUITE, shared_key,client_random,server_random)
    
    #print("public key:  ", public_key.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo))

    #print("server's public key:  ", peer_public_key.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo))

    req = s.get(f'{SERVER_URL}/' + encrypt_comunication(CHOSEN_CYPHER_SUITE, b"api/finished").decode("latin"))


    

    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")

    media_list = req.json()



    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
    print("----")

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection < len(media_list):
            break

    # Example: Download first file
    media_item = media_list[selection]
    print(f"Playing {media_item['name']}")

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()
       
        # TODO: Process chunk

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break

if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)