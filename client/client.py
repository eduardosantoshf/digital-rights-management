import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


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
SERVER_PUBLIC_KEY=None

CLIENT_CERTIFICATE = open("client_cert.pem",'rb').read().decode()

CLIENT_CYPHER_SUITES = ['ECDHE_ECDSA_AES256-GCM_SHA384', 'DHE_RSA_AES256_SHA256']

CHOSEN_CYPHER_SUITE= None
s= requests.Session()

def make_signature(cypher_suite,data):
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

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    y = public_key.public_numbers().y

    signature = make_signature(CHOSEN_CYPHER_SUITE, client_random + server_random + str(y).encode())
    print(signature)
    req = s.post(f'{SERVER_URL}/api/key', data={'certificate': CLIENT_CERTIFICATE , 'DH_PARAMETER':y, 'signature': signature})

    shared_key = private_key.exchange(peer_public_key)
    print(shared_key)
    #print("public key:  ", public_key.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo))

    #print("server's public key:  ", peer_public_key.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo))

    
    

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