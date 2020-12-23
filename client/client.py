import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'
SERVER_PUBLIC_KEY=None

CLIENT_CYPHER_SUITES = ['1', '2']


def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    
    req = requests.get(f'{SERVER_URL}/api/protocols', params= {"cypher_suite":CLIENT_CYPHER_SUITES})
    # TODO: Secure the session
    req=req.json()
    cert = x509.load_pem_x509_certificate(req['certificate'].encode())
    print(cert.not_valid_before)
    SERVER_PUBLIC_KEY=cert.public_key()
    print(cert.public_key())

    ciphertext = SERVER_PUBLIC_KEY.encrypt(b'helloooo',padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    print(ciphertext)
    req= requests.get(f'{SERVER_URL}/api/key', params=ciphertext)

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