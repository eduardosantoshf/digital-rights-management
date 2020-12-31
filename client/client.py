import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import PyKCS11
import binascii
import platform
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives import padding as real_padding
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID,ExtensionOID


logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

with open("./Media_Client_Private_Key.pem", "rb") as key_file:
    CLIENT_PRIVATE_KEY = serialization.load_pem_private_key(
        key_file.read(),
        password = b'k8V_R&WGe6v5De^4'
    )

SERVER_URL = 'http://127.0.0.1:8080'
SERVER_PUBLIC_KEY = None

CLIENT_WRITE_MAC_KEY = None
CLIENT_WRITE_KEY = None
SERVER_WRITE_MAC_KEY = None
SERVER_WRITE_KEY = None

CLIENT_CERTIFICATE = open("./Media_Client.crt",'rb').read().decode()

CLIENT_LOADED_CERTIFICATE = x509.load_pem_x509_certificate(open("./Media_Client.crt",'rb').read())
CLIENT_COMMON_NAME = CLIENT_LOADED_CERTIFICATE.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

ROOT_CA = x509.load_pem_x509_certificate(open("../Media_CA.crt",'rb').read())

USER_ID = None

# Client knows the songs distributor
DISTRIBUTER_CERTIFICATE = open("../Media_Distributor.crt",'rb').read()
DISTRIBUTER_PUBLIC_KEY = x509.load_pem_x509_certificate(DISTRIBUTER_CERTIFICATE).public_key()

CLIENT_CIPHER_SUITES = ['DHE_AES256_CBC_SHA384','DHE_AES256_CFB_SHA384','DHE_AES256_CFB_SHA256',
                        'DHE_AES128_CBC_SHA256','DHE_AES128_CBC_SHA384','DHE_AES128_CBF_SHA384',
                        'DHE_ChaCha20_SHA384','DHE_ChaCha20_SHA384','DHE_ChaCha20_SHA256'
                       ]
CHOSEN_CIPHER_SUITE = None

s = requests.Session()

#---------------------Generate session keys------------------------#

def get_session_keys(cipher_suite, dh_key, client_random, server_random):
    if "SHA384" in cipher_suite:
            hash_type = hashes.SHA384()
            size = 48

    elif "SHA256" in cipher_suite:
        hash_type = hashes.SHA256()
        size = 32

    if "AES128" in cipher_suite:
        cipher_size = 32

    elif "AES256" in cipher_suite or "ChaCha20" in cipher_suite:
        cipher_size = 64
    
    hkdf = HKDF(
        algorithm = hash_type,
        length = cipher_size + size * 2,
        salt = client_random + server_random,
        info = None
    )
    key = hkdf.derive(dh_key)

    # divide the key into 4 different keys
    c_w_mac_k = key[:size]
    s_w_mac_k = key[size:size * 2]
    c_w_k = key[size * 2:size * 2 + (cipher_size // 2)]
    s_w_k = key[size * 2 + (cipher_size // 2):size * 2 + cipher_size]

    return c_w_mac_k, s_w_mac_k, c_w_k, s_w_k

#------------------------------------------------------------------#


#--------------------------Sign data-------------------------------#

def make_signature(cipher_suite, data, key = CLIENT_PRIVATE_KEY):
    if "SHA384" in cipher_suite:
        signature = key.sign(
            data,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA384()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA384()
        )
    
    elif "SHA256" in cipher_suite:
        signature = key.sign(
            data,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    return signature

#------------------------------------------------------------------#


#---------------------Encrypt comunication-------------------------#

def encrypt_comunication(cipher_suite, data, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY):
    iv = os.urandom(16)

    if "AES256" in cipher_suite or "AES128" in cipher_suite:
        if "CBC" in cipher_suite:
            cipher = Cipher(
                algorithms.AES(CLIENT_WRITE_KEY),
                modes.CBC(iv)
            )

            encryptor = cipher.encryptor()

            encrypted_data = encryptor.update(padding_data(data, 128)) + encryptor.finalize()

        elif "CFB" in cipher_suite:
            cipher = Cipher(
                algorithms.AES(CLIENT_WRITE_KEY),
                modes.CFB(iv)
            )

            encryptor = cipher.encryptor()

            encrypted_data = encryptor.update(data) + encryptor.finalize()
        
    elif "ChaCha20" in cipher_suite:
        cipher = Cipher(
            algorithms.ChaCha20(CLIENT_WRITE_KEY, iv),
            mode = None
        )

        encryptor = cipher.encryptor()

        encrypted_data = encryptor.update(data) + encryptor.finalize()

    return iv + generate_hmac(CLIENT_WRITE_MAC_KEY, cipher_suite, iv + encrypted_data) + encrypted_data

#------------------------------------------------------------------#


#---------------------Decrypt comunication-------------------------#

def decrypt_comunication(s_w_k, s_w_m_k, cipher_suite, data):
    # for AES258, AES128 and ChaCha20, iv size is always 16
    iv_size = 16

    if "SHA384" in cipher_suite:
        iv = data[:iv_size]
        hmac = data[iv_size:iv_size + 48]
        h_data = iv + data[iv_size + 48:]
        m_data = data[iv_size + 48:]

    elif "SHA256" in cipher_suite:
        iv = data[:iv_size]
        hmac = data[iv_size:iv_size + 32]
        h_data = iv + data[iv_size + 32:]
        m_data =data[iv_size + 32:]


    if hmac == generate_hmac(s_w_m_k, cipher_suite, h_data):

        m_data = decrypt_symetric(s_w_k, iv, cipher_suite, m_data)

        if "CBC" in cipher_suite:
            return unpadding_data(m_data,128)

        return m_data

    else: return 0

#------------------------------------------------------------------#


#-----------------------Decrypt symetric---------------------------#

def decrypt_symetric(key, iv, cipher_suite, data):
    if "AES256" in cipher_suite or "AES128" in cipher_suite:
        if "CBC" in cipher_suite:
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv)
            )
        elif "CFB" in cipher_suite:
            cipher = Cipher(
                algorithms.AES(key),
                modes.CFB(iv)
            )

        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(data) + decryptor.finalize()

    elif "ChaCha20" in cipher_suite:
        cipher = Cipher(
            algorithms.ChaCha20(key, iv),
            mode = None
        )

        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(data)

    return decrypted_data

#------------------------------------------------------------------#


#-------------------------Padding Data-----------------------------#

def padding_data(data, bits):
    padder = real_padding.PKCS7(bits).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()

    return padded_data

#------------------------------------------------------------------#


#------------------------Unpadding Data----------------------------#

def unpadding_data(data, nbits):
    unpadder = real_padding.PKCS7(nbits).unpadder()
    unpadded_data = unpadder.update(data)
    unpadded_data += unpadder.finalize()

    return unpadded_data

#------------------------------------------------------------------#


#-------------------------Generate HMAC----------------------------#

def generate_hmac(key, cipher_suite, data):
    if "SHA256" in cipher_suite:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
    
    elif "SHA384" in cipher_suite:
        h = hmac.HMAC(key, hashes.SHA384())
        h.update(data)

    return h.finalize()

#------------------------------------------------------------------#


#------------------------Hash algorithm----------------------------#

def hash_stuff(cipher_suite, data):
        if "SHA256" in cipher_suite:
            digest = hashes.Hash(hashes.SHA256())
        
        elif "SHA384" in cipher_suite:
            digest = hashes.Hash(hashes.SHA384())

        digest.update(data)

        return digest.finalize()

#------------------------------------------------------------------#


#----------------------Verify a signature--------------------------#

def verify_signature(signature, cipher_suite, key, data):
    if "SHA256" in cipher_suite:
        hash_type = hashes.SHA256()
        hash_type2 = hashes.SHA256()

    elif "SHA384" in cipher_suite:
        hash_type = hashes.SHA384()
        hash_type2 = hashes.SHA384()

    key.verify(
        signature,
            data,
            padding.PSS(
                mgf = padding.MGF1(hash_type),
                salt_length = padding.PSS.MAX_LENGTH
        ),
        hash_type2
    )

#------------------------------------------------------------------#


#------------------Verify a server certificate---------------------# 

def verify_server_certificate(server_cert):
    
    # Validate certificate atributes
    if not (server_cert.not_valid_before < datetime.now() < server_cert.not_valid_after):
        return False
    if not (server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'Media Server'):
        return False
    if not (server_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'Media Certification Authority'):
        return False
    key_usage = server_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    if not key_usage.digital_signature or not key_usage.key_encipherment  or not key_usage.key_agreement or key_usage.key_cert_sign or key_usage.crl_sign: 
        return False  

    #Check root CA signature
    try:
        ROOT_CA.public_key().verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server_cert.signature_hash_algorithm,
        )
    except: 
        return False

    return True

#------------------------------------------------------------------#


#----------------------Authenticate User---------------------------#

def user_authentication(cipher_suite):

    # chose lib location depending on the OS
    #macOS
    if platform.system() == 'Darwin':
        lib = '/usr/local/lib/libpteidpkcs11.dylib'
    #linux
    elif platform.system() == 'Linux':
        lib = '/usr/local/lib/libpteidpkcs11.so'

    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)
    slots = pkcs11.getSlotList()

    session = pkcs11.openSession(slots[0])

    all_attr = list(PyKCS11.CKA.keys())
    all_attr = [e for e in all_attr if isinstance(e, int)]

    private_key = session.findObjects([
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
    ])[0]
    
    auth_sub_ca = session.findObjects([
        (PyKCS11.CKA_LABEL, 'AUTHENTICATION SUB CA')
    ])[0]

    attr = session.getAttributeValue(auth_sub_ca, all_attr)
    attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))

    #print(x509.load_der_x509_certificate(bytes(attr['CKA_VALUE'])))
    auth_sub_ca_certificate = bytes(attr['CKA_VALUE']).decode("latin")

    root_ca = session.findObjects([
        (PyKCS11.CKA_LABEL, 'ROOT CA')
    ])[0]

    attr = session.getAttributeValue(root_ca, all_attr)
    attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))

    #print(x509.load_der_x509_certificate(bytes(attr['CKA_VALUE'])))
    root_ca_certificate = bytes(attr['CKA_VALUE']).decode("latin")

    citizen_auth = session.findObjects([
        (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')
    ])[0]

    attr = session.getAttributeValue(citizen_auth, all_attr)
    attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))

    #print(x509.load_der_x509_certificate(bytes(attr['CKA_VALUE'])))
    loaded_citizen_auth_certificate = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']))

    global USER_ID 

    USER_ID = loaded_citizen_auth_certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
    citizen_auth_certificate = bytes(attr['CKA_VALUE']).decode("latin")

    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)

    signature = bytes(
        session.sign(
            private_key, 
            loaded_citizen_auth_certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value.encode(), 
            mechanism
        )
    )

    return [citizen_auth_certificate, auth_sub_ca_certificate, root_ca_certificate], signature

#------------------------------------------------------------------#


#-------------------------Client Menu------------------------------#

def menu():
    print("|--------------------------------------|")
    print("|                 MENU                 |")
    print("|--------------------------------------|\n")

    print("|----------  1 MUSIC LIST   -----------|")
    print("|--------  2 DOWNLOAD MUSIC   ---------|")
    print("|--------  3 AQUIRE LICENSE   ---------|")
    print("|-------------  q QUIT   --------------|")

#------------------------------------------------------------------#


#----------------------Choose License Menu-------------------------#

def license_menu():
    print("|--------------------------------------|")
    print("|             LICENSE TYPE             |")
    print("|--------------------------------------|\n")

    print("|----------  (1) SINGLE PLAY  ---------|")
    print("|----------  (2) 5 PLAYS    -----------|")
    print("|----------  (3) 10 PLAYS   -----------|")
    print("|----------  (4) 20 PLAYS   -----------|")
    print("|----------  (q) RETURN  --------------|")

#------------------------------------------------------------------#


#---------------------Cooroborate Licenses-------------------------#

def check_licenses(licence_list):
    files = os.listdir('./licenses/')
    h = hashes.Hash(hashes.SHA1())
    h.update((CLIENT_COMMON_NAME + USER_ID).encode("latin"))
    file_name = str(int.from_bytes(h.finalize(), byteorder = 'big'))
    user_licences = [f for f in files if file_name in f ]

    for user_licence in user_licences:
        with open("./licenses/" + user_licence) as json_file:
            data = json.load(json_file)
            if not any(data["media_id"] == l["media_id"] and data["plays"] == l["plays"] for l in licence_list ):
                return False

    return True

#------------------------------------------------------------------#


#-----------------Get Music and Licenses List----------------------#

def getMusicList(CHOSEN_CIPHER_SUITE, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY, SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY):
    e = encrypt_comunication(CHOSEN_CIPHER_SUITE, b"api/list", CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
    req = s.get(f'{SERVER_URL}/', params = {'data':e})

    print(req.status_code)

    req = req.json()
    list_data = req['data'].encode('latin')
    
    message = decrypt_comunication(SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY,CHOSEN_CIPHER_SUITE,list_data)

    media_list = json.loads(message.decode('latin'))
    license_list = media_list['licence_list']
    media_list = media_list['media_list']

    if not check_licenses(license_list):
        print("Server gave wrong licenses")

    else:
        print("USER LICENSES\n")
        for item in license_list:
            print(" Name: " + item['media_name'] + "    Number of Plays " + item['plays'])
        
        print("----")

    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:      
        verify_signature(
            item['distributor_signature'].encode("latin"), 
            CHOSEN_CIPHER_SUITE, 
            DISTRIBUTER_PUBLIC_KEY, 
            (item['media']['id'] + item['media']['name'] + item['media']['description'] + str(item['media']['chunks']) + str(item['media']['duration'])).encode("latin")
        )
        print(f'{idx} - {item["media"]["name"]}')

        idx += 1

    print("----")

    return media_list

#------------------------------------------------------------------#


#------------------------Aquire a License--------------------------#

def aquireLicense(CHOSEN_CIPHER_SUITE, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY, SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY, SERVER_PUBLIC_KEY):
    media_list = getMusicList(CHOSEN_CIPHER_SUITE, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY, SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY)

    while True:
        license_menu()
        selection = input("-> ")

        if selection.strip() == 'q':
            return

        if not selection.isdigit():
            continue

        selection = int(selection)
        if selection == 1:
            nplay = '1'
            break
        elif selection == 2:
            nplay = '5'
            break
        elif selection == 3:
            nplay = '10'
            break
        elif selection == 4:
            nplay = '20'
            break

    while True:
        selection = input("Select a media file number (q to return): ")
        if selection.strip() == 'q':
            return

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection <= len(media_list):
            break

    media_item = media_list[selection]['media']
    uri = f'api/license?id={media_item["id"]}&type={nplay}'

    e = encrypt_comunication(CHOSEN_CIPHER_SUITE, uri.encode(), CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)

    req = s.get(f'{SERVER_URL}/', params = {'data':e})
    req = req.json()

    license_data =  req['data'].encode('latin')
    message = decrypt_comunication(SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY, CHOSEN_CIPHER_SUITE, license_data)

    license_data = json.loads(message.decode('latin'))
    license_signature = license_data['license_signature'].encode("latin")
    license_file = license_data['license']

    try:
        verify_signature(license_signature, CHOSEN_CIPHER_SUITE, SERVER_PUBLIC_KEY, license_file.encode("latin"))
    except:
        print("license signature check failed")
        return

    license_data = json.loads(license_file)

    if license_data["client"] == CLIENT_COMMON_NAME and license_data["user"] == USER_ID and license_data["plays"] == nplay and license_data["media_id"] == media_item["id"]:
        h = hashes.Hash(hashes.SHA1())
        h.update((CLIENT_COMMON_NAME + USER_ID).encode("latin"))
        file_name = str(int.from_bytes(h.finalize(), byteorder = 'big'))

        out_file = open("./licenses/" + file_name + "_" + media_item["id"],"w")
        out_file.write(license_file)
        out_file.close()
        print("\n!!--- LICENSE BOUGHT SUCCESSEFULLY --!!\n")

        return

    else:
        print("server gave bad license")
        return
    
#------------------------------------------------------------------#


#------------------------Download a Music--------------------------#

def downloadMusic(CHOSEN_CIPHER_SUITE, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY, SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY):
    
    # Get media and license list
    media_list = getMusicList(CHOSEN_CIPHER_SUITE, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY, SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY)

    #Choose a media to download
    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            e = encrypt_comunication(CHOSEN_CIPHER_SUITE, b"api/exit", CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
            req = s.get(f'{SERVER_URL}/', params = {'data':e})
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection <= len(media_list):
            break

    media_item = media_list[selection]['media']
    print(f"Playing {media_item['name']}")

    #Decrement on license file
    files = os.listdir('./licenses/')

    h = hashes.Hash(hashes.SHA1())
    h.update((CLIENT_COMMON_NAME + USER_ID).encode("latin"))

    file_name= str(int.from_bytes(h.finalize(), byteorder = 'big')) + "_" + media_item["id"]

    try:
        with open("./licenses/" + file_name) as json_file:
            data = json.load(json_file)
    except:
        print("\nERROR: The license for this song has expired or doesn't exists! Please request a new license.\n")

        return

    if int(data["plays"]) == 1:
        os.remove("./licenses/" + file_name)

    else:
        data["plays"] = str(int(data["plays"]) - 1)
        out_file = open("./licenses/" + file_name,"w")
        json.dump(data, out_file, indent = 6)

        out_file.close()

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin = subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin = subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        uri = f'api/download?id={media_item["id"]}&chunk={chunk}'
        e = encrypt_comunication(CHOSEN_CIPHER_SUITE, uri.encode(), CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
        req = s.get(f'{SERVER_URL}/', params = {'data':e})

        if req.status_code >= 400:
            error_message = req.json()
            error_message = error_message['data'].encode('latin')

            message = decrypt_comunication(SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY, CHOSEN_CIPHER_SUITE, error_message)
            print(error_message)

            return



        chunk_data = req.json()
        chunk_data = chunk_data['data'].encode('latin')

        # 1-hash chunk id
        hash_chunk = hash_stuff(CHOSEN_CIPHER_SUITE,chunk.to_bytes(2,'big'))

        #hash server_write_key + 1
        if "AES256" in CHOSEN_CIPHER_SUITE or "ChaCha20" in CHOSEN_CIPHER_SUITE:
            final_hash = hash_stuff(CHOSEN_CIPHER_SUITE, SERVER_WRITE_KEY + hash_chunk)
            final_hash = final_hash[:32]

        elif "AES128" in CHOSEN_CIPHER_SUITE:
            final_hash = hash_stuff(CHOSEN_CIPHER_SUITE, SERVER_WRITE_KEY + hash_chunk)
            final_hash = final_hash[:16]

        chunk_data = json.loads(decrypt_comunication(final_hash, SERVER_WRITE_MAC_KEY, CHOSEN_CIPHER_SUITE, chunk_data).decode('latin'))

        data = binascii.a2b_base64(chunk_data['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break

#------------------------------------------------------------------#


#-------------------------------Quit-------------------------------#

def quit_program(CHOSEN_CIPHER_SUITE, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY):
    #Send exit message and close
    e = encrypt_comunication(CHOSEN_CIPHER_SUITE, b"api/exit", CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
    req = s.get(f'{SERVER_URL}/', params={'data':e})
    sys.exit(0)

def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    print("Contacting Server")

    #Generate a client random
    client_random = os.urandom(28)

    #Client Hello with random and cipher_suite
    req = s.post(f'{SERVER_URL}/api/protocols', data = {"cipher_suite":CLIENT_CIPHER_SUITES,"client_random":client_random})

    if req.status_code >= 400:
        print("Error on Client Hello: " + req.text)
        print("Server error message: " + req.text)
        return

    req = req.json()
    
    #Get Server Random
    server_random = req['server_random'].encode('latin')

    #Get DH Parameters
    y = int(req['y'])
    p = int(req['p'])
    g = int(req['g'])

    cert = x509.load_pem_x509_certificate(req['certificate'].encode())

    #Verify Signature
    SERVER_PUBLIC_KEY = cert.public_key()
    CHOSEN_CIPHER_SUITE = req['cipher_suite']

    try:
        verify_signature(
            req['signature'].encode('latin'), 
            CHOSEN_CIPHER_SUITE, 
            SERVER_PUBLIC_KEY, 
            client_random + server_random + str(y).encode() + str(p).encode() + str(g).encode()
        )
    except:
        print("Invalid server signature")

    #Verify server certificate
    if not verify_server_certificate(cert):
        print("Invalid server certificate")

    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters()

    peer_public_numbers = dh.DHPublicNumbers(y, pn)
    peer_public_key = peer_public_numbers.public_key()

    # generating client's private and public keys
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    y = public_key.public_numbers().y

    signature = make_signature(CHOSEN_CIPHER_SUITE, client_random + server_random + str(y).encode())
    req = s.post(f'{SERVER_URL}/api/key', data = {'certificate': CLIENT_CERTIFICATE , 'DH_PARAMETER':y, 'signature': signature})

    if req.status_code >= 400:
        print("Error on key exchange: " + req.text)
        print("Server error message: " + req.text)
        return

    shared_key = private_key.exchange(peer_public_key)

    global CLIENT_WRITE_MAC_KEY
    global CLIENT_WRITE_KEY
    global SERVER_WRITE_MAC_KEY
    global SERVER_WRITE_KEY

    CLIENT_WRITE_MAC_KEY, SERVER_WRITE_MAC_KEY, CLIENT_WRITE_KEY, SERVER_WRITE_KEY = get_session_keys(CHOSEN_CIPHER_SUITE, shared_key,client_random,server_random)
    
    #Send client finished message encrypted with generated keys
    e = encrypt_comunication(CHOSEN_CIPHER_SUITE, b"api/finished", CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
    req = s.get(f'{SERVER_URL}/', params={'data':e})

    if req.status_code == 404:
        print("Different keys generated")
        return

    req = req.json()

    #Get servers finished message
    finished_data = req['data'].encode('latin')

    message = decrypt_comunication(SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY, CHOSEN_CIPHER_SUITE, finished_data)

    #Check if finished message matches
    if message != b'finished':
        print("Different keys generated")
        return
    else:
        print("Successfully connected with server!")
    

    # Send user authentication
    chain, signature = user_authentication(CHOSEN_CIPHER_SUITE)

    authorization_data = json.dumps({'url': 'api/auth','signature': signature.decode("latin"), 'certificate': chain})
    
    e = encrypt_comunication(CHOSEN_CIPHER_SUITE, authorization_data.encode("latin"), CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)

    req = s.post(f'{SERVER_URL}/', data = {'data': e})

    if req.status_code == 400:
        req = req.json()

        error_message = req['data'].encode('latin')
        error_message = decrypt_comunication(SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY, CHOSEN_CIPHER_SUITE, error_message)

        print("Server error message when authenticating user")
        print(error_message)

        return
    
    print("User " + USER_ID + " authenticated successfully!")

    # After authentication user can aquire licenses, list media and download musics
    while True:
        menu()
        selection = input("-> ")

        if selection.strip() == 'q':
            quit_program(CHOSEN_CIPHER_SUITE, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)

        if not selection.isdigit():
            continue
        
        #Get music and license list option
        if selection.strip() == '1':
            getMusicList(CHOSEN_CIPHER_SUITE, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY, SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY)
        
        #Download music option
        elif selection.strip() == '2':
            downloadMusic(CHOSEN_CIPHER_SUITE, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY, SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY)
        
        #Aquire License Option
        elif selection.strip()== '3':
            aquireLicense(CHOSEN_CIPHER_SUITE, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY, SERVER_WRITE_KEY, SERVER_WRITE_MAC_KEY, SERVER_PUBLIC_KEY)
        
        else:
            continue
    
if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)