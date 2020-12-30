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
from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives import padding as real_padding
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID


logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

with open("../private_keys_and_certificates/client_private_key.pem", "rb") as key_file:
    CLIENT_PRIVATE_KEY  = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

SERVER_URL = 'http://127.0.0.1:8080'
SERVER_PUBLIC_KEY = None
CLIENT_WRITE_MAC_KEY = None
CLIENT_WRITE_KEY = None
SERVER_WRITE_MAC_KEY = None
SERVER_WRITE_KEY = None

CLIENT_CERTIFICATE = open("../private_keys_and_certificates/client_certificate.pem",'rb').read().decode()

CLIENT_LOADED_CERTIFICATE= x509.load_pem_x509_certificate(open("../private_keys_and_certificates/client_certificate.pem",'rb').read())
CLIENT_COMMON_NAME=CLIENT_LOADED_CERTIFICATE.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

USER_ID=None

# client knows the songs distributor
DISTRIBUTER_CERTIFICATE = open("../private_keys_and_certificates/distributor_certificate.pem",'rb').read()
#DISTRIBUTER_PUBLIC_KEY = DISTRIBUTER_CERTIFICATE.public_key()
DISTRIBUTER_PUBLIC_KEY = x509.load_pem_x509_certificate(DISTRIBUTER_CERTIFICATE).public_key()

CLIENT_CIPHER_SUITES = ['ECDHE_ECDSA_AES256-GCM_SHA384', 'DHE_RSA_AES256_SHA256']
CHOSEN_CIPHER_SUITE = None

s = requests.Session()

def getSessionkeys(cipher_suite, dh_key,client_random,server_random):
    if "SHA384" in cipher_suite:
        hash_type = hashes.SHA384()
        size = 48
    elif "SHA256" in cipher_suite:
        hash_type = hashes.SHA256()
        size = 32

    if "AES256" in cipher_suite:
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

def encrypt_comunication(cipher_suite, data, CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY):
    if "AES256" in cipher_suite:
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(CLIENT_WRITE_KEY),
            modes.CBC(iv)
        )
    elif "AES256-GCM" in cipher_suite:
        """
        iv= os.urandom(12)
        cipher = Cipher(
            algorithms.AES(CLIENT_WRITE_KEY),
            modes.(iv)
        )
        """
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(padding_data(data, 128)) + encryptor.finalize()

    return iv + generate_hmac(CLIENT_WRITE_MAC_KEY, cipher_suite,   iv +encrypted_data) + encrypted_data

def decrypt_comunication(s_w_k, s_w_m_k,cipher_suite, data):
    if "AES256" in cipher_suite:
        iv_size = 16
        s_w_k=s_w_k[:32]
    elif "AES256-GCM" in cipher_suite:
        iv_size = 12
        s_w_k=s_w_k[:32]

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
        m_data = decrypt_symetric(s_w_k,iv,cipher_suite,m_data)
        unpadded_data = unpadding_data(m_data,128)
        return unpadded_data
    else:
        return 0

def decrypt_symetric(key,iv,cipher_suite,data):
    if "AES256" in cipher_suite:
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv)
        )
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(data) + decryptor.finalize()

    return decrypted_data

def padding_data(data, bits):
    padder = real_padding.PKCS7(bits).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()

    return padded_data

def unpadding_data(data,nbits):
    unpadder = real_padding.PKCS7(nbits).unpadder()
    unpadded_data = unpadder.update(data)
    unpadded_data += unpadder.finalize()

    return unpadded_data

def generate_hmac(key, cipher_suite, data):
    if "SHA256" in cipher_suite:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
    
    elif "SHA384" in cipher_suite:
        h = hmac.HMAC(key, hashes.SHA384())
        h.update(data)

    return h.finalize()

def hash_stuff(cipher_suite,data):
        if "SHA256" in cipher_suite:
            digest = hashes.Hash(hashes.SHA256())
        
        elif "SHA384" in cipher_suite:
            digest = hashes.Hash(hashes.SHA384())

        digest.update(data)

        return digest.finalize()

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

def user_authentication(cipher_suite):

    # mac
    #lib = '/usr/local/lib/libpteidpkcs11.dylib'

    #linux
    lib = '/usr/local/lib/libpteidpkcs11.so'
    #lib = '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so'

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

def menu():
    print("|--------------------------------------|")
    print("|                 MENU                 |")
    print("|--------------------------------------|\n")

    print("|----------  1 MUSIC LIST   -----------|")
    print("|--------  2 DOWNLOAD MUSIC   ---------|")
    print("|--------  3 AQUIRE LICENSE   ---------|")
    print("|-------------  q QUIT   --------------|")

def license_menu():
    print("|--------------------------------------|")
    print("|             LICENSE TYPE             |")
    print("|--------------------------------------|\n")

    print("|----------  (1) SINGLE PLAY      ---------|")
    print("|----------  (2) 5 PLAYS      ---------|")
    print("|--------    (3) 10 PLAYS   ----------|")
    print("|--------  (4) 20 PLAYS   ---------|")
    print("|-------------  q RETURN   --------------|")

def check_licenses(licence_list):
    files = os.listdir('./licenses/')
    h= hashes.Hash(hashes.SHA1())
    h.update((CLIENT_COMMON_NAME+USER_ID).encode("latin"))
    file_name= str(int.from_bytes(h.finalize(), byteorder='big'))
    user_licences= [f for f in files if file_name in f ]
    for user_licence in user_licences:
        with open("./licenses/"+user_licence) as json_file:
            data = json.load(json_file)
            if not any(data["media_id"]==l["media_id"] and data["plays"]==l["plays"] for l in licence_list ):
                return False
    return True

def getMusicList(CHOSEN_CIPHER_SUITE,CLIENT_WRITE_KEY,CLIENT_WRITE_MAC_KEY,SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY):
    e= encrypt_comunication(CHOSEN_CIPHER_SUITE, b"api/list", CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
    req = s.get(f'{SERVER_URL}/', params={'data':e})
    print(req.status_code)
    req = req.json()
    list_data=  req['data'].encode('latin')
    
    message = decrypt_comunication(SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY,CHOSEN_CIPHER_SUITE,list_data)

    media_list = json.loads(message.decode('latin'))

    license_list = media_list['licence_list']

    media_list = media_list['media_list']

    if not check_licenses(license_list):
        print("Server gave wrong licenses")
    else:
        print("USER LICENSES\n")
        for item in license_list:
            print("\n     Media id: "+ item['media_id']+ "    Number of plays " + item['plays'])
        
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
    print("----")

    return media_list
    
def aquireLicense(CHOSEN_CIPHER_SUITE,CLIENT_WRITE_KEY,CLIENT_WRITE_MAC_KEY,SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY, SERVER_PUBLIC_KEY):
    media_list=getMusicList(CHOSEN_CIPHER_SUITE,CLIENT_WRITE_KEY,CLIENT_WRITE_MAC_KEY,SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY)

    while True:
        license_menu()
        selection = input("-> ")
        if selection.strip() == 'q':
            return

        if not selection.isdigit():
            continue

        selection = int(selection)
        if selection==1:
            nplay='1'
            break
        elif selection ==2:
            nplay ='5'
            break
        elif selection ==3:
            nplay ='10'
            break
        elif selection ==4:
            nplay ='20'
            break
    while True:
        selection = input("Select a media file number (q to return): ")
        if selection.strip() == 'q':
            return

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection<=len(media_list):
            break
    media_item=media_list[selection]['media']
    uri= f'api/license?id={media_item["id"]}&type={nplay}'
    e= encrypt_comunication(CHOSEN_CIPHER_SUITE, uri.encode(), CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
    req = s.get(f'{SERVER_URL}/', params={'data':e})
    req = req.json()
    license_data=  req['data'].encode('latin')
    message = decrypt_comunication(SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY,CHOSEN_CIPHER_SUITE,license_data)

    license_data = json.loads(message.decode('latin'))

    license_signature = license_data['license_signature'].encode("latin")
    license_file = license_data['license']

    try:
        verify_signature(license_signature,CHOSEN_CIPHER_SUITE,SERVER_PUBLIC_KEY,license_file.encode("latin"))
    except:
        print("license signature check failed")
        return

    license_data= json.loads(license_file)

    if license_data["client"] == CLIENT_COMMON_NAME and license_data["user"] == USER_ID and license_data["plays"]==nplay and license_data["media_id"]==media_item["id"]:
        h= hashes.Hash(hashes.SHA1())
        h.update((CLIENT_COMMON_NAME+USER_ID).encode("latin"))
        file_name= str(int.from_bytes(h.finalize(), byteorder='big'))

        out_file= open("./licenses/"+file_name+"_"+media_item["id"],"w")
        out_file.write(license_file)
        out_file.close()
        print("\n!!--- LICENSE BOUGHT SUCCESSEFULLY --!!\n")
        return
    else:
        print("server gave bad license")
        return
    

def downloadMusic(CHOSEN_CIPHER_SUITE,CLIENT_WRITE_KEY,CLIENT_WRITE_MAC_KEY,SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY):
    media_list=getMusicList(CHOSEN_CIPHER_SUITE,CLIENT_WRITE_KEY,CLIENT_WRITE_MAC_KEY,SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY)

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            e= encrypt_comunication(CHOSEN_CIPHER_SUITE, b"api/exit", CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
            req = s.get(f'{SERVER_URL}/', params={'data':e})
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection<=len(media_list):
            break

    # Example: Download first file
    media_item = media_list[selection]['media']
    print(f"Playing {media_item['name']}")

    #Decrement on license file
    files = os.listdir('./licenses/')
    h= hashes.Hash(hashes.SHA1())
    h.update((CLIENT_COMMON_NAME+USER_ID).encode("latin"))
    file_name= str(int.from_bytes(h.finalize(), byteorder='big'))+"_"+ media_item["id"]
    with open("./licenses/"+file_name) as json_file:
        data = json.load(json_file)

    if int(data["plays"])<=0:
        os.remove("./licenses/"+file_name)
    else:
        data["plays"]= str(int(data["plays"])-1)
        out_file= open("./licenses/"+file_name,"w")
        json.dump(data, out_file,indent=6)
        out_file.close()

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        uri= f'api/download?id={media_item["id"]}&chunk={chunk}'
        e= encrypt_comunication(CHOSEN_CIPHER_SUITE, uri.encode(), CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
        req = s.get(f'{SERVER_URL}/', params={'data':e})

        chunk_data = req.json()
        chunk_data=  chunk_data['data'].encode('latin')

        # 1-hash chunk id
        hash_chunk = hash_stuff(CHOSEN_CIPHER_SUITE,chunk.to_bytes(2,'big'))

        #hash server_write_key + 1
        final_hash = hash_stuff(CHOSEN_CIPHER_SUITE,SERVER_WRITE_KEY+hash_chunk)

        chunk_data = json.loads(decrypt_comunication(final_hash,SERVER_WRITE_MAC_KEY,CHOSEN_CIPHER_SUITE,chunk_data).decode('latin'))
        print(chunk_data)
        # TODO: Process chunk

        data = binascii.a2b_base64(chunk_data['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break

def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    client_random = os.urandom(28)
    req = s.post(f'{SERVER_URL}/api/protocols', data= {"cipher_suite":CLIENT_CIPHER_SUITES,"client_random":client_random})
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
    CHOSEN_CIPHER_SUITE = req['cipher_suite']

    verify_signature(
        req['signature'].encode('latin'), 
        CHOSEN_CIPHER_SUITE, 
        SERVER_PUBLIC_KEY, 
        client_random + server_random + str(y).encode() + str(p).encode() + str(g).encode()
    )

    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters()

    peer_public_numbers = dh.DHPublicNumbers(y, pn)
    peer_public_key = peer_public_numbers.public_key()

    # generating client's private and public keys
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    y = public_key.public_numbers().y

    signature = make_signature(CHOSEN_CIPHER_SUITE, client_random + server_random + str(y).encode())
    req = s.post(f'{SERVER_URL}/api/key', data={'certificate': CLIENT_CERTIFICATE , 'DH_PARAMETER':y, 'signature': signature})

    shared_key = private_key.exchange(peer_public_key)

    global CLIENT_WRITE_MAC_KEY
    global CLIENT_WRITE_KEY
    global SERVER_WRITE_MAC_KEY
    global SERVER_WRITE_KEY

    CLIENT_WRITE_MAC_KEY, SERVER_WRITE_MAC_KEY, CLIENT_WRITE_KEY, SERVER_WRITE_KEY = getSessionkeys(CHOSEN_CIPHER_SUITE, shared_key,client_random,server_random)
    
    e= encrypt_comunication(CHOSEN_CIPHER_SUITE, b"api/finished", CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
    req = s.get(f'{SERVER_URL}/', params={'data':e})
    req= req.json()
    finished_data = req['data'].encode('latin')

    message = decrypt_comunication(SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY,CHOSEN_CIPHER_SUITE,finished_data)

    print(message)
    
    e= encrypt_comunication(CHOSEN_CIPHER_SUITE, b"api/list", CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
    req = s.get(f'{SERVER_URL}/', params={'data':e})
    print(req.status_code)
    req = req.json()
    list_data=  req['data'].encode('latin')
    
    



    # send user authentication
    chain, signature = user_authentication(CHOSEN_CIPHER_SUITE)

    authorization_data = json.dumps({'url': 'api/auth','signature': signature.decode("latin"), 'certificate': chain})
    
    e = encrypt_comunication(CHOSEN_CIPHER_SUITE, authorization_data.encode("latin"), CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)

    req = s.post(f'{SERVER_URL}/', data = {'data': e})


    while True:
        menu()
        selection = input("-> ")
        if selection.strip() == 'q':
            e= encrypt_comunication(CHOSEN_CIPHER_SUITE, b"api/exit", CLIENT_WRITE_KEY, CLIENT_WRITE_MAC_KEY)
            req = s.get(f'{SERVER_URL}/', params={'data':e})
            sys.exit(0)

        if not selection.isdigit():
            continue
        if selection.strip() == '1':
            getMusicList(CHOSEN_CIPHER_SUITE,CLIENT_WRITE_KEY,CLIENT_WRITE_MAC_KEY,SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY)
        elif selection.strip() == '2':
            downloadMusic(CHOSEN_CIPHER_SUITE,CLIENT_WRITE_KEY,CLIENT_WRITE_MAC_KEY,SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY)
        elif selection.strip()== '3':
            aquireLicense(CHOSEN_CIPHER_SUITE,CLIENT_WRITE_KEY,CLIENT_WRITE_MAC_KEY,SERVER_WRITE_KEY,SERVER_WRITE_MAC_KEY,SERVER_PUBLIC_KEY)
        else:
            continue
    
    


if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)