#!/usr/bin/env python

import requests
from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
from urllib import parse
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as real_padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

with open("../private_keys_and_certificates/server_private_key.pem", "rb") as key_file:
    SERVER_PRIVATE_KEY  = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

with open("../private_keys_and_certificates/distributor_private_key.pem", "rb") as key_file:
    DISTRIBUTOR_PRIVATE_KEY  = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

SERVER_CYPHER_SUITES = ['ECDHE_ECDSA_AES256-GCM_SHA384', 'DHE_RSA_AES256_SHA256']

SESSIONS={}

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

class MediaServer(resource.Resource):
    isLeaf = True

    # Send the list of media files to clients
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'
        session = request.getSession()
        if not 'user_id' in SESSIONS[session]:
            request.setResponseCode(401)
            s=self.encrypt_comunication(b'Not authorized',request.getSession())
            return json.dumps({'data':s.decode("latin")}).encode('latin')

        cipher_suite = SESSIONS[session]['cypher_suite']
        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]

            media_data= media_id+media['name']+media['description']+str(math.ceil(media['file_size'] / CHUNK_SIZE))+str(media['duration'])
            dist_signature= self.make_signature(cipher_suite,media_data.encode("latin"),key=DISTRIBUTOR_PRIVATE_KEY)

            media_list.append(
                {
                    'media':{
                        'id': media_id,
                        'name': media['name'],
                        'description': media['description'],
                        'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                        'duration': media['duration']
                        }
                    ,
                    'distributor_signature':dist_signature.decode("latin")

                })

        # Return list to client
        #TODO get license list
        media_json= json.dumps({'media_list':media_list,'licence_list':'lista'})
        data =self.encrypt_comunication(media_json.encode("latin"), request.getSession())
        return json.dumps({'data':data.decode("latin")}).encode('latin')


    # Send a media chunk to the client
    def do_download(self, args, session):
        logger.debug(f'Download: args: {args}')
        
        # Check if the media_id is not None as it is required
        if 'id' not in args:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        media_id = args['id']
        logger.debug(f'Download: id: {media_id}')


        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        valid_chunk = False
        if 'chunk' in args:
            chunk_id=args['chunk']
            try:
                chunk_id = int(chunk_id)
                if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                    valid_chunk = True
            except:
                logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)


            cipher_suite=SESSIONS[session]['cypher_suite']
            s_w_k = SESSIONS[session]['server_write_key']

            # 1-hash chunk id
            hash_chunk = self.hash(cipher_suite,chunk_id.to_bytes(2,'big'))

            #hash server_write_key + 1
            final_hash = self.hash(cipher_suite,s_w_k+hash_chunk)

            data = json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')

            data= self.encrypt_comunication(data,session,key=final_hash)
            print(data)
            return json.dumps({'data':data.decode("latin")}).encode('latin')

        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    def do_post_protocols(self, request):
        session = request.getSession()       
        client_cypher_suites = request.args.get(b'cypher_suite')
        chosen_cypher_suite = None

        for csuite in client_cypher_suites:
            csuite = csuite.decode()
            if csuite in SERVER_CYPHER_SUITES:
                chosen_cypher_suite = csuite
                break

        cert = open("../private_keys_and_certificates/server_certificate.pem",'rb').read().decode()

        # server and client's randoms
        server_random = os.urandom(28)
        client_random = request.args[b'client_random'][0]

        SESSIONS[session] = {'cypher_suite':chosen_cypher_suite, 'client_random':client_random, 'server_random':server_random}

        # generate DH parameters: y, p (large prime), g (primitive root mod p)
        y, p, g = self.generate_DH_parameter(session)

        # generate signature
        signature = self.make_signature(chosen_cypher_suite, client_random + server_random + str(y).encode() + str(p).encode() + str(g).encode())

        return json.dumps({'cypher_suite':chosen_cypher_suite, 'certificate':cert, 'server_random':server_random.decode('latin'), 'signature':signature.decode('latin'), 'y':y, 'p':p, 'g':g}).encode('latin')

    def do_key(self,request):
        session = request.getSession()

        cypher_suite = SESSIONS[session]['cypher_suite']
        print(request.args[b'certificate'][0])

        cert = x509.load_pem_x509_certificate(request.args[b'certificate'][0])
        print(cert.not_valid_before)

        DH_key = self.get_DH_Key(session,int(request.args[b'DH_PARAMETER'][0].decode()),cypher_suite)
        CLIENT_PUBLIC_KEY = cert.public_key()

        self.verify_signature(request.args[b'signature'][0], cypher_suite,CLIENT_PUBLIC_KEY, SESSIONS[session]['client_random']+ SESSIONS[session]['server_random'] + request.args[b'DH_PARAMETER'][0])
        self.getSessionkeys(session,cypher_suite,DH_key)
        

    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_post_protocols(request)
            elif request.path == b'/api/key':
                return self.do_key(request)
            #elif request.uri == 'api/auth':
            else:
                path =self.decrypt_comunication(request.getSession(), request.args[b'data'][0])
                if path == b'api/finished':
                    SESSIONS[request.getSession()]['finished']= True
                    s=self.encrypt_comunication(b'finished',request.getSession() )
                    return json.dumps({'data':s.decode("latin")}).encode('latin')
                elif path == b'api/list':
                    return self.do_list(request)
                elif b'api/download' in path:
                    url = 'http://127.0.0.1:8080/'+path.decode()
                    args=dict(parse.parse_qsl(parse.urlsplit(url).query))
                    return self.do_download(args,request.getSession())


                #request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                #return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
    
    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')
        request.setResponseCode(501)

        try:
            if request.path == b'/api/protocols':
                return self.do_post_protocols(request)

            elif request.path == b'/api/key':
                return self.do_key(request)
            
            #elif request.uri == 'api/auth':

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                session=request.getSession()
                data = self.decrypt_comunication(session, request.args[b'data'][0])

                data = json.loads(data.decode("latin"))

                path = data['url']

                if path == 'api/auth':
                    
                    #print(data['certificate'])
                    user_certificate = x509.load_der_x509_certificate(data['certificate'][0].encode("latin"))
                    uid= user_certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
                    #print(user_certificate)
                    try:
                        self.user_verify_signature(data['signature'].encode("latin"),user_certificate.public_key(),uid.encode())
                        if  self.check_user_cert_chain(data['certificate']):
                            print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                            SESSIONS[session]['user_id']=uid
                            message= "user_ " + uid + "authenticated"
                            s= self.encrypt_comunication(message.encode("latin"), session)
                            return json.dumps({'data':s.decode("latin")}).encode('latin')
                        
                        else:
                            s= self.encrypt_comunication(b'failed to authenticate user', session)
                            return json.dumps({'data':s.decode("latin")}).encode('latin')
                    except:
                        s= self.encrypt_comunication(b'failed to authenticate user', session)
                        return json.dumps({'data':s.decode("latin")}).encode('latin')
                    #s = self.encrypt_comunication(b'finished',request.getSession() )
                    #return json.dumps({'data':s.decode("latin")}).encode('latin')
                

                #request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                #return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

    def check_user_cert_chain(self,cert_chain):

        if not self.validate_attributes(cert_chain):
            return False
        if not self.validate_crl(cert_chain):
            return False

        if not self.check_cert_signature(cert_chain): 
            return False 
        return True 

    """
        CITIZEN AUTHENTICATION CERTIFICATE ATRIBUTES:
        ORGANIZATION_NAME: Cartão de Cidadão
        KEY_USAGE: digital_signature

        AUTHENTICATION SUB CA:
        ORGANIZATION_NAME: Cartão de Cidadão
        KEY_USAGE: key_cert_sign=True, crl_sign=True

        ROOT CA:
        ORGANIZATION_NAME: SCEE - Sistema de Certificação Electrónica do Estado
        KEY_USAGE: key_cert_sign=True, crl_sign=True

    """
    def validate_attributes(self,cert_chain):
        #CITIZEN AUTHENTICATION CERTIFICATE
        c=x509.load_der_x509_certificate(cert_chain[0].encode("latin"))
        key_usage=c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if (not key_usage.digital_signature or key_usage.content_commitment or key_usage.key_encipherment 
            or key_usage.data_encipherment or not key_usage.key_agreement or key_usage.key_cert_sign  
            or key_usage.crl_sign or key_usage.encipher_only or key_usage.decipher_only):
            return False

        if not (c.not_valid_before< datetime.now()< c.not_valid_after):
            return False

        if not (c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value=='Cartão de Cidadão'):
            return False
        
        c=x509.load_der_x509_certificate(cert_chain[1].encode("latin"))
        key_usage=c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if ( key_usage.digital_signature or key_usage.content_commitment or key_usage.key_encipherment 
            or key_usage.data_encipherment or key_usage.key_agreement or not key_usage.key_cert_sign  
            or not  key_usage.crl_sign):
            return False
        
        if not (c.not_valid_before< datetime.now()< c.not_valid_after):
            return False
        
        if not (c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value=='Cartão de Cidadão'):
            return False
        
        c=x509.load_der_x509_certificate(cert_chain[2].encode("latin"))
        key_usage=c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if (key_usage.digital_signature or key_usage.content_commitment or key_usage.key_encipherment 
            or key_usage.data_encipherment or key_usage.key_agreement or not key_usage.key_cert_sign  
            or not  key_usage.crl_sign ):
            return False
        if not (c.not_valid_before< datetime.now()< c.not_valid_after):
            return False
        if not (c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value=='SCEE - Sistema de Certificação Electrónica do Estado'):
            return False

        return True

    def check_cert_signature(self,cert_chain):
        for cert in range(len(cert_chain)-1):

            c = x509.load_der_x509_certificate(cert_chain[cert].encode("latin"))
            ci = x509.load_der_x509_certificate(cert_chain[cert+1].encode("latin"))
            issuer_public_key = ci.public_key()
            try:
                issuer_public_key.verify(
                    c.signature,
                    c.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    c.signature_hash_algorithm,
                )
            except:
                return False
        return True

    def validate_crl(self,cert_chain):
        for cert in range(len(cert_chain)-1):
            c = x509.load_der_x509_certificate(cert_chain[cert].encode("latin"))
            #print(c.extensions.get_extension_for_oid(ExtensionOID.FRESHEST_CRL).value[0].full_name)
            #print(c.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value[0].full_name)
            r= requests.get(c.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value[0].full_name[0].value, allow_redirects=True)
            crl= x509.load_der_x509_crl(r.content)
            if not crl.get_revoked_certificate_by_serial_number(c.serial_number) is  None:
                return False
            try:
                r= requests.get(c.extensions.get_extension_for_oid(ExtensionOID.FRESHEST_CRL).value[0].full_name[0].value, allow_redirects=True)
                crl= x509.load_der_x509_crl(r.content)
                if not crl.get_revoked_certificate_by_serial_number(c.serial_number) is None:
                    return False
            except:
                logger.warning("no crl delta")
        return True
    
    def generate_DH_parameter(self,session):
        
        parameters = dh.generate_parameters(generator = 2, key_size = 2048)

        # generate server's private and public keys
        private_key = parameters.generate_private_key()
        
        public_key = private_key.public_key()

        y = public_key.public_numbers().y

        p = parameters.parameter_numbers().p
        g = parameters.parameter_numbers().g

        SESSIONS[session]['parameters']=dh.DHParameterNumbers(p, g)
        SESSIONS[session]['DH_private_key']= private_key
        return y, p, g

    def encrypt_comunication(self,data,session,key=None):
        if not key:
            server_write_key = SESSIONS[session]['server_write_key']
        else:
            server_write_key= key
        cipher_suite = SESSIONS[session]['cypher_suite']
        
        server_write_MAC_key = SESSIONS[session]['server_write_MAC_key']

        if "AES256" in cipher_suite:
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(server_write_key[:32]),
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

        encrypted_data = encryptor.update(self.padding_data(data, 128)) + encryptor.finalize()

        return iv + self.generate_hmac(server_write_MAC_key, cipher_suite,   iv +encrypted_data) + encrypted_data

    def decrypt_comunication(self, session, data):
        cipher_suite = SESSIONS[session]['cypher_suite']
        client_write_key = SESSIONS[session]['client_write_key']
        client_write_MAC_key = SESSIONS[session]['client_write_MAC_key']

        if "AES256" in cipher_suite:
            iv_size = 16
        elif "AES256-GCM" in cipher_suite:
            iv_size = 12

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

        if hmac == self.generate_hmac(client_write_MAC_key, cipher_suite, h_data):
            m_data = self.decrypt_symetric(client_write_key,iv,cipher_suite,m_data)
            unpadded_data = self.unpadding_data(m_data,128)
            return unpadded_data

        else:
            return 0

    def padding_data(self,data, bits):
        padder = real_padding.PKCS7(bits).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        return padded_data

    def unpadding_data(self,data,nbits):
        unpadder = real_padding.PKCS7(nbits).unpadder()
        unpadded_data = unpadder.update(data)
        unpadded_data += unpadder.finalize()

        return unpadded_data

    def decrypt_symetric(self,key,iv,cypher_suite,data):
        if "AES256" in cypher_suite:
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv)
            )
            decryptor = cipher.decryptor()

            decrypted_data = decryptor.update(data) + decryptor.finalize()

        return decrypted_data

    def generate_hmac(self, key, cypher_suite, data):
        #print("data",data)
        if "SHA256" in cypher_suite:
            h = hmac.HMAC(key, hashes.SHA256())
            h.update(data)
        
        elif "SHA384" in cypher_suite:
            h = hmac.HMAC(key, hashes.SHA384())
            h.update(data)

        return h.finalize()

    def hash(self,cipher_suite,data):
        if "SHA256" in cipher_suite:
            digest = hashes.Hash(hashes.SHA256())
        
        elif "SHA384" in cipher_suite:
            digest = hashes.Hash(hashes.SHA384())
        digest.update(data)
        return digest.finalize()

    
    def make_signature(self, cypher_suite, data, key=SERVER_PRIVATE_KEY):
        if "SHA384" in cypher_suite:
            signature = SERVER_PRIVATE_KEY.sign(
                data,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA384()),
                    salt_length = padding.PSS.MAX_LENGTH
                ),
                hashes.SHA384()
            )
        
        elif "SHA256" in cypher_suite:
            signature = SERVER_PRIVATE_KEY.sign(
                data,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA256()),
                    salt_length = padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        
        return signature

    def user_verify_signature(self,signature,pub_key,data):
        pub_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA1()
        )

    def verify_signature(self,signature,cypher_suite,pub_key,data):
        if "SHA384" in cypher_suite:
            hash_type = hashes.SHA384()
            hash_type2 = hashes.SHA384()

        elif "SHA256" in cypher_suite:
            hash_type = hashes.SHA256()
            hash_type2 = hashes.SHA256()

        pub_key.verify(
            signature,
            data,
            padding.PSS(
                mgf = padding.MGF1(hash_type),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hash_type2
        )

    def get_DH_Key(self, session,y,cipher_suite):
        peer_public_numbers = dh.DHPublicNumbers(y, SESSIONS[session]['parameters'])
        peer_public_key = peer_public_numbers.public_key()
        shared_key = SESSIONS[session]['DH_private_key'].exchange(peer_public_key)
        return shared_key

    def getSessionkeys(self,session,cypher_suite, dh_key):
        if "SHA384" in cypher_suite:
            hash_type = hashes.SHA384()
            size = 48
        elif "SHA256" in cypher_suite:
            hash_type = hashes.SHA256()
            size = 32

        if "AES256" in cypher_suite:
            hkdf = HKDF(
                algorithm = hash_type,
                length = 64 + size * 2,
                salt = SESSIONS[session]['client_random'] + SESSIONS[session]['server_random'],
                info = None
            )
            key = hkdf.derive(dh_key)

            # divide the key into 4 different keys
            SESSIONS[session]['client_write_MAC_key']=key[:size]
            SESSIONS[session]['server_write_MAC_key']=key[size:size*2]
            SESSIONS[session]['client_write_key']=key[size*2:size*2+32]
            SESSIONS[session]['server_write_key']=key[size*2+32:size*2+64]

            #print(SESSIONS[session])


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()