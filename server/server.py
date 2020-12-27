#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

with open("MediaServerkey.pem", "rb") as key_file:
    SERVER_PRIVATE_KEY  = serialization.load_pem_private_key(
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


        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
                })

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(media_list, indent=4).encode('latin')


    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
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

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
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

        cert = open("MediaServer.pem",'rb').read().decode()

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

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

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
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

    def generate_DH_parameter(self,session):
        parameters = dh.generate_parameters(generator = 2, key_size = 2048)

        # generate server's private and public keys
        private_key = parameters.generate_private_key()
        
        public_key = private_key.public_key()

        #print("public key:  ", public_key.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo))

        y = public_key.public_numbers().y

        p = parameters.parameter_numbers().p
        g = parameters.parameter_numbers().g

        SESSIONS[session]['parameters']=dh.DHParameterNumbers(p, g)
        SESSIONS[session]['DH_private_key']= private_key
        return y, p, g
    
    def make_signature(self, cypher_suite, data):
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