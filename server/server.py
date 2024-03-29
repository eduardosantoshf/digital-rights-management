#!/usr/bin/env python

import requests
from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
import random
from urllib import parse
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import padding as real_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#SERVER PRIVATE KEY
with open("./Media_Server_Private_Key.pem", "rb") as key_file:
    SERVER_PRIVATE_KEY = serialization.load_pem_private_key(
        key_file.read(),
        password = b'xB&ke95S96@B!WJZ',
    )

#DISTRIBUTOR PRIVATE KEY
with open("./Media_Distributor_Private_Key.pem", "rb") as key_file:
    DISTRIBUTOR_PRIVATE_KEY = serialization.load_pem_private_key(
        key_file.read(),
        password = b'kLc_j*taAC%9Dw9j',
    )

#ROOT CA CERTIFICATE
ROOT_CA = x509.load_pem_x509_certificate(open("../Media_CA.crt",'rb').read())

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

SERVER_CIPHER_SUITES = ['DHE_AES256_CBC_SHA384','DHE_AES256_CFB_SHA384',
                        'DHE_AES128_CBC_SHA256','DHE_AES128_CBC_SHA384',
                        'DHE_ChaCha20_SHA384','DHE_ChaCha20_SHA384','DHE_ChaCha20_SHA256'
                       ]

SESSIONS={}

FILE_DECRYPTION_KEY = b'MayTheCodeBeWithYou'
FILE_DECRYPTION_SALT = b'IAmTheOneWhoCodes'

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            },
            'bv7vin4xdir1ny1bkgzoevbwkc74ppeiysyhqstz':
            {
                'name': 'E.R.F.',
                'album': '',
                'description': 'Music: www.bensound.com',
                'duration': 4 * 60 + 41,
                'file_name': 'bv7vin4xdir1ny1bkgzoevbwkc74ppeiysyhqstz.mp3',
                'file_size': 6736456
            },
            'b7twdi1w8h9r3065rp9vowruc1dos0578qag6pet':
            {
                'name': 'JAZZY FRENCHY',
                'album': '',
                'description': 'Music: www.bensound.com',
                'duration': 1 * 60 + 45,
                'file_name': 'b7twdi1w8h9r3065rp9vowruc1dos0578qag6pet.mp3',
                'file_size': 1467245
            },
            '6novk8kn7idiad1bon32qvbq7rnzlh10uw15lnp5':
            {
                'name': 'ACOUSTIC BREEZE',
                'album': '',
                'description': 'Music: www.bensound.com',
                'duration': 2 * 60 + 37,
                'file_name': '6novk8kn7idiad1bon32qvbq7rnzlh10uw15lnp5.mp3',
                'file_size': 2200868
            },
            '0woft9i8rz553vttlnc33yjzcs4li1a3mtt60e8v':
            {
                'name': 'HAPPY ROCK',
                'album': '',
                'description': 'Music: www.bensound.com',
                'duration': 1 * 60 + 46,
                'file_name': '0woft9i8rz553vttlnc33yjzcs4li1a3mtt60e8v.mp3',
                'file_size': 1481873
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

class MediaServer(resource.Resource):
    isLeaf = True


    #-------Send the list of media files  and licenses to clients------#
    #                                                                  #
    #    Function called when a client sends a api/list request        #
    #  Each media in the catalog will be signed using the distributor  #
    #                            private key.                          #
    # The server will scan its license store in order to fetch all     #
    #          licenses from the user with the current client.         #
    #------------------------------------------------------------------#

    def do_list(self, request):

        session = request.getSession()

        #User must be authenticated in order to get media and license list
        if not 'user_id' in SESSIONS[session]:
            request.setResponseCode(401)
            s = self.encrypt_comunication(b'Not authorized',session)

            return json.dumps({'data':s.decode("latin")}).encode('latin')

        cipher_suite = SESSIONS[session]['cipher_suite']

        # Build media list
        media_list = []

        for media_id in CATALOG:
            media = CATALOG[media_id]

            # Sign media with distributor private key
            media_data = media_id + media['name'] + media['description'] + str(math.ceil(media['file_size'] / CHUNK_SIZE)) + str(media['duration'])
            dist_signature = self.make_signature(cipher_suite,media_data.encode("latin"), key = DISTRIBUTOR_PRIVATE_KEY)

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

        #Build users license list
        license_list = []
        files = os.listdir('./licenses/')
        user_id = SESSIONS[session]['user_id']
        client_id = SESSIONS[session]['client'].get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        h = hashes.Hash(hashes.SHA1())
        h.update((client_id + user_id).encode("latin"))
        file_name = str(int.from_bytes(h.finalize(), byteorder = 'big'))

        user_licences = [f for f in files if file_name in f ]

        for user_licence in user_licences:
            with open("./licenses/"+user_licence) as json_file:
                data = json.load(json_file)
                license_list.append({"media_id":data["media_id"],"media_name":CATALOG[data["media_id"]]["name"],"plays":data["plays"]})

        # Return list to client

        media_json = json.dumps(
            {
                'media_list':media_list,
                'licence_list':license_list
            })

        data = self.encrypt_comunication(media_json.encode("latin"), session)

        request.setResponseCode(200)

        return json.dumps({'data':data.decode("latin")}).encode('latin')

    #------------------------------------------------------------------#


    #--------------------Generate a media license----------------------#
    #                                                                  #
    #    Function called when a client sends a api/license request.    #
    # The server will generate a license based on the arguments passed #
    #                          in the request.                         #
    #     The license is stored and then sent to the client signed.    #
    #------------------------------------------------------------------#
    
    def generate_license(self, music_id, license_type, request):

        session = SESSIONS[request.getSession()]

        #User must be authenticated in order to generate media license
        if not 'user_id' in session:
            request.setResponseCode(401)
            s = self.encrypt_comunication(b'Not authorized',request.getSession())

            return json.dumps({'data':s.decode("latin")}).encode('latin')

        # Check if media_id in the catalog
        if music_id not in CATALOG:
            request.setResponseCode(404)
            s = self.encrypt_comunication(b'Media file not found',request.getSession())

            return json.dumps({'data':s.decode("latin")}).encode('latin')

        # Check if license type is valid
        if license_type not in ['1','5','10','20']:
            request.setResponseCode(404)
            s = self.encrypt_comunication(b'Invalid License',request.getSession())
            
            return json.dumps({'data':s.decode("latin")}).encode('latin')


        user_id = session['user_id']
        client_id = session['client'].get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        license_json = {
            'client':client_id,
            'user': user_id,
            'plays': license_type,
            'media_id': music_id 
        }
        
        h = hashes.Hash(hashes.SHA1())
        h.update((client_id + user_id).encode("latin"))
        file_name = str(int.from_bytes(h.finalize(), byteorder='big'))

        out_file = open("./licenses/" + file_name + "_" + music_id, "w")
        json.dump(license_json, out_file,indent=6)
        out_file.close()
        file_content = open("./licenses/" + file_name + "_" + music_id,"rb")
        license_data = file_content.read()

        file_content.close()
        license_signature = self.make_signature(session['cipher_suite'],license_data)

        message_json = json.dumps(
            {
                'license_signature': license_signature.decode("latin"),
                'license':license_data.decode("latin")
            })

        s = self.encrypt_comunication(message_json.encode("latin"),request.getSession())

        return json.dumps({'data':s.decode("latin")}).encode('latin')

    #------------------------------------------------------------------#


    #----------------Send a media chunk to the client------------------#
    #                                                                  #
    #    Function called when a client sends a api/download request.   #
    # The server will see if the user is authenticated and has a valid #
    #                      license for that media.                     #
    # It will then update the user license and decrypt the chunk to be #
    #                         sent to the client.                      #
    #------------------------------------------------------------------#

    def do_download(self, args, request):
        session = request.getSession()
        logger.debug(f'Download: args: {args}')

        #User must be authenticated in order to do download
        if not 'user_id' in SESSIONS[session]:
            request.setResponseCode(401)
            s = self.encrypt_comunication(b'Not authorized',session)

            return json.dumps({'data':s.decode("latin")}).encode('latin')
        
        # Check if the media_id is not None as it is required
        if 'id' not in args:
            request.setResponseCode(400)
            s = self.encrypt_comunication(b'Invalid media id',session)

            return json.dumps({'data':s.decode("latin")}).encode('latin')

        
        media_id = args['id']
        logger.debug(f'Download: id: {media_id}')


        # Check if media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(400)
            s = self.encrypt_comunication(b'Media file not found',session)

            return json.dumps({'data':s.decode("latin")}).encode('latin')

        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        valid_chunk = False
        if 'chunk' in args:
            chunk_id = args['chunk']
            try:
                chunk_id = int(chunk_id)
                if chunk_id >= 0 and chunk_id < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                    valid_chunk = True
            except:
                logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            s = self.encrypt_comunication(b'Invalid chunk id',session)
            return json.dumps({'data':s.decode("latin")}).encode('latin')
        
        #Check if user has a valid license
        files = os.listdir('./licenses/')
        user_id = SESSIONS[session]['user_id']
        client_id = SESSIONS[session]['client'].get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        h = hashes.Hash(hashes.SHA1())
        h.update((client_id + user_id).encode("latin"))
        file_name = str(int.from_bytes(h.finalize(), byteorder = 'big')) + "_" + media_id

        if chunk_id == 0:
            if file_name in files:
                with open("./licenses/" + file_name) as json_file:
                    data = json.load(json_file)
                    if int(data["plays"]) <= 0:
                        os.remove("./licenses/" + file_name)

                        request.setResponseCode(400)

                        s = self.encrypt_comunication(b'User does not have a valid license',session)

                        return json.dumps({'data':s.decode("latin")}).encode('latin')      
            else:
                request.setResponseCode(400)

                s = self.encrypt_comunication(b'User does not have a valid license', session)

                return json.dumps({'data':s.decode("latin")}).encode('latin')
                
            if int(data["plays"]) == 1:
                os.remove("./licenses/" + file_name)
            else:
                data["plays"] = str(int(data["plays"]) - 1)
                out_file = open("./licenses/" + file_name,"w")
                json.dump(data, out_file, indent = 6)
                out_file.close()

        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)

            data = f.read(CHUNK_SIZE)

            data = self.decrypt_data(data, chunk_id - 1 == math.ceil(media_item['file_size'] / CHUNK_SIZE))

            cipher_suite = SESSIONS[session]['cipher_suite']
            s_w_k = SESSIONS[session]['server_write_key']

            # 1-hash chunk id
            hash_chunk = self.hash(cipher_suite,chunk_id.to_bytes(2,'big'))

            #hash server_write_key + 1
            #256: 32
            #128: 16
            #cha: 32
            if "AES256" in cipher_suite or "ChaCha20" in cipher_suite:
                final_hash = self.hash(cipher_suite, s_w_k + hash_chunk)
                final_hash = final_hash[:32]
            
            elif "AES128" in cipher_suite:
                final_hash = self.hash(cipher_suite, s_w_k + hash_chunk)
                final_hash = final_hash[:16]

            data = json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },
                    indent = 4
                ).encode('latin')

            request.setResponseCode(200)

            data = self.encrypt_comunication(data, session, key = final_hash)
            return json.dumps({'data':data.decode("latin")}).encode('latin')

        #if file did not open
        request.setResponseCode(500)
        s = self.encrypt_comunication(b'Unknown error with media file',session)

        return json.dumps({'data':s.decode("latin")}).encode('latin') 

    #------------------------------------------------------------------#


    #---------------------Client initial message-----------------------#
    #                                                                  #
    #   Function called when a client sends a api/protocols request.   #
    # The server chooses a cipher suit based on the cipher suites list #
    #                       sent by the client.                        #
    #       The server generates a random and the DH parameters.       #
    #   These will be sent signed along with the server certificate    #
    #------------------------------------------------------------------#
    def do_post_protocols(self, request):

        session = request.getSession()

        # Check if cipher suites were sent
        if b'cipher_suite' not in request.args:
            request.setResponseCode(400)
            return b'No cipher suite found'
        
        client_cipher_suites = request.args.get(b'cipher_suite')
        chosen_cipher_suite = None

        # Choose cipher suite 
        # Note:
        # In normal conditions the server would have a list ordered by preferences
        # in the project context we will do a random
        csuite_list = []

        for csuite in client_cipher_suites:
            csuite_list.append(csuite.decode())

        r = random.choice(csuite_list)

        while not r in SERVER_CIPHER_SUITES:
            r = random.choice(csuite_list)
        
        chosen_cipher_suite = r
        
        print("chosen cipher suite: ", chosen_cipher_suite)

        
        # load server's certificate
        cert = open("./Media_Server.crt",'rb').read().decode()

        # server and client's randoms
        server_random = os.urandom(28)
        client_random = request.args[b'client_random'][0]

        # save session data
        SESSIONS[session] = {'cipher_suite':chosen_cipher_suite, 'client_random':client_random, 'server_random':server_random}

        # generate DH parameters: y, p (large prime), g (primitive root mod p)
        y, p, g = self.generate_DH_parameter(session)

        # generate signature
        signature = self.make_signature(chosen_cipher_suite, client_random + server_random + str(y).encode() + str(p).encode() + str(g).encode())

        request.setResponseCode(200)

        return json.dumps({'cipher_suite':chosen_cipher_suite, 'certificate':cert, 'server_random':server_random.decode('latin'), 'signature':signature.decode('latin'), 'y':y, 'p':p, 'g':g}).encode('latin')

    #------------------------------------------------------------------#


    #---------------Process client cert and session keys---------------#
    #                                                                  #
    #      Function called when a client sends a api/keys request      #
    #           It will validate the client certificate.               #
    #             Then it will generate the session keys.              #
    #------------------------------------------------------------------#

    def do_key(self,request):
        session = request.getSession()

        # Check if client sent the initial message
        if session not in SESSIONS:
            request.setResponseCode(400)

            return b'Must exchange cipher suites first'

        cipher_suite = SESSIONS[session]['cipher_suite']

        cert = x509.load_pem_x509_certificate(request.args[b'certificate'][0])

        DH_key = self.get_DH_Key(session,int(request.args[b'DH_PARAMETER'][0].decode()),cipher_suite)
        CLIENT_PUBLIC_KEY = cert.public_key()

        #Verify Signature
        try:
            self.verify_signature(request.args[b'signature'][0], cipher_suite,CLIENT_PUBLIC_KEY, SESSIONS[session]['client_random'] + SESSIONS[session]['server_random'] + request.args[b'DH_PARAMETER'][0])
        except:
            request.setResponseCode(400)
            return b'Invalid signature'

        #Verify client certificate
        if not self.verify_client_certificate(cert):
            request.setResponseCode(400)
            return b'Invalid certificate'

        SESSIONS[session]['client'] = cert.subject
        self.get_session_keys(session,cipher_suite,DH_key)

        request.setResponseCode(200)
        return b''
        

    #------------------------------------------------------------------#


    #---------------------Handle a GET request-------------------------#
    #                                                                  #
    #              Function used to handle GET requests                #
    #------------------------------------------------------------------#
     
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            # Decrypt url path
            path = self.decrypt_comunication(request.getSession(), request.args[b'data'][0])

            if path == b'api/finished':

                #Client has generated session keys sucessfully
                SESSIONS[request.getSession()]['finished'] = True
                s = self.encrypt_comunication(b'finished',request.getSession() )

                return json.dumps({'data':s.decode("latin")}).encode('latin')

            elif path == b'api/list':
                return self.do_list(request)

            elif b'api/download' in path:

                url = 'http://127.0.0.1:8080/' + path.decode()
                args = dict(parse.parse_qsl(parse.urlsplit(url).query))

                return self.do_download(args,request)

            elif b'api/exit' == path:
                
                #Client exited, Session data deleted
                del SESSIONS[request.getSession()]
                
                return b''

            elif b'api/license' in path:
                url = 'http://127.0.0.1:8080/' + path.decode()

                args = dict(parse.parse_qsl(parse.urlsplit(url).query))

                return self.generate_license(args['id'],args['type'],request)
            
            request.setResponseCode(404)   
            request.responseHeaders.addRawHeader(b"content-type", b'text/plain')

            return b'Methods: /api/finished /api/license /api/exit /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")

            return b''
    
    #------------------------------------------------------------------#


    #---------------------Handle a POST request------------------------#
    #                                                                  #
    #             Function used to handle POST requests                #
    #------------------------------------------------------------------#

    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')
        request.setResponseCode(501)

        try:
            if request.path == b'/api/protocols':
                return self.do_post_protocols(request)

            elif request.path == b'/api/key':
                return self.do_key(request)

            else:
                session = request.getSession()
                data = self.decrypt_comunication(session, request.args[b'data'][0])

                data = json.loads(data.decode("latin"))

                path = data['url']

                if path == 'api/auth':
                    
                    #print(data['certificate'])
                    user_certificate = x509.load_der_x509_certificate(data['certificate'][0].encode("latin"))
                    uid = user_certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
                    #print(user_certificate)
                    try:
                        self.user_verify_signature(data['signature'].encode("latin"), user_certificate.public_key(), uid.encode())

                        if  self.check_user_cert_chain(data['certificate']):

                            SESSIONS[session]['user_id'] = uid
                            message = "user_ " + uid + "authenticated"

                            s = self.encrypt_comunication(message.encode("latin"), session)

                            request.setResponseCode(200)

                            return json.dumps({'data':s.decode("latin")}).encode('latin')
                        
                        else:
                            request.setResponseCode(400)  
                            s = self.encrypt_comunication(b'Failed to authenticate user. Invalid Certificate', session)

                            return json.dumps({'data':s.decode("latin")}).encode('latin')

                    except:
                        request.setResponseCode(400)  
                        s = self.encrypt_comunication(b'Failed to authenticate user. Invalid signature', session)

                        return json.dumps({'data':s.decode("latin")}).encode('latin')
                
                request.setResponseCode(404)  
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/key /api/auth'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

    #------------------------------------------------------------------#


    #------------------ check user certificate chain ------------------#
    #                                                                  #
    #   Function used to check the user certificate chain regarding    #
    #   the certificate attributes the certificates revogation lists   #
    #                  and the certificates signatures.                #
    #------------------------------------------------------------------#

    def check_user_cert_chain(self,cert_chain):

        if not self.validate_attributes(cert_chain):
            return False

        if not self.validate_crl(cert_chain):
            return False

        if not self.check_cert_signature(cert_chain): 
            return False 

        return True 

    #------------------------------------------------------------------#


    #---------------------- validate attributes -----------------------#
    #                                                                  #
    #    Function used to validate the user chain of certificates      #
    #             regarding the certificates atributes.                #
    #                                                                  #
    #                                                                  #
    #  CITIZEN AUTHENTICATION CERTIFICATE ATRIBUTES:                   #
    #  ORGANIZATION_NAME: Cartão de Cidadão                            #
    #  KEY_USAGE: digital_signature                                    #
    #                                                                  #
    #  AUTHENTICATION SUB CA:                                          #
    #  ORGANIZATION_NAME: Cartão de Cidadão                            #
    #  KEY_USAGE: key_cert_sign=True, crl_sign=True                    #
    #                                                                  #
    #  ROOT CA:                                                        #
    #  ORGANIZATION_NAME:                                              #
    #       SCEE - Sistema de Certificação Electrónica do Estado       #
    #  KEY_USAGE: key_cert_sign=True, crl_sign=True                    #
    #------------------------------------------------------------------#
    def validate_attributes(self,cert_chain):
        # CITIZEN AUTHENTICATION CERTIFICATE
        c = x509.load_der_x509_certificate(cert_chain[0].encode("latin"))
        key_usage = c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value

        if (not key_usage.digital_signature or key_usage.content_commitment or key_usage.key_encipherment 
            or key_usage.data_encipherment or not key_usage.key_agreement or key_usage.key_cert_sign  
            or key_usage.crl_sign or key_usage.encipher_only or key_usage.decipher_only):
            
            return False

        if not (c.not_valid_before < datetime.now() < c.not_valid_after):
            return False

        if not (c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == 'Cartão de Cidadão'):
            return False

        c = x509.load_der_x509_certificate(cert_chain[1].encode("latin"))
        key_usage = c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        
        if ( key_usage.digital_signature or key_usage.content_commitment or key_usage.key_encipherment 
            or key_usage.data_encipherment or key_usage.key_agreement or not key_usage.key_cert_sign  
            or not  key_usage.crl_sign):
            return False
        
        if not (c.not_valid_before< datetime.now()< c.not_valid_after):
            return False

        if not (c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == 'Cartão de Cidadão' 
        or c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == 'Instituto dos Registos e do Notariado I.P.'):
            return False
        
        c = x509.load_der_x509_certificate(cert_chain[2].encode("latin"))
        key_usage = c.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value

        if (key_usage.digital_signature or key_usage.content_commitment or key_usage.key_encipherment 
            or key_usage.data_encipherment or key_usage.key_agreement or not key_usage.key_cert_sign  
            or not  key_usage.crl_sign ):
            return False

        if not (c.not_valid_before < datetime.now() < c.not_valid_after):
            return False
        if not (c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == 'SCEE - Sistema de Certificação Electrónica do Estado'):
            return False
        
        return True

    #------------------------------------------------------------------#


    #----------------- check certification signature ------------------#
    #                                                                  #
    #    Function used to validate a certificate chain regarding the   #
    #                   certificates signatures.                       #
    #   For each certificate, uses the issuer public key in order to   #
    #                       verify its signature                       #
    #------------------------------------------------------------------#

    def check_cert_signature(self,cert_chain):
        for cert in range(len(cert_chain) - 1):

            c = x509.load_der_x509_certificate(cert_chain[cert].encode("latin"))
            ci = x509.load_der_x509_certificate(cert_chain[cert + 1].encode("latin"))

            issuer_public_key = ci.public_key()

            try:
                issuer_public_key.verify(
                    c.signature,
                    c.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    c.signature_hash_algorithm,
                )
            except: return False

        return True

    #------------------------------------------------------------------#


    #------------------------- validate crl ---------------------------#
    #                                                                  #
    #    Function used to validate a certificate chain regarding the   #
    #                    certificate revoked lists.                    #
    # For each certificate fetches the respective crl and sees if the  #    
    #            certificate serial number is in there.                #
    #------------------------------------------------------------------#

    def validate_crl(self,cert_chain):
        for cert in range(len(cert_chain) - 1):
            c = x509.load_der_x509_certificate(cert_chain[cert].encode("latin"))

            r = requests.get(c.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value[0].full_name[0].value, allow_redirects = True)

            crl = x509.load_der_x509_crl(r.content)

            if not crl.get_revoked_certificate_by_serial_number(c.serial_number) is  None:
                return False

            try:
                r = requests.get(c.extensions.get_extension_for_oid(ExtensionOID.FRESHEST_CRL).value[0].full_name[0].value, allow_redirects = True)
                crl = x509.load_der_x509_crl(r.content)

                if not crl.get_revoked_certificate_by_serial_number(c.serial_number) is None:
                    return False
            except:
                logger.warning("no crl delta")

        return True

    #------------------------------------------------------------------#


    #-------------------Validate Client Certificate--------------------#
    #                                                                  #
    #          Function used to validate a client Cartificate.         #
    #     It first checks the certificate atributes such as date of    #
    #   expiration, common name, and key usage. Then using the ROOT_CA #
    #    public key verifies if the certificate signature is valid.    #
    #------------------------------------------------------------------#

    def verify_client_certificate(self,cert):
        # Validate certificate atributes
        if not (cert.not_valid_before < datetime.now() < cert.not_valid_after):
            return False
        if not (cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'Media Certification Authority'):
            return False

        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if not key_usage.digital_signature or not key_usage.key_encipherment  or not key_usage.key_agreement or key_usage.key_cert_sign or key_usage.crl_sign: 
            return False  

        #Check root CA signature
        try:
            ROOT_CA.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except: 
            return False

        return True

    #------------------------------------------------------------------#


    #--------------------- generate DH parameter ----------------------#
    #                                                                  #
    #           Function used to generate DH parameters.               #
    #      The function generates the p, and g values and then Y       #
    # This values are stored in the respective session in the SESSIONS #
    #                           dictionary.                            #
    #------------------------------------------------------------------#
    
    def generate_DH_parameter(self, session):
        
        parameters = dh.generate_parameters(generator = 2, key_size = 2048)

        # generate server's private and public keys
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        # get y, p and g parameters
        y = public_key.public_numbers().y
        p = parameters.parameter_numbers().p
        g = parameters.parameter_numbers().g

        SESSIONS[session]['parameters'] = dh.DHParameterNumbers(p, g)
        SESSIONS[session]['DH_private_key'] = private_key

        return y, p, g

    #------------------------------------------------------------------#


    #--------------------- encrypt comunication -----------------------#
    #                                                                  #
    #         Function to encrypt data using a block cipher.           #
    #      Used to encrypt the responses to send to the client.        #
    #     The function returns the IV used in the encryption, the      #
    #       encrypted data and an MAC of the IV + encrypted data.      #
    #------------------------------------------------------------------#

    def encrypt_comunication(self, data, session, key = None):
        if not key:
            server_write_key = SESSIONS[session]['server_write_key']

        else:
            server_write_key = key

        cipher_suite = SESSIONS[session]['cipher_suite']
        
        server_write_MAC_key = SESSIONS[session]['server_write_MAC_key']

        iv = os.urandom(16)

        if "AES256" in cipher_suite or "AES128" in cipher_suite:
            if "CBC" in cipher_suite:
                cipher = Cipher(
                    algorithms.AES(server_write_key),
                    modes.CBC(iv)
                )
            
                encryptor = cipher.encryptor()

                encrypted_data = encryptor.update(self.padding_data(data, 128)) + encryptor.finalize()

            elif "CFB" in cipher_suite:
                cipher = Cipher(
                    algorithms.AES(server_write_key),
                    modes.CFB(iv)
                )
            
                encryptor = cipher.encryptor()

                encrypted_data = encryptor.update(data) + encryptor.finalize()

        elif "ChaCha20" in cipher_suite:
            cipher = Cipher(
                algorithms.ChaCha20(server_write_key, iv),
                mode = None
            )

            encryptor = cipher.encryptor()

            encrypted_data = encryptor.update(data) + encryptor.finalize()

        return iv + self.generate_hmac(server_write_MAC_key, cipher_suite, iv + encrypted_data) + encrypted_data

    #------------------------------------------------------------------#


    #--------------------- decrypt comunication -----------------------#
    #                                                                  #
    #               Function to decrypt and validate data.             #
    #        Used to decrypt the requests sent by the client.          #
    #     The function divides the data in IV, MAC, and encrypted      #
    # data. It then checks generates a MAC with the IV and encrypted   #
    # data and see if they are equal in the affirmative case decrypts  #
    #                           the data.                              #
    #------------------------------------------------------------------#

    def decrypt_comunication(self, session, data):
        cipher_suite = SESSIONS[session]['cipher_suite']
        client_write_key = SESSIONS[session]['client_write_key']
        client_write_MAC_key = SESSIONS[session]['client_write_MAC_key']

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

        if hmac == self.generate_hmac(client_write_MAC_key, cipher_suite, h_data):

            m_data = self.decrypt_symetric(client_write_key,iv,cipher_suite,m_data)

            if "CBC" in cipher_suite:
                return self.unpadding_data(m_data,128)

            return m_data

        else: return 0

    #------------------------------------------------------------------#


    #------------------------- padding data ---------------------------#
    #                                                                  #
    #      Function to pad data given a number of padding bits.        #
    #------------------------------------------------------------------#

    def padding_data(self, data, bits):
        padder = real_padding.PKCS7(bits).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        return padded_data

    #------------------------------------------------------------------#


    #------------------------ unpadding data --------------------------#
    #                                                                  #
    #     Function to unpad data given a number of padding bits.       #
    #------------------------------------------------------------------#

    def unpadding_data(self, data, nbits):
        unpadder = real_padding.PKCS7(nbits).unpadder()
        unpadded_data = unpadder.update(data)
        unpadded_data += unpadder.finalize()

        return unpadded_data

    #------------------------------------------------------------------#


    #--------------------- symetric decryption ------------------------#
    #                                                                  #
    #       Function used to decrypt data using a block cipher.        #
    #------------------------------------------------------------------#

    def decrypt_symetric(self, key, iv, cipher_suite, data):
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


    #------------------- generate hmac from data ----------------------#
    #                                                                  #
    #         Function used to generate a MAC on a given data          #
    #------------------------------------------------------------------#

    def generate_hmac(self, key, cipher_suite, data):
        if "SHA256" in cipher_suite:
            h = hmac.HMAC(key, hashes.SHA256())
            h.update(data)
        
        elif "SHA384" in cipher_suite:
            h = hmac.HMAC(key, hashes.SHA384())
            h.update(data)

        return h.finalize()

    #------------------------------------------------------------------#


    #-------------------------- hash data -----------------------------#
    #                                                                  #
    #                Function to hash a given data                     #
    #------------------------------------------------------------------#

    def hash(self, cipher_suite, data):
        if "SHA256" in cipher_suite:
            digest = hashes.Hash(hashes.SHA256())
        
        elif "SHA384" in cipher_suite:
            digest = hashes.Hash(hashes.SHA384())

        digest.update(data)

        return digest.finalize()

    #------------------------------------------------------------------#


    #----------------------- make signature ---------------------------#
    #                                                                  #
    #              Function used  to sign a given data.                #
    #           By default the key is the servers private key          #
    #------------------------------------------------------------------#
    
    def make_signature(self, cipher_suite, data, key = SERVER_PRIVATE_KEY):
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


    #-------------------- verify user signature -----------------------#
    #                                                                  #
    #        Function used to verify a signature made by the user      #
    #                   CITIZEN AUTHENTICATION KEY.                    #
    #------------------------------------------------------------------#

    def user_verify_signature(self, signature, pub_key, data):
        pub_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA1()
        )

    #------------------------------------------------------------------#


    #----------------------- verify signature -------------------------#
    #                                                                  #
    #       Function to verify a signature made on a given data.       #
    #             The public key is passed as argument.                #
    #------------------------------------------------------------------#

    def verify_signature(self, signature, cipher_suite, pub_key, data):
        if "SHA384" in cipher_suite:
            hash_type = hashes.SHA384()
            hash_type2 = hashes.SHA384()

        elif "SHA256" in cipher_suite:
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

    #------------------------------------------------------------------#


    #-------------------------- get DH key ----------------------------#
    #                                                                  #
    #   Function used to do the DH key exchange in order to get a key. #
    #       It receives as argument the exchanged parameter            #
    #------------------------------------------------------------------#

    def get_DH_Key(self, session, y, cipher_suite):
        peer_public_numbers = dh.DHPublicNumbers(y, SESSIONS[session]['parameters'])
        peer_public_key = peer_public_numbers.public_key()

        shared_key = SESSIONS[session]['DH_private_key'].exchange(peer_public_key)

        return shared_key

    #------------------------------------------------------------------#


    #----------------------- Get Session Keys -------------------------#
    #                                                                  #
    #           Function to generate the 4 session keys.               #
    # Using a Hash Key Derivation Function to extend the key produced  #
    #     in the DH key exchange, the salt is the client and server    #
    #                   randoms previously exchanged.                  #
    #  The keys are stored in the respective session in the SESSIONS   #
    #                           dictionary.                            #
    #------------------------------------------------------------------#

    def get_session_keys(self, session, cipher_suite, dh_key):
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
            salt = SESSIONS[session]['client_random'] + SESSIONS[session]['server_random'],
            info = None
        )
        key = hkdf.derive(dh_key)

        # divide the key into 4 different keys
        SESSIONS[session]['client_write_MAC_key'] = key[:size]
        SESSIONS[session]['server_write_MAC_key'] = key[size:size * 2]
        SESSIONS[session]['client_write_key'] = key[size * 2:size * 2 + (cipher_size // 2)]
        SESSIONS[session]['server_write_key'] = key[size * 2 + (cipher_size // 2):size * 2 + cipher_size]

    #------------------------------------------------------------------#


    #-------------------Decrypt music chunk data-----------------------#
    #                                                                  #
    #         Function used to decrypt a music chunk data              #
    #   The paddig_falg is True when the chunk is the last one and     #
    #                    therfore needs padding.                       #
    #------------------------------------------------------------------#

    def decrypt_data(self, data, padding_flag):
        hkdf = HKDF(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = FILE_DECRYPTION_SALT,
            info = None
        )
        key = hkdf.derive(FILE_DECRYPTION_KEY)

        cipher = Cipher(
                algorithms.AES(key),
                modes.ECB()
            )
    
        decryptor = cipher.decryptor()

        data = decryptor.update(data) + decryptor.finalize()

        if padding_flag:
            data = self.unpadding_data(data, 128)
        
        return data

print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()