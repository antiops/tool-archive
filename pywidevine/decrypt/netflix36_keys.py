# -*- coding: utf-8 -*-
# Module: Netflix Downloader
# Created on: 03-01-2018
# Authors: anons
# Version: 3.6

#'''
if __name__ == 'pywidevine.decrypt.netflix36_keys':
	import binascii
	import configparser
	import argparse
	import base64
	import glob
	import gzip
	import json
	import logging
	import os
	import pprint
	import pycountry
	import random
	import string
	import re
	import requests
	import sys
	import time
	import xml.etree.ElementTree as ET
	import zlib
	from Cryptodome.Cipher import AES
	from Cryptodome.Cipher import PKCS1_OAEP
	from Cryptodome.Hash import HMAC, SHA256
	from Cryptodome.PublicKey import RSA
	from Cryptodome.Random import get_random_bytes
	from Cryptodome.Util import Padding
	from io import StringIO
	from datetime import datetime
	from subprocess import call
	import subprocess
	import ffmpy
	from io import BytesIO
	import subprocess as sp

	from pywidevine.clientsconfig.netflix import NetflixConfig
	from pywidevine.decrypt.wvdecryptcustom import WvDecrypt

	from pywidevine.cdm import cdm, deviceconfig


	global args
	from netflix36 import args
	
	global esn_keys
	global esn_manifest
	global MANIFEST_ENDPOINT
	global LICENSE_ENDPOINT
	global account_info

	def generate_esn(prefix):
		"""
		generate_esn()
		@param prefix: Prefix of ESN to append generated device ID onto
		@return: ESN to use with MSL API
		"""

		return prefix + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(30))

	username, password, esn_keys, esn_manifest, MANIFEST_ENDPOINT, LICENSE_ENDPOINT, device_name = NetflixConfig.configNetflix()
	
	#esn_keys = generate_esn(esn_keys)
	#esn_manifest = generate_esn(esn_manifest)

	esn_manifest = esn_keys
	
	account_info = {
		"email": username,
		"password": password
	}

	global msl_data_path
	from netflix36 import msl_data_path

	def base64key_decode(payload):
		l = len(payload) % 4
		if l == 2:
			payload += '=='
		elif l == 3:
			payload += '='
		elif l != 0:
			raise ValueError('Invalid base64 string')
		return base64.urlsafe_b64decode(payload.encode('utf-8'))


	class MSL:
		handshake_performed = False  # Is a handshake already performed and the keys loaded
		last_drm_context = ''
		last_playback_context = ''
		current_message_id = 0
		session = requests.session()
		rndm = random.SystemRandom()
		tokens = []
		global current_sessionId
		current_sessionId = str(time.time()).replace('.', '')[0:-2]
		endpoints = {
			'manifest': MANIFEST_ENDPOINT,
			'license': LICENSE_ENDPOINT
		}

		# def __init__(self, kodi_helper):
		def __init__(self, test):
			"""
			#The Constructor checks for already existing crypto Keys.
			#If they exist it will load the existing keys
			"""
			# self.kodi_helper = kodi_helper

			self.logger = logging.getLogger(__name__)
			self.logger.debug("creating NetflixClient object")
			global wv_keyexchange
			if 'NFANDROID' in esn_manifest:
				wv_keyexchange = True
			else:
				wv_keyexchange = False

			global device
			device = getattr(deviceconfig, device_name)

			self.session = requests.Session()
			#self.change_user_agent(self.session)
			self.current_message_id = 0
			self.rsa_key = None
			self.encryption_key = None
			self.sign_key = None
			self.sequence_number = None
			self.mastertoken = None
			self.useridtoken = None
			self.playbackContextId = None
			self.drmContextId = None
			self.tokens = []
			self.rndm = random.SystemRandom()
			#self.cookies = self.cookie_login()

			# for operator sessions:
			if wv_keyexchange:
				self.wv_keyexchange = True
				self.cdm = cdm.Cdm()
				self.cdm_session = None
			else:
				self.wv_keyexchange = False
				self.cdm = None
				self.cdm_session = None

			try:
				os.mkdir(msl_data_path)
			except OSError:
				pass

			if self.file_exists(msl_data_path, msl_data_file):
				self.logger.info("old MSL data found, using")
				self.__load_msl_data()
			else:
				# could add support for other key exchanges here
				if not self.wv_keyexchange:
					if self.file_exists(msl_data_path, rsa_key_bin):
						self.logger.info('old RSA key found, using')
						self.__load_rsa_keys()
					else:
						self.logger.info('create new RSA Keys')
						# Create new Key Pair and save
						self.rsa_key = RSA.generate(2048)
						self.__save_rsa_keys()
				# both RSA and wv key exchanges can be performed now
				self.__perform_key_handshake()

			if not self.encryption_key:
				print("failed to perform key handshake")
				#return False



		def load_manifest(self, viewable_id, profiles):
			"""
			#Loads the manifets for the given viewable_id and returns a mpd-XML-Manifest
			#:param viewable_id: The id of of the viewable
			#:return: MPD XML Manifest or False if no success
			"""
			manifest_request_data = {
				'method': 'manifest',
				'lookupType': 'PREPARE',
				'viewableIds': [viewable_id],
				'profiles': profiles,
				'drmSystem': 'widevine',
				'appId': current_sessionId,
				'sessionParams': {
					'pinCapableClient': False,
					'uiplaycontext': 'null'
				},
				'sessionId': current_sessionId,
				'trackId': 0,
				'flavor': 'PRE_FETCH',
				'secureUrls': True,
				'supportPreviewContent': True,
				'forceClearStreams': False,
				'languages': ['en-US'],
				'clientVersion': '4.0004.899.011',
				'uiVersion': 'akira'
			}
			

			request_data = self.__generate_msl_request_data(manifest_request_data)
			while True:
				resp = self.session.post(self.endpoints['manifest'], request_data)
				if resp.ok:
					break
			#self.logger.debug(f'License manifest response: {resp.text}')
			data = {}

			resp = self.__parse_chunked_msl_response(resp.text)
			data = self.__decrypt_payload_chunk(resp['payloads'])
			return self.__tranform_to_dash(data)

		def get_license(self, challenge):
			challenge_encoded = base64.b64encode(challenge).decode('utf-8')
			self.logger.info("doing license request")
			self.logger.debug("challenge - {}".format(base64.b64encode(challenge)))
			license_request_data = {
				'method': 'license',
				'licenseType': 'STANDARD',
				'clientVersion': '4.0004.899.011',
				'uiVersion': 'akira',
				'languages': ['en-US'],
				'playbackContextId': playbackContextId,
				'drmContextIds': [last_drm_context],
				'challenges': [{
					'dataBase64': challenge_encoded,
					'sessionId': current_sessionId
				}],
				'clientTime': int(time.time()),
				'xid': int((int(time.time()) + 0.1612) * 1000)

			}

			request_data = self.__generate_msl_request_data(license_request_data)
			resp = self.session.post(self.endpoints['license'], request_data)

			try:
				# If is valid json the request for the license failed
				resp.json()
				print('Error getting license: ' + resp.text)
				exit(1)
			except ValueError:
				# json() failed so we have a chunked json response
				resp = self.__parse_chunked_msl_response(resp.text)
				data = self.__decrypt_payload_chunk(resp['payloads'])
				if data['success'] is True:
					return data['result']['licenses'][0]['data']
				else:
					print('Error getting license: ' + json.dumps(data))
					exit(1)


		def __decrypt_payload_chunk(self, payloadchunks):
			decrypted_payload = ''
			for chunk in payloadchunks:
				payloadchunk = json.JSONDecoder().decode(chunk)
				payload = payloadchunk.get('payload')
				decoded_payload = base64.standard_b64decode(payload)
				encryption_envelope = json.JSONDecoder().decode(decoded_payload.decode('utf-8'))
				# Decrypt the text
				cipher = AES.new(self.encryption_key, AES.MODE_CBC, base64.standard_b64decode(encryption_envelope['iv']))
				ciphertext = encryption_envelope.get('ciphertext')
				plaintext = cipher.decrypt(base64.standard_b64decode(ciphertext))
				# unpad the plaintext
				plaintext = json.JSONDecoder().decode(Padding.unpad(plaintext, 16).decode('utf-8'))
				data = plaintext.get('data')

				# uncompress data if compressed
				if plaintext.get('compressionalgo') == 'GZIP':
					decoded_data = base64.standard_b64decode(data)
					data = zlib.decompress(decoded_data, 16 + zlib.MAX_WBITS)
				else:
					data = base64.standard_b64decode(data)
				decrypted_payload += data.decode('utf-8')

			decrypted_payload = json.JSONDecoder().decode(decrypted_payload)[1]['payload']['data']
			decrypted_payload = base64.standard_b64decode(decrypted_payload)
			return json.JSONDecoder().decode(decrypted_payload.decode('utf-8'))


		def __tranform_to_dash(self, manifest):
			#print (manifest)
			#manifest = str(manifest)
			self.save_file_(msl_data_path, manifest_file, json.dumps(manifest))
			#json.dump(manifest, open(msl_data_path + 'manifest.json','wb'))
			#with open(msl_data_path + 'manifest.json', 'wb') as file_:
				#file_.write(json.dumps(manifest))
				#file_.flush()
				#file_.close()
			try:
				manifest = manifest['result']['viewables'][0]
			except Exception:
				pass
				#print("Your account has possibly exceeded the maximum number of connections.")
				#sys.exit(0)
			# manifest = json.dumps(manifest, sort_keys=True, indent=4)
			global playbackContextId
			global last_drm_context
			playbackContextId = manifest['playbackContextId']
			last_drm_context = manifest['drmContextId']
			self.last_playback_context = manifest['playbackContextId']
			self.last_drm_context = manifest['drmContextId']

			# Check for pssh
			global init_data_b64_new
			global cert_data_b64_new
			pssh = ''
			if 'psshb64' in manifest:
				if len(manifest['psshb64']) >= 1:
					pssh = manifest['psshb64']
					cert = manifest['cert']
					init_data_b64_new = pssh
					cert_data_b64_new = cert

			return manifest


		def __get_base_url(self, urls):
			for key in urls:
				return urls[key]

		def __parse_chunked_msl_response(self, message):
			header = message.split('}}')[0] + '}}'
			payloads = re.split(',\"signature\":\"[0-9A-Za-z=/+]+\"}', message.split('}}')[1])
			payloads = [x + '}' for x in payloads][:-1]

			return {
				'header': header,
				'payloads': payloads
			}

		def __generate_msl_request_data(self, data):
			header_encryption_envelope = self.__encrypt(self.__generate_msl_header())
			header = {
				'headerdata': base64.standard_b64encode(header_encryption_envelope.encode('utf-8')).decode('utf-8'),
				'signature': self.__sign(header_encryption_envelope).decode('utf-8'),
				'mastertoken': self.mastertoken,
			}
			# Serialize the given Data
			serialized_data = json.dumps(data)
			serialized_data = serialized_data.replace('"', '\\"')
			serialized_data = '[{},{"headers":{},"path":"/cbp/cadmium-29","payload":{"data":"' + serialized_data + '"},"query":""}]\n'
			compressed_data = self.__compress_data(serialized_data)

			# Create FIRST Payload Chunks
			first_payload = {
				"messageid": self.current_message_id,
				"data": compressed_data.decode('utf-8'),
				"compressionalgo": "GZIP",
				"sequencenumber": 1,
				"endofmsg": True
			}
			first_payload_encryption_envelope = self.__encrypt(json.dumps(first_payload))
			first_payload_chunk = {
				'payload': base64.standard_b64encode(first_payload_encryption_envelope.encode('utf-8')).decode('utf-8'),
				'signature': self.__sign(first_payload_encryption_envelope).decode('utf-8'),
			}
			request_data = json.dumps(header) + json.dumps(first_payload_chunk)
			return request_data

		def __compress_data(self, data):
			# GZIP THE DATA
			out = BytesIO()
			with gzip.GzipFile(fileobj=out, mode="w") as f:
				f.write(data.encode('utf-8'))
			return base64.standard_b64encode(out.getvalue())


		def __generate_msl_header(self, is_handshake=False, is_key_request=False, compressionalgo="GZIP", encrypt=True):
			"""
			Function that generates a MSL header dict
			:return: The base64 encoded JSON String of the header
			"""
			global account_info
			self.current_message_id = self.rndm.randint(0, pow(2, 52))

			header_data = {
				'sender': esn_manifest,
				'handshake': is_handshake,
				'nonreplayable': False,
				'capabilities': {
					'languages': ["en-US"],
					'compressionalgos': [],
					'encoderformats' : ['JSON'],
				},
				'recipient': 'Netflix',
				'renewable': True,
				'messageid': self.current_message_id,
				'timestamp': int(time.time())
			}

			# Add compression algo if not empty
			if compressionalgo is not "":
				header_data['capabilities']['compressionalgos'].append(compressionalgo)

			# If this is a keyrequest act diffrent then other requests
			if is_key_request:
				if not self.wv_keyexchange:
					public_key = base64.standard_b64encode(self.rsa_key.publickey().exportKey(format='DER')).decode('utf-8')
					header_data['keyrequestdata'] = [{
						'scheme': 'ASYMMETRIC_WRAPPED',
						'keydata': {
							'publickey': public_key,
							'mechanism': 'JWK_RSA',
							'keypairid': 'superKeyPair'
						}
					}]
				else:
					self.cdm_session = self.cdm.open_session(None, deviceconfig.DeviceConfig(device), b'\x0A\x7A\x00\x6C\x38\x2B', True) # persist
					# should a client cert be set? most likely nonreplayable
					wv_request = base64.b64encode(self.cdm.get_license_request(self.cdm_session)).decode("utf-8")

					header_data['keyrequestdata'] = [{
						'scheme': 'WIDEVINE',
						'keydata': {'keyrequest': wv_request}
					}]

			else:
				if 'usertoken' in self.tokens:
					pass
				else:
					# Auth via email and password
					header_data['userauthdata'] = {
						'scheme': 'EMAIL_PASSWORD',
						'authdata': {
							'email': account_info['email'],
							'password': account_info['password']
						}
					}
			return json.dumps(header_data)


		def __encrypt(self, plaintext):
			"""
			Encrypt the given Plaintext with the encryption key
			:param plaintext:
			:return: Serialized JSON String of the encryption Envelope
			"""
			iv = get_random_bytes(16)
			encryption_envelope = {
				'ciphertext': '',
				'keyid': esn_manifest + '_' + str(self.sequence_number),
				'sha256': 'AA==',
				'iv': base64.standard_b64encode(iv).decode('utf-8')
			}
			# Padd the plaintext
			plaintext = Padding.pad(plaintext.encode('utf-8'), 16)
			# Encrypt the text
			cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
			ciphertext = cipher.encrypt(plaintext)
			encryption_envelope['ciphertext'] = base64.standard_b64encode(ciphertext).decode('utf-8')
			return json.dumps(encryption_envelope)

		def __sign(self, text):
			"""
			Calculates the HMAC signature for the given text with the current sign key and SHA256
			:param text:
			:return: Base64 encoded signature
			"""
			signature = HMAC.new(self.sign_key, text.encode('utf-8'), SHA256).digest()
			return base64.standard_b64encode(signature)

		def __perform_key_handshake(self):
			header = self.__generate_msl_header(is_key_request=True, is_handshake=True, compressionalgo="", encrypt=False)
			request = {
				'entityauthdata': {
					'scheme': 'NONE',
					'authdata': {
						'identity': esn_manifest
					}
				},
				'headerdata': base64.standard_b64encode(header.encode('utf-8')).decode('utf-8'),
				'signature': '',
			}
			self.logger.debug('Key Handshake Request:')
			self.logger.debug(json.dumps(request))

			resp = self.session.post(self.endpoints['manifest'], json.dumps(request, sort_keys=True))
			if resp.status_code == 200:
				resp = resp.json()
				if 'errordata' in resp:
					self.logger.debug('Key Exchange failed')
					self.logger.debug(base64.standard_b64decode(resp['errordata']))
					return False
				self.logger.debug(resp)
				self.logger.debug('Key Exchange Sucessful')
				self.__parse_crypto_keys(json.JSONDecoder().decode(base64.standard_b64decode(resp['headerdata']).decode('utf-8')))
			else:
				print('Key Exchange failed')
				self.logger.debug('Key Exchange failed')
				self.logger.debug(resp.text)


		def __parse_crypto_keys(self, headerdata):
			keyresponsedata = headerdata['keyresponsedata']
			self.__set_master_token(keyresponsedata['mastertoken'])
			self.logger.debug("response headerdata: %s" % headerdata)
			#self.__set_userid_token(headerdata['useridtoken'])
			if self.wv_keyexchange:
				expected_scheme = 'WIDEVINE'
			else:
				expected_scheme = 'ASYMMETRIC_WRAPPED'

			scheme = keyresponsedata['scheme']

			if scheme != expected_scheme:
				self.logger.debug('Key Exchange failed:')
				self.logger.debug('Unexpected scheme in response, expected %s, got %s' % (expected_scheme, scheme))
				return False

			keydata = keyresponsedata['keydata']

			if self.wv_keyexchange:
				self.__process_wv_keydata(keydata)
			else:
				self.__parse_rsa_wrapped_crypto_keys(keydata)

			self.__save_msl_data()
			self.handshake_performed = True

		def __process_wv_keydata(self, keydata):
			wv_response_b64 = keydata['cdmkeyresponse'] # pass as b64
			encryptionkeyid = base64.standard_b64decode(keydata['encryptionkeyid'])
			hmackeyid = base64.standard_b64decode(keydata['hmackeyid'])
			self.cdm.provide_license(self.cdm_session, wv_response_b64)
			keys = self.cdm.get_keys(self.cdm_session)
			self.logger.info('wv key exchange: obtained wv key exchange keys %s' % keys)
			# might be better not to hardcode wv proto field names
			self.encryption_key = self.__find_wv_key(encryptionkeyid, keys, ["AllowEncrypt", "AllowDecrypt"])
			self.sign_key = self.__find_wv_key(hmackeyid, keys, ["AllowSign", "AllowSignatureVerify"])

		# will fail if wrong permission or type
		def __find_wv_key(self, kid, keys, permissions):
			for key in keys:
				if key.kid != kid:
					continue
				if key.type != "OPERATOR_SESSION":
					self.logger.debug("wv key exchange: Wrong key type (not operator session) key %s" % key)
					continue

				if not set(permissions) <= set(key.permissions):
					self.logger.debug("wv key exchange: Incorrect permissions, key %s, needed perms %s" % (key, permissions))
					continue
				return key.key

			return None

		def __parse_rsa_wrapped_crypto_keys(self, keydata):
			# Init Decryption
			encrypted_encryption_key = base64.standard_b64decode(keydata['encryptionkey'])
			encrypted_sign_key = base64.standard_b64decode(keydata['hmackey'])
			cipher_rsa = PKCS1_OAEP.new(self.rsa_key)

			# Decrypt encryption key
			encryption_key_data = json.JSONDecoder().decode(cipher_rsa.decrypt(encrypted_encryption_key).decode('utf-8'))
			self.encryption_key = base64key_decode(encryption_key_data['k'])

			# Decrypt sign key
			sign_key_data = json.JSONDecoder().decode(cipher_rsa.decrypt(encrypted_sign_key).decode('utf-8'))
			self.sign_key = base64key_decode(sign_key_data['k'])

		def __load_msl_data(self):
			msl_data = json.JSONDecoder().decode(
				self.load_file(msl_data_path, msl_data_file).decode('utf-8'))
			# Check expire date of the token
			master_token = json.JSONDecoder().decode(
				base64.standard_b64decode(msl_data['tokens']['mastertoken']['tokendata']).decode('utf-8'))
			valid_until = datetime.utcfromtimestamp(int(master_token['expiration']))
			present = datetime.now()
			difference = valid_until - present
			difference = difference.total_seconds() / 60 / 60
			# If token expires in less then 10 hours or is expires renew it
			if difference < 10:
				self.__load_rsa_keys()
				self.__perform_key_handshake()
				return

			self.__set_master_token(msl_data['tokens']['mastertoken'])
			#self.__set_userid_token(msl_data['tokens']['useridtoken'])
			self.encryption_key = base64.standard_b64decode(msl_data['encryption_key'])
			self.sign_key = base64.standard_b64decode(msl_data['sign_key'])

		def __save_msl_data(self):
			"""
			Saves the keys and tokens in json file
			:return:
			"""
			data = {
				"encryption_key": base64.standard_b64encode(self.encryption_key).decode('utf-8'),
				'sign_key': base64.standard_b64encode(self.sign_key).decode('utf-8'),
				'tokens': {
					'mastertoken': self.mastertoken,
					#'useridtoken': self.useridtoken,
				}
			}
			serialized_data = json.JSONEncoder().encode(data)
			self.save_file(msl_data_path, msl_data_file, serialized_data.encode('utf-8'))

		def __set_master_token(self, master_token):
			self.mastertoken = master_token
			self.sequence_number = json.JSONDecoder().decode(base64.standard_b64decode(master_token['tokendata']).decode('utf-8'))['sequencenumber']

		def __set_userid_token(self, userid_token):
			self.useridtoken = userid_token

		def __load_rsa_keys(self):
			loaded_key = self.load_file(msl_data_path, rsa_key_bin)
			self.rsa_key = RSA.importKey(loaded_key)

		def __save_rsa_keys(self):
			self.logger.debug('Save RSA Keys')
			# Get the DER Base64 of the keys
			encrypted_key = self.rsa_key.exportKey()
			self.save_file(msl_data_path, rsa_key_bin, encrypted_key)

		@staticmethod
		def file_exists(msl_data_path, filename):
			"""
			Checks if a given file exists
			:param filename: The filename
			:return: True if so
			"""
			return os.path.isfile(os.path.join(msl_data_path, filename))

		@staticmethod
		def save_file(msl_data_path, filename, content):
			"""
			Saves the given content under given filename
			:param filename: The filename
			:param content: The content of the file
			"""
			with open(os.path.join(msl_data_path,filename), 'wb') as file_:
				file_.write(content)
				file_.flush()
				file_.close()

		@staticmethod
		def load_file(msl_data_path, filename):
			"""
			Loads the content of a given filename
			:param filename: The file to load
			:return: The content of the file
			"""
			with open(os.path.join(msl_data_path,filename), 'rb') as file_:
				file_content = file_.read()
				file_.close()
			return file_content

		@staticmethod
		def save_file_(msl_data_path, filename, content):
			"""
			#Saves the given content under given filename
			#:param filename: The filename
			#:param content: The content of the file
			"""
			#print (str(content.decode('utf-8')))
			with open(msl_data_path + filename, 'w') as file_:
				file_.write(content)
				file_.flush()
				file_.close()

		@staticmethod
		def load_file(msl_data_path, filename):
			"""
			#Loads the content of a given filename
			#:param filename: The file to load
			#:return: The content of the file
			"""
			with open(msl_data_path + filename, 'rb') as file_:
				file_content = file_.read()
				file_.close()
			return file_content


		def do_decrypt(pssh, cert, device):
			wvdecrypt = WvDecrypt(init_data_b64=pssh, cert_data_b64=cert, device=device)
			chal = wvdecrypt.get_challenge()
			msl = MSL("")
			license_b64 = msl.get_license(chal)
			wvdecrypt.update_license(license_b64)
			Correct, keyswvdecrypt = wvdecrypt.start_process()
			return Correct, keyswvdecrypt

		def GettingKEYS(pssh, cert, device):
			#print("\nGetting KEY...")
			Correct = False
			keys_new=[]
			while Correct == False:
				Correct, keys_new = MSL.do_decrypt(pssh=pssh, cert=cert, device=device)
			#print("Done!")
			return keys_new



	def GettingKEYS_Netflix(nfID, profiles, profilename):
		global rsa_key_bin
		global msl_data_file
		global manifest_file
		#global profiles
		
		rsa_key_bin = 'rsa_keys.bin'
		msl_data_file = 'msl_data_keys.json'
		manifest_file = 'manifest_keys.json'

		if os.path.isfile(msl_data_path + rsa_key_bin): os.remove(msl_data_path + rsa_key_bin)
		if os.path.isfile(msl_data_path + msl_data_file): os.remove(msl_data_path + msl_data_file)
		if os.path.isfile(msl_data_path + manifest_file): os.remove(msl_data_path + manifest_file)
		if not 'High Profile-test' in profilename:
			print("\nGetting "+profilename+" Keys...")
		manifest = str(MSL.load_manifest(MSL(int(nfID)), int(nfID), profiles))
		
		KEYS = []

		if profilename == 'Main Profile':
			if not 'playready-h264mpl' in manifest and 'playready-h264bpl' not in manifest:
				return KEYS
		elif profilename == 'High Profile':
			if not 'playready-h264hpl' in manifest:
				return KEYS
		elif profilename == 'High Profile-test':
			if not 'playready-h264hpl' in manifest:
				return KEYS
		elif profilename == 'VP9 Profile':
			if not 'vp9-profile' in manifest:
				return KEYS
		elif profilename == 'HEVC and HDR-10':
			if not 'hevc-main10-L' in manifest:
				return KEYS
		elif profilename == 'HDR-DV':
			if not 'hevc-dv5-' in manifest and 'hevc-dv-' not in manifest:
				return KEYS

		for x in init_data_b64_new:
			new_keys = MSL.GettingKEYS(x, cert_data_b64_new, device)
			for k in new_keys:
				if k not in KEYS:
					KEYS.append(k)

		if os.path.isfile(msl_data_path + rsa_key_bin): os.remove(msl_data_path + rsa_key_bin)
		if os.path.isfile(msl_data_path + msl_data_file): os.remove(msl_data_path + msl_data_file)
		if os.path.isfile(msl_data_path + manifest_file): os.remove(msl_data_path + manifest_file)
		return KEYS



#'''



#if not 'playready-h264mpl' in manifest_keys_main or 'playready-h264bpl' not in manifest_keys_main:

'''
if __name__ == 'pywidevine.decrypt.netflix36_keys':
	import binascii
	import configparser
	import argparse
	import base64
	import glob
	import gzip
	import json
	import os
	import pprint
	import pycountry
	import random
	import string
	import re
	import requests
	import sys
	import time
	import xml.etree.ElementTree as ET
	import zlib
	from Cryptodome.Cipher import AES
	from Cryptodome.Cipher import PKCS1_OAEP
	from Cryptodome.Hash import HMAC, SHA256
	from Cryptodome.PublicKey import RSA
	from Cryptodome.Random import get_random_bytes
	from Cryptodome.Util import Padding
	from io import StringIO
	from datetime import datetime
	from subprocess import call
	import subprocess
	import ffmpy
	from io import BytesIO
	import subprocess as sp

	from pywidevine.clientsconfig.netflix import NetflixConfig
	from pywidevine.decrypt.wvdecryptcustom import WvDecrypt


	global args
	from netflix36 import args

	global esn_keys
	global esn_manifest
	global MANIFEST_ENDPOINT
	global LICENSE_ENDPOINT
	global account_info

	def generate_esn(prefix):
		"""
		generate_esn()
		@param prefix: Prefix of ESN to append generated device ID onto
		@return: ESN to use with MSL API
		"""

		return prefix + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(30))

	username, password, esn_keys, esn_manifest, MANIFEST_ENDPOINT, LICENSE_ENDPOINT = NetflixConfig.configNetflix()

	#esn_keys = generate_esn(esn_keys)
	#esn_manifest = generate_esn(esn_manifest)

	esn_manifest = esn_keys
	
	account_info = {
		"email": username,
		"password": password
	}


	def base64key_decode(payload):
		l = len(payload) % 4
		if l == 2:
			payload += '=='
		elif l == 3:
			payload += '='
		elif l != 0:
			raise ValueError('Invalid base64 string')
		return base64.urlsafe_b64decode(payload.encode('utf-8'))



	def GettingKEYS_Netflix(nfID, Profiles):
		import pywidevine.pymsl as pymsl

		print("\nGetting Main Profile Keys...")

		account = account_info
		user_auth_data = {
			'scheme': 'EMAIL_PASSWORD',
			'authdata': {
				'email': account['email'],
				'password': account['password']
				}
		}

		client = pymsl.MslClient(
			user_auth_data,
			esn=esn_keys,
			drm_system='widevine',
			profiles=Profiles
			)

		manifest_keys = client.load_manifest(nfID)
		print(manifest_keys)
		try:
			manifest = manifest_keys['result']
		except Exception:
			pass
			#print("Your account has possibly exceeded the maximum number of connections.")
			#sys.exit(0)
		
		"""
		print()
		print("Profile:")
		print(manifest['video_tracks'][0]['profile'])
		print()
		print("PSSH:")
		print(manifest['video_tracks'][0]['drmHeader']['bytes'])
		print()
		"""
		
		current_sessionId = str(time.time()).replace('.', '')[0:-2]

		#Check for pssh
		global init_data_b64_new_v2
		init_data_b64_new_v2 = manifest['video_tracks'][0]['drmHeader']['bytes']

		#Cert from JS (not work):
		#cert_data_b64_new_v2 = "Cr0CCAMSEOVEukALwQ8307Y2+LVP+0MYh/HPkwUijgIwggEKAoIBAQDm875btoWUbGqQD8eAGuBlGY+Pxo8YF1LQR+Ex0pDONMet8EHslcZRBKNQ/09RZFTP0vrYimyYiBmk9GG+S0wB3CRITgweNE15cD33MQYyS3zpBd4z+sCJam2+jj1ZA4uijE2dxGC+gRBRnw9WoPyw7D8RuhGSJ95OEtzg3Ho+mEsxuE5xg9LM4+Zuro/9msz2bFgJUjQUVHo5j+k4qLWu4ObugFmc9DLIAohL58UR5k0XnvizulOHbMMxdzna9lwTw/4SALadEV/CZXBmswUtBgATDKNqjXwokohncpdsWSauH6vfS6FXwizQoZJ9TdjSGC60rUB2t+aYDm74cIuxAgMBAAE6EHRlc3QubmV0ZmxpeC5jb20SgAOE0y8yWw2Win6M2/bw7+aqVuQPwzS/YG5ySYvwCGQd0Dltr3hpik98WijUODUr6PxMn1ZYXOLo3eED6xYGM7Riza8XskRdCfF8xjj7L7/THPbixyn4mULsttSmWFhexzXnSeKqQHuoKmerqu0nu39iW3pcxDV/K7E6aaSr5ID0SCi7KRcL9BCUCz1g9c43sNj46BhMCWJSm0mx1XFDcoKZWhpj5FAgU4Q4e6f+S8eX39nf6D6SJRb4ap7Znzn7preIvmS93xWjm75I6UBVQGo6pn4qWNCgLYlGGCQCUm5tg566j+/g5jvYZkTJvbiZFwtjMW5njbSRwB3W4CrKoyxw4qsJNSaZRTKAvSjTKdqVDXV/U5HK7SaBA6iJ981/aforXbd2vZlRXO/2S+Maa2mHULzsD+S5l4/YGpSt7PnkCe25F+nAovtl/ogZgjMeEdFyd/9YMYjOS4krYmwp3yJ7m9ZzYCQ6I8RQN4x/yLlHG5RH/+WNLNUs6JAZ0fFdCmw="
		
		#Cert from older API MSL manifest (work):
		cert_data_b64_new_v2 = "CAUSwwUKvQIIAxIQ5US6QAvBDzfTtjb4tU/7QxiH8c+TBSKOAjCCAQoCggEBAObzvlu2hZRsapAPx4Aa4GUZj4/GjxgXUtBH4THSkM40x63wQeyVxlEEo1D/T1FkVM/S+tiKbJiIGaT0Yb5LTAHcJEhODB40TXlwPfcxBjJLfOkF3jP6wIlqbb6OPVkDi6KMTZ3EYL6BEFGfD1ag/LDsPxG6EZIn3k4S3ODcej6YSzG4TnGD0szj5m6uj/2azPZsWAlSNBRUejmP6Tiota7g5u6AWZz0MsgCiEvnxRHmTRee+LO6U4dswzF3Odr2XBPD/hIAtp0RX8JlcGazBS0GABMMo2qNfCiSiGdyl2xZJq4fq99LoVfCLNChkn1N2NIYLrStQHa35pgObvhwi7ECAwEAAToQdGVzdC5uZXRmbGl4LmNvbRKAA4TTLzJbDZaKfozb9vDv5qpW5A/DNL9gbnJJi/AIZB3QOW2veGmKT3xaKNQ4NSvo/EyfVlhc4ujd4QPrFgYztGLNrxeyRF0J8XzGOPsvv9Mc9uLHKfiZQuy21KZYWF7HNedJ4qpAe6gqZ6uq7Se7f2JbelzENX8rsTpppKvkgPRIKLspFwv0EJQLPWD1zjew2PjoGEwJYlKbSbHVcUNygplaGmPkUCBThDh7p/5Lx5ff2d/oPpIlFvhqntmfOfumt4i+ZL3fFaObvkjpQFVAajqmfipY0KAtiUYYJAJSbm2DnrqP7+DmO9hmRMm9uJkXC2MxbmeNtJHAHdbgKsqjLHDiqwk1JplFMoC9KNMp2pUNdX9TkcrtJoEDqIn3zX9p+itdt3a9mVFc7/ZL4xpraYdQvOwP5LmXj9galK3s+eQJ7bkX6cCi+2X+iBmCMx4R0XJ3/1gxiM5LiStibCnfInub1nNgJDojxFA3jH/IuUcblEf/5Y0s1SzokBnR8V0KbA=="
		
		KEYS = []

		Correct = False

		while Correct == False:
			wvdecrypt = WvDecrypt(init_data_b64=init_data_b64_new_v2, cert_data_b64=cert_data_b64_new_v2)
			chal = wvdecrypt.get_challenge()			
			license_b64 = client.get_license(chal, current_sessionId)
			try:
				license_b64 = license_b64['result'][0]['licenseResponseBase64']
			except Exception:
				print(license_b64)
			wvdecrypt.update_license(license_b64)
			Correct, keyswvdecrypt = wvdecrypt.start_process()
			KEYS = keyswvdecrypt

		return KEYS


'''
