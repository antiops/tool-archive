import configparser
import os

CONFIG_FILE = 'primevideo.cfg'

user_config = {
	'device': None,
}

c = configparser.ConfigParser(interpolation=None)
if c.read(CONFIG_FILE):
	user_config['device'] = c['config'].get('device')


email_pv = "nothing"
password_pv = "nothing"
email_pv_no_european = "nothing"
password_pv_no_european = "nothing"
email_amazon_usa = "nothing"
password_amazon_usa = "nothing"
email_amazon_jpn = "nothing"
password_amazon_jpn = "nothing"
email_amazon_uk = "nothing"
password_amazon_uk = "nothing"
email_amazon_ger = "nothing"
password_amazon_ger = "nothing"


config = {}

config['ps'] = {
	'cookies_file': 'cookies_ps.txt',
	'site_base_url': 'www.primevideo.com',
	'video_base_url': None,  # auto-detected
	'marketplace_id': 'A3K6Y4MI8GDYMT',
	'clientId': 'f22dbddb-ef2c-48c5-8876-bed0d47594fd',
	'email': email_pv,
	'password': password_pv,
	'proxies': None
}

config['us'] = {
	'cookies_file': 'cookies_us.txt',
	'site_base_url': 'www.amazon.com',
	'video_base_url': 'atv-ps.amazon.com',
	'marketplace_id': 'ATVPDKIKX0DER',
	'clientId': 'f22dbddb-ef2c-48c5-8876-bed0d47594fd',
	'email': email_amazon_usa,
	'password': password_amazon_usa,
	'proxies': None
}

config['jp'] = {
	'cookies_file': 'cookies_jp.txt',
	'site_base_url': 'www.amazon.co.jp',
	'video_base_url': 'atv-ps-fe.amazon.co.jp',
	'marketplace_id': 'A1VC38T7YXB528',
	'clientId': 'f22dbddb-ef2c-48c5-8876-bed0d47594fd',
	'email': email_amazon_jpn,
	'password': password_amazon_jpn,
	'proxies': None
}

config['uk'] = {
	'cookies_file': 'cookies_uk.txt',
	'site_base_url': 'www.amazon.co.uk',
	'video_base_url': 'atv-ps-eu.amazon.co.uk',
	'marketplace_id': 'A2IR4J4NTCP2M5',
	'clientId': 'f22dbddb-ef2c-48c5-8876-bed0d47594fd',
	'email': email_amazon_uk,
	'password': password_amazon_uk,
	'proxies': None
}

config['de'] = {
	'cookies_file': 'cookies_de.txt',
	'site_base_url': 'www.amazon.de',
	'video_base_url': 'atv-ps-eu.amazon.de',
	'marketplace_id': 'A1PA6795UKMFR9',
	'clientId': 'f22dbddb-ef2c-48c5-8876-bed0d47594fd',
	'email': email_amazon_ger,
	'password': password_amazon_ger,
	'proxies': None
}





class PrimevideoConfig(object):
	def configPrimeVideo():
		video_base_url = config['ps']['video_base_url']
		site_base_url = config['ps']['site_base_url']
		marketplace_id = config['ps']['marketplace_id']
		cookies_file = config['ps']['cookies_file']
		clientId = config['ps']['clientId']
		email = config['ps']['email']
		password = config['ps']['password']
		return video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password
	
	def configPrimeVieoInternational():
		video_base_url = config['ps-int']['video_base_url']
		site_base_url = config['ps-int']['site_base_url']
		marketplace_id = config['ps-int']['marketplace_id']
		cookies_file = config['ps-int']['cookies_file']
		clientId = config['ps-int']['clientId']
		email = config['ps-int']['email']
		password = config['ps-int']['password']
		return video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password
	
	def configAmazonUS():
		video_base_url = config['us']['video_base_url']
		site_base_url = config['us']['site_base_url']
		marketplace_id = config['us']['marketplace_id']
		cookies_file = config['us']['cookies_file']
		clientId = config['us']['clientId']
		email = config['us']['email']
		password = config['us']['password']
		return video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password
	
	def configAmazonJP():
		video_base_url = config['jp']['video_base_url']
		site_base_url = config['jp']['site_base_url']
		marketplace_id = config['jp']['marketplace_id']
		cookies_file = config['jp']['cookies_file']
		clientId = config['jp']['clientId']
		email = config['jp']['email']
		password = config['jp']['password']
		return video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password
	
	def configAmazonUK():
		video_base_url = config['uk']['video_base_url']
		site_base_url = config['uk']['site_base_url']
		marketplace_id = config['uk']['marketplace_id']
		cookies_file = config['uk']['cookies_file']
		clientId = config['uk']['clientId']
		email = config['uk']['email']
		password = config['uk']['password']
		return video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password

	def configAmazonDE():
		video_base_url = config['de']['video_base_url']
		site_base_url = config['de']['site_base_url']
		marketplace_id = config['de']['marketplace_id']
		cookies_file = config['de']['cookies_file']
		clientId = config['de']['clientId']
		email = config['de']['email']
		password = config['de']['password']
		return video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password


