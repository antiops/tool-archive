import configparser
import sys

CONFIG_FILE = 'netflix.cfg'

c = configparser.ConfigParser(interpolation=None)

if not c.read(CONFIG_FILE):
	print('Configuration file not found, please copy netflix.cfg.example to netflix.cfg '
	      'and change the settings as needed.')
	sys.exit(1)

email = c['config']['email']
password = c['config']['password']
esn_license = c['config'].get('esn_license') or c['config']['esn']
esn_manifest = c['config'].get('esn_manifest') or c['config']['esn']
manifest_url = 'https://www.netflix.com/api/msl/cadmium/manifest'
license_url = 'https://www.netflix.com/api/msl/cadmium/license'

device_name = c['config'].get('device')

class NetflixConfig(object):
	def configNetflix():
		return email, password, esn_license, esn_manifest, manifest_url, license_url, device_name
