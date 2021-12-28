import argparse
import base64
import binascii
import json
import os
import requests
import subprocess
import sys
from colorama import init, Fore
from prettytable import PrettyTable
from pywidevine.decrypt.wvdecrypt import WvDecrypt


init(autoreset=True)


class Main(object):
    def __init__(self, folders, args):
        self.folders = folders
        self.args = args
        self.auth_json = None
        self.movie_id = args.url.split('id=')[-1]
        self.movie_details = None
        self.movie_resources = {}
        self.mpd_representations = {'video': [], 'audio': [], 'subtitle': []}
        self.license = None

    def auth(self):
        if os.path.exists('auth.json'):
            with open('auth.json', 'r') as src:
                self.auth_json = json.loads(src.read())
        else:
            sys.exit()

    def requests_headers(self):
        return {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': 'Bearer {0}'.format(self.auth_json['authorization']),
            'Host': 'www.googleapis.com',
            'origin': 'chrome-extension://gdijeikdkaembjbdobgfkoidjkpbmlkd',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36',
            'x-client-data': '{0}'.format(self.auth_json['x-client-data']),
        }
    
    def get_movie_details(self):
        url = 'https://www.googleapis.com/android_video/v1/asset/list?id=yt%3Amovie%3A{0}&if=imbrg&lr=en_US&cr=US&alt=json&access_token={1}&make=Google&model=ChromeCDM-Windows-x86-32&product=generic&device=generic'.format(self.movie_id, self.auth_json['authorization'])
        self.movie_details = requests.get(url=url, headers=self.requests_headers()).json()

    def get_movie_resources(self):
        url = 'https://www.googleapis.com/android_video/v1/mpd?id=yt%3Amovie%3A{0}&ac3=true&all51=true&nd=false&all=false&secure=true&msu=false&ma=true&fc=true&hdcp=true&alt={1}&ssrc=googlevideo&access_token={2}&make=Google&model=ChromeCDM-Windows-x86-32&product=generic&device=generic'
        self.movie_resources['json'] = requests.get(
            url = url.format(self.movie_id, 'json', self.auth_json['authorization']),
            headers = self.requests_headers()
        ).json()
        #self.movie_resources['protojson'] = requests.get(
            #url = url.format(self.movie_id, 'protojson', self.auth_json['authorization']),
            #headers = self.requests_headers()
        #).json()
    
    def parse_movie_resources(self):
        av_representations = self.movie_resources['json']['representations']
        for x in av_representations:
            if 'audio_info' not in x:
                self.mpd_representations['video'].append({
                    'playback_url': x['playback_url'],
                    'codec': x['codec'],
                    'init': x['init'],
                    'bitrate': x['bitrate'],
                    'quality': str(x['height'])+'p',
                    'fps': x['video_fps']
                })
            elif 'audio_info' in x:
                self.mpd_representations['audio'].append({
                    'playback_url': x['playback_url'],
                    'codec': x['codec'],
                    'init': x['init'],
                    'bitrate': x['bitrate'],
                    'language': x['audio_info']['language'] 
                })
        #subtitle_representations = self.movie_resources['protojson']['1007']['4']
        #for x in subtitle_representations:
            #self.mpd_representations['subtitle'].append({
                #'language': x['1'],
                #'url': x['3'] ,
                #'format': x['5']
            #})

    def aria2c(self, url, output_file_name):
        aria2c = os.path.join(self.folders['binaries'], 'aria2c.exe')
        aria2c_command = [
            aria2c, url,
            '-d', self.folders['temp'], '-j16',
            '-o', output_file_name, '-s16', '-x16',
            '-U', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36',
            '--allow-overwrite=false',
            '--async-dns=false',
            '--auto-file-renaming=false',
            '--console-log-level=warn',
            '--retry-wait=5',
            '--summary-interval=0',       
        ]
        subprocess.run(aria2c_command)
        return os.path.join(self.folders['temp'], output_file_name)

    def extract_pssh(self, mp4_file):
        mp4dump = os.path.join(self.folders['binaries'], 'mp4dump.exe')
        wv_system_id = '[ed ef 8b a9 79 d6 4a ce a3 c8 27 dc d5 1d 21 ed]'
        pssh = None
        data = subprocess.check_output([mp4dump, '--format', 'json', '--verbosity', '1', mp4_file])
        data = json.loads(data)
        for atom in data:
            if atom['name'] == 'moov':
                for child in atom['children']:
                    if child['name'] == 'pssh' and child['system_id'] == wv_system_id:
                        pssh = child['data'][1:-1].replace(' ', '')
                        pssh = binascii.unhexlify(pssh)
                        pssh = pssh[0:]
                        pssh = base64.b64encode(pssh).decode('utf-8')
                        return pssh
    
    def license_request(self, pssh):
        license_url = 'https://play.google.com/video/license/GetCencLicense?source=YOUTUBE&video_id={0}&oauth={1}'.format(self.movie_id, self.auth_json['authorization'])
        license_headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36'
        }
        wvdecrypt = WvDecrypt(pssh)
        challenge = wvdecrypt.get_challenge()
        resp = requests.post(url=license_url, headers=license_headers, data=challenge)
        resp1 = resp.content.split('\r\n\r\n'.encode('utf-8'))
        resp2 = resp1[1]
        license_b64 = base64.b64encode(resp2).decode('utf-8')
        wvdecrypt.update_license(license_b64)
        keys = wvdecrypt.start_process()
        return keys

    def mp4decrypt(self, keys):
        mp4decrypt_command = [os.path.join(self.folders['binaries'], 'mp4decrypt.exe')]
        for key in keys:
            if key.type == 'CONTENT':
                mp4decrypt_command.append('--show-progress')           
                mp4decrypt_command.append('--key')
                mp4decrypt_command.append('{}:{}'.format(key.kid.hex(), key.key.hex()))
        return mp4decrypt_command

    def decrypt(self, keys, input, output):
        mp4decrypt_command = self.mp4decrypt(keys)
        mp4decrypt_command.append(input)
        mp4decrypt_command.append(output)
        wvdecrypt_process = subprocess.Popen(mp4decrypt_command)
        wvdecrypt_process.communicate()
        wvdecrypt_process.wait() 

    def video(self):
        table = PrettyTable()
        table.field_names = ['ID', 'CODEC', 'QUALITY', 'BITRATE', 'FPS']
        for i, j in enumerate(self.mpd_representations['video']):
            table.add_row([i, j['codec'], j['quality'], j['bitrate'], j['fps']])
        print('\n' + Fore.RED + 'VIDEO')
        print(table)
        selected_video = self.mpd_representations['video'][int(input('ID: '))]
        init_url = selected_video['playback_url'] + '?range={0}-{1}'.format(selected_video['init']['first'], selected_video['init']['last'])
        self.aria2c(init_url, 'init.mp4')
        selected_video['pssh'] = self.extract_pssh(os.path.join(self.folders['temp'], 'init.mp4'))
        os.remove(os.path.join(self.folders['temp'], 'init.mp4'))
        print(Fore.YELLOW+'\nAcquiring Content License')
        self.license = self.license_request(selected_video['pssh'])
        print(Fore.GREEN+'License Acquired Successfully')
        print(Fore.YELLOW+'\nURL:', selected_video['playback_url'])
        if not self.args.keys:
            output_file_name = self.movie_details['resource'][0]['metadata']['title'] + ' ' + f'[{selected_video["quality"]}] Encrypted.mp4' 
            print(Fore.YELLOW+'\nDownloading', output_file_name)
            video_downloaded = self.aria2c(selected_video['playback_url'], output_file_name.replace(':', ''))
            print(Fore.YELLOW+'\nDecrypting Video')
            self.decrypt(self.license, video_downloaded, video_downloaded.replace(' Encrypted', ''))
            os.remove(video_downloaded)
        else:
            print(Fore.GREEN + 'n\KEYS')
            for key in self.license:
                if key.type == 'CONTENT':
                    print('{}:{}'.format(key.kid.hex(), key.key.hex()))
    
    def audio(self):
        table = PrettyTable()
        table.field_names = ['ID', 'CODEC', 'BITRATE', 'LANGUAGE']
        for i, j in enumerate(self.mpd_representations['audio']):
            table.add_row([i, j['codec'], j['bitrate'], j['language']])
        print('\n' + Fore.RED +'AUDIO')
        print(table)
        selected_audio = input('ID: ')
        if self.args.audio:
            init_url = self.mpd_representations['audio'][int(selected_audio.split(',')[-1])]['playback_url']
            init_url += '?range={0}-{1}'.format(self.mpd_representations['audio'][int(selected_audio.split(',')[-1])]['init']['first'], self.mpd_representations['audio'][int(selected_audio.split(',')[-1])]['init']['last'])
            self.aria2c(init_url, 'init.mp4')
            pssh = self.extract_pssh(os.path.join(self.folders['temp'], 'init.mp4'))
            os.remove(os.path.join(self.folders['temp'], 'init.mp4'))
            print(Fore.YELLOW+'\nAcquiring Content License')
            self.license = self.license_request(pssh)
            print(Fore.GREEN+'License Acquired Successfully')
        for x in selected_audio.split(','):
            x = int(x.strip())
            playback_url = self.mpd_representations['audio'][x]['playback_url']
            print(Fore.YELLOW+'\nURL:', playback_url)
            if not self.args.keys:
                output_file_name = self.movie_details['resource'][0]['metadata']['title'] + ' ' + f'[{self.mpd_representations["audio"][x]["language"]}-{self.mpd_representations["audio"][x]["codec"]}-{self.mpd_representations["audio"][x]["bitrate"]}] Encrypted.mp4'
                print(Fore.YELLOW+'\nDownloading', output_file_name)
                audio_downloaded = self.aria2c(playback_url, output_file_name.replace(':', ''))
                self.decrypt(self.license, audio_downloaded, audio_downloaded.replace(' Encrypted', ''))
                os.remove(audio_downloaded)
            else:
                print(Fore.GREEN + 'n\KEYS')
                for key in self.license:
                    if key.type == 'CONTENT':
                        print('{}:{}'.format(key.kid.hex(), key.key.hex()))

    def subtitle(self):
        table = PrettyTable()
        table.field_names = ['ID', 'LANGUAGE', 'FORMAT']
        for i, j in enumerate(self.mpd_representations['subtitle']):
            table.add_row([i, j['language'], j['format']])
        print('\n' + Fore.RED +'SUBTITLE')
        print(table)
        selected_subtitle = input('ID: ')
        for x in selected_subtitle.split(','):
            x = int(x.strip())
            url = self.mpd_representations['subtitle'][x]['url']
            output_file_name = self.movie_details['resource'][0]['metadata']['title'] + ' ' + f'{self.mpd_representations["subtitle"][x]["language"]}-{self.mpd_representations["subtitle"][x]["format"]}'
            print(Fore.YELLOW+'\nDownloading', output_file_name)
            self.aria2c(url, output_file_name)


cwd = os.getcwd()
folders = {'binaries': os.path.join(cwd, 'binaries'), 'output': os.path.join(cwd, 'output'), 'temp': os.path.join(cwd, 'temp')}


arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('-u', '--url', required=True)
arg_parser.add_argument('-a', '--audio', action='store_true')
arg_parser.add_argument('-k', '--keys', action='store_true')
args = arg_parser.parse_args()


if __name__ == "__main__":
    movie = Main(folders, args)
    movie.auth()
    movie.get_movie_details()
    movie.get_movie_resources()
    movie.parse_movie_resources()
    if not args.audio:
        #movie.subtitle()
        movie.video()
    movie.audio()
  
    