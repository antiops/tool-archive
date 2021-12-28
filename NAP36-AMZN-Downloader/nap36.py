#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Module: Netflix - Amazon/Primevideo Downloader
# Created on: 11-09-2018
# Authors: anons
# Version: 6.3

import argparse
import os
import sys
import re
import urllib.parse

import requests


parser = argparse.ArgumentParser()
#Common:
parser.add_argument("content", nargs="?", help="Content URL or ID")
parser.add_argument("-t", dest="title", nargs="?", help="Content URL or ID")
parser.add_argument("--url", dest="url_season", help="If set, it will download all assets from the season provided.")
parser.add_argument("--mode", dest="mode", nargs=1, help="netflix, amazon, primevideo or hboespana.", default=[])
parser.add_argument("--info", dest="only_info", help="If set, don't download video", action="store_true")
parser.add_argument("--nv", "--no-video", dest="novideo", help="If set, don't download video", action="store_true")
parser.add_argument("--na", "--no-audio", dest="noaudio", help="If set, don't download audio", action="store_true")
parser.add_argument("--ns", "--no-subs", dest="nosubs", help="If set, don't download subs", action="store_true")
parser.add_argument("--all-season", dest="all_season", help="If set, active download mode.", action="store_true")
parser.add_argument("-e", "--episode", dest="episodeStart", help="If set, it will start downloading the season from that episode.")
parser.add_argument("-s", dest="season", help="If set, it will download all assets from the season provided.")
parser.add_argument("-q", "--quality", dest="customquality", type=lambda x: [x.rstrip('p')], help="For configure quality of video.", default=[])
parser.add_argument("-o", "--output", dest="output", default="downloads", help="If set, it will download all assets to directory provided.")
parser.add_argument("--keep", dest="keep", help="If set, it will list all formats available.", action="store_true")
parser.add_argument("--no-mux", dest="nomux", help="If set, dont mux.", action="store_true")
parser.add_argument("--force-mux", dest="force_mux", nargs=1, help="If set, force mux.", default=[])
parser.add_argument("--langtag", dest="langtag", nargs=1, help="For configure language tag of MKV.", default=[])
parser.add_argument("--only-2ch-audio", dest="only_2ch_audio", help="If set, no clean tag subtitles.", action="store_true")
parser.add_argument("--custom-command", dest="custom_command", nargs=1, help="If set, download only selected audio languages", default=[])
parser.add_argument("--fix-pitch", "--fpitch", dest="fpitch", nargs="*", help="If set, download only selected audio languages", default=[])
parser.add_argument("--source-fps", dest="sourcefps", nargs=1, help="For configure language tag of MKV.", default=[])
parser.add_argument("--target-fps", dest="targetfps", nargs=1, help="For configure language tag of MKV.", default=[])
parser.add_argument("--alang", "--audio-language", dest="audiolang", nargs="*", help="If set, download only selected audio languages", default=[])
parser.add_argument("--slang", "--subtitle-language", dest="sublang", nargs="*", help="If set, download only selected subtitle languages", default=[])
parser.add_argument("--flang", "--forced-language", dest="forcedlang", nargs="*", help="If set, download only selected forced subtitle languages", default=[])
parser.add_argument("--no-cleansubs", dest="nocleansubs", help="If set, no clean tag subtitles.", action="store_true")
parser.add_argument("--title", dest="titlecustom", nargs=1, help="Customize the title of the show", default=[])
parser.add_argument("--video-high", dest="video_high", help="If set, it will return H.264 High manifest", action="store_true")
parser.add_argument("--hevc", dest="hevc", help="If set, it will return HEVC manifest", action="store_true")
parser.add_argument("--uhd", dest="uhd", help="If set, it will return UHD manifest", action="store_true")
parser.add_argument("--micro", dest="lower", help="If set, it will return HEVC manifest", action="store_true")
parser.add_argument("--private", dest="private_secret", help="...", action="store_true")
parser.add_argument("--only-keys", dest="onlykeys", help="Only print keys, don't download", action="store_true")
parser.add_argument("--debug", action="store_true", help="Enable debug logging")
#Amazon/Primevideo:
parser.add_argument("--asin", dest="asin", help="Enter ASIN.")
parser.add_argument("--retry", dest="retry", help="Retry.", action="store_true")
parser.add_argument("--cbr", dest="cbr_bitrate", help="CBR", action="store_true")
parser.add_argument("--atmos", dest="atmos", help="If set, it will return Atmos MPDs", action="store_true")
parser.add_argument("--nc", "--no-chapters", dest="nochpaters", help="If set, don't download chapters", action="store_true")
parser.add_argument("-r", "--region", choices=["ps", "ps-int", "us", "uk", "de", "jp"], help="amazon video region")
parser.add_argument("--clang", "--chapters-language", dest="chapterslang", nargs=1, help="If set, download only selected forced subtitle languages", default=[])
parser.add_argument("--tlang", "--title-language", dest="titlelang", nargs=1, help="If set, download only selected forced subtitle languages", default=[])
parser.add_argument("--force-sd", action="store_true", help="Force SD manifest for Amazon")
parser.add_argument("--all-keys", dest="allkeys", action="store_true", help="Get CVBR, CBR and HEVC keys")
parser.add_argument("-c", "--cookies", help="specify name of cookies file (cookies_<region>_<name>.txt)")
parser.add_argument("--nm", "--no-mpd", dest="nompd", help="Do not request MPD (to download forced subtitles/chapters for non-owned titles)")
parser.add_argument("--ad", "--desc-audio", action="store_true", dest="desc_audio", help="Download descriptive audio instead of normal dialogue")
#HBO:
parser.add_argument("--audio-dublang", dest="audio_dublang", nargs=1, help="If set, download only selected audio languages", default=[])
parser.add_argument("--audio-volang", dest="audio_volang", nargs=1, help="If set, download only selected audio languages", default=[])
parser.add_argument("--subs-dublang", dest="subs_dublang", nargs=1, help="If set, download only selected audio languages", default=[])
parser.add_argument("--subs-volang", dest="subs_volang", nargs=1, help="If set, download only selected audio languages", default=[])

#Netflix:
parser.add_argument("--ID", dest="nflxID", nargs="?", help="The Netflix viewable ID.")
parser.add_argument("--hdr", dest="hdr", help="If set, it will return HDR manifest", action="store_true")
parser.add_argument("--hdrdv", dest="hdrdv", help="If set, it will return HDR-DV manifest", action="store_true")
parser.add_argument("--force-audiohq", dest="forceaudiohq", help="If set, it will return HDR manifest", action="store_true")
parser.add_argument("--aformat-2ch", "--audio-format-2ch", dest="aformat_2ch", help="For configure format of audio.")
parser.add_argument("--aformat-51ch", "--audio-format-51ch", dest="aformat_51ch", help="For configure format of audio.")
parser.add_argument("--vp9", dest="video_vp9", help="If set, no clean tag subtitles.", action="store_true")
parser.add_argument("--np", "--no-prompt", dest="noprompt", help="If set, it will disable the yes/no prompt when URLs are grabbed.", action="store_true")
parser.add_argument("--nar", "--no-all-regions", dest="noallregions", help="If set, it will disable collating assets from all regions.", action="store_true")
#VPN:
parser.add_argument("--vpngate", dest="country_code", help="If set, you'll be connected to the desired country using VPNGate.", default=None)
parser.add_argument("--bind", default="", help="Bind to the specified IP or interface")
parser.add_argument("--bind-meta", help="Bind to the specified IP or interface for metadata and license requests")
parser.add_argument("--bind-dl", default="", help="Bind to the specified IP or interface for aria2c downloads")

#PROXY:
parser.add_argument("--proxy", dest="proxy", help="Proxy URL to use for both fetching metadata and downloading")
#proxy format: http://email@email:password@host:port

args = parser.parse_args()

if args.debug:
	import logging
	logging.basicConfig(level=logging.DEBUG)


def host_match(url, host):
	url_host = urllib.parse.urlparse(url).netloc

	if host.startswith('.') and (url_host.endswith(host) or url_host == host[1:]):
		return True

	return (host == url_host)


#args.onlykeys = True
args.forceaudiohq = False

currentFile = '__main__'
realPath = os.path.realpath(currentFile)
dirPath = os.path.dirname(realPath)
dirName = os.path.basename(dirPath)


if __name__ == "__main__":
	if args.country_code is not None:
		from binaries.VPN.VPNGate import VPNGateConnect
		print("Killing previous OpenVPN sessions...")
		os.system("taskkill /im openvpn.exe /f")
		VPNGateConnect(args.country_code)

	if args.title:
		args.content = args.title

	if args.content:
		if args.url_season or args.asin or args.nflxID:
			print('Error: Too many arguments.')
			sys.exit(1)

		if re.search(r'^https?://', args.content):
			print(f'Detected URL: {args.content}')
			args.url_season = args.content
		elif re.fullmatch(r'[0-9]{8}', args.content):
			print(f'Detected Netflix ID: {args.content}')
			args.nflxID = args.content
		elif re.fullmatch(r'[A-Z0-9]{10}|amzn1\.dv\.gti\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', args.content):
			print(f'Detected ASIN: {args.content}')
			args.asin = args.content
		else:
			print('Error: Unable to detect content type, please specify --url/--asin/--id')
			sys.exit(1)

	if not args.region:
		if args.asin:
			print(f'Error: --region option is required when using ASIN')
			sys.exit(1)

		if args.url_season:
			if host_match(args.url_season, '.amazon.com'):
				args.region = 'us'
			elif host_match(args.url_season, '.amazon.co.uk'):
				args.region = 'uk'
			elif host_match(args.url_season, '.amazon.de'):
				args.region = 'de'
			elif host_match(args.url_season, '.amazon.co.jp'):
				args.region = 'jp'
			elif host_match(args.url_season, '.primevideo.com'):
				args.region = 'ps'

			if args.region:
				print(f'Amazon region detected as {args.region.upper()}')

	if args.allkeys:
		args.onlykeys = True

	if args.bind:
		args.bind_meta = args.bind
		args.bind_dl = args.bind

	session = requests.Session()

	if args.bind_meta:
		from requests_toolbelt.adapters.source import SourceAddressAdapter
		session.mount('http://', SourceAddressAdapter(args.bind_meta))
		session.mount('https://', SourceAddressAdapter(args.bind_meta))

	binaries_dirs = []
	for root, dirs, files in os.walk('binaries'):
		binaries_dirs += [os.path.realpath(os.path.join(root, d)) for d in dirs]
	os.environ['PATH'] = os.pathsep.join(binaries_dirs + os.environ['PATH'].split(os.pathsep))

	if (args.url_season and 'netflix' in args.url_season) or args.nflxID or (args.mode and args.mode[0] == 'netflix'):
		mode = 'netflix'
		import netflix36
		netflix36.main(args, session)
	elif (args.url_season and 'amazon' in args.url_season) or args.asin or (args.mode and args.mode[0] == 'amazon'):
		mode = 'amazon'
		import primevideo36
		primevideo36.main(args, session)
	elif (args.url_season and 'primevideo.com' in args.url_season) or args.asin or (args.mode and args.mode[0] == 'primevideo'):
		mode = 'primevideo'
		import primevideo36
		primevideo36.main(args, session)
	elif (args.url_season and 'es.hboespana.com' in args.url_season) or args.asin or (args.mode and args.mode[0] == 'hboespana'):
		mode = 'hboes'
		import hboes
		hboes.main(args, session)
	else:
		url_season = input("Enter the HBO ES, Netflix, Amazon or Primevideo URL (with https): ")
		args.url_season = url_season

		if 'netflix' in url_season:
			mode = 'netflix'
			import netflix36
			netflix36.main(args, session)
		elif 'amazon' in url_season:
			mode = 'amazon'
			import primevideo36
			primevideo36.main(args, session)
		elif 'primevideo.com' in url_season:
			mode = 'primevideo'
			import primevideo36
			primevideo36.main(args, session)
		elif 'es.hboespana.com' in url_season:
			mode = 'hboes'
			import hboes
			hboes.main(args, session)
		else:
			if args.country_code is not None:
				os.system("taskkill /im openvpn.exe /f")

			print("Error! This url or mode is not recognized.")
			sys.exit(0)
