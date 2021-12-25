# -*- coding: utf-8 -*-
# Module: Amazon/Primevideo Downloader
# Created on: 03-01-2018
# Authors: anons
# Version: 3.6

import hashlib
import datetime
from titlecase import titlecase
import html
import http.cookiejar
import uuid
import hmac
import requests
import json
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import re
import subprocess
import os
import xmltodict
import time
import base64
import sys
import ffmpy
import glob
import gzip
import pycaption
import shutil
from collections import defaultdict
from bs4 import BeautifulSoup
import binascii
from xml.parsers.expat import ExpatError


from kanji_to_romaji.kanji_to_romaji_module import kanji_to_romaji
#__all__ = ["load_mappings_dict", "convert_hiragana_to_katakana", "convert_katakana_to_hiragana", "translate_to_romaji", "translate_soukon", "translate_long_vowel", "translate_soukon_ch", "kanji_to_romaji"]


from pywidevine.clientsconfig.amazonprimevideo import PrimevideoConfig, user_config
from pywidevine.decrypt.wvdecryptcustom import WvDecrypt
from pywidevine.muxer.muxer import Muxer
from pywidevine.cdm import cdm, deviceconfig
from pywidevine.clientsconfig.proxy_config import ProxyConfig


def main(args, session):

    currentFile = 'primevideo36'
    realPath = os.path.realpath(currentFile)
    dirPath = os.path.dirname(realPath)
    dirName = os.path.basename(dirPath)

    TimeStretch_dll = dirPath + "/binaries/BeHappy/plugins32/TimeStretch.dll"
    lsmashsource_dll = dirPath + "/binaries/BeHappy/plugins32/LSMASHSource.dll"

    mp4decryptexe = "mp4decrypt"
    mp4dumptexe = "mp4dump"
    ffmpegpath = "ffmpeg"
    ffprobepath = "ffprobe"
    mkvmergeexe = "mkvmerge"
    aria2cexe = "aria2c"
    SubtitleEditexe = shutil.which("subtitleedit") or shutil.which("SubtitleEdit")
    MediaInfo_exe = shutil.which("mediainfo") or shutil.which("MediaInfo")

    wvDecrypterexe = dirPath + "/binaries/wvDecrypter/wvDecrypter"
    challengeBIN = dirPath + "/binaries/wvDecrypter/challenge.bin"
    licenceBIN = dirPath + "/binaries/wvDecrypter/licence.bin"

    config_data = dirPath + "/binaries/amz_decrypted/config.xml"
    amz_decrypterexe = dirPath + "/binaries/amz_decrypted/amz_decrypter"

    proxies = {}
    proxy_meta = args.proxy
    if proxy_meta == 'none':
        proxies['meta'] = {'http': None, 'https': None}
    elif proxy_meta:
        proxies['meta'] = {'http': proxy_meta, 'https': proxy_meta}
    SESSION = requests.Session()
    SESSION.proxies = proxies.get('meta')
    proxy_cfg = ProxyConfig(proxies)

    qual_sd = args.customquality and str(args.customquality[0]).lower() == 'sd'
    if qual_sd:
        args.customquality = []

    if args.force_sd or qual_sd:
        QualityGlobal = 'SD'
        operatingSystemName = "Linux"
        operatingSystemVersion ="unknown"
    else:
        QualityGlobal = 'HD'
        operatingSystemName = "Windows"
        operatingSystemVersion = "10.0"

    #if os.path.isfile(challengeBIN): os.remove(challengeBIN)
    #if os.path.isfile(licenceBIN): os.remove(licenceBIN)


    if not os.path.exists(dirPath + "/KEYS"):
        os.makedirs(dirPath + "/KEYS")
    keys_file = dirPath + "/KEYS/KEYS_AMAZON_PRIMEVIDEO.txt"

    try:
        keys_file_amazon_primevideo = open(keys_file, "r", encoding="utf8")
        keys_file_txt = keys_file_amazon_primevideo.readlines()
    except Exception:
        with open(keys_file, "a", encoding="utf8") as file:
            file.write("##### Una KEY por linea. (One KEY for line.) #####\n")
        keys_file_amazon_primevideo = open(keys_file, "r", encoding="utf8")
        keys_file_txt = keys_file_amazon_primevideo.readlines()

    if args.chapterslang:
        chapterslang = args.chapterslang[0]
    else:
        chapterslang = "en-US"

    if args.titlelang:
        titlelang = args.titlelang[0].replace("-", "_")
    else:
        titlelang = "en_US"

    def ReplaceCodeLanguages(X):
        X = X.replace("_subtitle_dialog_0", "").replace("_narrative_dialog_0", "").replace("_caption_dialog_0", "").\
            replace("_dialog_0", "").replace("_descriptive_0", "_descriptive").replace("_descriptive", "").replace("_sdh", "-sdh").\
            replace("es-es","es").replace("es-ar", "es").replace("en-es","es").replace("kn-in","kn").replace("gu-in","gu").replace("ja-jp","ja").\
            replace("mni-in","mni").replace("si-in","si").replace("as-in","as").replace("ml-in","ml").replace("sv-se","sv").\
            replace("hy-hy","hy").replace("sv-sv","sv").replace("da-da","da").replace("fi-fi","fi").replace("nb-nb","nb").\
            replace("is-is","is").replace("uk-uk","uk").replace("hu-hu","hu").replace("bg-bg","bg").replace("hr-hr","hr").\
            replace("lt-lt","lt").replace("et-et","et").replace("el-el","el").replace("he-he","he").replace("ar-ar","ar").\
            replace("fa-fa","fa").replace("ro-ro","ro").replace("sr-sr","sr").replace("cs-cs","cs").replace("sk-sk","sk").\
            replace("mk-mk","mk").replace("hi-hi","hi").replace("bn-bn","bn").replace("ur-ur","ur").replace("pa-pa","pa").\
            replace("ta-ta","ta").replace("te-te","te").replace("mr-mr","mr").replace("kn-kn","kn").replace("gu-gu","gu").\
            replace("ml-ml","ml").replace("si-si","si").replace("as-as","as").replace("mni-mni","mni").replace("tl-tl","tl").\
            replace("id-id","id").replace("ms-ms","ms").replace("vi-vi","vi").replace("th-th","th").replace("km-km","km").\
            replace("ko-ko","ko").replace("zh-zh","zh").replace("ja-ja","ja").replace("ru-ru","ru").replace("tr-tr","tr").\
            replace("it-it","it").replace("es-mx","es-la").replace("ar-sa","ar").replace("zh-cn","zh").replace("nl-nl","nl").\
            replace("pl-pl","pl").replace("pt-pt","pt").replace("hi-in","hi").replace("mr-in","mr").replace("bn-in","bn").\
            replace("te-in","te").replace("cmn-hans","zh-hans").replace("cmn-hant","zh-hant").replace("ko-kr","ko").replace("en-au","en").\
            replace("es-419","es-la").replace("en-us","en").replace("en-gb","en").replace("fr-fr","fr").replace("de-de","de").\
            replace("las-419","es-la").replace("ar-ae","ar").replace("da-dk","da").replace("yue-hant","yue").replace("bn-in","bn").\
            replace("ur-in","ur").replace("ta-in","ta").replace("sl-si","sl").replace("cs-cz","cs").replace("hi-jp","hi").replace("-001","").replace("en-US","en").\
            replace("deu","de").replace("eng","en").replace("ca-es","cat").replace("fil-ph","fil").replace("en-ca","en").replace("eu-es","fcustomquality").\
            replace("en-ph", "en").replace("zh-sg", "zh")


        return X

    def ReplaceChapters(X):
        pattern1 = re.compile(r'(?:[A-Z]*)(?:[A-Za-z_ -=]*)( )')
        X = pattern1.sub('', X)
        return X

    def ReplaceASIN(X):
        pattern1 = re.compile(r'(?:[A-Za-z0-9]*)(,)')
        X = pattern1.sub('', X)
        return X

    def ReplaceChaptersNumber(X):
        pattern1 = re.compile(r'(\d+)(\.)( )')
        X = pattern1.sub('', X)
        return X

    def list_to_str(list, separator, lastseparator):
        list_str = ''
        audio_or_subs_num = len(list)
        listcounter = 1

        for x in list:
            if len(list) == 1:
                list_str = str(x)
            else:
                if list_str != '' and listcounter < int(audio_or_subs_num):
                    list_str = list_str + separator + str(x)

                if listcounter==int(audio_or_subs_num):
                    list_str = list_str + lastseparator + str(x)

                if list_str == '':
                    list_str = str(x)

                listcounter = listcounter + 1
        return list_str

    def fix_subtitles(text):
        text = re.sub(r'(</?)tt:', r'\1', text)
        return text

    def ReplaceSubs1(X):
        pattern1 = re.compile(r'(?!<i>|<b>|<u>|<\/i>|<\/b>|<\/u>)(<)(?:[A-Za-z0-9_ -=]*)(>)')
        pattern2 = re.compile(r'(?!<\/i>|<\/b>|<\/u>)(<\/)(?:[A-Za-z0-9_ -=]*)(>)')

        X = X.replace("&rlm;", "").replace("{\\an1}", "").replace("{\\an2}", "").replace("{\\an3}", "").replace("{\\an4}", "").\
            replace("{\\an5}", "").replace("{\\an6}", "").replace("{\\an7}", "").replace("{\\an8}", "").replace("{\\an9}", "").replace("¨", "¿").\
            replace("­", "¡").replace("&lrm;", "")
        X = pattern1.sub('', X)
        X = pattern2.sub('', X)
        return X

    def ReplaceSubs2(X):
        pattern1 = re.compile(r'(?!<i>|<b>|<u>|<\/i>|<\/b>|<\/u>)(<)(?:[A-Za-z0-9_ -=]*)(>)')
        pattern2 = re.compile(r'(?!<\/i>|<\/b>|<\/u>)(<\/)(?:[A-Za-z0-9_ -=]*)(>)')

        X = X.replace("&rlm;", "").replace("{\\an1}", "").replace("{\\an2}", "").replace("{\\an3}", "").replace("{\\an4}", "").\
            replace("{\\an6}", "").replace("{\\an7}", "").replace("{\\an9}", "").replace("¨", "¿").replace("­", "¡").replace("&lrm;", "")
        X = pattern1.sub('', X)
        X = pattern2.sub('', X)
        return X

    def ReplaceDontLikeWord(x):
        x = re.sub(r'[]¡!"#$%\'()*+,:;<=>¿?@\\^_`{|}~[-]', '', x)
        x = x.replace('\\', '').replace('/', ' & ')
        return titlecase(x)

    def find_str(s, char):
        index = 0

        if char in s:
            c = char[0]
            for ch in s:
                if ch == c:
                    if s[index:index+len(char)] == char:
                        return index

                index += 1

        return -1


    def mediainfo_(file):
        mediainfo_output = subprocess.Popen([MediaInfo_exe, '--Output=JSON', '-f', file], stdout=subprocess.PIPE)
        mediainfo_json = json.load(mediainfo_output.stdout)
        return mediainfo_json
        
    def mediainfo_ffprobe(file):
        mediainfo_output = subprocess.Popen([ffprobe_exe, "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", file], stdout=subprocess.PIPE)
        mediainfo_json = json.load(mediainfo_output.stdout)
        return mediainfo_json

    def getKeyId(name):
        mp4dump = subprocess.Popen([mp4dumptexe, name], stdout=subprocess.PIPE)
        mp4dump = str(mp4dump.stdout.read())
        A=find_str(mp4dump, "default_KID")
        KEY_ID_ORI=""
        KEY_ID_ORI=mp4dump[A:A+63].replace("default_KID = ", "").replace("[", "").replace("]", "").replace(" ", "")
        if KEY_ID_ORI == "" or KEY_ID_ORI == "'":
            KEY_ID_ORI = "nothing"
        return KEY_ID_ORI


    def substring(s, start, end):
        return s[start:end]

    def alphanumericSort(l):
        def convert(text): return int(text) if text.isdigit() else text
        def alphanum_key(key): return [ convert(c) for c in re.split("([0-9]+)", key) ]
        return sorted(l, key = alphanum_key)

    def downloadFile(link, file_name):
        print("\n" + file_name)
        aria_command = [aria2cexe, link,
                        '--user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"',
                        '--header="Range: bytes=0-"',
                        '--header="DNT: 1"',
                        f"--interface={args.bind_dl}",
                        '--async-dns=false',
                        '--enable-color=false',
                        '--allow-overwrite=true',
                        '--auto-file-renaming=false',
                        '--file-allocation=none',
                        '--summary-interval=0',
                        '--retry-wait=5',
                        '--uri-selector=inorder',
                        '--console-log-level=warn',
                        '-x16', '-j16', '-s16',
                        '-o', file_name]

        if sys.version_info >= (3, 5):
            aria_out = subprocess.run(aria_command)
            aria_out.check_returncode()
        else:
            aria_out = subprocess.call(aria_command)
            if aria_out != 0:
                raise ValueError("aria failed with exit code {}".format(aria_out))

    def downloadFile2(link, file_name):
        with open(file_name, "wb") as f:
            print("Downloading %s" % file_name)
            response = session.get(link, stream=True)
            total_length = response.headers.get('content-length')

            if total_length is None:  # no content length header
                f.write(response.content)
            else:
                dl = 0
                total_length = int(total_length)
                for data in response.iter_content(chunk_size=4096):
                    dl += len(data)
                    f.write(data)
                    done = int(50 * dl / total_length)
                    sys.stdout.write("\r[%s%s]" % ('=' * done, ' ' * (50 - done)))
                    sys.stdout.flush()



    def merge_lists(l1, l2, key):
        merged = {}
        for item in l1+l2:
            if item[key] in merged:
                merged[item[key]].update(item)
            else:
                merged[item[key]] = item
        return merged.values()


    def pp_json(json_thing, sort=True, indents=4):
        if type(json_thing) is str:
            print(json.dumps(json.loads(json_thing), sort_keys=sort, indent=indents))
        else:
            print(json.dumps(json_thing, sort_keys=sort, indent=indents))
        return None

    global folderdownloader
    if args.output:
        if not os.path.exists(args.output):
            os.makedirs(args.output)
        os.chdir(args.output)
        if ":" in str(args.output):
            folderdownloader = str(args.output).replace('/','\\').replace('.\\','\\')
        else:
            folderdownloader = dirPath + str(args.output).replace('/','\\').replace('.\\','\\')
    else:
        folderdownloader = dirPath.replace('/','\\').replace('.\\','\\')

    global video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password

    if args.region == "ps-int":
        print("ps-int region is no longer used, use ps instead.")
        sys.exit(1)

    if args.region == "ps":
        video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password = PrimevideoConfig.configPrimeVideo()
        region = "ps"

    if args.region == "us":
        video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password = PrimevideoConfig.configAmazonUS()
        region = "us"

    if args.region == "jp":
        video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password = PrimevideoConfig.configAmazonJP()
        region = "jp"

    if args.region == "uk":
        video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password = PrimevideoConfig.configAmazonUK()
        region = "uk"

    if args.region == "de":
        video_base_url, site_base_url, marketplace_id, cookies_file, clientId, email, password = PrimevideoConfig.configAmazonDE()
        region = "de"

    if args.cookies:
        cookies_file = f'{cookies_file[:-4]}_{args.cookies}.txt'

    def get_cookies():
        try:
            cj = http.cookiejar.MozillaCookieJar(dirPath + '/cookies/' + cookies_file)
            cj.load()
        except Exception:
            print("\nCookies not found! Please dump the cookies with the Chrome extension https://chrome.google.com/webstore/detail/cookiestxt/njabckikapfpffapmjgojcnbfjonfjfg and place the generated file in " + dirPath + '/cookies/' + cookies_file)
            print('\nWarning, do not click on "download all cookies", you have to click on "click here".\n')
            sys.exit(0)

        cookies = str()
        for cookie in cj:
            cookie.value = urllib.parse.unquote(html.unescape(cookie.value))
            cookies = cookies + cookie.name + '=' + cookie.value + ';'

        cookies = list(cookies)
        del cookies[-1]
        cookies = "".join(cookies)

        return cookies

    def parseCookieFile():
        cookies = {}
        with open (dirPath + '/cookies/' + cookies_file, 'r') as fp:
            for line in fp:
                if not re.match(r'^\#', line):
                    lineFields = line.strip().split('\t')
                    cookies[lineFields[5]] = lineFields[6]
        return cookies["csm-hit"].split('-')[-1].split('|')[0]

    cookies = get_cookies()
    #AMAZON_REQ_ID = parseCookieFile()


    custom_headers_GetPlaybackResources = {
                                            'Accept': 'application/json',
                                            'Accept-Encoding': 'gzip, deflate, br',
                                            'Accept-Language': 'es,ca;q=0.9,en;q=0.8',
                                            'Cache-Control': 'no-cache',
                                            'Connection': 'keep-alive',
                                            'Content-Type': 'application/x-www-form-urlencoded',
                                            'Pragma': 'no-cache',
                                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
                                            'Cookie': cookies}


    UserAgent = str("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36").encode('utf-8')
    global deviceID
    deviceID = hmac.new(UserAgent, uuid.uuid4().bytes, hashlib.sha224).hexdigest()

    def get_pv_baseurl(url, display_region=True):
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'Cookie': cookies,
        }

        # NOTE: For some unknown reason, if requests handles the redirects
        # it sometimes results in an extra redirect to the wrong region.
        # Handling redirects manually seems to fix the issue.
        r = session.get(url, headers=headers, allow_redirects=False)

        while 'location' in r.headers:
            r = session.get(r.headers['location'], headers=headers, allow_redirects=False)


        html_data = r.text
        #print(BeautifulSoup(html_data).prettify())

        pv_region = re.search(r'ue_furl *= *([\'"])fls-(na|eu|fe)\.amazon\.[a-z.]+\1', html_data).group(2)

        # This is not used, just informational
        pv_country = re.search(r'"currentTerritory": *"([^"]+)"', html_data).group(1)

        if display_region:
            print(f'PrimeVideo account region: {pv_region.upper()} (current location: {pv_country})')

        if pv_region == 'na':
            video_base_url = 'atv-ps.primevideo.com'
        elif pv_region == 'eu':
            video_base_url = 'atv-ps-eu.primevideo.com'
        elif pv_region == 'fe':
            video_base_url = 'atv-ps-fe.primevideo.com'

        return video_base_url, html_data



    def getLicenseTemp(asin, clientId):
        global licurl
        global params
        global url
        global video_base_url

        if region == "ps":
            video_base_url, html_data = get_pv_baseurl(f'https://primevideo.com/detail/{asin}')

            url = "https://" + video_base_url + "/cdp/catalog/GetPlaybackResources"
            if args.cbr_bitrate:
                params = dict(
                    asin=asin,
                    consumptionType="Streaming",
                    desiredResources="AudioVideoUrls,PlaybackUrls,CatalogMetadata,ForcedNarratives,SubtitlePresets,SubtitleUrls,TransitionTimecodes,TrickplayUrls,CuepointPlaylist,XRayMetadata,PlaybackSettings",
                    deviceID=deviceID,
                    deviceTypeID="AOAGZA014O5RE",
                    firmware="1",
                    gascEnabled="true",
                    marketplaceID=marketplace_id,
                    resourceUsage="CacheResources",
                    audioTrackId="all",
                    videoMaterialType="Feature",
                    operatingSystemName=operatingSystemName,
                    operatingSystemVersion=operatingSystemVersion,
                    deviceDrmOverride="CENC",
                    deviceStreamingTechnologyOverride="DASH",
                    deviceProtocolOverride="Https",
                    supportedDRMKeyScheme="DUAL_KEY",
                    deviceBitrateAdaptationsOverride="CBR",
                    titleDecorationScheme="primary-content",
                    subtitleFormat="TTMLv2",
                    languageFeature="MLFv2",
                    uxLocale=titlelang,
                    xrayDeviceClass="normal",
                    xrayPlaybackMode="playback",
                    xrayToken="INCEPTION_LITE_FILMO_V2",
                    playbackSettingsFormatVersion="1.0.0",
                    clientId=clientId
                    )

            else:
                params = dict(
                    asin=asin,
                    consumptionType="Streaming",
                    desiredResources="AudioVideoUrls,PlaybackUrls,CatalogMetadata,ForcedNarratives,SubtitlePresets,SubtitleUrls,TransitionTimecodes,TrickplayUrls,CuepointPlaylist,XRayMetadata,PlaybackSettings",
                    deviceID=deviceID,
                    deviceTypeID="AOAGZA014O5RE",
                    firmware="1",
                    gascEnabled="true",
                    marketplaceID=marketplace_id,
                    resourceUsage="CacheResources",
                    audioTrackId="all",
                    videoMaterialType="Feature",
                    operatingSystemName=operatingSystemName,
                    operatingSystemVersion=operatingSystemVersion,
                    deviceDrmOverride="CENC",
                    deviceStreamingTechnologyOverride="DASH",
                    deviceProtocolOverride="Https",
                    supportedDRMKeyScheme="DUAL_KEY",
                    deviceBitrateAdaptationsOverride="CVBR,CBR",
                    titleDecorationScheme="primary-content",
                    subtitleFormat="TTMLv2",
                    languageFeature="MLFv2",
                    uxLocale=titlelang,
                    xrayDeviceClass="normal",
                    xrayPlaybackMode="playback",
                    xrayToken="INCEPTION_LITE_FILMO_V2",
                    playbackSettingsFormatVersion="1.0.0",
                    clientId=clientId
                    )

        else:
            url = "https://" + video_base_url + "/cdp/catalog/GetPlaybackResources"
            if args.cbr_bitrate:
                params = dict(
                    asin=asin,
                    consumptionType="Streaming",
                    desiredResources="AudioVideoUrls,PlaybackUrls,CatalogMetadata,ForcedNarratives,SubtitlePresets,SubtitleUrls,TransitionTimecodes,TrickplayUrls,CuepointPlaylist,XRayMetadata,PlaybackSettings",
                    deviceID=deviceID,
                    deviceTypeID="AOAGZA014O5RE",
                    firmware="1",
                    gascEnabled="false",
                    marketplaceID=marketplace_id,
                    resourceUsage="CacheResources",
                    audioTrackId="all",
                    videoMaterialType="Feature",
                    operatingSystemName=operatingSystemName,
                    operatingSystemVersion=operatingSystemVersion,
                    clientId=clientId,
                    deviceDrmOverride="CENC",
                    deviceStreamingTechnologyOverride="DASH",
                    deviceProtocolOverride="Https",
                    supportedDRMKeyScheme="DUAL_KEY",
                    deviceBitrateAdaptationsOverride="CBR",
                    titleDecorationScheme="primary-content",
                    subtitleFormat="TTMLv2",
                    languageFeature="MLFv2",
                    uxLocale=titlelang,
                    xrayDeviceClass="normal",
                    xrayPlaybackMode="playback",
                    xrayToken="INCEPTION_LITE_FILMO_V2",
                    playbackSettingsFormatVersion="1.0.0"
                )

            else:
                params = dict(
                    asin=asin,
                    consumptionType="Streaming",
                    desiredResources="AudioVideoUrls,PlaybackUrls,CatalogMetadata,ForcedNarratives,SubtitlePresets,SubtitleUrls,TransitionTimecodes,TrickplayUrls,CuepointPlaylist,XRayMetadata,PlaybackSettings",
                    deviceID=deviceID,
                    deviceTypeID="AOAGZA014O5RE",
                    firmware="1",
                    gascEnabled="false",
                    marketplaceID=marketplace_id,
                    resourceUsage="CacheResources",
                    audioTrackId="all",
                    videoMaterialType="Feature",
                    operatingSystemName=operatingSystemName,
                    operatingSystemVersion=operatingSystemVersion,
                    clientId=clientId,
                    deviceDrmOverride="CENC",
                    deviceStreamingTechnologyOverride="DASH",
                    deviceProtocolOverride="Https",
                    supportedDRMKeyScheme="DUAL_KEY",
                    deviceBitrateAdaptationsOverride="CVBR,CBR",
                    titleDecorationScheme="primary-content",
                    subtitleFormat="TTMLv2",
                    languageFeature="MLFv2",
                    uxLocale=titlelang,
                    xrayDeviceClass="normal",
                    xrayPlaybackMode="playback",
                    xrayToken="INCEPTION_LITE_FILMO_V2",
                    playbackSettingsFormatVersion="1.0.0"
                )

        if args.hevc:
            params["deviceVideoCodecOverride"] = "H265"
        elif args.atmos:
            params["deviceVideoQualityOverride"] = "UHD"
            params["deviceHdrFormatsOverride"] = "Hdr10"


        resp = session.get(url=url, params=params, headers=custom_headers_GetPlaybackResources, proxies=proxy_cfg.get_proxy('meta'))
        #Error_Not_Avaiable = False
        try:
            data = json.loads(resp.text)
            licurl = url + "?" + urllib.parse.urlencode(params).replace("AudioVideoUrls%2CPlaybackUrls%2CCatalogMetadata%2CForcedNarratives%2CSubtitlePresets%2CSubtitleUrls%2CTransitionTimecodes%2CTrickplayUrls%2CCuepointPlaylist%2CXRayMetadata%2CPlaybackSettings", "Widevine2License")
            return data

        except ValueError:
            print(data)
            print("\nEpisode or Movie not available yet in your region. Possible VPN error.")
            #print(resp)
            #print("\n" + url + "?" + urllib.parse.urlencode(params))
            #Error_Not_Avaiable = True




    def get_cert2():
        custom_headers_license = {
                                    'Accept': 'application/json',
                                    'Accept-Encoding': 'gzip, deflate, br',
                                    'Accept-Language': 'es,ca;q=0.9,en;q=0.8',
                                    'Cache-Control': 'no-cache',
                                    'Connection': 'keep-alive',
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                    'Pragma': 'no-cache',
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
                                    'Cookie': cookies
                                }

        license_form_data = dict(
            widevine2Challenge='CAQ=',
            includeHdcpTestKeyInLicense="false"
            )
        license_res = session.post(url=licurl, data=license_form_data, headers=custom_headers_license, proxies=proxy_cfg.get_proxy('meta'))
        license_res_json = json.loads(license_res.text)

        try:
            license_base64 = license_res_json['widevine2License']['license']
            return license_base64
        except KeyError:
            try:
                print(license_res_json['errorsByResource']['Widevine2License'])
            except KeyError:
                print(license_res_json)

            raise

    def get_license2(challenge):
        custom_headers_license = {
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'es,ca;q=0.9,en;q=0.8',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Pragma': 'no-cache',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'Cookie': cookies
        }

        challenge_encoded = base64.b64encode(challenge)
        license_form_data = dict(
            widevine2Challenge=challenge_encoded,
            includeHdcpTestKeyInLicense="false"
            )
        license_res = session.post(url=licurl, data=license_form_data, headers=custom_headers_license, proxies=proxy_cfg.get_proxy('meta'))
        license_res_json = json.loads(license_res.text)
        try:
            license_base64 = license_res_json['widevine2License']['license']
        except KeyError:
            try:
                print(license_res_json['errorsByResource']['Widevine2License'])
            except KeyError:
                print(license_res_json)

            license_base64 = "Error"

        return license_base64


    def do_decrypt(init_data_b64, cert_data_b64, device, asin):
        if device:
            wvdecrypt = WvDecrypt(init_data_b64=init_data_b64, cert_data_b64=cert_data_b64, device=device)
            chal = wvdecrypt.get_challenge()
            license_b64 = get_license2(chal)
            if license_b64 != 'Error':
                wvdecrypt.update_license(license_b64)
                wvdecrypt.start_process()
                Correct, keyswvdecrypt = wvdecrypt.start_process()
                return Correct, keyswvdecrypt
            else:
                keyswvdecrypt = []
                Correct = True
                return Correct, keyswvdecrypt
        else:
            sys.path.append('/opt/wvapi')
            from wvapi import WVAPI
            from wvapiconfig import apiurl, uk, ak

            pssh_raw = base64.b64decode(init_data_b64)
            kid = pssh_raw[pssh_raw.index(b'id:')+3:pssh_raw.rindex(b'*')].split(b',')

            args = ['pssh-box.py', '--base64', '--widevine-system-id']
            for k in kid:
                args += ['--key-id', bytes.hex(base64.b64decode(k))]

            pssh_new = subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()

            with WVAPI(apiurl, uk, ak) as wvapi:
                j = wvapi.gc(pssh_new, asin)
                # cached pssh
                if 'keys' in j:
                    #print(j['keys'])
                    return True, [f'{x["kid"]}:{x["key"]}' for x in j['keys']]

                if 'challenge' not in j:
                    print("fail")
                    exit(1)

                #print(j['challenge'] + '\n\n')
                lic = get_license2(base64.b64decode(j['challenge']))
                print(lic + '\n\n')

                j = wvapi.gk(pssh_new, lic)
                #print(j['keys'])
                return True, [f'{x["kid"]}:{x["key"]}' for x in j['keys']]

    #___________________________________________________________________________________________________________________

    def DownloadAll(asin):
        def GetKey(pssh):
            Correct = False
            keys_new=[]
            certb64 = get_cert2()

            if user_config['device']:
                device = getattr(deviceconfig, user_config['device'])
            else:
                device = None

            while Correct is False:
                Correct, keys_new = do_decrypt(init_data_b64=bytes(pssh.encode()), cert_data_b64=certb64, device=device, asin=asin)

            return keys_new

        def DecryptAudio(inputAudio, keys_audio):
            key_audio_id_original = getKeyId(inputAudio)
            outputAudioTemp = inputAudio.replace(".mp4", "_dec.mp4")
            if key_audio_id_original != "nothing":
                for key in keys_audio:
                    key_id=key[0:32]
                    #key_key=key[33:]
                    if key_id == key_audio_id_original:
                        print("\nDecrypting audio...")
                        print ("Using KEY: " + key)
                        wvdecrypt_process = subprocess.Popen([mp4decryptexe, "--show-progress", "--key", key, inputAudio, outputAudioTemp])
                        stdoutdata, stderrdata = wvdecrypt_process.communicate()
                        wvdecrypt_process.wait()
                        time.sleep (50.0/1000.0)
                        os.remove(inputAudio)
                        print("\nDemuxing audio...")
                        mediainfo = mediainfo_(outputAudioTemp)
                        for m in mediainfo['media']['track']:
                            if m['@type'] == 'Audio':
                                codec_name = m['Format']
                                try:
                                    codec_tag_string = m['Format_Commercial_IfAny']
                                except Exception:
                                    codec_tag_string = ''
                        ext = ''
                        if codec_name == "AAC":
                            ext = '.m4a'
                        elif codec_name == "E-AC-3":
                            ext = ".eac3"
                        elif codec_name == "AC-3":
                            ext = ".ac3"
                        outputAudio = outputAudioTemp.replace("_dec.mp4", ext)
                        print("{} -> {}".format(outputAudioTemp, outputAudio))
                        ff = ffmpy.FFmpeg(executable=ffmpegpath, inputs={outputAudioTemp: None}, outputs={outputAudio: '-c copy'}, global_options="-y -hide_banner -loglevel warning")
                        ff.run()
                        time.sleep (50.0/1000.0)
                        os.remove(outputAudioTemp)
                        print("Done!")
                        return True

            elif key_audio_id_original == "nothing":
                return True


        def DecryptVideo(inputVideo, keys_video):
            key_video_id_original = getKeyId(inputVideo)
            inputVideo = inputVideo
            outputVideoTemp = inputVideo.replace(".mp4", "_dec.mp4")
            outputVideo = inputVideo
            if key_video_id_original != "nothing":
                for key in keys_video:
                    key_id=key[0:32]
                    #key_key=key[33:]
                    if key_id == key_video_id_original:
                        print("\nDecrypting video...")
                        print ("Using KEY: " + key)
                        wvdecrypt_process = subprocess.Popen([mp4decryptexe, "--show-progress", "--key", key, inputVideo, outputVideoTemp])
                        stdoutdata, stderrdata = wvdecrypt_process.communicate()
                        wvdecrypt_process.wait()
                        print("\nRemuxing video...")
                        ff = ffmpy.FFmpeg(executable=ffmpegpath, inputs={outputVideoTemp: None}, outputs={outputVideo: '-c copy'}, global_options="-y -hide_banner -loglevel warning")
                        ff.run()
                        time.sleep (50.0/1000.0)
                        os.remove(outputVideoTemp)
                        print("Done!")
                        return True

            elif key_video_id_original == "nothing":
                return True


        def getKeyId_v2(name):
            mp4dump = subprocess.Popen([mp4dumptexe, name], stdout=subprocess.PIPE)
            mp4dump = str(mp4dump.stdout.read())
            A=find_str(mp4dump, "default_KID")
            KID=mp4dump[A:A+63].replace("default_KID = ", "").replace("[", "").replace("]", "").replace(" ", "")
            KID = KID.upper()
            KID = KID[0:8] + "-" + KID[8:12] + "-" + KID[12:16] + "-" + KID[16:20] + "-" + KID[20:32]
            if KID == "":
                KID = "nothing"
            return KID

        def Get_PSSH(mp4_file):
            WV_SYSTEM_ID = '[ed ef 8b a9 79 d6 4a ce a3 c8 27 dc d5 1d 21 ed]'
            pssh = None
            data = subprocess.check_output([mp4dumptexe, '--format', 'json', '--verbosity', '1', mp4_file])
            data = json.loads(data)
            for atom in data:
                if atom['name'] == 'moov':
                    for child in atom['children']:
                        if child['name'] == 'pssh' and child['system_id'] == WV_SYSTEM_ID:
                            pssh = child['data'][1:-1].replace(' ', '')
                            pssh = binascii.unhexlify(pssh)
                            if pssh.startswith(b'\x08\x01'):
                                pssh = pssh[0:]
                            pssh = base64.b64encode(pssh).decode('utf-8')
                            return pssh

            if not pssh:
                #print('Unable to extract PSSH')
                pssh = "Error"
                return pssh

        def get_cert():
            custom_headers_license = {
                                        'Accept': 'application/json',
                                        'Accept-Encoding': 'gzip, deflate, br',
                                        'Accept-Language': 'es,ca;q=0.9,en;q=0.8',
                                        'Cache-Control': 'no-cache',
                                        'Connection': 'keep-alive',
                                        'Content-Type': 'application/x-www-form-urlencoded',
                                        'Pragma': 'no-cache',
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
                                        'Cookie': cookies
                                    }

            license_form_data = dict(
                widevine2Challenge='CAQ=',
                includeHdcpTestKeyInLicense="false")

            license_res = session.post(url=licurl, data=license_form_data, headers=custom_headers_license, proxies=proxy_cfg.get_proxy('meta'))
            license_res_json = json.loads(license_res.text)

            try:
                license_base64 = license_res_json['widevine2License']['license']
                return license_base64
            except KeyError:
                try:
                    print(license_res_json['errorsByResource']['Widevine2License'])
                except KeyError:
                    print(license_res_json)

                raise

        def get_license(challenge):
            custom_headers_license = {
                                        'Accept': 'application/json',
                                        'Accept-Encoding': 'gzip, deflate, br',
                                        'Accept-Language': 'es,ca;q=0.9,en;q=0.8',
                                        'Cache-Control': 'no-cache',
                                        'Connection': 'keep-alive',
                                        'Content-Type': 'application/x-www-form-urlencoded',
                                        'Pragma': 'no-cache',
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
                                        'Cookie': cookies
                                    }
            
            challenge_encoded = base64.b64encode(challenge)
            license_form_data = dict(
                widevine2Challenge=challenge_encoded,
                includeHdcpTestKeyInLicense="false")

            license_res = session.post(url=licurl, data=license_form_data, headers=custom_headers_license, proxies=proxy_cfg.get_proxy('meta'))
            license_res_json = json.loads(license_res.text)
            
            if 'errorCode' in str(license_res_json):
                print()
                os.system("taskkill /im wvDecrypter.exe /f")
                if os.path.isfile(mpd_file) and not args.keep:
                    os.remove(mpd_file)
                print(license_res_json)
            license_base64 = license_res_json['widevine2License']['license']
            #license_decoded = base64.b64decode(license_base64)
            return license_base64

        def DecryptAlternativeV2(PSSH, FInput, Type):
            KID = getKeyId_v2(FInput)
            PSSH_file = Get_PSSH(FInput)

            if PSSH_file == "Error":
                PSSH = PSSH
            else:
                PSSH = PSSH_file

            if KID != "nothing":
                if Type == "audio":
                    print("\nDecrypting audio...")
                    mediainfo = subprocess.Popen([ffprobepath, "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", FInput], stdout=subprocess.PIPE)
                    mediainfo = json.load(mediainfo.stdout)
                    codec_name = mediainfo["streams"][0]["codec_name"]
                    codec_tag_string = mediainfo["streams"][0]["codec_tag_string"]
                    ext = ".test"
                    if codec_name == "aac":
                        ext = ".m4a"
                    elif codec_name == "ac3" or codec_name == "eac3":
                        if codec_tag_string == "ec-3":
                            ext = ".eac3"
                        else:
                            ext = ".ac3"
                    else:
                        print(mediainfo)
                    FOutput_temp = FInput.replace(".mp4", "_dec.mp4")
                    FOutput = FInput.replace(".mp4", ext)

                elif Type == "video":
                    print("\nDecrypting video...")
                    mediainfo = subprocess.Popen([ffprobepath, "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", FInput], stdout=subprocess.PIPE)
                    mediainfo = json.load(mediainfo.stdout)
                    codec_name = mediainfo["streams"][0]["codec_name"]
                    codec_tag_string = mediainfo["streams"][0]["codec_tag_string"]
                    ext = ".test"
                    if codec_name == "h264":
                        ext = ".h264"
                    elif codec_name == "hevc":
                        ext = ".h265"
                    else:
                        print(mediainfo)
                    FOutput_temp = FInput.replace(".mp4", "_dec.mp4")
                    FOutput = FInput.replace(".mp4", ".mp4")

                if os.path.isfile(challengeBIN): os.remove(challengeBIN)
                if os.path.isfile(licenceBIN): os.remove(licenceBIN)

                certb64 = get_cert()

                wvdecrypt_video = subprocess.Popen([wvDecrypterexe, '--kid', KID, '--pssh', PSSH, '--certificate', certb64, '--input', FInput, '--output', FOutput_temp])

                while not os.path.isfile(challengeBIN):
                    time.sleep(1)

                with open(challengeBIN, "rb") as fd:
                    challenge_decoded = fd.read()

                license_b64 = get_license(challenge_decoded).encode()

                with open(licenceBIN, "wb") as ld:
                    ld.write(license_b64)

                stdoutdata, stderrdata = wvdecrypt_video.communicate()

                if str(wvdecrypt_video.returncode) == "0":
                    if os.path.isfile(challengeBIN): os.remove(challengeBIN)
                    if os.path.isfile(licenceBIN): os.remove(licenceBIN)
                    os.remove(FInput)
                    if Type == "audio":
                        print("\nDemuxing audio...")
                        ff = ffmpy.FFmpeg(executable=ffmpegpath, inputs={FOutput_temp: None}, outputs={FOutput: '-c copy'}, global_options="-y -hide_banner -loglevel warning")
                        ff.run()
                        time.sleep (50.0/1000.0)
                        os.remove(FOutput_temp)
                        print("Done!")
                    elif Type == "video":
                        print("\nRemuxing video...")
                        ff = ffmpy.FFmpeg(executable=ffmpegpath, inputs={FOutput_temp: None}, outputs={FOutput: '-c copy'}, global_options="-y -hide_banner -loglevel warning")
                        ff.run()
                        time.sleep (50.0/1000.0)
                        os.remove(FOutput_temp)
                        print("Done!")

                    return True

                else:
                    print("\nError in decryption!")
                    return False

            else:
                return True



        def GettingMPD(data):
            if args.nompd:
                return

            global mpd_url
            #Error_Not_Avaiable = False
            mpd_url = ""
            #print(data["audioVideoUrls"]["avCdnUrlSets"])
            try:
                if mpd_url == "":
                    for x in data["audioVideoUrls"]["avCdnUrlSets"]:
                        if x['cdn'] == 'Akamai':
                            for y in x['avUrlInfoList']:
                                mpd = re.split("(/)(?i)", y['url'])
                                del mpd[5:9]
                                mpd_url = "".join(mpd)

            except KeyError:
                print(data)
                print("\nEpisode or Movie not available yet in your region. Possible VPN error.")
                #Error_Not_Avaiable = True

            try:
                print(f'Detected encodingVersion={next(iter(data["playbackUrls"]["urlSets"].values()))["urls"]["manifest"]["encodingVersion"]}')
            except (KeyError, StopIteration):
                print('Unable to detect encodingVersion')

            print(mpd_url)
            global mpd_file
            if args.hevc:
                mpd_file = seriesName + " [HEVC].mpd"
            elif args.atmos:
                mpd_file = seriesName + " [HEVC-atmos].mpd"
            elif args.cbr_bitrate:
                mpd_file = seriesName + " [CBR].mpd"
            else:
                mpd_file = seriesName + ".mpd"
            if QualityGlobal == 'SD':
                mpd_file = mpd_file.replace('.mpd', '_SD.mpd')

            r = requests.get(url=mpd_url)
            xml = xmltodict.parse(r.text)
            mpd = json.loads(json.dumps(xml))

            base_url = re.split("(/)(?i)", mpd_url)
            del base_url[-1]
            base_url = "".join(base_url)

            return mpd_url, base_url, mpd

        def ParsingMPD(mpd, height):
            def get_height(width, height):
                if width == '1920':
                    return '1080'
                elif width in ('1280', '1248'):
                    return '720'
                else:
                    return height

            height_all = []
            video_urls = []
            audioList = []
            novideo = False
            global video_pssh, audio_pssh
            video_pssh = str()
            audio_pssh = str()
            try:
                try:
                    if args.customquality:
                        for x in mpd["MPD"]["Period"]["AdaptationSet"]:
                            if x["@mimeType"].startswith("video"):
                                for z in x["ContentProtection"]:
                                    if z["@schemeIdUri"] == "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED":
                                        video_pssh = z["cenc:pssh"]
                                        for y in x["Representation"]:
                                            vid_height = get_height(y["@width"], y["@height"])
                                            height_all.append(vid_height)
                                            try:
                                                if height == vid_height:
                                                    video_urls.append(y["BaseURL"])
                                            except Exception:
                                                continue
                    else:
                        for x in mpd["MPD"]["Period"]["AdaptationSet"]:
                            if x["@mimeType"].startswith("video"):
                                for z in x["ContentProtection"]:
                                    if z["@schemeIdUri"] == "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED":
                                        video_pssh = z["cenc:pssh"]
                                        for y in x["Representation"]:
                                            vid_height = get_height(y["@width"], y["@height"])
                                            height_all.append(vid_height)
                                            video_urls.append(y["BaseURL"])

                    for x in mpd["MPD"]["Period"]["AdaptationSet"]:
                        if x["@mimeType"].startswith("audio"):
                            if args.desc_audio:
                                if x.get("@audioTrackSubtype") != "descriptive":
                                    continue
                            else:
                                if x.get("@audioTrackSubtype") == "descriptive":
                                    continue

                            for z in x["ContentProtection"]:
                                if z["@schemeIdUri"] == "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED":
                                    audio_pssh = z.get("cenc:pssh")
                                    if isinstance(x['Representation'], list):
                                        rep = x['Representation']
                                    else:
                                        rep = [x['Representation']]

                                    for y in rep:
                                        is_2ch = (y['AudioChannelConfiguration']['@value'] in ('2', 'A000'))


                                        if (not is_2ch) and args.only_2ch_audio:
                                            continue

                                        if is_2ch and args.aformat_2ch == 'aac' and not y['@codecs'].startswith('mp4a'):
                                            continue

                                        if OnlyOneAudio == True:
                                            audioDict = (OnlyOneAudioID, y["BaseURL"])
                                        else:
                                            audioDict = (ReplaceCodeLanguages(x["@audioTrackId"]), y["BaseURL"])
                                        audioList.append(audioDict)
                except Exception:
                    if args.customquality:
                        for x in mpd["MPD"]["Period"]["AdaptationSet"]:
                            if x["@mimeType"].startswith("video"):
                                for z in x["ContentProtection"]:
                                    if z["@schemeIdUri"] == "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED":
                                        video_pssh = z["cenc:pssh"]
                                        for y in x["Representation"]:
                                            vid_height = get_height(y["@width"], y["@height"])
                                            height_all.append(vid_height)
                                            try:
                                                if height == vid_height:
                                                    video_urls.append(y["BaseURL"])
                                            except Exception:
                                                continue
                    else:
                        for x in mpd["MPD"]["Period"]["AdaptationSet"]:
                            if x["@mimeType"].startswith("video"):
                                for z in x["ContentProtection"]:
                                    if z["@schemeIdUri"] == "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED":
                                        video_pssh = z["cenc:pssh"]
                                        for y in x["Representation"]:
                                            vid_height = get_height(y["@width"], y["@height"])
                                            height_all.append(vid_height)
                                            video_urls.append(y["BaseURL"])

                    try:
                        for x in mpd["MPD"]["Period"]["AdaptationSet"]:
                            if x["@mimeType"].startswith("audio"):
                                if args.desc_audio:
                                    if x.get("@audioTrackSubtype") != "descriptive":
                                        continue
                                else:
                                    if x.get("@audioTrackSubtype") == "descriptive":
                                        continue

                                for z in x["ContentProtection"]:
                                    if z["@schemeIdUri"] == "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED" and z["cenc:pssh"] != video_pssh:
                                        audio_pssh = z["cenc:pssh"]
                                        if not args.only_2ch_audio:
                                            try:
                                                for y in x["Representation"]:
                                                    if OnlyOneAudio == True:
                                                        audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                    else:
                                                        audioDict = (ReplaceCodeLanguages(x["@lang"]), y["BaseURL"])
                                                    audioList.append(audioDict)
                                            except Exception:
                                                if OnlyOneAudio == True:
                                                    audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                                else:
                                                    audioDict = (ReplaceCodeLanguages(x["@lang"]), x["Representation"]["BaseURL"])
                                                audioList.append(audioDict)

                                        else:
                                            try:
                                                for y in x["Representation"]:
                                                    if y["@bandwidth"] == '224000':
                                                        if OnlyOneAudio == True:
                                                            audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                        else:
                                                            audioDict = (ReplaceCodeLanguages(x["@lang"]), y["BaseURL"])
                                                        audioList.append(audioDict)
                                            except Exception:
                                                if x["Representation"]["@bandwidth"] == '224000':
                                                    if OnlyOneAudio == True:
                                                        audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                                    else:
                                                        audioDict = (ReplaceCodeLanguages(x["@lang"]), x["Representation"]["BaseURL"])
                                                    audioList.append(audioDict)


                                    elif z["@schemeIdUri"] == "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED" and z["cenc:pssh"] == video_pssh:
                                        audio_pssh = z["cenc:pssh"]
                                        if not args.only_2ch_audio:
                                            try:
                                                for y in x["Representation"]:
                                                    if OnlyOneAudio == True:
                                                        audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                    else:
                                                        audioDict = (ReplaceCodeLanguages(x["@lang"]), y["BaseURL"])
                                                    audioList.append(audioDict)
                                            except Exception:
                                                if OnlyOneAudio == True:
                                                    audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                                else:
                                                    audioDict = (ReplaceCodeLanguages(x["@lang"]), x["Representation"]["BaseURL"])
                                                audioList.append(audioDict)
                                        else:
                                            try:
                                                for y in x["Representation"]:
                                                    if y["@bandwidth"] == '224000':
                                                        if OnlyOneAudio == True:
                                                            audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                        else:
                                                            audioDict = (ReplaceCodeLanguages(x["@lang"]), y["BaseURL"])
                                                        audioList.append(audioDict)
                                            except Exception:
                                                if x["Representation"]["@bandwidth"] == '224000':
                                                    if OnlyOneAudio == True:
                                                        audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                                    else:
                                                        audioDict = (ReplaceCodeLanguages(x["@lang"]), x["Representation"]["BaseURL"])
                                                    audioList.append(audioDict)

                    except Exception:
                        for x in mpd["MPD"]["Period"]["AdaptationSet"]:
                            if x["@mimeType"].startswith("audio"):
                                if args.desc_audio:
                                    if x.get("@audioTrackSubtype") != "descriptive":
                                        continue
                                else:
                                    if x.get("@audioTrackSubtype") == "descriptive":
                                        continue

                                if not args.only_2ch_audio:
                                    try:
                                        for y in x["Representation"]:
                                            if OnlyOneAudio == True:
                                                audioDict = (OnlyOneAudioID, y["BaseURL"])
                                            else:
                                                audioDict = (ReplaceCodeLanguages(x["@audioTrackId"]), y["BaseURL"])
                                            audioList.append(audioDict)

                                    except Exception:
                                        if OnlyOneAudio == True:
                                            audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                        else:
                                            audioDict = (ReplaceCodeLanguages(x["@audioTrackId"]), x["Representation"]["BaseURL"])
                                        audioList.append(audioDict)

                                else:
                                    try:
                                        for y in x["Representation"]:
                                            if y["@bandwidth"] == '224000':
                                                if OnlyOneAudio == True:
                                                    audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                else:
                                                    audioDict = (ReplaceCodeLanguages(x["@audioTrackId"]), y["BaseURL"])
                                                audioList.append(audioDict)

                                    except Exception:
                                        if x["Representation"]["@bandwidth"] == '224000':
                                            if OnlyOneAudio == True:
                                                audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                            else:
                                                audioDict = (ReplaceCodeLanguages(x["@audioTrackId"]), x["Representation"]["BaseURL"])
                                            audioList.append(audioDict)


            except Exception:
                try:
                    for x in mpd["MPD"]["Period"]["AdaptationSet"]:
                        if x["@mimeType"].startswith("audio"):
                            if args.desc_audio:
                                if x.get("@audioTrackSubtype") != "descriptive":
                                    continue
                            else:
                                if x.get("@audioTrackSubtype") == "descriptive":
                                    continue

                            if not args.only_2ch_audio:
                                try:
                                    for y in x["Representation"]:
                                        if OnlyOneAudio == True:
                                            audioDict = (OnlyOneAudioID, y["BaseURL"])
                                        else:
                                            audioDict = (ReplaceCodeLanguages(x["@audioTrackId"]), y["BaseURL"])
                                        audioList.append(audioDict)

                                except Exception:
                                    if OnlyOneAudio == True:
                                        audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                    else:
                                        audioDict = (ReplaceCodeLanguages(x["@audioTrackId"]), x["Representation"]["BaseURL"])
                                    audioList.append(audioDict)

                            else:
                                try:
                                    for y in x["Representation"]:
                                        if y["@bandwidth"] == '224000':
                                            if OnlyOneAudio == True:
                                                audioDict = (OnlyOneAudioID, y["BaseURL"])
                                            else:
                                                audioDict = (ReplaceCodeLanguages(x["@audioTrackId"]), y["BaseURL"])
                                            audioList.append(audioDict)

                                except Exception:
                                    if x["Representation"]["@bandwidth"] == '224000':
                                        if OnlyOneAudio == True:
                                            audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                        else:
                                            audioDict = (ReplaceCodeLanguages(x["@audioTrackId"]), x["Representation"]["BaseURL"])
                                        audioList.append(audioDict)

                except Exception:
                    try:
                        for x in mpd["MPD"]["Period"]["AdaptationSet"]:
                            if x["@mimeType"].startswith("audio"):
                                if args.desc_audio:
                                    if x.get("@audioTrackSubtype") != "descriptive":
                                        continue
                                else:
                                    if x.get("@audioTrackSubtype") == "descriptive":
                                        continue

                                for z in x["ContentProtection"]:
                                    if z["@schemeIdUri"] == "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED" and z["cenc:pssh"] != video_pssh:
                                        audio_pssh = z["cenc:pssh"]
                                        if not args.only_2ch_audio:
                                            try:
                                                for y in x["Representation"]:
                                                    if OnlyOneAudio == True:
                                                        audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                    else:
                                                        audioDict = (ReplaceCodeLanguages(x["@lang"]), y["BaseURL"])
                                                    audioList.append(audioDict)
                                            except Exception:
                                                if OnlyOneAudio == True:
                                                    audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                                else:
                                                    audioDict = (ReplaceCodeLanguages(x["@lang"]), x["Representation"]["BaseURL"])
                                                audioList.append(audioDict)

                                        else:
                                            try:
                                                for y in x["Representation"]:
                                                    if y["@bandwidth"] == '224000':
                                                        if OnlyOneAudio == True:
                                                            audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                        else:
                                                            audioDict = (ReplaceCodeLanguages(x["@lang"]), y["BaseURL"])
                                                        audioList.append(audioDict)
                                            except Exception:
                                                if x["Representation"]["@bandwidth"] == '224000':
                                                    if OnlyOneAudio == True:
                                                        audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                                    else:
                                                        audioDict = (ReplaceCodeLanguages(x["@lang"]), x["Representation"]["BaseURL"])
                                                    audioList.append(audioDict)

                                    elif z["@schemeIdUri"] == "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED" and z["cenc:pssh"] == video_pssh:
                                        audio_pssh = z["cenc:pssh"]
                                        if not args.only_2ch_audio:
                                            try:
                                                for y in x["Representation"]:
                                                    if OnlyOneAudio == True:
                                                        audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                    else:
                                                        audioDict = (ReplaceCodeLanguages(x["@lang"]), y["BaseURL"])
                                                    audioList.append(audioDict)
                                            except Exception:
                                                if OnlyOneAudio == True:
                                                    audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                                else:
                                                    audioDict = (ReplaceCodeLanguages(x["@lang"]), x["Representation"]["BaseURL"])
                                                audioList.append(audioDict)
                                        else:
                                            try:
                                                for y in x["Representation"]:
                                                    if y["@bandwidth"] == '224000':
                                                        if OnlyOneAudio == True:
                                                            audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                        else:
                                                            audioDict = (ReplaceCodeLanguages(x["@lang"]), y["BaseURL"])
                                                        audioList.append(audioDict)
                                            except Exception:
                                                if x["Representation"]["@bandwidth"] == '224000':
                                                    if OnlyOneAudio == True:
                                                        audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                                    else:
                                                        audioDict = (ReplaceCodeLanguages(x["@lang"]), x["Representation"]["BaseURL"])
                                                    audioList.append(audioDict)
                    except Exception:
                        try:
                            for x in mpd["MPD"]["Period"]["AdaptationSet"]:
                                if x["@mimeType"].startswith("audio"):
                                    if args.desc_audio:
                                        if x.get("@audioTrackSubtype") != "descriptive":
                                            continue
                                    else:
                                        if x.get("@audioTrackSubtype") == "descriptive":
                                            continue

                                    if not args.only_2ch_audio:
                                        try:
                                            for y in x["Representation"]:
                                                if OnlyOneAudio == True:
                                                    audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                else:
                                                    audioDict = (ReplaceCodeLanguages(x["@lang"]), y["BaseURL"])
                                                audioList.append(audioDict)

                                        except Exception:
                                            if OnlyOneAudio == True:
                                                audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                            else:
                                                audioDict = (ReplaceCodeLanguages(x["@lang"]), x["Representation"]["BaseURL"])
                                            audioList.append(audioDict)

                                    else:
                                        try:
                                            for y in x["Representation"]:
                                                if y["@bandwidth"] == '224000':
                                                    if OnlyOneAudio == True:
                                                        audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                    else:
                                                        audioDict = (ReplaceCodeLanguages(x["@lang"]), y["BaseURL"])
                                                    audioList.append(audioDict)

                                        except Exception:
                                            if x["Representation"]["@bandwidth"] == '224000':
                                                if OnlyOneAudio == True:
                                                    audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                                else:
                                                    audioDict = (ReplaceCodeLanguages(x["@lang"]), x["Representation"]["BaseURL"])
                                                audioList.append(audioDict)

                        except Exception:
                            try:
                                for x in mpd["MPD"]["Period"]["AdaptationSet"]:
                                    if x["@mimeType"].startswith("audio"):
                                        if args.desc_audio:
                                            if x.get("@audioTrackSubtype") != "descriptive":
                                                continue
                                        else:
                                            if x.get("@audioTrackSubtype") == "descriptive":
                                                continue

                                        if not args.only_2ch_audio:
                                            try:
                                                for y in x["Representation"]:
                                                    if OnlyOneAudio == True:
                                                        audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                    else:
                                                        audioDict = ("en", y["BaseURL"])
                                                    audioList.append(audioDict)

                                            except Exception:
                                                if OnlyOneAudio == True:
                                                    audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                                else:
                                                    audioDict = ("en", x["Representation"]["BaseURL"])
                                                audioList.append(audioDict)

                                        else:
                                            try:
                                                for y in x["Representation"]:
                                                    if y["@bandwidth"] == '224000':
                                                        if OnlyOneAudio == True:
                                                            audioDict = (OnlyOneAudioID, y["BaseURL"])
                                                        else:
                                                            audioDict = ("en", y["BaseURL"])
                                                        audioList.append(audioDict)

                                            except Exception:
                                                if x["Representation"]["@bandwidth"] == '224000':
                                                    if OnlyOneAudio == True:
                                                        audioDict = (OnlyOneAudioID, x["Representation"]["BaseURL"])
                                                    else:
                                                        audioDict = ("en", x["Representation"]["BaseURL"])
                                                    audioList.append(audioDict)

                            except Exception:
                                print("Audio not supported.")
                                raise

            return height_all, video_urls, audioList, novideo, video_pssh, audio_pssh

        def getLicense(asin, clientId):
            global licurl
            global params
            global url
            if region == "ps" or region == "ps-int":
                url = "https://" + video_base_url + "/cdp/catalog/GetPlaybackResources"
                if args.cbr_bitrate:
                    params = dict(
                        asin=asin,
                        consumptionType="Streaming",
                        desiredResources="AudioVideoUrls,PlaybackUrls,CatalogMetadata,ForcedNarratives,SubtitlePresets,SubtitleUrls,TransitionTimecodes,TrickplayUrls,CuepointPlaylist,XRayMetadata,PlaybackSettings",
                        deviceID=deviceID,
                        deviceTypeID="AOAGZA014O5RE",
                        firmware="1",
                        gascEnabled="true",
                        marketplaceID=marketplace_id,
                        resourceUsage="CacheResources",
                        audioTrackId="all",
                        videoMaterialType="Feature",
                        operatingSystemName=operatingSystemName,
                        operatingSystemVersion=operatingSystemVersion,
                        deviceDrmOverride="CENC",
                        deviceStreamingTechnologyOverride="DASH",
                        deviceProtocolOverride="Https",
                        supportedDRMKeyScheme="DUAL_KEY",
                        deviceBitrateAdaptationsOverride="CBR",
                        titleDecorationScheme="primary-content",
                        subtitleFormat="TTMLv2",
                        languageFeature="MLFv2",
                        uxLocale=titlelang,
                        xrayDeviceClass="normal",
                        xrayPlaybackMode="playback",
                        xrayToken="INCEPTION_LITE_FILMO_V2",
                        playbackSettingsFormatVersion="1.0.0",
                        clientId=clientId
                        )

                else:
                    params = dict(
                        asin=asin,
                        consumptionType="Streaming",
                        desiredResources="AudioVideoUrls,PlaybackUrls,CatalogMetadata,ForcedNarratives,SubtitlePresets,SubtitleUrls,TransitionTimecodes,TrickplayUrls,CuepointPlaylist,XRayMetadata,PlaybackSettings",
                        deviceID=deviceID,
                        deviceTypeID="AOAGZA014O5RE",
                        firmware="1",
                        gascEnabled="true",
                        marketplaceID=marketplace_id,
                        resourceUsage="CacheResources",
                        audioTrackId="all",
                        videoMaterialType="Feature",
                        operatingSystemName=operatingSystemName,
                        operatingSystemVersion=operatingSystemVersion,
                        deviceDrmOverride="CENC",
                        deviceStreamingTechnologyOverride="DASH",
                        deviceProtocolOverride="Https",
                        supportedDRMKeyScheme="DUAL_KEY",
                        deviceBitrateAdaptationsOverride="CVBR,CBR",
                        titleDecorationScheme="primary-content",
                        subtitleFormat="TTMLv2",
                        languageFeature="MLFv2",
                        uxLocale=titlelang,
                        xrayDeviceClass="normal",
                        xrayPlaybackMode="playback",
                        xrayToken="INCEPTION_LITE_FILMO_V2",
                        playbackSettingsFormatVersion="1.0.0",
                        clientId=clientId
                        )

            else:
                url = "https://" + video_base_url + "/cdp/catalog/GetPlaybackResources"
                if args.cbr_bitrate:
                    params = dict(
                        asin=asin,
                        consumptionType="Streaming",
                        desiredResources="AudioVideoUrls,PlaybackUrls,CatalogMetadata,ForcedNarratives,SubtitlePresets,SubtitleUrls,TransitionTimecodes,TrickplayUrls,CuepointPlaylist,XRayMetadata,PlaybackSettings",
                        deviceID=deviceID,
                        deviceTypeID="AOAGZA014O5RE",
                        firmware="1",
                        gascEnabled="false",
                        marketplaceID=marketplace_id,
                        resourceUsage="CacheResources",
                        audioTrackId="all",
                        videoMaterialType="Feature",
                        operatingSystemName=operatingSystemName,
                        operatingSystemVersion=operatingSystemVersion,
                        clientId=clientId,
                        deviceDrmOverride="CENC",
                        deviceStreamingTechnologyOverride="DASH",
                        deviceProtocolOverride="Https",
                        supportedDRMKeyScheme="DUAL_KEY",
                        deviceBitrateAdaptationsOverride="CBR",
                        titleDecorationScheme="primary-content",
                        subtitleFormat="TTMLv2",
                        languageFeature="MLFv2",
                        uxLocale=titlelang,
                        xrayDeviceClass="normal",
                        xrayPlaybackMode="playback",
                        xrayToken="INCEPTION_LITE_FILMO_V2",
                        playbackSettingsFormatVersion="1.0.0"
                    )

                else:
                    params = dict(
                        asin=asin,
                        consumptionType="Streaming",
                        desiredResources="AudioVideoUrls,PlaybackUrls,CatalogMetadata,ForcedNarratives,SubtitlePresets,SubtitleUrls,TransitionTimecodes,TrickplayUrls,CuepointPlaylist,XRayMetadata,PlaybackSettings",
                        deviceID=deviceID,
                        deviceTypeID="AOAGZA014O5RE",
                        firmware="1",
                        gascEnabled="false",
                        marketplaceID=marketplace_id,
                        resourceUsage="CacheResources",
                        audioTrackId="all",
                        videoMaterialType="Feature",
                        operatingSystemName=operatingSystemName,
                        operatingSystemVersion=operatingSystemVersion,
                        clientId=clientId,
                        deviceDrmOverride="CENC",
                        deviceStreamingTechnologyOverride="DASH",
                        deviceProtocolOverride="Https",
                        supportedDRMKeyScheme="DUAL_KEY",
                        deviceBitrateAdaptationsOverride="CVBR,CBR",
                        titleDecorationScheme="primary-content",
                        subtitleFormat="TTMLv2",
                        languageFeature="MLFv2",
                        uxLocale=titlelang,
                        xrayDeviceClass="normal",
                        xrayPlaybackMode="playback",
                        xrayToken="INCEPTION_LITE_FILMO_V2",
                        playbackSettingsFormatVersion="1.0.0"
                    )

            if args.hevc:
                params["deviceVideoCodecOverride"] = "H265"
            elif args.atmos:
                params["deviceVideoQualityOverride"] = "UHD"
                params["deviceHdrFormatsOverride"] = "Hdr10"

            #ulr_metadata = url + "?" + urllib.parse.urlencode(params)
            #print(ulr_metadata)

            resp = session.get(url=url, params=params, headers=custom_headers_GetPlaybackResources, proxies=proxy_cfg.get_proxy('meta'))
            #Error_Not_Avaiable = False
            try:
                data = json.loads(resp.text)
                licurl = url + "?" + urllib.parse.urlencode(params).replace("AudioVideoUrls%2CPlaybackUrls%2CCatalogMetadata%2CForcedNarratives%2CSubtitlePresets%2CSubtitleUrls%2CTransitionTimecodes%2CTrickplayUrls%2CCuepointPlaylist%2CXRayMetadata%2CPlaybackSettings", "Widevine2License")
                return data

            except ValueError:
                print(data)
                print("\nEpisode or Movie not available yet in your region. Possible VPN error.")
                #print(resp)
                #print("\n" + url + "?" + urllib.parse.urlencode(params))
                #Error_Not_Avaiable = True

        global licurl2
        global params2
        global url2
        if region == "ps" or region == "ps-int":
            url2 = "https://" + video_base_url + "/cdp/catalog/GetPlaybackResources"
            params2 = dict(
                asin=asin,
                consumptionType="Streaming",
                desiredResources="Widevine2License",
                deviceID=deviceID,
                deviceTypeID="AOAGZA014O5RE",
                firmware="1",
                gascEnabled="true",
                marketplaceID=marketplace_id,
                resourceUsage="CacheResources",
                videoMaterialType="Feature",
                clientId=clientId,
                operatingSystemName=operatingSystemName,
                operatingSystemVersion=operatingSystemVersion,
                deviceDrmOverride="CENC",
                deviceStreamingTechnologyOverride="DASH"
                )

        else:
            url2 = "https://" + video_base_url + "/cdp/catalog/GetPlaybackResources"
            params2 = dict(
                asin=asin,
                consumptionType="Streaming",
                desiredResources="Widevine2License",
                deviceID=deviceID,
                deviceTypeID="AOAGZA014O5RE",
                firmware="1",
                gascEnabled="false",
                marketplaceID=marketplace_id,
                resourceUsage="ImmediateConsumption",
                videoMaterialType="Feature",
                clientId=clientId,
                operatingSystemName=operatingSystemName,
                operatingSystemVersion=operatingSystemVersion,
                deviceDrmOverride="CENC",
                deviceStreamingTechnologyOverride="DASH"
                )

        if args.hevc:
            params2["deviceVideoCodecOverride"] = "H265"
        elif args.atmos:
            params2["deviceVideoQualityOverride"] = "UHD"
            params2["deviceHdrFormatsOverride"] = "Hdr10"

        licurl2 = url2 + "?" + urllib.parse.urlencode(params2)

        if args.retry:
            attempt_number = 0
            error=True
            while error==True:
                data = getLicense(asin, clientId)
                try:
                    data["audioVideoUrls"]["avCdnUrlSets"][0]["avUrlInfoList"][0]["url"]
                    error=False
                except Exception:
                    if attempt_number == 0:
                        print()
                        print("No MPD found! Trying again...")
                    attempt_number += 1
                    sys.stdout.write("Attempt %d...\r" % (attempt_number) )
                    sys.stdout.flush()
                    time.sleep(15)
                    error=True

            time_now = datetime.datetime.now()

            if attempt_number != 0:
                print()
                print('Episode found at ' + str(time_now.hour) + ':' + str(time_now.minute) + ':' + str(time_now.second))

        else:
            data = getLicense(asin, clientId)

        nochpaters=False

        def getXray(asin, clientId, serviceToken):
            global params2
            global url2
            if region == "ps" or region == "ps-int":
                url2 = 'https://' + video_base_url + '/swift/page/xray'
                params2 = dict(
                    firmware='1',
                    format='json',
                    gascEnabled='true',
                    deviceID=deviceID,
                    deviceTypeID='AOAGZA014O5RE',
                    marketplaceId=marketplace_id,
                    decorationScheme='none',
                    version='inception-v2',
                    featureScheme='INCEPTION_LITE_FILMO_V2',
                    uxLocale=chapterslang,
                    pageType='xray',
                    pageId='fullScreen',
                    serviceToken=serviceToken
                    )
            else:
                url2 = 'https://' + video_base_url + '/swift/page/xray'
                params2 = dict(
                    firmware='1',
                    format='json',
                    gascEnabled='false',
                    deviceID=deviceID,
                    deviceTypeID='AOAGZA014O5RE',
                    marketplaceId=marketplace_id,
                    decorationScheme='none',
                    version='inception-v2',
                    featureScheme='INCEPTION_LITE_FILMO_V2',
                    uxLocale='en-US',
                    pageType='xray',
                    pageId='fullScreen',
                    serviceToken=serviceToken
                    )

            resp2 = session.get(url=url2, params=params2, headers=custom_headers_GetPlaybackResources, proxies=proxy_cfg.get_proxy('meta'))
            try:
                data2 = json.loads(resp2.text)
                return data2
            except ValueError:
                data2 = None
                #nochpaters=True
                return data2

        if args.debug:
            print(json.dumps(data))

        if "error" in data:
            print(f"Error: {data}")
            sys.exit(1)

        if "errorsByResource" in data:
            for (res, err) in data["errorsByResource"].items():
                if err['type'] == 'PRSOwnershipException':
                    print(f'Error: You do not own this title. Check cookies and URL.')
                    #sys.exit(1)

                if res == 'XRayMetadata' and err['type'] == 'PRSDependencyException':
                    # No chapters available
                    continue

                print(f"Error getting {res}: {err}")

        try:
            if data["catalogMetadata"]["catalog"]["type"] == "MOVIE":
                amazonType = "movie"
            elif data["catalogMetadata"]["catalog"]["type"] == "EPISODE":
                amazonType = "show"
            else:
                print("Unrecognized type!")
                sys.exit(0)
        except Exception:
            print("Error in cookies or URL.")
            raise

        global seriesList
        seriesList = []
        bonus = False

        if amazonType == "show":
            NumEpisode = data["catalogMetadata"]["catalog"]["episodeNumber"]
            NumSeason = data["catalogMetadata"]["family"]["tvAncestors"][0]["catalog"]["seasonNumber"]

            if NumEpisode == 0:
                bonus = True

            if args.titlecustom:
                SerieTitle = ReplaceDontLikeWord(args.titlecustom[0])
            else:
                try:
                    SerieTitle = ReplaceDontLikeWord(data["catalogMetadata"]["family"]["tvAncestors"][1]["catalog"]["title"])
                except Exception:
                    SerieTitle = ReplaceDontLikeWord(kanji_to_romaji(data["catalogMetadata"]["family"]["tvAncestors"][1]["catalog"]["title"]))

            try:
                EpTitle = ReplaceDontLikeWord(data["catalogMetadata"]["catalog"]["title"])
            except Exception:
                EpTitle = ReplaceDontLikeWord(kanji_to_romaji(data["catalogMetadata"]["catalog"]["title"]))

            seriesName3 = f"{SerieTitle} S{NumSeason:02d}"
            seriesName = seriesName2 = f"{seriesName3}E{NumEpisode:02d} - {EpTitle}"

        elif amazonType == "movie":
            if args.titlecustom:
                SerieTitle = ReplaceDontLikeWord(args.titlecustom[0])
            else:
                try:
                    SerieTitle = ReplaceDontLikeWord(data["catalogMetadata"]["catalog"]["title"])
                except Exception:
                    SerieTitle = ReplaceDontLikeWord(kanji_to_romaji(data["catalogMetadata"]["catalog"]["title"]))
            seriesName = SerieTitle
            seriesName2 = SerieTitle

        if not args.nochpaters:
            try:
                global serviceToken
                contentId = data["returnedTitleRendition"]["contentId"]
                serviceToken = '{"consumptionType":"Streaming","deviceClass":"normal","playbackMode":"playback","vcid":"' + contentId + '"}'
                data2 = getXray(asin, clientId, serviceToken)

            except Exception:
                nochpaters=True

            if nochpaters==False:
                ChapterList = []
                try:
                    for x in data2["page"]["sections"]["center"]["widgets"]["widgetList"]:
                        if x["tabType"] == "scenesTab":
                            for y in x["widgets"]["widgetList"]:
                                if y["items"]["itemList"][0]["blueprint"]["id"] == "XraySceneItem":
                                    for z in y["items"]["itemList"]:
                                        ChapterDict = (z["textMap"]["PRIMARY"], ReplaceChapters(z["textMap"]["TERTIARY"]))
                                        ChapterList.append(ChapterDict)

                    ChaptersList_new = defaultdict(list)
                    for ChapterName, ChapterTime in ChapterList:
                        ChaptersList_new[ChapterName].append(ChapterTime)

                    if str(ChaptersList_new.items()) == "dict_items([])":
                        nochpaters=True
                except Exception:
                    nochpaters=True

        global AudioListAll
        AudioListAll = []
        OnlyOneAudio = False
        Error_Not_Avaiable = False
        try:
            for audios_track in data["audioVideoUrls"]["audioTrackMetadata"]:
                try:
                    AudioListDict = {"AudioCode": audios_track["languageCode"],
                                    "AudioName": audios_track["displayName"],
                                    "AudioID": ReplaceCodeLanguages(audios_track["audioTrackId"])}
                except Exception:
                    AudioListDict = {"AudioCode": audios_track["languageCode"],
                                    "AudioName": audios_track["displayName"],
                                    "AudioID": ReplaceCodeLanguages(audios_track["languageCode"])}

                AudioListAll.append(AudioListDict)

            if len(AudioListAll) == 1:
                OnlyOneAudio = True
                OnlyOneAudioID = AudioListAll[0]["AudioID"]

        except KeyError:
            if not args.noaudio:
                print(data)
                print("\nEpisode or Movie not available yet in your region. Possible VPN error.")
                Error_Not_Avaiable = True

        global subsList
        global subsForList
        nosubs = False
        nosubsfor = False

        if args.nosubs:
            nosubs = True
            nosubsfor = True
        else:
            nosubs=nosubs
            nosubsfor=nosubs

        subsList = []
        subsForList = []

        if not args.nosubs:
            if nosubs != True:
                try:
                    for subs_track in data["subtitleUrls"]:
                        try:
                            subsDict = {"SubsCode": subs_track["languageCode"],
                                        "SubsName": subs_track["displayName"],
                                        "SubsID": ReplaceCodeLanguages(subs_track["timedTextTrackId"]),
                                        "subs_urls": subs_track["url"]}
                        except Exception:
                            subsDict = {"SubsCode": subs_track["languageCode"],
                                        "SubsName": subs_track["displayName"],
                                        "SubsID": ReplaceCodeLanguages(subs_track["languageCode"]),
                                        "subs_urls": subs_track["url"]}

                        if args.sublang:
                            if str(subsDict["SubsID"]) in list(args.sublang):
                                subsList.append(subsDict)
                            if str(subsDict["SubsID"]) not in list(args.sublang):
                                continue
                        else:
                            subsList.append(subsDict)
                            continue

                except Exception:
                    nosubs=True

            if nosubsfor != True:
                try:
                    for subsFor_track in data["forcedNarratives"]:
                        try:
                            subsForDict ={"SubsForCode": subsFor_track["languageCode"],
                                        "SubsForName": subsFor_track["displayName"],
                                        "SubsForID": ReplaceCodeLanguages(subsFor_track["timedTextTrackId"]),
                                        "subsFor_urls": subsFor_track["url"]}
                        except Exception:
                            subsForDict ={"SubsForCode": subsFor_track["languageCode"],
                                        "SubsForName": subsFor_track["displayName"],
                                        "SubsForID": ReplaceCodeLanguages(subsFor_track["languageCode"]),
                                        "subsFor_urls": subsFor_track["url"]}

                        if args.forcedlang:
                            if str(subsForDict["SubsForID"]) in list(args.forcedlang):
                                subsForList.append(subsForDict)
                            if str(subsForDict["SubsForID"]) not in list(args.forcedlang):
                                continue
                        else:
                            subsForList.append(subsForDict)
                            continue
                except Exception:
                    nosubsfor=True

        audioList = []
        audio_pssh = None

        if not Error_Not_Avaiable and not (args.novideo and args.noaudio):
            print("\nGetting MPD...")
            mpd_url, base_url, mpd = GettingMPD(data)

            print("\nParsing MPD...")
            if args.customquality:
                height=str(args.customquality[0])
            else:
                height=None

            height_all, video_urls, audioList, novideo, video_pssh, audio_pssh = ParsingMPD(mpd, height)
            height_all_ord = alphanumericSort(list(set(height_all)))

            errorinheight = False
            listheightprint = list_to_str(list=height_all_ord, separator=', ', lastseparator=' and ')
            try:
                video_url = base_url + alphanumericSort(video_urls)[-1]
                print(f"Video quality: {listheightprint.split(' ')[-1]}p")
            except Exception:
                print("\nThis quality is not available, the available ones are: " + listheightprint + '.')
                height = input("Enter a correct quality (without p): ")
                errorinheight = True
                height_all, video_urls, audioList, novideo, video_pssh, audio_pssh = ParsingMPD(mpd, height)
                try:
                    video_url = base_url + alphanumericSort(video_urls)[-1]
                except Exception:
                    novideo=True


        if Error_Not_Avaiable == True:
            if amazonType == "show":
                CurrentHeigh="Unknown"
                CurrentName=seriesName
                return str(CurrentName), str(seriesName3), str(CurrentHeigh)

            else:
                CurrentHeigh="Unknown"
                CurrentName=seriesName
                return str(CurrentName), str(CurrentName), str(CurrentHeigh)

        #if not args.noaudio or not args.novideo:
        audioList_new = defaultdict(list)

        noaudio = False

        if args.audiolang:
            noaudio = False
        else:
            noaudio = noaudio

        if args.noaudio:
            noaudio=True
        else:
            noaudio=noaudio

        for audioTrackId, BaseURL in audioList:
            if args.audiolang:
                if str(audioTrackId) in list(args.audiolang):
                    audioList_new[audioTrackId].append(BaseURL)
                else:
                    continue
            else:
                audioList_new[audioTrackId].append(BaseURL)
                continue

        if str(audioList_new.items()) == "dict_items([])":
            print("\nThere is no audio available for download.")
            noaudio=True

        listaudios=[]
        for k, v in audioList_new.items():
            listaudios.append(k)
        listaudiosprint = list_to_str(list=listaudios, separator=', ', lastseparator=' and ')
        if not args.onlykeys:
            print("\nAudios that will be downloaded: " + listaudiosprint + '.')

        noprotection = False
        if not audio_pssh:
            noprotection=True

        if args.customquality:
            heightp = height
        elif args.novideo and args.noaudio:
            heightp = 'Unknown'
        else:
            heightp = height_all_ord[-1]


        if amazonType == "show":
            CurrentName=seriesName
            CurrentHeigh=str(heightp)
            if args.hevc:
                VideoOutputName = folderdownloader + '\\' + str(seriesName3)+'\\'+str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC].mkv'
            elif args.atmos:
                VideoOutputName = folderdownloader + '\\' + str(seriesName3)+'\\'+str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC-atmos].mkv'
            elif args.cbr_bitrate:
                VideoOutputName = folderdownloader + '\\' + str(seriesName3)+'\\'+str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [CBR].mkv'
            else:
                VideoOutputName = folderdownloader + '\\' + str(seriesName3)+'\\'+str(CurrentName) + ' [' + str(CurrentHeigh) + 'p].mkv'
        else:
            CurrentName=seriesName
            CurrentHeigh=str(heightp)
            if args.hevc:
                VideoOutputName = folderdownloader + '\\' + str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC].mkv'
            elif args.atmos:
                VideoOutputName = folderdownloader + '\\' + str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC-atmos].mkv'
            elif args.cbr_bitrate:
                VideoOutputName = folderdownloader + '\\' + str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [CBR].mkv'
            else:
                VideoOutputName = folderdownloader + '\\' + str(CurrentName) + ' [' + str(CurrentHeigh) + 'p].mkv'



        if args.onlykeys:
            print("\nGetting KEYS...")
            keys_video = []
            keys_audio = []
            format_mpd = ""
            if args.hevc:
                format_mpd = "HEVC KEYS"
            elif args.cbr_bitrate:
                format_mpd = "CBR KEYS"
            else:
                format_mpd = "CVBR KEYS"

            try:
                keys_video = GetKey(video_pssh)
            except KeyError:
                print('License request failed, using keys from txt')
                keys_video = keys_file_txt
            else:
                with open(keys_file, "a", encoding="utf8") as file:
                    file.write(seriesName + " (video) " + format_mpd + "\n")
                    print("\n" + seriesName + " (video) " + format_mpd)
                for key in keys_video:
                    with open(keys_file, "a", encoding="utf8") as file:
                        file.write(key + "\n")
                        print(key)

            if noprotection is False and audio_pssh != video_pssh:
                try:
                    keys_audio = GetKey(audio_pssh)
                except KeyError:
                    print('License request failed, using keys from txt')
                    keys_audio = keys_file_txt
                else:
                    with open(keys_file, "a", encoding="utf8") as file:
                        file.write(seriesName + " (audio) " + format_mpd + "\n")
                        print("\n" + seriesName + " (audio) " + format_mpd)
                    for key in keys_audio:
                        with open(keys_file, "a", encoding="utf8") as file:
                            file.write(key + "\n")
                            print(key)
            print("\nDone!")
            
            if not args.keep:
                for f in os.listdir():
                    if re.fullmatch(re.escape(CurrentName) + r'.*\.mpd', f):
                        os.remove(f)

            CurrentHeigh="Unknown"
            CurrentName=seriesName
            return str(CurrentName), str(CurrentName), str(CurrentHeigh)





        if not args.novideo and novideo==False or (not args.noaudio and noaudio==False):
            print("\nGetting KEYS...")
            keys_video = []
            keys_audio = []

            try:
                keys_video = GetKey(video_pssh)
            except KeyError:
                print('License request failed, using keys from txt')
                keys_video = keys_file_txt
            else:
                with open(keys_file, "a", encoding="utf8") as file:
                    file.write(seriesName + "\n")
                for key in keys_video:
                    with open(keys_file, "a", encoding="utf8") as file:
                        file.write(key + "\n")

            if noprotection == False:
                try:
                    keys_audio = GetKey(audio_pssh)
                except KeyError:
                    print('License request failed, using keys from txt')
                    keys_audio = keys_file_txt
                else:
                    with open(keys_file, "a", encoding="utf8") as file:
                        file.write(seriesName + "\n")
                    for key in keys_audio:
                        with open(keys_file, "a", encoding="utf8") as file:
                            file.write(key + "\n")

            print("Done!")



        if not os.path.isfile(VideoOutputName):
            if not args.nosubs:
                if subsList != []:
                    print ("\nDownloading subtitles...")
                    for z in subsList:
                        langAbbrev = str(dict(z)["SubsID"])
                        if os.path.isfile(seriesName + " " + "(" + langAbbrev + ")" + ".srt") or os.path.isfile(seriesName + " " + "(" + langAbbrev + ")" + ".dfxp"):
                            print(seriesName + " " + "(" + langAbbrev + ")" + " has already been successfully downloaded previously.")
                            continue
                        else:
                            downloadFile2(str(dict(z)["subs_urls"]), seriesName + " " + "(" + langAbbrev + ")" + ".dfxp")
                            print ("Downloaded!")

                else:
                    print ("\nNo subtitles available.")

                if subsForList != []:
                    print ("\nDownloading forced subtitles...")
                    for z in subsForList:
                        langAbbrev = str(dict(z)["SubsForID"])
                        if os.path.isfile(seriesName + " " + "(" + langAbbrev + ")" + " " + "Forced" + ".srt") or os.path.isfile(seriesName + " " + "(" + langAbbrev + ")" + " " + "Forced" + ".dfxp"):
                            print(seriesName + " " + "(" + langAbbrev + ")" + " " + "Forced" + " has already been successfully downloaded previously.")
                            continue
                        else:
                            downloadFile2(str(dict(z)["subsFor_urls"]), seriesName + " " + "(" + langAbbrev + ")" + " " + "Forced" + ".dfxp")
                            print ("Downloaded!")
                else:
                    print ("\nNo forced subtitles available.")


                if subsForList != [] or subsList != []:
                    subsinfolder=False
                    subsinfolderFOR=False
                    for z in subsForList:
                        langAbbrev = str(dict(z)["SubsForID"])
                        if os.path.isfile(seriesName + " " + "(" + langAbbrev + ")" + " " + "Forced" + ".dfxp"):
                            subsinfolderFOR=True

                    for z in subsList:
                        langAbbrev = str(dict(z)["SubsID"])
                        if os.path.isfile(seriesName + " " + "(" + langAbbrev + ")" + ".dfxp"):
                            subsinfolder=True

                    if subsinfolder==True or subsinfolderFOR==True:
                        print ("\nConverting subtitles...")
                        for dfxp_name in glob.glob(seriesName + '*.dfxp'):
                            srt_name = re.sub(r'\.dfxp$', '.srt', dfxp_name)
                            empty = False
                            with open(dfxp_name, 'r+', encoding='utf-8') as dfxp_file, open(srt_name, 'w', encoding='utf-8') as srt_file:
                                dfxp_text = fix_subtitles(dfxp_file.read())
                                dfxp_file.seek(0)
                                dfxp_file.truncate()
                                dfxp_file.write(dfxp_text)

                                try:
                                    capt = pycaption.DFXPReader().read(dfxp_text)
                                except Exception as e:
                                    print(f'Warning: Unable to read subtitle file {dfxp_name!r}, leaving original file for debugging '
                                                                              f'({e.__class__.__name__}: {e})')
                                    empty = True
                                else:
                                    srt_text = pycaption.SRTWriter().write(capt)
                                    srt_file.write(srt_text)
                            if empty:
                                os.remove(srt_name)
                            else:
                                os.remove(dfxp_name)
                        print("Done!")

            if not args.nochpaters:
                if nochpaters==False:
                    print("\nGenerating Chapters file...")
                    if os.path.isfile(seriesName + ' Chapters.txt'):
                        print(seriesName + " Chapters.txt" + " has already been successfully downloaded previously.")
                        pass
                    else:
                        count=1
                        with open(seriesName + ' Chapters.txt', 'a', encoding='utf-8') as f:
                            for k, v in ChaptersList_new.items():
                                if int(count)>= 10:
                                    ChapterNumber = str(count)
                                else:
                                    ChapterNumber = "0"+str(count)
                                ChapterName = str(k).replace("['", "").replace("']", "").replace("’", "'")
                                ChapterTime = str(v).replace("['", "").replace("']", "") + ".000"
                                f.write("CHAPTER"+ChapterNumber+"="+ChapterTime+"\n"+"CHAPTER"+ChapterNumber+"NAME="+ReplaceChaptersNumber(ChapterName)+"\n")
                                count=count+1
                        print ("Done!")
                else:
                    print ("\nNo chapters available.")

            if bonus == True and args.novideo and args.noaudio:
                if nosubs == False:
                    for z in subsList:
                        langAbbrev = str(dict(z)["SubsID"])
                        os.rename(seriesName + " " + "(" + langAbbrev + ")" + ".srt", seriesName2 + " " + "(" + langAbbrev + ")" + ".srt")
                if nosubsfor == False:
                    for z in subsForList:
                        langAbbrev = str(dict(z)["SubsForID"])
                        os.rename(seriesName + " " + "(" + langAbbrev + ")" + " " + "Forced" + ".srt", seriesName2 + " " + "(" + langAbbrev + ")" + " " + "Forced" + ".srt")
                if nochpaters==False:
                    os.rename(seriesName + ' Chapters.txt', seriesName2 + ' Chapters.txt')


            if not args.novideo and novideo==False:
                print("\nDownloading video...")
                if args.hevc:
                    inputVideo=seriesName + " [" + str(heightp) + "p] [HEVC].mp4"
                    inputVideoDemuxed=seriesName + " [" + str(heightp) + "p] [HEVC].h265"
                elif args.atmos:
                    inputVideo=seriesName + " [" + str(heightp) + "p] [HEVC-atmos].mp4"
                    inputVideoDemuxed=seriesName + " [" + str(heightp) + "p] [HEVC-atmos].h265"
                elif args.cbr_bitrate:
                    inputVideo=seriesName + " [" + str(heightp) + "p] [CBR].mp4"
                    inputVideoDemuxed=seriesName + " [" + str(heightp) + "p] [CBR].h264"
                else:
                    inputVideo=seriesName + " [" + str(heightp) + "p].mp4"
                    inputVideoDemuxed=seriesName + " [" + str(heightp) + "p].h264"

                if (os.path.isfile(inputVideo) and not os.path.isfile(inputVideo + ".aria2")) or os.path.isfile(inputVideoDemuxed):
                    print("\n" + inputVideo + "\nFile has already been successfully downloaded previously.")
                else:
                    downloadFile(str(video_url), inputVideo)


            if not args.noaudio and noaudio==False:
                if noprotection == True:
                    print ("\nDownloading audios...")
                    for k, v in audioList_new.items():
                        langAbbrev = str(k)
                        inputAudio=seriesName + " " + "(" + langAbbrev + ")" + ".mp4"
                        inputAudio2=seriesName + " " + "(" + langAbbrev + ")" + ".eac3"
                        originalAudio=seriesName + " " + "(" + langAbbrev + ")" + "_original.eac3"
                        if os.path.isfile(inputAudio) and not os.path.isfile(inputAudio + ".aria2") or os.path.isfile(inputAudio2) or os.path.isfile(originalAudio):
                            print("\n" + inputAudio + "\nFile has already been successfully downloaded previously.")
                        else:
                            downloadFile(str(base_url + alphanumericSort(v)[-1]), inputAudio)

                else:
                    print ("\nDownloading audios...")
                    for k, v in audioList_new.items():
                        langAbbrev = str(k)
                        inputAudio=seriesName + " " + "(" + langAbbrev + ")" + ".mp4"
                        inputAudio2=seriesName + " " + "(" + langAbbrev + ")" + ".eac3"
                        originalAudio=seriesName + " " + "(" + langAbbrev + ")" + "_original.eac3"
                        if os.path.isfile(inputAudio) and not os.path.isfile(inputAudio + ".aria2") or os.path.isfile(inputAudio2) or os.path.isfile(originalAudio):
                            print("\n" + inputAudio + "\nFile has already been successfully downloaded previously.")
                        else:
                            downloadFile(str(base_url + alphanumericSort(v)[-1]), inputAudio)


            CorrectDecryptVideo = False
            CorrectDecryptAudio = False
            if os.path.isfile(config_data):
                os.remove(config_data)

            if not args.novideo and novideo==False:
                if args.hevc:
                    inputVideo=seriesName + " [" + str(heightp) + "p] [HEVC].mp4"

                elif args.atmos:
                    inputVideo=seriesName + " [" + str(heightp) + "p] [HEVC-atmos].mp4"

                elif args.cbr_bitrate:
                    inputVideo=seriesName + " [" + str(heightp) + "p] [CBR].mp4"

                else:
                    inputVideo=seriesName + " [" + str(heightp) + "p].mp4"

                CorrectDecryptVideo = False
                if os.path.isfile(inputVideo):
                    CorrectDecryptVideo = DecryptVideo(inputVideo=inputVideo, keys_video=keys_video)
                    if CorrectDecryptVideo == False or CorrectDecryptVideo == None:
                        print("\nKEY for " + inputVideo + " is not in txt.")
                        CorrectDecryptVideo = DecryptAlternativeV2(PSSH=video_pssh, FInput=inputVideo, Type="video")

                else:
                    CorrectDecryptVideo = True

            if not args.noaudio and noaudio==False:
                if noprotection == True:
                    for k, v in audioList_new.items():
                        langAbbrev = str(k)
                        inputAudio=seriesName + " " + "(" + langAbbrev + ")" + ".mp4"
                        outputAudio=seriesName + " " + "(" + langAbbrev + ")" + ".eac3"
                        outputAudio_aac=seriesName + " " + "(" + langAbbrev + ")" + ".m4a"
                        if os.path.isfile(inputAudio):
                            print("\nDemuxing audio...")
                            mediainfo = subprocess.Popen([ffprobepath, "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", inputAudio], stdout=subprocess.PIPE)
                            mediainfo = json.load(mediainfo.stdout)
                            codec_name = mediainfo["streams"][0]["codec_name"]
                            if codec_name == "aac":
                                print(inputAudio + " -> " + outputAudio_aac)
                                ff = ffmpy.FFmpeg(executable=ffmpegpath, inputs={inputAudio: None}, outputs={outputAudio_aac: '-c copy'}, global_options="-y -hide_banner -loglevel warning")
                                ff.run()
                                time.sleep (50.0/1000.0)
                                os.remove(inputAudio)
                                print ("\nDone!")
                                CorrectDecryptAudio = True

                            else:
                                print(inputAudio + " -> " + outputAudio)
                                ff = ffmpy.FFmpeg(executable=ffmpegpath, inputs={inputAudio: None}, outputs={outputAudio: '-c copy'}, global_options="-y -hide_banner -loglevel warning")
                                ff.run()
                                time.sleep (50.0/1000.0)
                                os.remove(inputAudio)
                                print ("\nDone!")
                                CorrectDecryptAudio = True
                        else:
                            CorrectDecryptAudio = True

                else:
                    for k, v in audioList_new.items():
                        langAbbrev = str(k)
                        inputAudio=seriesName + " " + "(" + langAbbrev + ")" + ".mp4"
                        outputAudioTemp=seriesName + " " + "(" + langAbbrev + ")" + "_dec.mp4"
                        outputAudio=seriesName + " " + "(" + langAbbrev + ")" + ".eac3"
                        if os.path.isfile(inputAudio):
                            CorrectDecryptAudio = DecryptAudio(inputAudio=inputAudio, keys_audio=keys_audio)
                            if CorrectDecryptAudio == False or CorrectDecryptAudio == None:
                                print("\nKEY for " + inputAudio + " is not in txt.")
                                CorrectDecryptAudio = DecryptAlternativeV2(PSSH=audio_pssh, FInput=inputAudio, Type="audio")
                        else:
                            CorrectDecryptAudio = True

            #if os.path.isfile(challengeBIN): os.remove(challengeBIN)
            #if os.path.isfile(licenceBIN): os.remove(licenceBIN)

            if args.nomux and bonus == True:
                if not args.novideo and novideo==False:
                    if os.path.isfile(seriesName + " [" + str(heightp) + "p].mp4"):
                        os.rename(seriesName + " [" + str(heightp) + "p].mp4", seriesName2 + " [" + str(heightp) + "p].mp4")
                if nosubs == False:
                    for z in subsList:
                        langAbbrev = str(dict(z)["SubsID"])
                        if os.path.isfile(seriesName + " " + "(" + langAbbrev + ")" + ".srt"):
                            os.rename(seriesName + " " + "(" + langAbbrev + ")" + ".srt", seriesName2 + " " + "(" + langAbbrev + ")" + ".srt")
                if nosubsfor == False:
                    for z in subsForList:
                        langAbbrev = str(dict(z)["SubsForID"])
                        if os.path.isfile(seriesName + " " + "(" + langAbbrev + ")" + " " + "Forced" + ".srt"):
                            os.rename(seriesName + " " + "(" + langAbbrev + ")" + " " + "Forced" + ".srt", seriesName2 + " " + "(" + langAbbrev + ")" + " " + "Forced" + ".srt")
                if not args.noaudio and noaudio==False:
                    for k, v in audioList_new.items():
                        langAbbrev = str(k)
                        if os.path.isfile(seriesName + " " + "(" + langAbbrev + ")" + ".eac3"):
                            os.rename(seriesName + " " + "(" + langAbbrev + ")" + ".eac3", seriesName2 + " " + "(" + langAbbrev + ")" + ".eac3")
                if nochpaters==False:
                    if os.path.isfile(seriesName + ' Chapters.txt'):
                        os.rename(seriesName + ' Chapters.txt', seriesName2 + ' Chapters.txt')


            if not args.noaudio and noaudio==False and args.fpitch:
                if args.sourcefps:
                    sourcefps = float(args.sourcefps[0])
                else:
                    sourcefps = float(23.976)

                if args.targetfps:
                    targetfps = float(args.targetfps[0])
                else:
                    targetfps = float(25)

                pitch = float((targetfps*100)/sourcefps)
                pitch = round(pitch, 4)

                for k, v in audioList_new.items():
                    langAbbrev = str(k)
                    if str(langAbbrev) in list(args.fpitch):
                        inputAudio=seriesName + " " + "(" + langAbbrev + ")" + ".eac3"
                        outputAudio=seriesName + " " + "(" + langAbbrev + ")" + ".eac3"
                        originalAudio=seriesName + " " + "(" + langAbbrev + ")" + "_original.eac3"
                        avsfile= originalAudio + ".avs"

                        if os.path.isfile(inputAudio):
                            if not os.path.isfile(originalAudio):
                                os.rename(inputAudio, originalAudio)
                                if not os.path.isfile(avsfile):
                                    with open(avsfile, 'w+', encoding='utf-8') as f:
                                        f.write('LoadPlugin("' + TimeStretch_dll + '")' +"\n")
                                        f.write('LoadPlugin("' + lsmashsource_dll + '")' +"\n")
                                        f.write('TimeStretchPlugin(LWLibavAudioSource("' + originalAudio + '"), pitch=' + str(pitch) + ')')

                        if not (os.path.isfile(originalAudio) and os.path.isfile(outputAudio)):
                            print("\nFixing pitch of " + langAbbrev + "...")
                            print(str(sourcefps) + " -> " + str(targetfps))
                            mediainfo = subprocess.Popen([ffprobepath, "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", originalAudio], stdout=subprocess.PIPE)
                            mediainfo = json.load(mediainfo.stdout)
                            audio_bitrate=int(float(mediainfo["streams"][0]["bit_rate"])/1000)
                            ff = ffmpy.FFmpeg(executable=ffmpegpath, inputs={avsfile: None}, outputs={outputAudio: '-c:a eac3 -b:a ' + str(audio_bitrate) + 'k -room_type -1 -copyright 1 -original 1 -mixing_level -1 -dialnorm -31'}, global_options='-y -hide_banner -loglevel warning')
                            ff.run()
                            print ("Done!")

            if args.force_mux:
                print("\n\nMuxing...")
                CurrentHeigh=str(args.force_mux[0])
                CurrentName=seriesName

                if amazonType=="show":
                    MKV_Muxer=Muxer(CurrentName=CurrentName,
                                    SeasonFolder=seriesName3,
                                    CurrentHeigh=CurrentHeigh,
                                    Type=amazonType,
                                    mkvmergeexe=mkvmergeexe)

                else:
                    MKV_Muxer=Muxer(CurrentName=CurrentName,
                                    SeasonFolder=None,
                                    CurrentHeigh=CurrentHeigh,
                                    Type=amazonType,
                                    mkvmergeexe=mkvmergeexe)

                if args.langtag:
                    MKV_Muxer.AmazonAndPrimeVideoMuxer(lang=str(args.langtag[0]))

                else:
                    MKV_Muxer.AmazonAndPrimeVideoMuxer(lang="English")

                if not args.keep:
                    for f in os.listdir():
                        if re.fullmatch(re.escape(CurrentName) + r'.*\.(mp4|m4a|h264|h265|eac3|srt|txt|avs|lwi|mpd)', f):
                            os.remove(f)
                print("Done!")


            if not args.nomux and not args.novideo and novideo==False and not args.noaudio and noaudio==False and CorrectDecryptVideo==True and CorrectDecryptAudio==True:
                print("\n\nMuxing...")
                CurrentHeigh=str(heightp)
                CurrentName=seriesName

                if amazonType=="show":
                    MKV_Muxer=Muxer(CurrentName=CurrentName,
                                    SeasonFolder=seriesName3,
                                    CurrentHeigh=CurrentHeigh,
                                    Type=amazonType,
                                    mkvmergeexe=mkvmergeexe)

                else:
                    MKV_Muxer=Muxer(CurrentName=CurrentName,
                                    SeasonFolder=None,
                                    CurrentHeigh=CurrentHeigh,
                                    Type=amazonType,
                                    mkvmergeexe=mkvmergeexe)

                if args.langtag:
                    MKV_Muxer.AmazonAndPrimeVideoMuxer(lang=str(args.langtag[0]))

                else:
                    MKV_Muxer.AmazonAndPrimeVideoMuxer(lang="English")

                if not args.keep:
                    for f in os.listdir():
                        if re.fullmatch(re.escape(CurrentName) + r'.*\.(mp4|m4a|h264|h265|eac3|srt|txt|avs|lwi|mpd)', f):
                            os.remove(f)
                print("Done!")

            elif not args.keep:
                for f in os.listdir():
                    if re.fullmatch(re.escape(CurrentName) + r'.*\.mpd', f):
                        os.remove(f)

        else:
            if not args.keep:
                os.remove(mpd_file)

            print("File '" + str(VideoOutputName) + "' already exists.")

        if amazonType == "show":
            try:
                CurrentHeigh=str(heightp)
            except Exception:
                CurrentHeigh="Unknown"
            CurrentName=seriesName
            return str(CurrentName), str(seriesName3), str(CurrentHeigh)

        else:
            try:
                CurrentHeigh=str(heightp)
            except Exception:
                CurrentHeigh="Unknown"
            CurrentName=seriesName
            return str(CurrentName), str(CurrentName), str(CurrentHeigh)


    def SearchASINAmazon(url, episodes_from=0, asin_list={}, season=False):
        if region == "ps":
            global video_base_url
            video_base_url, html_data = get_pv_baseurl(url, display_region=not season)

        custom_headers_season = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'accept-encoding': 'gzip, deflate, br',
            'cache-control': 'max-age=0',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'upgrade-insecure-requests': '1',
            'cookie': cookies,
            'origin': f'https://{video_base_url}',
        }

        html_data = session.get(url, params={'episodesFrom': episodes_from}, headers=custom_headers_season, proxies=proxy_cfg.get_proxy('meta')).text
        soup = BeautifulSoup(html_data, 'lxml-html')
        try:
            canonical_url = soup.find('link', rel='canonical').get('href')
        except AttributeError:
            print('Error in URL.')
            sys.exit(1)
        season_asin = canonical_url.split('/')[-1]

        if args.season and not season:
            season_link = soup.select_one(f'a[href$="atv_dp_season_select_s{args.season}"]')
            if not season_link:
                print('Error: Requested season not found')
                sys.exit(1)
            season_url = season_link.get('href')
            season_url = urllib.parse.urljoin(url, season_url)
            return SearchASINAmazon(season_url, 0, {}, season=True)

        asin_info = None

        for script in soup.select('script[type="text/template"]'):
            if '"collections":{"' in script.text:
                asin_info = json.loads(script.text)
                break

        if not asin_info:
            for script in soup.select('script[type="text/template"]'):
                if 'fullDetailUrl' in script.text:
                    asin_info = json.loads(script.text)
                    break

        if not asin_info:
            print('Error: Unable to get ASIN info')
            sys.exit(1)

        if args.debug:
            print(json.dumps(asin_info, indent=2))
        try:
            headers = {
                'sec-ch-ua': '"Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"',
                'rtt': '200',
                'sec-ch-ua-mobile': '?0',
                'x-amzn-requestid': "XPV9P58ZHYGZZQB943PE",
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36',
                'X-Amzn-Client-TTL-Seconds': '15',
                'x-requested-with': 'XMLHttpRequest',
                'downlink': '7.5',
                'ect': '4g',
                'sec-ch-ua-platform': '"Windows"',
            }

            titleId = asin_info['args']['titleID']
            params = (
                ('pageTypeIdSource', 'ASIN'),
                ('titleID', titleId),
                ('sections', 'Btf'),
                ('widgets', '{"btf":["Episodes"]}'),
                ('widgetsConfig', '{"episodes":{"startIndex":0,"pageSize":1000}}'),
            )

            response = requests.get('https://www.primevideo.com/gp/video/api/getDetailPage', headers=headers, params=params).json()

            collection = response['widgets']['titleContent'][0]
            
            all_eps = collection['totalCardSize']
            page_eps = len(collection['cards'])

            for (asin, title) in enumerate(collection['cards']): 
                if title['detail']['titleType'] == 'episode':
                    num = title['detail']['episodeNumber']
                    asin_list[num] = title['titleID']

            if all_eps > episodes_from + page_eps:
                asin_list, _ = SearchASINAmazon(url, episodes_from + 200, asin_list)
        except (KeyError, IndexError):
            pass

        if asin_list:
            return asin_list, 'show'
        else:
            return asin_info['props']['state']['pageTitleId'], 'movie'


    if not args.url_season and not args.asin:
        url_season = input("Enter the Amazon PrimeVideo url (with https): ")
    else:
        url_season = str(args.url_season)

    if not args.url_season and args.asin:
        asin = args.asin
        try:
            datatemp = getLicenseTemp(asin, clientId)

            if "error" in datatemp:
                print(f"Error: {datatemp}")
                sys.exit(1)

            if "errorsByResource" in datatemp:
                for (res, err) in datatemp["errorsByResource"].items():
                    if err['type'] == 'PRSOwnershipException':
                        print(f'Error: You do not own this title. Check cookies and URL.')
                        #sys.exit(1)

                    if res == 'XRayMetadata' and err['type'] == 'PRSDependencyException':
                        # No chapters available
                        continue

                    print(f"Error getting {res}: {err}")

            if datatemp["catalogMetadata"]["catalog"]["type"] == "MOVIE":
                amazonTypeTemp = "movie"
            elif datatemp["catalogMetadata"]["catalog"]["type"] == "EPISODE":
                amazonTypeTemp = "show"
            else:
                print("Unrecognized type!")
                sys.exit(0)

        except Exception:
            print("Error in cookies or in URL.")
            raise
        try:
            if args.onlykeys and args.allkeys:
                args.hevc = False
                args.cbr_bitrate = False
                CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(asin)
                args.cbr_bitrate = True
                CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(asin)
                args.hevc = True
                args.cbr_bitrate = False
                CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(asin)
            else:
                CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(asin)

            if args.country_code != None:
                os.system("taskkill /im openvpn.exe /f")

        except Exception:
            print("No more episodes to download.")
            if args.country_code != None:
                os.system("taskkill /im openvpn.exe /f")
            raise

        if args.custom_command:
            print("\n")
            if args.hevc:
                CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC].mkv'
            elif args.atmos:
                CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC-atmos].mkv'
            elif args.cbr_bitrate:
                CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [CBR].mkv'
            else:
                CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p].mkv'

            if amazonTypeTemp == "show":
                CustomCommand = '"' + folderdownloader + '\\' + str(SeasonFolder) + '\\' + CurrentName_out + '"'
            else:
                CustomCommand = '"' + folderdownloader + '\\' + CurrentName_out + '"'
            str(args.custom_command[0]) + ' --file-folder ' + CustomCommand
            CustomCommand_process = subprocess.Popen(str(args.custom_command[0]) + ' --file-folder ' + CustomCommand)
            stdoutdata, stderrdata = CustomCommand_process.communicate()
            CustomCommand_process.wait()
            sys.exit(0)

        else:
            sys.exit(0)

    else:
        def gen_episode_list(ep_str, num_eps):
            if args.all_season and ep_str.isdigit():
                ep_str += '-'

            if '-' in ep_str:
                (start, end) = ep_str.split('-')
                start = int(start)
                end = int(end or num_eps)

                return range(start, end + 1)

            if ',' in ep_str:
                return [int(x) for x in ep_str.split(',')]

            return [int(ep_str)]

        if not args.episodeStart:
            args.episodeStart = "1-"

        if region == "ps" or region == "ps-int":
            print("\nSearching asins...")
            ASINS, amazonTypeTemp = SearchASINAmazon(url=url_season)
            print("Done!")

            if amazonTypeTemp == "movie":
                try:
                    if args.onlykeys and args.allkeys:
                        args.hevc = False
                        args.cbr_bitrate = False
                        CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(ASINS)
                        args.cbr_bitrate = True
                        CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(ASINS)
                        args.hevc = True
                        args.cbr_bitrate = False
                        CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(ASINS)
                    else:
                        CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(ASINS)

                    if args.country_code != None:
                        os.system("taskkill /im openvpn.exe /f")

                except Exception:
                    print("No more episodes to download.")
                    if args.country_code != None:
                        os.system("taskkill /im openvpn.exe /f")
                    raise

                if args.custom_command:
                    print("\n")
                    if args.hevc:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC].mkv'
                    elif args.atmos:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC-atmos].mkv'
                    elif args.cbr_bitrate:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [CBR].mkv'
                    else:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p].mkv'
                    CustomCommand = '"' + folderdownloader + '\\' + CurrentName_out + '"'
                    str(args.custom_command[0]) + ' --file-folder ' + CustomCommand
                    CustomCommand_process = subprocess.Popen(str(args.custom_command[0]) + ' --file-folder ' + CustomCommand)
                    stdoutdata, stderrdata = CustomCommand_process.communicate()
                    CustomCommand_process.wait()
                    sys.exit(0)

                else:
                    sys.exit(0)

            else:
                asinList2=[]
                episodes = gen_episode_list(args.episodeStart, len(ASINS))
                for (num, asin) in sorted(ASINS.items()):
                    if num in episodes:
                        asinList2.append(asin)
                CurrentHeigh2=""
                CurrentName2=""
                SeasonFolder2=""

                for y in asinList2:
                    try:
                        if args.onlykeys and args.allkeys:
                            args.hevc = False
                            args.cbr_bitrate = False
                            CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(y)
                            args.cbr_bitrate = True
                            CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(y)
                            args.hevc = True
                            args.cbr_bitrate = False
                            CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(y)
                        else:
                            CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(y)

                    except Exception:
                        print("No more episodes to download.")
                        if args.country_code != None:
                            os.system("taskkill /im openvpn.exe /f")
                        raise

                    if CurrentHeigh != "Unknown":
                        CurrentHeigh2 = CurrentHeigh
                        CurrentName2 = CurrentName
                        SeasonFolder2 = SeasonFolder

                if args.country_code != None:
                    os.system("taskkill /im openvpn.exe /f")

                if args.custom_command:
                    print("\n")
                    if args.hevc:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC].mkv'
                    elif args.atmos:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC-atmos].mkv'
                    elif args.cbr_bitrate:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [CBR].mkv'
                    else:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p].mkv'
                    CustomCommand = '"' + folderdownloader + '\\' + str(SeasonFolder) + '"'
                    str(args.custom_command[0]) + ' --file-folder ' + CustomCommand
                    CustomCommand_process = subprocess.Popen(str(args.custom_command[0]) + ' --file-folder ' + CustomCommand)
                    stdoutdata, stderrdata = CustomCommand_process.communicate()
                    CustomCommand_process.wait()
                    sys.exit(0)

                else:
                    sys.exit(0)
        else:
            print("\nSearching asins...")
            ASINS, amazonTypeTemp = SearchASINAmazon(url=url_season)
            
            print("\nDone!")

            if amazonTypeTemp == "movie":
                print("\nMovie dont have seasons!")
                try:
                    if args.onlykeys and args.allkeys:
                        args.hevc = False
                        args.cbr_bitrate = False
                        CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(ASINS)
                        args.cbr_bitrate = True
                        CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(ASINS)
                        args.hevc = True
                        args.cbr_bitrate = False
                        CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(ASINS)
                    else:
                        CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(ASINS)

                    if args.country_code != None:
                        os.system("taskkill /im openvpn.exe /f")

                except Exception:
                    print("No more episodes to download.")
                    if args.country_code != None:
                        os.system("taskkill /im openvpn.exe /f")
                    raise

                if args.custom_command:
                    print("\n")
                    if args.hevc:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC].mkv'
                    elif args.atmos:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC-atmos].mkv'
                    elif args.cbr_bitrate:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [CBR].mkv'
                    else:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p].mkv'
                    CustomCommand = '"' + folderdownloader + '\\' + CurrentName_out + '"'
                    str(args.custom_command[0]) + ' --file-folder ' + CustomCommand
                    CustomCommand_process = subprocess.Popen(str(args.custom_command[0]) + ' --file-folder ' + CustomCommand)
                    stdoutdata, stderrdata = CustomCommand_process.communicate()
                    CustomCommand_process.wait()
                    sys.exit(0)

                else:
                    sys.exit(0)

            else:
                asinList2=[]
                episodes = gen_episode_list(args.episodeStart, len(ASINS))
                for (num, asin) in sorted(ASINS.items()):
                    if num in episodes:
                        asinList2.append(asin)

                for y in asinList2:
                    try:
                        if args.onlykeys and args.allkeys:
                            args.hevc = False
                            args.cbr_bitrate = False
                            CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(y)
                            args.cbr_bitrate = True
                            CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(y)
                            args.hevc = True
                            args.cbr_bitrate = False
                            CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(y)
                        else:
                            CurrentName, SeasonFolder, CurrentHeigh = DownloadAll(y)
                    except Exception:
                        print("No more episodes to download.")
                        if args.country_code != None:
                            os.system("taskkill /im openvpn.exe /f")
                        raise

                if args.country_code != None:
                    os.system("taskkill /im openvpn.exe /f")

                if args.custom_command:
                    print("\n")
                    if args.hevc:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC].mkv'
                    elif args.atmos:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [HEVC-atmos].mkv'
                    elif args.cbr_bitrate:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p] [CBR].mkv'
                    else:
                        CurrentName_out = str(CurrentName) + ' [' + str(CurrentHeigh) + 'p].mkv'
                    CustomCommand = '"' + folderdownloader + '\\' + str(SeasonFolder) + '"'
                    str(args.custom_command[0]) + ' --file-folder ' + CustomCommand
                    CustomCommand_process = subprocess.Popen(str(args.custom_command[0]) + ' --file-folder ' + CustomCommand)
                    stdoutdata, stderrdata = CustomCommand_process.communicate()
                    CustomCommand_process.wait()
                    sys.exit(0)

                else:
                    sys.exit(0)
