import sys, os, random, string, platform
from os.path import dirname
from os.path import join
from pywidevine.cdm import cdm, deviceconfig

dirPath = dirname(dirname(__file__)).replace("\\", "/")

class utils:
	def __init__(self):
		self.dir = dirPath

	def random_hex(self, length: int) -> str:
		"""return {length} of random string"""
		return "".join(random.choice("0123456789ABCDEF") for _ in range(length))

utils_ = utils()

#####################################(DEVICES)#####################################

devices_dict = {
	"android_general": deviceconfig.device_android_general,
}

DEVICES = {
	"NETFLIX-MANIFEST": devices_dict["android_general"],
	"NETFLIX-LICENSE": devices_dict["android_general"],
}

#####################################(MUXER)#####################################

MUXER = {
	"muxer_file": f"{dirPath}/bin/muxer.json",
	"mkv_folder": None,
	"DEFAULT": False,  # to use the normal renaming. EX: Stranger Things S01E01 [1080p].mkv
	"AUDIO": "hin",  # default audio language.
	"SUB": "None",  # default subtitle language. EX: "eng" or "spa"
	"GROUP": "TJUPT",  # to change the group name!. it's also possible to use this "--gr LOL", on the ripping commands.
	"noTitle": True,  # this will remove titles from the episodes EX: (The Witcher S01E01). insstead of (The Witcher S01E01 The End's Beginning).
	"scheme": "p2p",  # add/change any needed scheme naming. it's also possible to use this "--muxscheme repack", on the ripping commands.
	"schemeslist": {
		"p2p": "{t}.{r}.{s}.WEB-DL.{vc}.{ac}-{gr}",
		"test": "{t}.{r}.{s}.WEB-DL-{gr}",
	},
	"EXTRAS": [],  # extra mkvmerge.exe commands.
	"FPS24": [],
}

#####################################(PATHS)#####################################

PATHS = {
	"DL_FOLDER": f"{dirPath}", #
	"DIR_PATH": f"{dirPath}",
	"BINARY_PATH": f"{dirPath}/bin",
	"COOKIES_PATH": f"{dirPath}/configs/Cookies",
	"KEYS_PATH": f"{dirPath}/configs/KEYS",
	"TOKENS_PATH": f"{dirPath}/configs/Tokens",
	"JSON_PATH": f"{dirPath}/json",
	"LOGA_PATH": f"{dirPath}/bin/tools/aria2c",
}

ARIA2C = {
	"enable_logging": False,  # True
	"enable_pass_config_to_aria2c": True, #传递aria2c参数
	"file_allocation": "none", # 文件预分配方式：机械硬盘 falloc，固态硬盘 none
	"http_proxy_aria2c": "http://127.0.0.1:7890", # 代理地址，根据需要修改
    "https_proxy_aria2c": "http://127.0.0.1:7890",
	"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36",
	"connection": "64", # 单服务器最大连接线程数
	"split": "64", # 单任务最大连接线程数
	"summary_interval": "0", # 下载进度摘要输出间隔时间
	"continue_aria2c": "true", # 断点续传
	"max_tries": "0", # 最大尝试次数，0 表示无限
	"piece_length": "1M", # HTTP/FTP下载分片大小
	"min_split_size": "4M", # 文件最小分段大小，理论上值越小下载速度越快
	"disk_cache": "64M", # 磁盘缓存，提升读写性能，有足够内存情况下增加
}

SETTINGS = {
	"skip_video_demux": [],
}

#####################################(VPN)#####################################
# 不要修改这部分
VPN = {
	"proxies": None, # "http://151.253.165.70:8080",
	"nordvpn": {
		"port": "80",
		"email": "xxx",
		"passwd": "xxx",
		"http": "http://{email}:{passwd}@{ip}:{port}",
	},
	"private": {
		"port": "8080",
		"email": "xxx",  
		"passwd": "123456", 
		"http": "http://{email}:{passwd}@{ip}:{port}",
	},
}

#####################################(BIN)#####################################

BIN = {
		"mp4decrypt_moded": f"{dirPath}/bin/tools/mp4decrypt.exe",
		"mp4dump": f"{dirPath}/bin/tools/mp4dump.exe",
		"ffmpeg": f"{dirPath}/bin/tools/ffmpeg.exe",
		"ffprobe": f"{dirPath}/bin/tools/ffprobe.exe",
		"MediaInfo": f"{dirPath}/bin/tools/MediaInfo.exe",
		"mkvmerge": f"{dirPath}/bin/tools/mkvmerge.exe",
		"aria2c": f"{dirPath}/bin/tools/aria2c.exe",
	}

#####################################(Config)#####################################

Config = {}

Config["NETFLIX"] = {
	"cookies_file": f"{dirPath}/configs/Cookies/cookies_nf.txt",
	"cookies_txt": f"{dirPath}/configs/Cookies/cookies.txt",
	"keys_file": f"{dirPath}/configs/KEYS/netflix.keys",
	"token_file": f"{dirPath}/configs/Tokens/netflix_token.json",
	"email": "xxxxxx@gmail.com",
	"password": "123123",
	"manifest_language": "en-US",
	"metada_language": "en",
	"manifestEsn": "NFCDIE-03-{}".format(utils().random_hex(30)),
	"androidEsn": "NFANDROID1-PRV-P-GOOGLEPIXEL=4=XL-8162-" + utils_.random_hex(64),
}

#####################################(DIRS & FILES)##############################

def make_dirs():
	FILES = []

	DIRS = [
		f"{dirPath}/configs/Cookies",
		f"{dirPath}/configs/Tokens",
		f"{dirPath}/bin/tools/aria2c",
	]

	for dirs in DIRS:
		if not os.path.exists(dirs):
			os.makedirs(dirs)

	for files in FILES:
		if not os.path.isfile(files):
			with open(files, "w") as f:
				f.write("\n")

make_dirs()

#####################################(tool)#####################################

class tool:
	def config(self, service):
		return Config[service]

	def bin(self):
		return BIN

	def vpn(self):
		return VPN

	def paths(self):
		return PATHS

	def muxer(self):
		return MUXER

	def devices(self):
		return DEVICES

	def aria2c(self):
		return ARIA2C

	def video_settings(self):
		return SETTINGS
