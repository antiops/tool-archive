# -*- coding: utf-8 -*-
import os
import subprocess

class Muxer(object):
	def __init__(self, CurrentName, SeasonFolder, CurrentHeigh, Type, mkvmergeexe):
		self.CurrentName = CurrentName
		self.SeasonFolder = SeasonFolder
		self.CurrentHeigh = CurrentHeigh
		self.Type = Type
		self.mkvmergeexe = mkvmergeexe

	def AmazonAndPrimeVideoMuxer(self, lang):
		VideoInputNoExist = False
		if os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p] [CBR].h264'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [CBR].h264'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p] [CBR].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [CBR].mkv'

		if os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p].h264'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p].h264'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p].mkv'

		elif os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HEVC].mp4'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HEVC].mp4'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HEVC].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HEVC].mkv'

		elif os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HEVC].h265'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HEVC].h265'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HEVC].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HEVC].mkv'

		elif os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p] [VP9].mp4'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [VP9].mp4'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p] [VP9].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [VP9].mkv'

		elif os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p] [VP9].vp9'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [VP9].vp9'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p] [VP9].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [VP9].mkv'

		elif os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HDR].mp4'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HDR].mp4'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HDR].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HDR].mkv'

		elif os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HDR].h265'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HDR].h265'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HDR].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [HDR].mkv'

		elif os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p] [AVC HIGH].mp4'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [AVC HIGH].mp4'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p] [AVC HIGH].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [AVC HIGH].mkv'

		elif os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p] [AVC HIGH].h264'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [AVC HIGH].h264'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p] [AVC HIGH].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [AVC HIGH].mkv'

		elif os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p] [CBR].mp4'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [CBR].mp4'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p] [CBR].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p] [CBR].mkv'
		
		elif os.path.isfile(self.CurrentName + ' [' + self.CurrentHeigh + 'p].mp4'):
			VideoInputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p].mp4'
			if self.Type == "show":
				VideoOutputName = os.path.join(self.SeasonFolder, self.CurrentName + ' [' + self.CurrentHeigh + 'p].mkv')
			else:
				VideoOutputName = self.CurrentName + ' [' + self.CurrentHeigh + 'p].mkv'
		else:
			VideoInputNoExist = True

		if VideoInputNoExist == False:
			AudioExtensionsList=[
									".ac3",
									".eac3",
									".m4a",
									".dts",
									".mp3",
									".aac"
								]
			
			SubsExtensionsList= [
									".srt",
									".ass",
								]

			if lang == "English":
				language_tag = "English"
			
			elif lang == "Spanish":
				language_tag = "Spanish"
			
			elif lang == "German":
				language_tag = "German"
			
			else:
				language_tag = "English"

			if language_tag == "English":
				subs_forced = '[Forced]'
				subs_full = '[Full]'
				subs_sdh = '[SDH]'
				#["en", "en", "eng", "English", "yes", "yes"]
				#[audio_language, subs_language, language_id, language_name, audio_default, subs_default]
				LanguageList = [
									["es-la", "es-la", "spa", "Spanish", "yes", "no"],
									["es", "es", "spa", "Castilian", "no", "no"],
									["en", "en", "eng", "English", "no", "no"],
									["cat", "cat", "cat", "Catalan", "no", "no"],
									["eu", "eu", "baq", "Basque", "no", "no"],
									["fr", "fr", "fre", "French", "no", "no"],
									["fr-bg", "fr-bg", "fre", "French (Belgium)", "no", "no"],
									["fr-lu", "fr-lu", "fre", "French (Luxembourg)", "no", "no"],
									["fr-ca", "fr-ca", "fre", "French (Canada)", "no", "no"],
									["de", "de", "ger", "German", "no", "no"],
									["it", "it", "ita", "Italian", "no", "no"],
									["pt", "pt", "por", "Portuguese", "no", "no"],
									["pt-br", "pt-br", "por", "Brazilian Portuguese", "no", "no"],
									["pl", "pl", "pol", "Polish", "no", "no"],
									["tr", "tr", "tur", "Turkish", "no", "no"],
									["hy", "hy", "arm", "Armenian", "no", "no"],
									["sv", "sv", "swe", "Swedish", "no", "no"],
									["da", "da", "dan", "Danish", "no", "no"],
									["fi", "fi", "fin", "Finnish", "no", "no"],
									["nl", "nl", "dut", "Dutch", "no", "no"],
									["nl-be", "nl-be", "dut", "Flemish", "no", "no"],
									["no", "no", "nor", "Norwegian", "no", "no"],
									["lv", "lv", "lav", "Latvian", "no", "no"],
									["is", "is", "ice", "Icelandic", "no", "no"],
									["ru", "ru", "rus", "Russian", "no", "no"],
									["ru-by", "ru-by", "rus", "Belarusian", "no", "no"],
									["uk", "uk", "ukr", "Ukrainian", "no", "no"],
									["hu", "hu", "hun", "Hungarian", "no", "no"],
									["bg", "bg", "bul", "Bulgarian", "no", "no"],
									["hr", "hr", "hrv", "Croatian", "no", "no"],
									["lt", "lt", "lit", "Lithuanian", "no", "no"],
									["et", "et", "est", "Estonian", "no", "no"],
									["el", "el", "gre", "Greek", "no", "no"],
									["he", "he", "heb", "Hebrew", "no", "no"],
									["ar", "ar", "ara", "Arabic", "no", "no"],
									["fa", "fa", "per", "Persian", "no", "no"],
									["ro", "ro", "rum", "Romanian", "no", "no"],
									["sr", "sr", "srp", "Serbian", "no", "no"],
									["cs", "cs", "cze", "Czech", "no", "no"],
									["sk", "sk", "slo", "Slovak", "no", "no"],
									["sl", "sl", "slv", "Slovenian", "no", "no"],
									["sq", "sq", "alb", "Albanian", "no", "no"],
									["bs", "bs", "bos", "Bosnian", "no", "no"],
									["mk", "mk", "mac", "Macedonian", "no", "no"],
									["hi", "hi", "hin", "Hindi", "no", "no"],
									["bn", "bn", "ben", "Bengali", "no", "no"],
									["ur", "ur", "urd", "Urdu", "no", "no"],
									["pa", "pa", "pan", "Punjabi", "no", "no"],
									["ta", "ta", "tam", "Tamil", "no", "no"],
									["te", "te", "tel", "Telugu", "no", "no"],
									["mr", "mr", "mar", "Marathi", "no", "no"],
									["kn", "kn", "kan", "Kannada (India)", "no", "no"],
									["gu", "gu", "guj", "Gujarati", "no", "no"],
									["ml", "ml", "mal", "Malayalam", "no", "no"],
									["si", "si", "sin", "Sinhala", "no", "no"],
									["as", "as", "asm", "Assamese", "no", "no"],
									["mni", "mni", "mni", "Manipuri", "no", "no"],
									["tl", "tl", "tgl", "Tagalog", "no", "no"],
									["id", "id", "ind", "Indonesian", "no", "no"],
									["ms", "ms", "may", "Malay", "no", "no"],
									["fil", "fil", "fil", "Filipino", "no", "no"],
									["vi", "vi", "vie", "Vietnamese", "no", "no"],
									["th", "th", "tha", "Thai", "no", "no"],
									["km", "km", "khm", "Khmer", "no", "no"],
									["ko", "ko", "kor", "Korean", "no", "no"],
									["zh", "zh", "chi", "Mandarin", "no", "no"],
									["yue", "yue", "chi", "Cantonese", "no", "no"],
									["zh-hans", "zh-hans", "chi", "Chinese (Simplified)", "no", "no"],
									["zh-hant", "zh-hant", "chi", "Chinese (Traditional)", "no", "no"],
									["zh-hk", "zh-hk", "chi", "Chinese (Simplified)", "no", "no"],
									["zh-tw", "zh-tw", "chi", "Chinese (Traditional)", "no", "no"],
									["zh-sg", "zh-sg", "chi", "Chinese (Singapore)", "no", "no"],
									["ja", "ja", "jpn", "Japanese", "no", "no"],
									["tlh", "tlh", "tlh", "Klingon", "no", "no"],
									["zxx", "zxx", "zxx", "No Dialogue", "no", "no"]
								]

			elif language_tag == "Spanish":
				subs_forced = '[Forzados]'
				subs_full = '[Completos]'
				subs_sdh = '[Para sordos]'
				#["en", "en", "eng", "English", "yes", "yes"]
				#[audio_language, subs_language, language_id, language_name, audio_default, subs_default]
				LanguageList = [
									["es", "es", "spa", "Castellano", "yes", "no"],
									["es-la", "es-la", "spa", "Español latino", "no", "no"],
									["cat", "cat", "cat", "Catalán", "no", "no"],
									["eu", "eu", "baq", "Euskera", "no", "no"],
									["en", "en", "eng", "Inglés", "no", "no"],
									["fr", "fr", "fre", "Francés", "no", "no"],
									["fr-bg", "fr-bg", "fre", "Francés (Bélgica)", "no", "no"],
									["fr-lu", "fr-lu", "fre", "Francés (Luxemburgo)", "no", "no"],
									["fr-ca", "fr-ca", "fre", "Francés (Canadá)", "no", "no"],
									["de", "de", "ger", "Alemán", "no", "no"],
									["it", "it", "ita", "Italiano", "no", "no"],
									["pt", "pt", "por", "Portugués", "no", "no"],
									["pt-br", "pt-br", "por", "Portugués brasileño", "no", "no"],
									["pl", "pl", "pol", "Polaco", "no", "no"],
									["tr", "tr", "tur", "Turco", "no", "no"],
									["hy", "hy", "arm", "Armenio", "no", "no"],
									["sv", "sv", "swe", "Sueco", "no", "no"],
									["da", "da", "dan", "Danés", "no", "no"],
									["fi", "fi", "fin", "Finés", "no", "no"],
									["nl", "nl", "dut", "Holandés", "no", "no"],
									["nl-be", "nl-be", "dut", "Flamenco", "no", "no"],
									["no", "no", "nor", "Noruego", "no", "no"],
									["lv", "lv", "lav", "Letón", "no", "no"],
									["is", "is", "ice", "Islandés", "no", "no"],
									["ru", "ru", "rus", "Ruso", "no", "no"],
									["ru-by", "ru-by", "rus", "Bielorruso", "no", "no"],
									["uk", "uk", "ukr", "Ucrainés", "no", "no"],
									["hu", "hu", "hun", "Húngaro", "no", "no"],
									["bg", "bg", "bul", "Búlgaro", "no", "no"],
									["hr", "hr", "hrv", "Croata", "no", "no"],
									["lt", "lt", "lit", "Lituano", "no", "no"],
									["et", "et", "est", "Estonio", "no", "no"],
									["el", "el", "gre", "Griego", "no", "no"],
									["he", "he", "heb", "Hebreo", "no", "no"],
									["ar", "ar", "ara", "Árabe", "no", "no"],
									["fa", "fa", "per", "Persa", "no", "no"],
									["ro", "ro", "rum", "Rumano", "no", "no"],
									["sr", "sr", "srp", "Serbio", "no", "no"],
									["cs", "cs", "cze", "Checo", "no", "no"],
									["sk", "sk", "slo", "Eslovaco", "no", "no"],
									["sl", "sl", "slv", "Esloveno", "no", "no"],
									["sq", "sq", "alb", "Albanés", "no", "no"],
									["bs", "bs", "bos", "Bosnio", "no", "no"],
									["mk", "mk", "mac", "Macedonio", "no", "no"],
									["hi", "hi", "hin", "Hindi", "no", "no"],
									["bn", "bn", "ben", "Bengalí", "no", "no"],
									["ur", "ur", "urd", "Urdú", "no", "no"],
									["pa", "pa", "pan", "Panyabí", "no", "no"],
									["ta", "ta", "tam", "Tamil", "no", "no"],
									["te", "te", "tel", "Télugu", "no", "no"],
									["mr", "mr", "mar", "Maratí", "no", "no"],
									["kn", "kn", "kan", "Canarés", "no", "no"],
									["gu", "gu", "guj", "Guyaratí", "no", "no"],
									["ml", "ml", "mal", "Malabar", "no", "no"],
									["si", "si", "sin", "Cingalés", "no", "no"],
									["as", "as", "asm", "Asamés", "no", "no"],
									["mni", "mni", "mni", "Meitei", "no", "no"],
									["tl", "tl", "tgl", "Tagalo", "no", "no"],
									["id", "id", "ind", "Indonesio", "no", "no"],
									["ms", "ms", "may", "Malayo", "no", "no"],
									["fil", "fil", "fil", "Filipino", "no", "no"],
									["vi", "vi", "vie", "Vietnamita", "no", "no"],
									["th", "th", "tha", "Tailandés", "no", "no"],
									["km", "km", "khm", "Camboyano", "no", "no"],
									["ko", "ko", "kor", "Coreano", "no", "no"],
									["zh", "zh", "chi", "Mandarín", "no", "no"],
									["yue", "yue", "chi", "Cantonés", "no", "no"],
									["zh-hans", "zh-hans", "chi", "Chino (Simplificado)", "no", "no"],
									["zh-hant", "zh-hant", "chi", "Chino (Tradicional)", "no", "no"],
									["zh-hk", "zh-hk", "chi", "Chino (Simplificado)", "no", "no"],
									["zh-tw", "zh-tw", "chi", "Chino (Tradicional)", "no", "no"],
									["ja", "ja", "jpn", "Japonés", "no", "no"],
									["tlh", "tlh", "tlh", "Klingon", "no", "no"],
									["zxx", "zxx", "zxx", "Sin diálogo", "no", "no"]
								]

			ALLAUDIOS = []
			default_active_audio = False
			for audio_language, subs_language, language_id, language_name, audio_default, subs_default in LanguageList:
				for AudioExtension in AudioExtensionsList:
					if os.path.isfile(self.CurrentName + ' (' + audio_language + ')' + AudioExtension):
						if default_active_audio == True: audio_default = "no"
						ALLAUDIOS = ALLAUDIOS + ['--language', '0:' + language_id, '--track-name', '0:' + language_name, '--default-track', '0:' + audio_default, '(', self.CurrentName + ' (' + audio_language + ')' + AudioExtension, ')']
						if audio_default == "yes": default_active_audio = True

			for audio_language, subs_language, language_id, language_name, audio_default, subs_default in LanguageList:
				for AudioExtension in AudioExtensionsList:
					if os.path.isfile(self.CurrentName + ' (' + audio_language + '_descriptive)' + AudioExtension):
						if default_active_audio == True: audio_default = "no"
						ALLAUDIOS = ALLAUDIOS + ['--language', '0:' + language_id, '--track-name', '0:' + language_name + ' (Audio Description)', '--default-track', '0:no', '(', self.CurrentName + ' (' + audio_language + '_descriptive)' + AudioExtension, ')']
						if audio_default == "yes": default_active_audio = True

			OnlyOneLanguage = False
			if len(ALLAUDIOS) == 9:
				OnlyOneLanguage = True
			
			elif len(ALLAUDIOS) == 18:
				if ALLAUDIOS[1] == ALLAUDIOS[10]:
					if '_descriptive' in ALLAUDIOS[7] or '_descriptive' in ALLAUDIOS[16]:
						OnlyOneLanguage = True
			else:
				OnlyOneLanguage = False


			ALLSUBS = []
			default_active_subs = False
			for audio_language, subs_language, language_id, language_name, audio_default, subs_default in LanguageList:
				for SubsExtension in SubsExtensionsList:
					if os.path.isfile(self.CurrentName + ' (' + subs_language + ') Forced' + SubsExtension):
						if subs_default == "yes": default_active_subs = True
						ALLSUBS = ALLSUBS + ['--language', '0:' + language_id, '--track-name', '0:' + language_name + ' ' + subs_forced, '--forced-track', '0:yes', '--default-track', '0:' + subs_default, '--compression', '0:none', '(', self.CurrentName + ' (' + subs_language + ') Forced' + SubsExtension, ')']
					
					if OnlyOneLanguage == True:
						if default_active_subs == True: subs_default = "no"
						if os.path.isfile(self.CurrentName + ' (' + subs_language + ')' + SubsExtension):
							ALLSUBS = ALLSUBS + ['--language', '0:' + language_id, '--track-name', '0:' + language_name + ' ' + subs_full, '--forced-track', '0:no', '--default-track', '0:' + subs_default, '--compression', '0:none', '(', self.CurrentName + ' (' + subs_language + ')' + SubsExtension, ')']
					
					else:
						if os.path.isfile(self.CurrentName + ' (' + subs_language + ')' + SubsExtension):
							ALLSUBS = ALLSUBS + ['--language', '0:' + language_id, '--track-name', '0:' + language_name + ' ' + subs_full, '--forced-track', '0:no', '--default-track', '0:no', '--compression', '0:none', '(', self.CurrentName + ' (' + subs_language + ')' + SubsExtension, ')']

					if os.path.isfile(self.CurrentName + ' (' + subs_language + '-sdh)' + SubsExtension):
						ALLSUBS = ALLSUBS + ['--language', '0:' + language_id, '--track-name', '0:' + language_name + ' ' + subs_sdh, '--forced-track', '0:no', '--default-track', '0:no', '--compression', '0:none', '(', self.CurrentName + ' (' + subs_language + '-sdh)' + SubsExtension, ')']

			#(Chapters)
			if os.path.isfile(self.CurrentName+' Chapters.txt'):
				CHAPTERS=['--chapter-charset', 'UTF-8', '--chapters',self.CurrentName+' Chapters.txt']
			else:
				CHAPTERS=[]


			mkvmerge_command_video = [self.mkvmergeexe,
									'-q',
									'--output',
									VideoOutputName,
									'--language',
									'0:und',
									'--default-track',
									'0:yes',
									'(',
									VideoInputName,
									')']
			


			mkvmerge_command = mkvmerge_command_video + ALLAUDIOS + ALLSUBS + CHAPTERS
			mkvmerge_process = subprocess.run(mkvmerge_command, check=True)
