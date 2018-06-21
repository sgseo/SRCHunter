#coding:utf-8

from lib.common import requests_headers,requests_proxies
from lib.config import code_flag

import re
import requests
import traceback

def getitle(url):
	'''
	Get title,status_code,content_lenth
	'''
	headers = requests_headers()
	proxies = requests_proxies()
	title,code,lenth,content = '','','',''
	try:
		req = requests.get(url = url, headers = headers, proxies = proxies,verify = False,timeout = 5)
		code = req.status_code
		content = req.content
		# req_headers = req.headers
		lenth = len(content)
		if code in range(200,405) and lenth != 0:
			title = re.findall(r'<title*?>([\s\S]*?)</title>',content)[0].strip()
			try:
				charset = re.findall(r'charset=(.*?)>',str(content))[0]
				charset = charset.strip().replace('"','').replace('/','').replace('utf8','utf-8')
				title = title.decode(charset)
			except Exception,e:
				title = title.decode("gbk","ignore").encode('utf-8')# decode("ascii","ignore")
				pass
	except Exception,e:
		# print traceback.format_exc()
		pass# Ignore Exception
	if title == '' and lenth < 35:
		title = content
	return title,code,lenth,content

if __name__ == '__main__':
	pass