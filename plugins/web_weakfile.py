#coding:utf-8

from lib.common import requests_headers,requests_proxies
from lib.config import code_flag

import re
import requests
import urlparse
import traceback

# Ignore warning
requests.packages.urllib3.disable_warnings()

def weakfile(url):
	'''
	Weakfile scan with some tricks
	'''
	dirs = []
	headers = requests_headers()
	proxies = requests_proxies()
	payloads = ["/.git/config","/.DS_Store","/www.zip","/.svn/entries","/.svn/wc.db","/.git/index","/www.tar.gz",'/index.php']
	url_path = urlparse.urlparse(url).path
	if url[-1:] == '/':
		url = url[:-1]
	try:
		count_flag,len_flag = 0,[]
		print '[*] Now scan path weakfile: %s' % url
		for payload in payloads:
			try:
				if count_flag < 5:
					req = requests.get(url=url+payload,proxies=proxies,verify=False,headers=headers,timeout=5)
					if req.status_code in code_flag and len(req.content) != 0 and len(req.content) not in len_flag:
						count_flag += 1
						len_flag.append(len(req.content))
						print '[+] Get %s%s 200 %s' % (url,payload,len(req.content))
						dir_flag = '<a href="'+url+payload+'" target=_blank />'+urlparse.urlparse(url).path[:10]+payload+'</a>'
						dirs.append(dir_flag)
				else:
					print '[!] Maybe Got weakdir waf'
					return ["waf"]
			except Exception,e:
				# print traceback.format_exc()
				pass
	except Exception,e:
		# print traceback.format_exc()
		pass
	if len(dirs) >= 3:
		return ["waf"]
	elif ".git" in str(dirs) and ".svn" in str(dirs):
		return ["waf"]
	else:
		return dirs

if __name__ == '__main__':
	pass