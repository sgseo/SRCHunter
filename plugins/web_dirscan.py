#coding:utf-8

from lib.common import requests_headers,requests_proxies,ranStr,base64str,open_file# getMonth
from lib.config import dir_payloads,code_flag,dir_payloads_file

import re,time
import requests
import traceback
from urllib import quote

# Ignore warning
requests.packages.urllib3.disable_warnings()

def dirscan(url):
	'''
	Webdir weakfile scan with some tricks
	'''
	dirs = []
	headers = requests_headers()
	proxies = requests_proxies()
	# hostbak = urlparse.urlparse(url).hostname
	# month = getMonth()
	random_str = base64str()
	payloads = ["/robots.txt","/README.md","/crossdomain.xml","/.git/config","/.git/index",\
	"/.svn/entries","/.svn/wc.db","/.DS_Store","/CVS/Root","/CVS/Entries",\
	"/.idea/workspace.xml","/composer.lock","/composer.json","/.gitignore"]
	payloads += ["/index.htm","/index.html","/index.php","/index.asp","/index.aspx",\
	"/index.jsp","/index.do","/index.action","/index.shtml"]
	if dir_payloads:
		payloads = list(set(payloads + open_file(dir_payloads_file)))
	# payloads += ["/%flag%.7z","/%flag%.rar","/%flag%.zip","/%flag%.tar.gz"] # hostbak
	# payloads += month
	if url[-1:] == '/':
		url = url[:-1]
	try:
		check_url = url + '/' + str(random_str)# '/Wo4N1Dx1aoKeI'
		print '[*] Now check waf: ' + check_url
		count_flag = 0
		check_waf = requests.get(url=check_url,proxies=proxies,verify=False,headers=headers,timeout=5)
		for payload in payloads:
			try:
				if count_flag < 25: # 30
					# payload = payload.replace('%flag%',hostbak)
					headers = requests_headers()
					req = requests.get(url=url+payload,proxies=proxies,verify=False,headers=headers,timeout=5)
					time.sleep(0.1)
					# req = requests.head(url + payload)in [200,301,302,403]
					if req.status_code in code_flag and len(req.content) != len(check_waf.content) and len(req.content) != 0:
						count_flag += 1
						print '[+] Get %s%s %s %s' % (url,payload,req.status_code,len(req.content))
						dir_flag = '<a href="'+url+payload+'" target=_blank />'+payload+'</a>'
						dirs.append(dir_flag)
				else:
					print '[!] Maybe Got dir waf'
					return ["waf"]
			except Exception,e:
				# print traceback.format_exc()
				pass
	except Exception,e:
		# print traceback.format_exc()
		pass
	if ".git" in str(dirs) and ".svn" in str(dirs):
		return ["waf"]
	if ".asp" in str(dirs) and ".php" in str(dirs) and ".jsp" in str(dirs):
		return ["waf"]
	else:
		return dirs

if __name__ == '__main__':
	pass