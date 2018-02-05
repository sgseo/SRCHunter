# coding:utf-8
# 
# author:whoam1
#
# blog:http://www.cnnetarmy.com/
#
# Use to Collect information for web Pentest.
#

import os
import re
import sys
import time
import json
import socket
import random
import base64
import datetime
import urlparse
from multiprocessing.pool import Pool

try:
	import requests
except:
	print 'pip install requests[security]'
	os._exit(0)

reload(sys)
sys.setdefaultencoding('utf-8')
#sys.dont_write_bytecode = True
requests.packages.urllib3.disable_warnings()

global filter_ips,filter_ports
filter_ips = [] # filter ip for already scaned ip queue
filter_ports = [21,22,23,25,53,110,135,139,143,389,445,465,587,873,993,995,1080,1433,1521,1723,2181,3306,3389,5432,5900,6379,11211,27017]

def report():
	'''
	Report result to target_time.html
	'''
	output_file = sys.argv[2].split('.')[0] + time.strftime('%Y-%m-%d',time.localtime(time.time()))+'.html'
	return output_file

def requests_headers():
	'''
	Random UA  for every requests && Use cookie to scan
	'''
	cookie = 'Change Me !!!'
	user_agent = ['Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0',
	'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0',
	'Mozilla/5.0 (Windows; U; Windows NT 5.1 ; x64; en-US; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre',
	'Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60','Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)',
	'Mozilla/5.0 (Windows; U; Windows NT 5.1; ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14',
	'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
	'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr; rv:1.9.2.4) Gecko/20100523 Firefox/3.6.4 ( .NET CLR 3.5.30729)',
	'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
	'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5']
	UA = random.choice(user_agent)
	headers = {
	'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
	'User-Agent':UA,'Upgrade-Insecure-Requests':'1','Connection':'keep-alive','Cache-Control':'max-age=0',
	'Accept-Encoding':'gzip, deflate, sdch','Accept-Language':'zh-CN,zh;q=0.8','Cookie':cookie}
	return headers

def requests_proxies():
	'''
	Proxies for every requests
	'''
	proxies = {
	'http':'',# 127.0.0.1:1080shadowsocks
	'https':''#127.0.0.1:8080 BurpSuite
	}
	return proxies

def getallink(url):
	'''
	Get response all link 
	'''
	headers = requests_headers()
	proxies = requests_proxies()
	links = []
	tags = ['a','A','link','script','area','iframe','form']#img
	tos = ['href','src','action']
	try:
		req = requests.get(url=url,proxies=proxies,verify=False,headers=headers,timeout=3)
		#if req.status_code in range(300,310):
		#	return req.url
		if 'location.href="' in req.content:
			url = url + re.findall(r'location.href="(.*?)";',req.content)[0].replace(url,'').replace(urlparse.urlparse(url).hostname,'')
		for tag in tags:
			for to in tos:
				link = re.findall(r'<%s.*?%s="(.*?)"'%(tag,to),str(req.content))
				for i in link:#filter					
					if i not in links and '.png' not in i and 'javascript' not in i and '.svg' not in i and '.jpg' not in i and '.js' not in i and '.css' not in i and '/css?' not in i and '.gif' not in i and '.jpeg' not in i and '.ico' not in i and '.swf' not in i and '.mpg' not in i:
						links.append(i)
	except Exception,e:
		print e
		pass
	return links

def email_regex(raw):
	'''
	Collect email
	test#cnnetarmy.com | Admin01@cnnetarmy.com.cn | san.Zhang@cnnetarmy.com | si01.Li@cnnetarmy.com | zhaowu01@cnnetarmy.com
	'''
	emails = []
	regex = '[-_\w\.]{0,64}\@[-_\w\.]{0,64}\.{1,2}[-_\w\.]{0,64}'
	regex_one = '([\w-]+@[\w-]+\.[\w-]+)+'
	regex_two = '[-_\w\.]{0,64}[@#][-_\w\.]{0,64}\.{1,2}[-_\w\.]{0,64}'
	regex_three = "[\w!#$%&'*+/=?^_`{|}~-]+(?:\.[\w!#$%&'*+/=?^_`{|}~-]+)*[@#](?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])"
	regex_four = '\w[-\w.+]*[@#]([A-Za-z0-9][-A-Za-z0-9]+\.)+[A-Za-z]{2,14}'
	mailto = r'mailto:(.*?)"'
	try:
		emails = re.findall(regex_three,str(raw))
	except Exception,e:
		print e
		pass
	return emails
	#baidu_email = baidu_email()
	#github_email = github_email()
	#baidu_email() / google() / github() / haosou() / weibo() / zhihu()
	#somo(api_url="http://115.159.184.207:8080/",target=raw) # Search register in hot website.

def ip_regex(raw):
	'''
	Collect ip
	1.1.1.1 | 10.1.1.1 | 256.10.1.256 | 222.212.22.11
	'''
	ips = []
	regex = '((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)'
	regex_one = '[1-9]{1,3}\.[1-9]{1,3}\.[1-9]{1,3}\.[1-9]{1,3}'
	try:
		ips = re.findall(regex,str(raw))
	except Exception,e:
		print e
		pass
	return ips

def idcard(raw):
	'''
	Collect idcard -- Disable plugins
	'''
	#regex_18 = "\b([1-9]\d{5}[1-9]\d{3}((0\d)|(1[0-2]))(([0|1|2]\d)|3[0-1])\d{3}([0-9]|X))\b"
	#regex_15 = r"\b([1-9]\d{7}((0\d)|(1[0-2]))(([0|1|2]\d)|3[0-1])\d{3})\b"

def url_regex(raw):
	'''
	Collect url
	'''
	urls = []
	regex = '[a-zA-z]+://[^\s]*'
	regex_one = r"\b(http://(\d{1,3}\.){3}\d{1,3}(:\d+)?)\b"
	regex_two = r"((?:https?|ftp|file):\/\/[\-A-Za-z0-9+&@#/%?=~_|!:,.;\*]+[\-A-Za-z0-9+&@#/%=~_|])"
	try:
		urls = re.findall(regex_two,str(raw))
	except Exception,e:
		print e
		pass
	return urls

def c_duan(ip):
	'''
	Collect ip C.x
	'''
	ip_list = []
	try:
		ip_split = ip.split('.')
		for c in xrange(1,255):
			ip = "%s.%s.%s.%d" % (ip_split[0],ip_split[1],ip_split[2],c)
			ip_list.append(ip)
			open_ports = portscan(ip)
			print ip,open_ports
	except Exception,e:
		print e
		pass
	return ip_list

def SameIpDomain(ip):
	'''
	Same Ip Domains
	https://www.bing.com/search?q=IP:43.242.128.230&ensearch=1
	Yujian 2014
	SameIpDomain = ["69116912.com","allensnote.com","baidudaili.net","cbbteam.com","cnnetarmy.com","howeal.com","manbajs.com","njchao.com","nxrtts.com","ourjob.it","shuadanla.com","sijiyoumei.net","wiliu.com","woobian.com","www.cnnetarmy.com","www.shuadanla.com","www.xitongbashi.com","xitongbashi.com","yanghe56.com","yuxith.com"]
	https://www.tcpiputils.com/reverse-ip/43.242.128.230
	'''
	SameIpDomain = []
	headers = requests_headers()
	proxies = requests_proxies()
	if str(proxies) == "{'http': '', 'https': ''}":
		print 'Host api.hackertarget.com need use proxies'
		return SameIpDomain
	else:
		try:
			api = 'http://api.hackertarget.com/reverseiplookup/?q={}'.format(ip)#43.242.128.230
			req = requests.get(url=api,headers=headers,proxies=proxies,timeout=5,verify = False)
			keys = req.content.split('\n')
			for key in keys:
				if key not in SameIpDomain:
					SameIpDomain.append(key)
					print '[+] Get SameIpDomainList: ' + key
		except Exception,e:
			print e
			pass
	return SameIpDomain

def portscan(ip):
	'''
	Scan open port | all ports
	'''
	open_ports = []
	try:
		m = __import__('portscan')
		p = m.Work(scan_target = ip)
		open_ports = p.run()
	except:
		print '[*] Need load portscan.py plugin'
		print '[*] Download from: http://www.cnnetarmy.com/soft/portscan.py'
		pass
	if len(open_ports) > 100:
		print '[!] Maybe got waf'
		return open_ports
	return open_ports

def url2ip(url):
	'''
	Url to ip
	'''
	ip = None
	try:
		handel_url = urlparse.urlparse(url).hostname
		ip = socket.gethostbyname(handel_url)
	except:
		print '[!] Can not get ip'
		pass
	return ip

def ipaddr(ip):
	'''
	Get ip addr info
	'''
	headers = requests_headers()
	proxies = requests_proxies()
	ip_data = {}
	try:
		api_url = 'http://ip.taobao.com/service/getIpInfo.php?ip={}'.format(ip)
		#api_one = 'https://api.shodan.io/shodan/host/218.196.240.8'
		req = requests.get(url = api_url, headers = headers, proxies = proxies,verify = False,timeout = 5)
		local_ip = json.loads(req.content)
		ip_data = local_ip['data']
	except Exception,e:
		print e
		pass
	return ip_data

def whois(url):
	'''
	Get whois
	'''
	api = 'http://whois.chinaz.com/www.cnnetarmy.com'
	api_one = 'https://x.threatbook.cn/domain/www.cnnetarmy.com'
	whois_result = []
	try:
		import whois
		domain_whois = whois.whois(url)#"http://www.cnnetarmy.com"
		whois_result = json.loads(str(domain_whois))
	except:
		print 'pip install whois'
		pass
	return whois_result

def baidu_site(url):
	'''
	Baidu site
	'''
	if '://' in url:
		url = urlparse.urlparse(url).hostname
	baidu_url = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{}'.format(url)
	headers = requests_headers()
	proxies = requests_proxies()
	try:
		r = requests.get(url = baidu_url, headers = headers, proxies = proxies,verify = False,timeout = 5).content
		if 'class=\"nors\"' not in r:
			#return '<a href="%s" target=_blank />Baidu_site</a>' % baidu_url
			domains = []
			for i in xrange(0,100):#max page_number
				pn = i * 10
				newurl = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{}&pn={}&oq=site:{}'.format(url,pn,url)
				keys = requests.get(url = newurl, headers = headers, proxies = proxies,verify = False,timeout = 5).content
				flag = re.findall(r'style=\"text-decoration:none;\">(.*?)<\/a><div class=\"c-tools\"',keys)
				for j in flag:
					domain = j.split('.')[0]
					domain_handle = domain.replace('https://','').replace('http://','')
					if domain_handle not in domains:
						print domain_handle
						domains.append(domain_handle)
			return domains
		else:
			return ''
	except Exception,e:
		print e
		pass
		return ''

def subdomain(url):
	'''
	Collect subdomain
	subdomain twice -> (good.txt).urlparse.urlparse(url).hostname
	FuzzDomain.jar -> https://github.com/Chora10/FuzzDomain
	https://github.com/yanxiu0614/subdomain3
	Layer
	'''
	baidu_site = baidu_site(url)#site:cnnetarmy.com |google()|github()

def whatcms(url):
	'''
	Cms type identify
	Handle BugScan whatcms.py to requests only leave common cms type data
	To do load xxxcms payload
	api_one = 'http://whatweb.bugscaner.com/look/'	
	'''
	headers = requests_headers()
	proxies = requests_proxies()
	try:
		s = requests.Session()
		r = s.get(url='http://whatweb.bugscaner.com/look/',headers = headers, proxies = proxies,verify = False,timeout = 5).content
		hash_r = re.findall(r'<input type="hidden" value="(.*?)" name="hash" id="hash">',str(r))[0]
		url_handle = url.replace(':8080','').replace(':80','')
		if '://' in url:
			url_handle = url.split('://')[1].replace("/",'')
		data = "url={}&hash={}".format(url_handle,hash_r)
		key = s.post(url='http://whatweb.bugscaner.com/what/',headers = headers, proxies = proxies,verify = False,timeout = 5).content
		result = json.loads(key)
		if len(result["cms"]) > 0:
			return result["cms"]
		else:
			return 'www'
	except:
		return 'www'
		pass

def base64str():
	'''
	Return Random base64 string
	'''
	key = random.random() * 10 # Handle "0." ->"/MC4" Character
	return base64.b64encode(str(key)).replace('=','')

def checkFast(url):
	'''
	Main requests function no Dirscan
	'''
	headers = requests_headers()
	proxies = requests_proxies()
	output_file = report()
	if '://' not in url:
		url = 'http://' + url
		if ':80' in url:
			url = urlparse.urlparse(url).scheme + "://" + urlparse.urlparse(url).netloc.split(':')[0]
		if ':443' in url:
			url = 'https://' + url.replace(':443','').replace('http://','')
	try:
		print '[*] Now is scanning: ' + url
		req = requests.get(url = url, headers = headers, proxies = proxies,verify = False,timeout = 5)
		if req.status_code in range(200,405):# and len(req.content) != 0:
			open_ports = '[]'
			try:
				ip = url2ip(url)
				if str(ip) not in filter_ips:
					filter_ips.append(str(ip))
					print '[+] Get ip: ' + ip
					open_ports = portscan(ip)
			except 	Exception,e:
				print e
				pass
			print '[+] Get open ports: ' + str(open_ports)
			if str(open_ports) == '[]':
				print '[!] Get open port lists None. Just scan 80 port...'
				newtitle = ''
				code = ''
				lenth = ''
				try:
					newtitle,code,lenth =  getitle(url)
				except Exception,e:
					print e
					pass
				if code in range(200,405):# add Do not scan 401 status_code
					print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)				
					output = open(output_file,"a")
					flag = '<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;bytes</td></tr>' % (url,url,ip,code,newtitle,lenth)#,weakuri <td><font color="red">%s</font></td>)#,open_ports)<td><font color="blue">%s</font></td>
					output.write(flag)
					output.close()
			try:
				for port in open_ports:
					if port not in filter_ports:
						if url[-1:] == '/':
							url = url[:-1]
						newurl = url + ':' + str(port)
						if ':443' in newurl:# and 'https://' in url:
							newurl = url.replace(':443','').replace('http://','https://')
						print '[*] Scan new_url: ' + newurl
						newtitle = ''
						code = ''
						lenth = ''
						try:
							newtitle,code,lenth =  getitle(newurl)
						except Exception,e:
							print e
							pass
						if code in range(200,405):# add Do not scan 401 status_code
							print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)						
							output = open(output_file,"a")
							flag = '<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;bytes</td></tr>' % (newurl,newurl,ip,code,newtitle,lenth)
							output.write(flag)
							output.close()
			except Exception,e:
				print e
				pass
	except Exception,e:
		print e
		pass
		#server = ''
		#try:
		#	server = req.headers['Server']
		#	#if len(server) > 16:
		#	#	server = server[:16]
		#except:pass
		#X_Powered_By = ' '
		#try:
		#	X_Powered_By = req.headers['X-Powered-By']
		#except:pass

def getitle(url):
	'''
	Get title,status_code,content_lenth
	'''
	headers = requests_headers()
	proxies = requests_proxies()
	if '://' not in url:
		url = 'http://' + url
	if ':443' in url:
		url = 'https://' + url.replace(':443','').replace('http://','')
	title = ''
	code = ''
	lenth = ''
	try:
		req = requests.get(url = url, headers = headers, proxies = proxies,verify = False,timeout = 3)
		code = req.status_code
		lenth = len(req.content)
		if code in range(200,405) and len(req.content) != 0:
			title = re.findall(r'<title>(.*?)</title>',req.content)[0]
	except:pass#ignore Exception
	return title,code,lenth

def getMonth():
	'''
	Return 3x days ago backup file. eg:20171228.rar
	'''
	month = []
	monPayload = ["/%test%.7z","/%test%.rar","/%test%.zip","/%test%.tar.gz"]
	for mon in monPayload:
		for i in range(3):
			i = (datetime.datetime.now() - datetime.timedelta(days = i))
			flag = i.strftime('%Y%m%d')
			flag = mon.replace('%test%',flag)
			month.append(flag)
	return month

def dirscan(url):
	'''
	Webdir weakfile scan
	'''
	dirs = []
	headers = requests_headers()
	proxies = requests_proxies()
	hostbak = urlparse.urlparse(url).hostname
	month = getMonth()
	random_str = base64str()
	payloads = ["/robots.txt","/README.md","/crossdomain.xml","/.git/config","/.svn/entries","/.svn/wc.db","/.DS_Store","/CVS/Root","/CVS/Entries","/.idea/workspace.xml"]
	payloads += ["/index.htm","/index.html","/index.php","/index.asp","/index.aspx","/index.jsp","/index.do","/index.action"]
	payloads += ["/www/","/console","/web-console","/web_console","/jmx-console","/jmx_console","/JMXInvokerServlet","/invoker","/phpinfo.php","/info.php"]
	payloads += ["/index.bak","/index.swp","/index.old","/.viminfo","/.bash_history","/.bashrc","/project.properties","/config.properties","/config.inc","/common.inc","/db_mysql.inc","/install.inc","/conf.inc","/db.inc","/setup.inc","/init.inc","/config.ini","/php.ini","/info.ini","/setup.ini","/www.ini","/http.ini","/conf.ini","/core.config.ini","/ftp.ini","/data.mdb","/db.mdb","/test.mdb","/database.mdb","/Database.mdf","/BookStore.mdf","/DB.mdf","/1.sql","/install.sql","/schema.sql","/mysql.sql","/dump.sql","/users.sql","/update.sql","/test.sql","/user.sql","/database.sql","/sql.sql","/setup.sql","/init.sql","/login.sql","/backup.sql","/all.sql","/passwd.sql","/init_db.sql","/fckstyles.xml","/Config.xml","/conf.xml","/build.xml","/web.xml","/test.xml","/ini.xml","/www.xml","/db.xml","/database.xml","/admin.xml","/login.xml","/sql.xml","/sample.xml","/settings.xml","/setting.xml","/info.xml","/install.xml","/Php.xml","/.mysql_history"]
	payloads += ["/nginx.conf","/httpd.conf","/test.conf","/conf.conf","/local.conf","/user.txt","/LICENSE.txt","/sitemap.xml","/username.txt","/pass.txt","/passwd.txt","/password.txt","/.htaccess","/web.config","/app.config","/log.txt","/config.xml","/CHANGELOG.txt","/INSTALL.txt","/error.log"]
	payloads += ["/login","/phpmyadmin","/pma","/pmd","/SiteServer","/admin","/Admin/","/manage","/manager","/manage/html","/resin-admin","/resin-doc","/axis2-admin","/admin-console","/system","/wp-admin","/uc_server","/debug","/Conf","/webmail","/service","/ewebeditor"]
	payloads += ["/xmlrpc.php","/search.php","/install.php","/admin.php","/login.php","/l.php","/forum.php"]
	payloads += ["/portal","/blog","/bbs","/webapp","/webapps","/plugins","/cgi-bin","/htdocs","/wsdl","/html","/install","/test","/tmp","/file","/solr/#/","/WEB-INF","/zabbix","/backup","/log"]
	payloads += ["/www.7z","/www.rar","/www.zip","/www.tar.gz","/wwwroot.zip","/wwwroot.rar","/wwwroot.7z","/wwwroot.tar.gz","/%flag%.7z","/%flag%.rar","/%flag%.zip","/%flag%.tar.gz","/backup.7z","/backup.rar","/backup.tar","/backup.tar.gz","/backup.zip","/index.7z","/index.rar","/index.sql","/index.tar","/index.tar.gz","/index.zip"]
	payloads += month
	if url[-1:] == '/':
		url = url[:-1]
	try:
		check_url = url + '/' + str(random_str)#'/Wo4N1Dx1aoKeI'
		print '[*] Now is check waf: ' + check_url
		check_waf = requests.get(url=check_url,proxies=proxies,verify=False,headers=headers,timeout=5)
		for payload in payloads:
			try:
				payload = payload.replace('%flag%',hostbak)
				req = requests.get(url=url+payload,proxies=proxies,verify=False,headers=headers,timeout=5)
				#req = requests.head(url + payload)
				if req.status_code == 200 and abs(len(req.content) - len(check_waf.content)) > 5 and len(req.content) != 0:
					print '[+] Get %s%s 200 %s' % (url,payload,len(req.content))
					dirs.append(payload)
			except Exception,e:
				print e
				pass
	except Exception,e:
		print e
		pass
	if len(dirs) > 40:
		print '[*] Maybe Got waf.'
		return '[]'
	else:
		return dirs

def checkDir(url):
	'''
	Main requests function with  Portscan && Dirscan
	'''
	headers = requests_headers()
	proxies = requests_proxies()
	output_file = report()
	if '://' not in url:
		url = 'http://' + url
		if ':80' in url:
			url = urlparse.urlparse(url).scheme + "://" + urlparse.urlparse(url).netloc.split(':')[0]
		if ':443' in url:
			url = 'https://' + url.replace(':443','').replace('http://','')
	try:
		print '[*] Now is scanning: ' + url
		req = requests.get(url = url, headers = headers, proxies = proxies,verify = False,timeout = 5)
		if req.status_code in range(200,405):# and len(req.content) != 0:
			open_ports = '[]'
			try:
				ip = url2ip(url)
				if str(ip) not in filter_ips:
					filter_ips.append(str(ip))
					print '[+] Get ip: ' + ip
					open_ports = portscan(ip)
			except 	Exception,e:
				print e
				pass
			print '[+] Get open ports: ' + str(open_ports)
			if str(open_ports) == '[]':
				print '[!] Get open port lists None. Just scan 80 port...'
				newtitle = ''
				code = ''
				lenth = ''
				try:
					newtitle,code,lenth =  getitle(url)
				except Exception,e:
					print e
					pass
				if code in range(200,405) and code != 401:# add Do not scan 401 status_code
					print '[*] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)
					weakuri = '[]'
					try:
						weakuri = dirscan(url)
					except Exception,e:
						print e
						pass
					output = open(output_file,"a")
					flag = '<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;bytes</td><td><font color="red">%s</font></td></tr>' % (url,url,ip,code,newtitle,lenth,weakuri)
					output.write(flag)
					output.close()
			try:
				for port in open_ports:
					if port not in filter_ports:
						if url[-1:] == '/':
							url = url[:-1]
						newurl = url + ':' + str(port)
						if ':443' in newurl:# and 'https://' in url:
							newurl = url.replace(':443','').replace('http://','https://')
						print '[+] Scan new_url: ' + newurl
						newtitle = ''
						code = ''
						lenth = ''
						try:
							newtitle,code,lenth =  getitle(newurl)
						except Exception,e:
							print e
							pass
						if code  in range(200,405) and code != 401:# add Do not scan 401 status_code
							print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)
							weakuri = '[]'
							try:
								weakuri = dirscan(newurl)
							except Exception,e:
								print e
								pass
							output = open(output_file,"a")
							flag = '<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;bytes</td><td><font color="red">%s</font></td></tr>' % (newurl,newurl,ip,code,newtitle,lenth,weakuri)#,open_ports)<td><font color="blue">%s</font></td>
							output.write(flag)
							output.close()
			except Exception,e:
				print e
				pass
	except Exception,e:
		print e
		pass

if __name__ == '__main__':
	start_time = time.time()
	use = '''
	Use python webmain.py -f vuln_domains.txt  -> webscan not scanDir
	Use python webmain.py -d vuln_domains.txt  -> webscan Portscan && scanDir
	'''
	if len(sys.argv) != 3:
		print use
	elif sys.argv[1] == '-f' or sys.argv[1] == '-F':
		domains = []
		f = open(sys.argv[2],'r')
		for domain in f.readlines():
			domain = domain.strip()
			if domain not in domains:
				domains.append(domain)
		output_file = sys.argv[2].split('.')[0] + time.strftime('%Y-%m-%d',time.localtime(time.time()))+'.html'
		output_file = report()
		output = open(output_file,"w")#<td><font color="green">X_powered_by</font></b></td>
		str1 = '''
		<meta charset='UTF-8'>
		<style>td {text-align:center}</style>
		<table border="1" cellpadding="3" cellspacing="0" style="width: 80%;margin:auto">
		<tr>
		<td><b><font color="blue">Url</font></b></td>
		<td><b>Ip</b></td>
		<td><b><font color="blue">Status_code</font></b></td>
		<td><b><font color="red">Title</font></b></td>
		<td><b>Length</b></td>
		</tr>'''
		output.write(str1)
		output.close()
		pool = Pool(10)
		print '[+] Get %s task.' % len(domains)
		pool.map(checkFast,domains)
		pool.close()
		pool.join()
		end_time = time.time()
		print end_time - start_time
	elif sys.argv[1] == '-d' or sys.argv[1] == '-D':
		domains = []
		f = open(sys.argv[2],'r')
		for domain in f.readlines():
			domain = domain.strip()
			if domain not in domains:
				domains.append(domain)
		output_file = sys.argv[2].split('.')[0] + time.strftime('%Y-%m-%d',time.localtime(time.time()))+'.html'
		output_file = report()
		output = open(output_file,"w")#<td><font color="green">X_powered_by</font></b></td>
		str1 = '''
		<meta charset='UTF-8'>
		<style>td {text-align:center}</style>
		<table border="1" cellpadding="3" cellspacing="0" style="width: 80%;margin:auto">
		<tr>
		<td><b><font color="blue">Url</font></b></td>
		<td><b>Ip</b></td>
		<td><b><font color="blue">Status_code</font></b></td>
		<td><b><font color="red">Title</font></b></td>
		<td><b>Length</b></td>
		<td><b><font color="red">Dirscan</font></b></td>
		</tr>'''
		output.write(str1)
		output.close()
		pool = Pool(5)
		print '[+] Get %s task.' % len(domains)
		pool.map(checkDir,domains)
		pool.close()
		pool.join()
		end_time = time.time()
		print end_time - start_time
	else:
		print use