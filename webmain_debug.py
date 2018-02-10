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
import glob
import socket
import random
import base64
import string
import datetime
import urlparse
from urllib import quote
from multiprocessing.pool import Pool

try:
	import requests
except:
	print 'pip install requests[security]'
	os._exit(0)

# Check py version
pyversion = sys.version.split()[0]
if pyversion >= "3" or pyversion < "2.7":
	exit('Need python version 2.6.x or 2.7.x')

reload(sys)
sys.setdefaultencoding('utf-8')

# Ignore warning
requests.packages.urllib3.disable_warnings()

# Make report dir
if not os.path.exists('./report'):
	os.makedirs('./report')

global filter_ips,filter_ports,cookie,filter_urls

# The filter for has been scaned ip
filter_ips = []

# global filter for some special ports
filter_ports = [21,22,23,25,53,110,111,135,139,143,389,445,465,587,843,873,993,995,1080,1433,1521,1723,2181,3306,3389,5432,5631,5900,6379,11211,27017]

# The filter for has been scaned url
filter_urls = []

# global logged cookie
cookie = 'www.cnnetarmy.com'

def report():
	'''
	Report result to ./report/target_timestamp_sys.argv.html
	'''
	output_file = '.'.join(sys.argv[2].replace('https','').replace('http','').replace(':','').replace('/','').split('.')[:-1]) + '_' +time.strftime('%Y-%m-%d',time.localtime(time.time()))
	return output_file

def write_file(ip,service):
	'''
	Save special openport like ./report/mysql_3306.txt
	'''
	file_service = open('./report/%s.txt'%service,'a')
	file_service.write(ip)
	file_service.write('\n')
	return service

def requests_headers():
	'''
	Random UA  for every requests && Use cookie to scan
	'''
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
	'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8','Referer': 'http://www.cnnetarmy.com',
	'User-Agent':UA,'Upgrade-Insecure-Requests':'1','Connection':'keep-alive','Cache-Control':'max-age=0',
	'Accept-Encoding':'gzip, deflate, sdch','Accept-Language':'zh-CN,zh;q=0.8','Cookie':cookie}
	return headers

def requests_proxies():
	'''
	Proxies for every requests
	'''
	proxies = {
	'http':'',#127.0.0.1:1080 shadowsocks
	'https':''#127.0.0.1:8080 BurpSuite
	}
	return proxies

def ip_into_int(ip):
	'''
	Check internal ip child function
	'''
	return reduce(lambda x, y: (x << 8) + y, map(int, ip.split('.')))

def is_internal_ip(ip):
	'''
	Filter internal ip
	10.x.x.x
	127.x.x.x
	172.x.x.x  # 172.16 | 172.31
	192.168.x.x
	'''
	ip = ip_into_int(ip)
	net_a = ip_into_int('10.255.255.255') >> 24
	net_b = ip_into_int('172.255.255.255') >> 24
	net_c = ip_into_int('192.168.255.255') >> 16
	net_d = ip_into_int('127.255.255.255') >> 24
	return ip >> 24 == net_a or ip >> 24 == net_b or ip >> 16 == net_c or ip >> 24 == net_d

def email_regex(raw):
	'''
	Collect email
	test#cnnetarmy.com | Admin01@cnnetarmy.com.cn | san.Zhang@cnnetarmy.com | si01.Li@cnnetarmy.com | zhaowu01@cnnetarmy.com
	'''
	emails = []
	try:
		emails = re.findall(r"[\w!#$%&'*+=^_`|~-]+(?:\.[\w!#$%&'*+=^_`|~-]+)*[@#](?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])",str(raw))
	except Exception,e:
		print e
		pass
	return emails

def ip_regex(raw):
	'''
	Collect legal ip
	1.1.1.1 | 10.1.1.1 | 256.10.1.256 | 222.212.22.11 | 0.0.150.150 | 232.21.234.256
	'''
	ips = []
	try:
		re_ips = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',str(raw))
		for ip in re_ips:
			compile_ip = re.compile(r'^((?:(?:[1-9])|(?:[1-9][0-9])|(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])))(?:\.(?:(?:[0-9])|(?:[1-9][0-9])|(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])))){3})$')
			if compile_ip.match(ip):
				ips.append(ip)
	except Exception,e:
		print e
		pass
	return ips

def url_regex(raw):
	'''
	Collect url
	'''
	urls = []
	try:
		urls_regex = re.findall(r"((?:https?|ftp|file):\/\/[\-A-Za-z0-9+&@#/%?=~_|!:,.;\*]+[\-A-Za-z0-9+&@#/%=~_|])",str(raw))
		for url in urls_regex:
			url_flag = '<a href="'+url+'" target=_blank />'+url+'</a>'
			urls.append(url_flag)
	except Exception,e:
		print e
		pass
	return urls

def ranStr():
	'''
	Return random 8 lowercase string
	'''
	flag = ''.join([random.choice(string.lowercase) for _ in range(8)])
	return flag

def get_parent_paths(path):
	'''
	Get a path's parent paths
	'''
	paths = []
	if not path or path[0] != '/':
		return paths
	paths.append(path)
	if path[-1] == '/':
		path = path[:-1]
	while path:
		path = path[:path.rfind('/') + 1]
		paths.append(path)
		path = path[:-1]
	return paths

def url_paths(url):
	'''
	Get url paths
	'''
	key_urls = []
	url_path = urlparse.urlparse(url)
	url_pathss = get_parent_paths(url_path.path)
	for path in url_pathss:
		path = path.replace('//','/')
		if path != '/' and path[-1] == '/' and path[1] != '.':
			if path[:1] != '/':
				key_url = '%s://%s%s' % (url_path.scheme, url_path.netloc, path[-1])
				key_urls.append(key_url)
			else:
				key_url = '%s://%s%s' % (url_path.scheme, url_path.netloc, path)
				key_urls.append(key_url)
	return key_urls

def scandir_again(url,alllinks):
	'''
	Handle link to dir_path
	'''
	links,url_keys,url_dirs = [],[],[]
	if url[-1:] != '/':
		url = url + '/'
	for link in alllinks:
		check_url_netloc = urlparse.urlparse(url)
		check_link_netloc = urlparse.urlparse(link)		
		if '://' in link:
			if ':' in check_url_netloc.netloc:# check domain:port
				check_url_netloc_again = check_url_netloc.netloc.split(':')[0]
				if check_url_netloc_again == check_link_netloc.netloc:
					links.append(link)
			elif check_url_netloc.netloc == check_link_netloc.netloc:# check same domain | cannot check http://ip:port
				links.append(link)
		elif '//' in link:
			if ':' in check_url_netloc.netloc:# check domain:port
				check_url_netloc_again = check_url_netloc.netloc.split(':')[0]
				if check_url_netloc_again == check_link_netloc.netloc:
					link_s = check_url_netloc.scheme + ':' + link
					links.append(link_s)
			elif check_url_netloc.netloc == check_link_netloc.netloc:
				link_s_one = check_url_netloc.scheme + ':' + link
				links.append(link_s_one)
		else:
			if link[:1] == '/':
				url_links = url + link[1:]
			else:
				url_links = url + link
			links.append(url_links)
	for url_key in set(links):
		url_keys += url_paths(url_key)
	for url_dir in set(url_keys):
		url_dirs.append(url_dir)
	return url_dirs

def weakfile(url):
	'''
	Weakfile scan with some tricks
	'''
	dirs = []
	headers = requests_headers()
	proxies = requests_proxies()
	payloads = ["/.git/config","/.DS_Store","/www.zip","/.svn/entries","/.svn/wc.db","/.git/index","/www.tar.gz"]
	url_path = urlparse.urlparse(url).path
	if url[-1:] == '/':
		url = url[:-1]
	try:
		count_flag,len_flag = 0,[]
		print '[*] Now scan %s weakfile' % url
		for payload in payloads:
			try:
				if count_flag < 5:
					req = requests.get(url=url+payload,proxies=proxies,verify=False,headers=headers,timeout=5)
					if req.status_code == 200 and len(req.content) != 0 and len(req.content) not in len_flag:
						count_flag += 1
						len_flag.append(len(req.content))
						print '[+] Get %s%s 200 %s' % (url,payload,len(req.content))
						dir_flag = '<a href="'+url+payload+'" target=_blank />'+urlparse.urlparse(url).path[:10]+payload+'</a>'
						dirs.append(dir_flag)
				else:
					print '[!] Maybe Got weakdir waf'
					return ["waf"]
			except Exception,e:
				print e
				pass
	except Exception,e:
		print e
		pass
	if len(dirs) >= 3:
		return ["waf"]
	else:
		return dirs

def getallink(url,content):
	'''
	Get response all link
	'''
	links,emails,ips,check = [],[],[],[]
	tags = ['a','A','link','script','area','iframe','form']#img
	tos = ['href','src','action']
	if url[-1:] == '/':
		url = url[:-1]
	try:
		print '[*] Now regex emails,ips,alllinks'
		emails_source = email_regex(str(content))
		ips = ip_regex(str(content))
		#print '[*] Now regex urls'
		#urls = url_regex(content)
		for tag in tags:
			for to in tos:
				link = re.findall(r'<%s.*?%s="(.*?)"' % (tag,to),str(content))
				for i in link:
					if i not in check and '.png' not in i and 'javascript' not in i and '.svg' not in i and '.jpg' not in i and '.js' not in i and '.css' not in i and '/css?' not in i and '.gif' not in i and '.jpeg' not in i and '.ico' not in i and '.swf' not in i and '.mpg' not in i and 'mailto:' not in i and 'data:image' not in i and i != '':
						check.append(i)
						if '://' in i or '//' in i:
							i = i.replace(' ','')
							if str(urlparse.urlparse(i).path) in ['/',''] and str(urlparse.urlparse(i).query) in ['/','']:
								link_flag = '<a href="'+i+'" target=_blank />'+urlparse.urlparse(str(i)).netloc+'</a>'
								#write_file(i,'Maybe_subdomain')
							else:
								link_flag = '<a href="'+i+'" target=_blank />'+quote(urlparse.urlparse(str(i)).path+urlparse.urlparse(str(i)).query)[:25]+'</a>'
						else:
							link_flag = '<a href="'+url+'/'+i+'" target=_blank />'+quote(i)[:25]+'</a>'
							check.append(url + i)
						links.append(link_flag)
	except Exception,e:
		print e
		print '[!] Get link error'
		pass
	#urls = set(links) - set(urls)
	emails_handle = [email[-30:] for email in set(emails_source)] # Filter too lang email
	for email_check in emails_handle:
		if '.png' not in email_check and '.svg' not in email_check and '.jpg' not in email_check and '.gif' not in email_check:#loading@2x.gif/png
			emails.append(email_check)
	ips = [ip for ip in set(ips)]
	if len(links) > 10:
		# Click more_links to get detail result
		mainDiv = ranStr()
		childDiv = ranStr()
		return check,u'''<div id="%s" style="color:red" onclick="document.all.%s.style.display=(document.all.%s.style.display =='none')?'':'none'">[more_links]</div><div id="%s" style="display:none">%s</div>'''%(mainDiv,childDiv,childDiv,childDiv,'<br />'.join(links)),'<br />'.join(emails),'<br />'.join(ips)
	else:
		return check,links,'<br />'.join(emails),'<br />'.join(ips)

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
		print '[*] Download from: http://www.cnnetarmy.com/soft/debug/portscan.py'
		pass
	if len(open_ports) > 90:
		print '[!] Maybe got port waf'
		write_file(ip,'portscan_error')
		return []
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
		write_file(url,'url2ip_error')
		pass
	return ip
def c_ip(ip):
	'''
	Get c_ip
	'''
	ip_list = []
	ip_split = ip.split('.')
	for c in xrange(1,255):
		ip = "%s.%s.%s.%d" % (ip_split[0],ip_split[1],ip_split[2],c)
		ip_list.append(ip)
	return ip_list

def baidu_site(key_domain):
	'''
	Get baidu site:target.com result
	'''
	headers = requests_headers()
	proxies = requests_proxies()
	baidu_domains,check = [],[]
	baidu_url = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{}'.format(key_domain)
	try:
		r = requests.get(url=baidu_url,headers=headers,timeout=10,proxies=proxies,verify=False).content
		if 'class=\"nors\"' not in r:# Check first
			for page in xrange(0,100):# max page_number
				pn = page * 10
				newurl = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{}&pn={}&oq=site:{}'.format(key_domain,pn,key_domain)
				keys = requests.get(url=newurl,headers=headers,proxies=proxies,timeout=10,verify=False).content
				flags = re.findall(r'style=\"text-decoration:none;\">(.*?)%s.*?<\/a><div class=\"c-tools\"'%key_domain,keys)
				check_flag = re.findall(r'class="(.*?)"',keys)
				for flag in flags:
					domain_handle = flag.replace('https://','').replace('http://','')
					# xxooxxoo.xoxo.com ignore "..."
					if domain_handle not in check and domain_handle != '':
						check.append(domain_handle)
						domain_flag = domain_handle + key_domain
						print '[+] Get baidu site:domain > ' + domain_flag
						baidu_domains.append(domain_flag)
						if len(check_flag) < 2:
							return baidu_domains
		else:
			print '[!] baidu site:domain no result'
			return baidu_domains
	except Exception,e:
		print e
		pass
	return baidu_domains

def base64str():
	'''
	Return random base64 string
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
		#req = requests.get(url = url, headers = headers, proxies = proxies,verify = False,timeout = 5)
		#if req.status_code in range(200,405):
		ip,open_ports = url,[]
		try:
			ip = url2ip(url)
			if str(ip) not in filter_ips and not is_internal_ip(ip):# filter internal_ip
				filter_ips.append(str(ip))
				print '[+] Get url2ip: ' + ip
				open_ports = portscan(ip)
				ports_log = file('./report/'+output_file+'_openports'+sys.argv[1]+'.csv','a')
				ports_log.write(ip)
				ports_log.write(',')
				ports_log.write(str(open_ports).replace(',','/'))
				ports_log.write('\n')
		except Exception,e:
			print e
			pass
		print '[+] Get open ports: ' + str(open_ports)
		if str(open_ports) == '[]':#or 80 not in open_ports
			print '[!] Get open port lists None. Just scan default port'
			try:
				newtitle,code,lenth,content = '','','',''
				try:
					newtitle,code,lenth,content =  getitle(url)
				except Exception,e:
					print e
					pass
				if code in range(200,405):
					alllink,alllinks,emails,ips = [],[],[],[]
					try:
						alllink,alllinks,emails,ips = getallink(url,content)
					except Exception,e:
						print e
						pass
					if code in range(200,405):# add Do not scan 401 status_code
						print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)
						try:
							output = open('./report/'+output_file+'_'+sys.argv[1]+'.html',"a")
							flag = '<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;bytes</td><td><font color="blue">%s</font></td><td><ul><li>%s</li><li>%s</li><ul/></td></tr>' % (url,url,ip,code,newtitle,lenth,alllinks,emails,ips)#,weakuri <td><font color="red">%s</font></td>)#,open_ports)<td><font color="blue">%s</font></td>
							output.write(flag)
							output.close()
						except Exception,e:
							print e
							print '[!] output_error'
							write_file(url,'output_error')
							pass
			except Exception,e:
				print e
				pass
		else:
			for port in open_ports:
				if port not in filter_ports:
					if url[-1:] == '/':
						url = url[:-1]
					newurl = url + ':' + str(port)
					if newurl not in filter_urls:
						filter_urls.append(newurl)
						if ':80' in newurl:
							newurl = newurl.replace('https://','http://')
						if ':443' in newurl:
							newurl = newurl.replace(':443','').replace('http://','https://')
						print '[*] Scan new_url: ' + newurl
						try:
							newtitle,code,lenth,content = '','','',''
							try:
								newtitle,code,lenth,content =  getitle(newurl)
							except Exception,e:
								print e
								pass
							if code in range(200,405):
								alllink,alllinks,emails,ips = [],[],[],[]
								try:
									alllink,alllinks,emails,ips = getallink(newurl,content)
								except Exception,e:
									print e
									pass
								print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)
								try:
									output = open('./report/'+output_file+'_'+sys.argv[1]+'.html',"a")
									flag = '<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;bytes</td><td><font color="blue">%s</font></td><td><ul><li>%s</li><li>%s</li><ul/></td></tr>' % (newurl,newurl,ip,code,newtitle,lenth,alllinks,emails,ips)
									output.write(flag)
									output.close()
								except Exception,e:
									print e
									print '[!] output_error'
									write_file(newurl,'output_error')
									pass
						except Exception,e:
							print e
							pass
				elif port == 21:
					write_file(ip,'ftp_21')
				elif port == 22:
					write_file(ip,'ssh_22')
				elif port == 23:
					write_file(ip,'telnet_23')
				elif port == 53:
					write_file(ip,'dns_53')
				elif port == 873:
					write_file(ip,'rsync_873')
				elif port == 1433:
					write_file(ip,'mssql_1433')
				elif port == 1521:
					write_file(ip,'oracle_1521')
				elif port == 1723:
					write_file(ip,'pppoe_1721')
				elif port == 2181:
					write_file(ip,'zookeeper_2181')
				elif port == 3306:
					write_file(ip,'mysql_3306')
				elif port == 3389:
					write_file(ip,'rpc_3389')
				elif port == 5432:
					write_file(ip,'postgresql_5432')
				elif port == 5631:
					write_file(ip,'pcanywhere_5631')
				elif port == 5900:
					write_file(ip,'vnc_5900')
				elif port == 6379:
					write_file(ip,'redis_6379')
				elif port == 11211:
					write_file(ip,'memcache_11211')
				elif port == 27017:
					write_file(ip,'mongodb_27017')
				else:
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
		#X_Powered_By = ''
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
	title,code,lenth,content = '','','',''
	try:
		req = requests.get(url = url, headers = headers, proxies = proxies,verify = False,timeout = 3)
		code = req.status_code
		content = req.content
		lenth = len(content)
		if code in range(200,405) and len(req.content) != 0:
			title = re.findall(r'<title>(.*?)</title>',req.content)[0]
	except:pass#ignore Exception
	return title,code,lenth,content

def getMonth():
	'''
	Return 3x days ago backup file. eg:20180101.rar
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
	Webdir weakfile scan with some tricks
	'''
	dirs = []
	headers = requests_headers()
	proxies = requests_proxies()
	hostbak = urlparse.urlparse(url).hostname
	month = getMonth()
	random_str = base64str()
	payloads = ["/robots.txt","/README.md","/crossdomain.xml","/.git/config","/.git/index","/.svn/entries","/.svn/wc.db","/.DS_Store","/CVS/Root","/CVS/Entries","/.idea/workspace.xml"]
	payloads += ["/index.htm","/index.html","/index.php","/index.asp","/index.aspx","/index.jsp","/index.do","/index.action"]
	payloads += ["/www.7z","/www.rar","/www.zip","/www.tar.gz","/wwwroot.zip","/wwwroot.rar","/wwwroot.7z","/wwwroot.tar.gz","/backup.7z","/backup.rar","/backup.tar","/backup.tar.gz","/backup.zip","/index.7z","/index.rar","/index.sql","/index.tar","/index.tar.gz","/index.zip","/web.7z","/web.rar","/web.sql","/web.tar","/web.tar.gz","/web.zip"]
	payloads += ["/www/","/console","/web-console","/web_console","/jmx-console","/jmx_console","/JMXInvokerServlet","/invoker"]
	payloads += ["/index.bak","/index.swp","/index.old","/.viminfo","/.bash_history","/.bashrc","/project.properties","/config.properties"]
	payloads += ["/config.inc","/common.inc","/db_mysql.inc","/install.inc","/conf.inc","/db.inc","/setup.inc","/init.inc"]
	#payloads += ["/config.ini","/php.ini","/info.ini","/setup.ini","/www.ini","/http.ini","/conf.ini","/core.config.ini","/ftp.ini"]
	#payloads += ["/data.mdb","/db.mdb","/test.mdb","/database.mdb","/Database.mdf","/BookStore.mdf","/DB.mdf"]
	#payloads += ["/1.sql","/install.sql","/schema.sql","/mysql.sql","/dump.sql","/users.sql","/update.sql","/test.sql","/user.sql","/database.sql","/sql.sql","/setup.sql","/init.sql","/login.sql","/backup.sql","/all.sql","/passwd.sql","/init_db.sql"]
	#payloads += ["/fckstyles.xml","/Config.xml","/conf.xml","/build.xml","/web.xml","/test.xml","/ini.xml","/www.xml","/db.xml","/database.xml","/admin.xml","/login.xml","/sql.xml","/sample.xml","/settings.xml","/setting.xml","/info.xml","/install.xml","/Php.xml"]
	payloads += ["/nginx_status","/nginx.conf","/httpd.conf","/test.conf","/conf.conf","/local.conf","/user.txt","/LICENSE.txt","/sitemap.xml","/username.txt","/pass.txt","/passwd.txt","/password.txt","/.htaccess","/web.config","/app.config","/log.txt","/config.xml","/CHANGELOG.txt","/INSTALL.txt","/error.log","/.mysql_history"]
	payloads += ["/login","/phpMyAdmin","/pma","/pmd","/SiteServer","/admin","/Admin/","/manage","/manager","/manage/html","/resin-admin","/resin-doc","/axis2-admin","/admin-console","/system","/wp-admin","/uc_server","/debug","/Conf","/webmail","/service","/memadmin","/owa","/harbor","/master","/root"]
	payloads += ["/xmlrpc.php","/search.php","/install.php","/admin.php","/login.php","/l.php","/forum.php","/phpinfo.php","/info.php","/p.php","/test.php","/cmd.php","/shell.php"]
	payloads += ["/portal","/blog","/bbs","/webapp","/webapps","/plugins","/cgi-bin","/htdocs","/wsdl","/html","/install","/test","/tmp","/file","/solr/#/","/WEB-INF","/zabbix","/backup","/log","/ckeditor","/FCKeditor","/ewebeditor","/editor","/DataBackup","/api","/plus","/php","/web","/inc","/default","/forum"]
	payloads += ["/%flag%.7z","/%flag%.rar","/%flag%.zip","/%flag%.tar.gz"] # hostbak
	payloads += month
	if url[-1:] == '/':
		url = url[:-1]
	try:
		check_url = url + '/' + str(random_str)#'/Wo4N1Dx1aoKeI'
		print '[*] Now is check waf: ' + check_url
		count_flag = 0
		check_waf = requests.get(url=check_url,proxies=proxies,verify=False,headers=headers,timeout=5)
		for payload in payloads:
			try:
				if count_flag < 25:
					payload = payload.replace('%flag%',hostbak)
					req = requests.get(url=url+payload,proxies=proxies,verify=False,headers=headers,timeout=5)
					#req = requests.head(url + payload)
					if req.status_code == 200 and abs(len(req.content) - len(check_waf.content)) > 5 and len(req.content) != 0:
						count_flag += 1
						print '[+] Get %s%s 200 %s' % (url,payload,len(req.content))
						dir_flag = '<a href="'+url+payload+'" target=_blank />'+payload+'</a>'
						dirs.append(dir_flag)
				else:
					print '[!] Maybe Got dir waf'
					return ["waf"]
			except Exception,e:
				print e
				pass
	except Exception,e:
		print e
		pass
	return dirs

def checkDir(url):
	'''
	Main requests function with Portscan && Dirscan
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
		ip,open_ports = url,[]
		try:
			ip = url2ip(url)
			if str(ip) not in filter_ips and not is_internal_ip(ip):# filter internal_ip
				filter_ips.append(str(ip))
				print '[+] Get url2ip: ' + ip
				open_ports = portscan(ip)
				ports_log = file('./report/'+output_file+'_openports'+sys.argv[1]+'.csv','a')
				ports_log.write(ip)
				ports_log.write(',')
				ports_log.write(str(open_ports).replace(',','/'))
				ports_log.write('\n')
		except Exception,e:
			print e
			pass
		print '[+] Get open ports: ' + str(open_ports)
		if str(open_ports) == '[]':#or 80 not in open_ports
			print '[!] Get open port lists None. Just scan default port'
			try:
				newtitle,code,lenth,content = '','','',''
				try:
					newtitle,code,lenth,content =  getitle(url)
				except Exception,e:
					print e
					pass
				if code in range(200,405) and code != 401:# add Do not scan 401 status_code
					print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)
					alllink,alllinks,emails,ips = [],[],[],[]
					try:
						alllink,alllinks,emails,ips = getallink(url,content)
					except Exception,e:
						print e
						pass
					dirpaths = []
					try:
						dir_urls = scandir_again(url,alllink)
						if len(dir_urls) < 50:
							for dir_url in dir_urls:
								dirpaths += weakfile(dir_url)
					except Exception,e:
						print e
						pass
					if len(dirpaths) > 10:
						dirpaths = ["more_path"]
					weakuri = []
					try:
						weakuri = dirscan(url)
					except Exception,e:
						print e
						pass
					try:
						output = open('./report/'+output_file+'_'+sys.argv[1]+'.html',"a")
						flag = '<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;bytes</td><td>%s</td><td><font color="blue">%s</font></td><td><ul><li>%s</li><li>%s</li><ul/></td></tr>' % (url,url,ip,code,newtitle,lenth,[dirpath_key for dirpath_key in set(dirpaths + weakuri)],alllinks,emails,ips)
						output.write(flag)
						output.close()
					except Exception,e:
						print e
						print '[!] output_error'
						write_file(url,'output_error')
						pass
			except Exception,e:
				print e
				pass
		else:
			for port in open_ports:
				if port not in filter_ports:
					if url[-1:] == '/':
						url = url[:-1]
					newurl = url + ':' + str(port)
					if newurl not in filter_urls:
						filter_urls.append(newurl)
						if ':80' in newurl:
							newurl = newurl.replace('https://','http://')
						if ':443' in newurl:
							newurl = newurl.replace(':443','').replace('http://','https://')
						print '[*] Scan new_url: ' + newurl
						try:
							newtitle,code,lenth,content = '','','',''
							try:
								newtitle,code,lenth,content =  getitle(newurl)
							except Exception,e:
								print e
								pass
							if code in range(200,405) and code != 401:# add Do not scan 401 status_code
								alllink,alllinks,emails,ips = [],[],[],[]
								try:
									alllink,alllinks,emails,ips = getallink(newurl,content)
								except Exception,e:
									print e
									pass
								print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)
								dirpaths = []
								try:
									dir_urls = scandir_again(newurl,alllink)
									if len(dir_urls) < 50:# Pass num
										for dir_url in dir_urls:
											dirpaths += weakfile(dir_url)
								except Exception,e:
									print e
									pass
								if len(dirpaths) > 10:# Check num
									dirpaths = ["more_path"]
								weakuri = []
								try:
									weakuri = dirscan(newurl)
								except Exception,e:
									print e
									pass
								try:
									output = open('./report/'+output_file+'_'+sys.argv[1]+'.html',"a")
									flag = '<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;bytes</td><td>%s</td><td><font color="blue">%s</font></td><td><ul><li>%s</li><li>%s</li><ul/></td></tr>' % (newurl,newurl,ip,code,newtitle,lenth,[dirpath_key for dirpath_key in set(dirpaths + weakuri)],alllinks,emails,ips)#'<li>'.join(weakuri)
									output.write(flag)
									output.close()
								except Exception,e:
									print e
									print '[!] output_error'
									write_file(newurl,'output_error')
									pass
						except Exception,e:
							print e
							pass
				elif port == 21:
					write_file(ip,'ftp_21')
				elif port == 22:
					write_file(ip,'ssh_22')
				elif port == 23:
					write_file(ip,'telnet_23')
				elif port == 53:
					write_file(ip,'dns_53')
				elif port == 873:
					write_file(ip,'rsync_873')
				elif port == 1433:
					write_file(ip,'mssql_1433')
				elif port == 1521:
					write_file(ip,'oracle_1521')
				elif port == 1723:
					write_file(ip,'pppoe_1721')
				elif port == 2181:
					write_file(ip,'zookeeper_2181')
				elif port == 3306:
					write_file(ip,'mysql_3306')
				elif port == 3389:
					write_file(ip,'rpc_3389')
				elif port == 5432:
					write_file(ip,'postgresql_5432')
				elif port == 5631:
					write_file(ip,'pcanywhere_5631')
				elif port == 5900:
					write_file(ip,'vnc_5900')
				elif port == 6379:
					write_file(ip,'redis_6379')
				elif port == 11211:
					write_file(ip,'memcache_11211')
				elif port == 27017:
					write_file(ip,'mongodb_27017')
				else:
					pass
	except Exception,e:
		print e
		pass

if __name__ == '__main__':
	start_time = time.time()
	use = '''
	Use python webmain_debug.py -a  target.com        -->  baidu_site && port/dir scan	
	Use python webmain_debug.py -u  http://127.0.0.1  -->  webscan Portscan && scanDir
	Use python webmain_debug.py -f  vuln_domains.txt  -->  webscan not scanDir
	Use python webmain_debug.py -d  vuln_domains.txt  -->  webscan Portscan && scanDir
	Use python webmain_debug.py -cf 192.168.1.1       -->  C scan  not scanDir
	Use python webmain_debug.py -cd 192.168.1.1       -->  C scan  Portscan && scanDir

		Result save to ./report/flag.html
	'''
	str_d = '''
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
	<td><b><font color="blue">Allinks</font></b></td>
	<td><b>Emails/Ips</b></td>
	</tr>'''
	str_f = '''
	<meta charset='UTF-8'>
	<style>td {text-align:center}</style>
	<table border="1" cellpadding="3" cellspacing="0" style="width: 80%;margin:auto">
	<tr>
	<td><b><font color="blue">Url</font></b></td>
	<td><b>Ip</b></td>
	<td><b><font color="blue">Status_code</font></b></td>
	<td><b><font color="red">Title</font></b></td>
	<td><b>Length</b></td>
	<td><b><font color="blue">Allinks</font></b></td>
	<td><b>Emails/Ips</b></td>
	</tr>'''
	check_ip = re.compile(r'^((?:(?:[1-9])|(?:[1-9][0-9])|(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])))(?:\.(?:(?:[0-9])|(?:[1-9][0-9])|(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])))){3})$')
	if len(sys.argv) != 3:
		print use
	elif sys.argv[1] == '-a' or sys.argv[1] == '-A':
		domains = []
		domains = baidu_site(sys.argv[2])
		output_file = report()
		output = open('./report/'+output_file+'_'+sys.argv[1]+'.html',"w")
		output.write(str_d)
		output.close()
		pool = Pool(2)
		print '[+] Get %s task.' % len(domains)
		pool.map(checkDir,domains)
		pool.close()
		pool.join()
		end_time = time.time()
		print '[*] Task scaned done. used time: %ss' % str(end_time - start_time).split('.')[0]
		for infile in glob.glob(os.path.join(os.getcwd(), '*.pyc')):
			os.remove(infile)
	elif sys.argv[1] == '-u' or sys.argv[1] == '-U':
		output_file = report()
		output = open('./report/'+output_file+'_'+sys.argv[1]+'.html',"w")
		output.write(str_d)
		output.close()
		checkDir(sys.argv[2])
		end_time = time.time()
		print '[*] Task scaned done. used time: %ss' % str(end_time - start_time).split('.')[0]
		for infile in glob.glob(os.path.join(os.getcwd(), '*.pyc')):
			os.remove(infile)
	elif sys.argv[1] == '-f' or sys.argv[1] == '-F':
		domains = []
		ff = file(sys.argv[2],'r')
		for domain in ff.readlines():
			domain = domain.strip()
			if domain not in domains:
				domains.append(domain)
		output_file = report()
		output = open('./report/'+output_file+'_'+sys.argv[1]+'.html',"w")# Server | X_powered_by
		output.write(str_f)
		output.close()
		pool = Pool(2)
		print '[+] Get %s task.' % len(domains)
		pool.map(checkFast,domains)
		pool.close()
		pool.join()
		end_time = time.time()
		print '[*] Task scaned done. used time: %ss' % str(end_time - start_time).split('.')[0]
		for infile in glob.glob(os.path.join(os.getcwd(), '*.pyc')):
			os.remove(infile)
	elif sys.argv[1] == '-d' or sys.argv[1] == '-D':
		domains = []
		fd = file(sys.argv[2],'r')
		for domain in fd.readlines():
			domain = domain.strip()
			if domain not in domains:
				domains.append(domain)
		output_file = report()
		output = open('./report/'+output_file+'_'+sys.argv[1]+'.html',"w")
		output.write(str_d)
		output.close()
		pool = Pool(2)
		print '[+] Get %s task.' % len(domains)
		pool.map(checkDir,domains)
		pool.close()
		pool.join()
		end_time = time.time()
		print '[*] Task scaned done. used time: %ss' % str(end_time - start_time).split('.')[0]
		for infile in glob.glob(os.path.join(os.getcwd(), '*.pyc')):
			os.remove(infile)
	elif sys.argv[1] in ['-cf','-CF','-cF','-Cf']:
		ip = sys.argv[2]
		if check_ip.match(ip):
			ip_list = c_ip(ip)
			output_file = report()
			output = open('./report/'+output_file+'_'+sys.argv[1]+'.html',"w")
			output.write(str_f)
			output.close()
			pool = Pool(2)
			print '[+] Get %s task.' % len(ip_list)
			pool.map(checkFast,ip_list)
			pool.close()
			pool.join()
			end_time = time.time()
			print '[*] Task scaned done. used time: %ss' % str(end_time - start_time).split('.')[0]
			for infile in glob.glob(os.path.join(os.getcwd(), '*.pyc')):
				os.remove(infile)
	elif sys.argv[1] in ['-cd','-CD','-cD','-Cd']:
		ip = sys.argv[2]
		if check_ip.match(ip):
			ip_list = c_ip(ip)
			output_file = report()
			output = open('./report/'+output_file+'_'+sys.argv[1]+'.html',"w")
			output.write(str_d)
			output.close()
			pool = Pool(2)
			print '[+] Get %s task.' % len(ip_list)
			pool.map(checkDir,ip_list)
			pool.close()
			pool.join()
			end_time = time.time()
			print '[*] Task scaned done. used time: %ss' % str(end_time - start_time).split('.')[0]
			for infile in glob.glob(os.path.join(os.getcwd(), '*.pyc')):
				os.remove(infile)
	else:
		print use