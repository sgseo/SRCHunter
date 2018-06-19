#coding:utf-8

import os
import re
import sys
import time
import socket
import random
import base64
import string
import datetime
import urlparse
import traceback
import threading
from collections import Counter

from config import *

def requests_headers():
	'''
	Random UA  for every requests && Use cookie to scan
	'''
	UA = random.choice(user_agent)
	headers = {
	'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8','Referer': referer,
	'User-Agent':UA,'Upgrade-Insecure-Requests':'1','Connection':'keep-alive','Cache-Control':'max-age=0',
	'Accept-Encoding':'gzip, deflate, sdch','Accept-Language':'zh-CN,zh;q=0.8','Cookie':cookie}
	return headers

def requests_proxies():
	'''
	Proxies for every requests
	'''
	proxies = {
	'http':http_proxies,
	'https':https_proxies
	}
	return proxies

def ranStr():
	'''
	Return random 8 lowercase string
	'''
	flag = ''.join([random.choice(string.lowercase) for _ in range(8)])
	return flag

def base64str():
	'''
	Return random base64 string
	'''
	key = random.random() * 10 # Handle "0." ->"/MC4" Character
	return base64.b64encode(str(key)).replace('=','')

def getMonth():
	'''
	Return 3x days ago backup file. eg:20180101.rar
	'''
	month = []
	monPayload = ["/%test%.7z","/%test%.rar","/%test%.zip","/%test%.tar.gz"]
	for mon in monPayload:
		for day in range(month_bak_num):
			days = (datetime.datetime.now() - datetime.timedelta(days = day))
			flag = days.strftime('%Y%m%d')
			flag = mon.replace('%test%',flag)
			month.append(flag)
	return month

def is_domain(domain):
	'''
	Check domain regex
	'''
	domain_regex = re.compile(r'(?:[A-Z0-9_](?:[A-Z0-9-_]{0,247}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,}(?<!-))\Z',re.IGNORECASE)
	return domain_regex.match(domain)

def check_ip(ip):
	'''
	Check ip regex
	'''
	check_ip = re.compile(r'^((?:(?:[1-9])|(?:[1-9][0-9])|(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])))(?:\.(?:(?:[0-9])|(?:[1-9][0-9])|(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])))){3})$')
	return check_ip.match(ip)

def write_file(ip,service):
	'''
	Save special openport like ./report/flag.txt
	'''
	file_service = open('%s'%(service),'a')
	if type(ip) == list:
		for key in ip:
			file_service.write(key)
			file_service.write('\n')
	else:
		file_service.write(ip)
		file_service.write('\n')
	return service

def open_file(filename):
	'''
	Open targets.txt
	'''
	content = []
	f = open('%s'%filename,'r')
	for i in f.readlines():
		line = i.strip()
		if line not in content:
			content.append(line)
	return content

def url_handle(url):
	'''
	Handle url
	'''
	if '://' not in url:
		url = 'http://' + url
		if url.split(':')[-1] == '80':
			url = urlparse.urlparse(url).scheme + "://" + urlparse.urlparse(url).netloc.split(':')[0]
		if url.split(':')[-1] == '443':
			url = 'https://' + url.replace(':443','').replace('http://','')
	return url

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
	if check_ip(ip):
		ip = ip_into_int(ip)
		net_a = ip_into_int('10.255.255.255') >> 24
		net_b = ip_into_int('172.255.255.255') >> 24
		net_c = ip_into_int('192.168.255.255') >> 16
		net_d = ip_into_int('127.255.255.255') >> 24
		if filter_internal_ip:
			return ip >> 24 == net_a or ip >> 24 == net_b or ip >> 16 == net_c or ip >> 24 == net_d
		else:
			return ip << 24 == net_a or ip << 24 == net_b or ip << 16 == net_c or ip << 24 == net_d

def email_regex(raw):
	'''
	Collect email
	test#cnnetarmy.com | Admin01@cnnetarmy.com.cn | san.Zhang@cnnetarmy.com | si01.Li@cnnetarmy.com | zhaowu01@cnnetarmy.com
	'''
	emails = []
	try:
		emails = re.findall(r"[\w!#$%&'*+=^_`|~-]+(?:\.[\w!#$%&'*+=^_`|~-]+)*[@#](?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])",str(raw))
	except Exception,e:
		# print traceback.format_exc()
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
		# print traceback.format_exc()
		pass
	return ips

def url2ip(url):
	'''
	Url to ip
	'''
	ip = ''
	try:
		handel_url = urlparse.urlparse(url).hostname
		ip = socket.gethostbyname(handel_url)
	except:
		print '[!] Can not get ip'
		pass
	return ip

def c_ip(ip):
	'''
	Get c_ip
	'''
	ip_list = []
	ip_split = ip.split('.')
	for c in xrange(c_min,c_max+1):
		ip = "%s.%s.%s.%d" % (ip_split[0],ip_split[1],ip_split[2],c)
		ip_list.append(ip)
	return ip_list

def get_parent_paths(path):
	'''
	Get a path's parent paths
	'''
	paths = []
	if not path or path[0] != '/':
		return paths
	#paths.append(path)
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
			elif check_url_netloc.netloc == check_link_netloc.netloc:# check same domain | can not check http://ip:port
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

def thread_run(targets,args_target,module,scanfunc):
	'''
	Main threading func
	'''
	# tsk = []
	for url in targets:
		t = threading.Thread(target=scanfunc,args=(url,args_target,module))
		t.start()
	# 	tsk.append(t)
	# for t in tsk:
	# 	t.start()
	# 	t.join()

def handle_ext_old(filename,ext=''):
	'''
	Handle file ext
	'''
	newname = filename
	try:
		newname = '.'.join(filename.replace('https','').replace('http','').replace(':','').replace('/','').split('.')[:-1])
	except Exception,e:
		# print traceback.format_exc()
		pass
	return newname

def handle_ext(strs):
	'''
	Hanlde dir path
	'''
	return '/'.join(strs.split('/')[:-1])

def result_paging(filename,module):
	'''
	Result paging 
	'''
	lines = []
	try:
		f = open(filename,'r')
		for i in f.readlines():
			line = i.strip()
			if line[:8] == '<tr><td>':
				lines.append(line)
	except Exception,e:
		# print traceback.format_exc()
		return 
	if len(lines) > 11:
		line_result = '\n\n'.join(key for key in lines)
		if module == 'fast':
			str_paging_fast = str_paging_f.replace('@flag@',line_result)
			with open('.'.join(filename.split('.')[:-1])+'_paging.html','w') as t:
				t.write(str_paging_fast)
		else:
			str_paging_dir = str_paging_d.replace('@flag@',line_result)
			with open('.'.join(filename.split('.')[:-1])+'_paging.html','w') as t:
				t.write(str_paging_dir)

def filter_list(module,filter_list):
	'''
	Filter List
	'''
	for filter_title in filter_list:
		if filter_title in module:
			return False
	return True

def ip_counter(filename):
	'''
	Counter portscan_opens ip to -cl Module
	'''
	ips,c_ips = [],[]
	f = open(filename,'r')
	for line in f.readlines():
		if ',' in line:
			line = line.split(',')[0]
		if not is_internal_ip(line) and check_ip(line):
			ip = '.'.join(line.split('.')[:-1])
			ips.append(ip)
	num = len(list(set(ips)))
	ip_count = Counter(ips).most_common(num)
	for c_ip,number in ip_count:
		if number >= ip_count_min:
			c_ip = c_ip + '.1'
			c_ips.append(c_ip)
	return c_ips

def report_filename(target,argmodule,ext='html'):
	'''
	Report result to ./report/target/target_timestamp_sys.argv.html
	'''
	output_dir = target.replace('https','').replace('http','').replace(':','').replace('/','')
	if '.txt' in target or '.csv' in target:
		output_dir = '.'.join(target.replace('https','').replace('http','').replace(':','').replace('/','').split('.')[:-1])
		output_dir = output_dir.replace('.txt','').replace('.csv','')
		if '_' in output_dir:
			output_dir = output_dir.split('_')[0]
	output_file = report_path + output_dir +'/'+ output_dir + '_' +time.strftime('%Y-%m-%d',time.localtime(time.time()))+'_'+argmodule+'.'+ext
	if not os.path.exists(report_path+output_dir):
		os.makedirs(report_path+output_dir)
	if not os.path.exists(output_file):
		output = open(output_file,"w")
		output.close()
	output_r = open(output_file,"r")
	if app_name not in output_r.read(50):
		if argmodule in ['fastscan','cfastscan']:
			output_w = open(output_file,"a")
			output_w.write(str_f)
			output_w.close()
		else:
			output_w = open(output_file,"a")
			output_w.write(str_d)
			output_w.close()
	output_r.close()
	return output_file