#coding:utf-8

from lib.common import requests_headers,requests_proxies,is_domain
from lib.config import baidu_domainss

import re
import requests
import urlparse
import traceback

def baidu_site(key_domain='',sub_domain='',command=''):
	'''
	Get baidu site:target.com result
	'''
	headers = requests_headers()
	proxies = requests_proxies()
	if '://' in key_domain:
		key_domain = urlparse.urlparse(key_domain).hostname
	check = []
	baidu_url = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{}'.format(key_domain)
	if command:
		baidu_url = 'https://www.baidu.com/s?ie=UTF-8&wd={}'.format(command)
	try:
		r = requests.get(url=baidu_url,headers=headers,timeout=10,proxies=proxies,verify=False).text
		if 'class="tip_head"' not in r:# Check first
			for page in xrange(0,21):# max page_number
				pn = page * 50
				if key_domain:
					newurl = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{}&pn={}&rn=50&tn=baiduadv'.format(key_domain,pn)
				if sub_domain:
					newurl = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{} -inurl:({})&pn={}&rn=50&tn=baiduadv'.format(key_domain,sub_domain,pn)# -site:(weibo.com)
				if command:
					newurl = 'https://www.baidu.com/s?ie=UTF-8&wd={}&pn={}&rn=50&tn=baiduadv'.format(command,pn)
				keys = requests.get(url=newurl,headers=headers,proxies=proxies,timeout=10,verify=False).content
				flags = re.findall(r'style=\"text-decoration:none;\">(.*?)%s.*?<\/a><div class=\"c-tools\"'%key_domain,keys)
				check_flag = keys.count('class="n"')
				for flag in flags:
					domain_handle = flag.replace('https://','').replace('http://','').replace('<b>','').replace('</b>','')
					if domain_handle != '':# xxooxxoo.xoxo.com ignore "..."
						domain_flag = domain_handle + key_domain
						if domain_flag not in check and is_domain(domain_flag):
							if domain_flag not in baidu_domainss:
								check.append(domain_flag)
								print '[+] Get baidu site: > ' + domain_flag
								baidu_domainss.append(domain_flag)
				if check_flag < 2 and page > 2:
					# for domain_key in baidu_domainss: # sub max num to inurl:( -flag)
					# 	baidu_domainss += baidu_site(domain_key)
					return check# list(set(baidu_domainss))
		else:
			print '[!] baidu site:domain no result'
			return []
	except Exception,e:
		# print traceback.format_exc()
		pass
	return check # list(set(baidu_domainss))

if __name__ == '__main__':
	pass
