#coding:utf-8

from lib.common import requests_headers,requests_proxies

import requests
import urlparse
import traceback

def baidu_check(key_domain):
	'''
	Get baidu site:target.com status
	'''
	headers = requests_headers()
	proxies = requests_proxies()
	flag = []
	if '://' in key_domain:
		key_domain = urlparse.urlparse(key_domain).hostname
	baidu_url = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{}'.format(key_domain)
	try:
		r = requests.get(url=baidu_url,headers=headers,timeout=5,proxies=proxies,verify=False).text
		if 'class="tip_head"' not in r:
			flag.append('<a href="%s" target=_blank />Baidu_site</a>' % baidu_url)
	except Exception,e:
		# print traceback.format_exc()
		pass
	return flag

if __name__ == '__main__':
	pass