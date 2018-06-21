#coding:utf-8

import requests
import re

# Ignore warning
requests.packages.urllib3.disable_warnings()

def ilinks(domain=''):
	domain_names = []
	burp0_url = "http://i.links.cn/subdomain/"
	burp0_headers = {"Cache-Control": "max-age=0", "Origin": "http://i.links.cn", "Upgrade-Insecure-Requests": "1", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "Referer": "http://i.links.cn/subdomain/", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
	burp0_data={"domain": domain, "b2": "1", "b3": "1", "b4": "1"}
	r = requests.post(burp0_url, headers=burp0_headers, data=burp0_data).content
	subs = re.compile(r'(?<=value\=\"http://).*?(?=\"><input)')
	for item in subs.findall(r):
		domain_names.append(item)
	return list(set(domain_names))

if __name__ == '__main__':
	pass
	# print ilinks('weibo.com')