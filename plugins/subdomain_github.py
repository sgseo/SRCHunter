#coding:utf-8

from lib.common import requests_headers,requests_proxies,filter_list,is_domain

from lib.config import github_cookie,sub_filter,github_sub_filter,github_domainss

import re
import requests
import urlparse
import traceback

def github_site(subdoamin,key_domain):
	headers = requests_headers()
	proxies = requests_proxies()
	if '://' in key_domain:
		key_domain = urlparse.urlparse(url).hostname
	github_domains = []
	session = requests.Session()
	headers['Cookie'] = github_cookie
	try:
		# check_login = 'https://github.com/settings/emails'
		# req_check = session.get(url=check_login,headers=headers,proxies=proxies,timeout=10,verify=False).content
		# if github_account in req_check:
		# 	print '[*] Github site:domain login check Success'
		headers['Host'] = 'github.com'
		headers['Referer'] = 'https://github.com/search?utf8=%E2%9C%93&q=*&type=Code'
		github_url = 'https://github.com/search?q={}&type=Code&utf8=%E2%9C%93'.format(subdoamin)
		req = session.get(url=github_url,headers=headers,proxies=proxies,timeout=10,verify=False).content
		if 'blankslate' not in req:#if 'code results' in req:
			for page in xrange(1,100):
				newurl = 'https://github.com/search?p={}&q={}&type=Code&s=&utf8=%E2%9C%93'.format(page,subdoamin)
				req_new = session.get(url=newurl,headers=headers,proxies=proxies,timeout=10,verify=False).content
				req_new = req_new.replace('</em>','').replace('<em>','').replace('</span>','')
				url_regexs = []
				url_regex_url,url_regex_host,url_regex_x,url_regex_a,url_regex_b,url_regex_c,url_regex_b_a,url_regex_c_a,url_regex_d = [],[],[],[],[],[],[],[],[]
				try:
					url_regex_url = re.findall(r'//([\s\S]*?)%s' % key_domain,req_new)
				except:pass
				try:
					url_regex_host = re.findall(r'&quot;([\s\S]*?)%s' % key_domain,req_new)
				except:pass
				try:
					url_regex_x = re.findall(r'&#39;([\s\S]*?)%s' % key_domain,req_new)
				except:pass
				try:
					url_regex_a = re.findall(r'/([\s\S]*?)%s' % key_domain,req_new)
				except:pass
				try:
					url_regex_b = re.findall(r'\[<span .*?>([\s\S]*?)%s' % key_domain,req_new)
				except:pass
				try:
					url_regex_b_a = re.findall(r'\[([\s\S]*?)%s' % key_domain,req_new)
				except:pass
				try:
					url_regex_c_a = re.findall(r'\(([\s\S]*?)%s' % key_domain,req_new)
				except:pass					
				try:
					url_regex_c = re.findall(r'\(<span .*?>([\s\S]*?)%s' % key_domain,req_new)
				except:pass
				try:
					url_regex_d = re.findall(r'<span .*?>([\s\S]*?)%s' % key_domain,req_new)
				except:pass
				url_regexs = url_regex_url + url_regex_host + url_regex_x + url_regex_a + url_regex_b + url_regex_c + url_regex_b_a + url_regex_c_a + url_regex_d
				for sub in url_regexs:
					if sub not in github_domains and sub_filter not in sub and sub != '.' and filter_list(module=sub,filter_list=github_sub_filter) and sub[-1:] != '-' and sub[-1:] != '_': 
						sub.replace(' ','')
						if sub[-1:] == '.':
							subs = sub + key_domain
						else:
							subs = sub + '.' + key_domain
						if is_domain(subs) and subs not in github_domainss:
							print '[+] Get github site:domain > ' + subs
							github_domainss.append(subs)
							github_domains.append(subs)
				if 'next_page disabled' in req_new:
					return github_domains
		else:
			print '[!] github site:domain no result'
			pass
		# else:
		# 	print '[!] Github login check Error'
		# 	print '[*] Please try again'
		# 	pass
	except Exception,e:
		# print traceback.format_exc()
		pass
	return github_domains

if __name__ == '__main__':
	pass