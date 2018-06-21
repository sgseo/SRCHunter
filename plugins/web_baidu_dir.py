#coding:utf-8

from lib.common import requests_headers,requests_proxies,ranStr

import re
import requests
import urlparse
import traceback
from urllib import quote

# Ignore warning
requests.packages.urllib3.disable_warnings()

def baidu_dir(key_domain='',sub_domain='',command=''):
	'''
	Get baidu site:target.com dirs result
	'''
	headers = requests_headers()
	proxies = requests_proxies()
	if '://' in key_domain:
		key_domain = urlparse.urlparse(key_domain).hostname
	sub_url,check = '',[]
	baidu_url = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{}'.format(key_domain)
	if command:
		baidu_url = 'https://www.baidu.com/s?ie=UTF-8&wd={}'.format(command)
	try:
		r = requests.get(url=baidu_url,headers=headers,timeout=10,proxies=proxies,verify=False).content
		if 'class="tip_head"' not in r:# Check first
			for page in xrange(0,21):# max page_number
				pn = page * 50
				if key_domain:
					newurl = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{}&pn={}&rn=50&tn=baiduadv'.format(key_domain,pn)
				if sub_domain:
					newurl = 'https://www.baidu.com/s?ie=UTF-8&wd=site:{} -inurl:({})&pn={}&rn=50&tn=baiduadv'.format(key_domain,sub_domain,pn)# -site:(weibo.com)
				if command:
					newurl = 'https://www.baidu.com/s?ie=UTF-8&wd={}&pn={}&rn=50&tn=baiduadv'.format(command,pn)
				headers = requests_headers()
				keys = requests.get(url=newurl,headers=headers,proxies=proxies,timeout=10,verify=False).content
				flags = re.findall(r'<div class="result c-container ".*<h3 class=".*"><a(?:[^\<]*\n[^\<]*)href = "(?P<url>.+?)"(?:[^\<]*\n[^\<]*)target="_blank"(?:[^\<]*\n[^\<]*)>(?P<title>.+?)</a></h3>',keys)
				check_flag = keys.count('class="n"')
				for flag in flags:
					baidu_url = flag[0]
					if baidu_url not in check:
						headers = requests_headers()
						try:
							sub_req = requests.head(url=baidu_url,headers=headers,proxies=proxies,timeout=10,verify=False)
							sub_url = sub_req.headers['Location']
						except:pass
						if key_domain in sub_url:
							sub_url = '<a href="'+sub_url+'" target=_blank />'+quote(urlparse.urlparse(str(sub_url)).path+urlparse.urlparse(str(sub_url)).query)[:25]+'</a>'
							check.append(sub_url)
				if check_flag < 2 and page > 2:
					if len(check) > 15:
						mainDiv,childDiv = ranStr(),ranStr()
						return u'''<div id="%s" style="color:red" onclick="document.all.%s.style.display=(document.all.%s.style.display =='none')?'':'none'">[more_dirs]</div><div id="%s" style="display:none">%s</div>'''%(mainDiv,childDiv,childDiv,childDiv,'<br />'.join(list(set(check))))
					else:
						return list(set(check))
		else:
			print '[!] baidu site:domain no result'
			return ''
	except Exception,e:
		# print traceback.format_exc()
		pass		

if __name__ == '__main__':
	pass
