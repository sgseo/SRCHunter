#coding:utf-8

from lib.common import *

def github_check(subdoamin):
	'''
	Get github target.com status
	'''
	flag = []
	headers = requests_headers()
	proxies = requests_proxies()
	if '://' in subdoamin:
		subdoamin = urlparse.urlparse(subdoamin).hostname
	session = requests.Session()
	headers['Cookie'] = github_cookie
	try:
		# check_login = 'https://github.com/settings/emails'
		# req_check = session.get(url=check_login,headers=headers,proxies=proxies,timeout=10,verify=False).content
		# if github_account in req_check:
		headers['Host'] = 'github.com'
		headers['Referer'] = 'https://github.com/search?utf8=%E2%9C%93&q=*&type=Code'
		github_url = 'https://github.com/search?q={}&type=Code&utf8=%E2%9C%93'.format(subdoamin)
		req = session.get(url=github_url,headers=headers,proxies=proxies,timeout=10,verify=False).text
		if 'blankslate' not in str(req):
			flag.append('<a href="%s" target=_blank />Github</a>' % github_url)
	except Exception,e:
		# print traceback.format_exc()
		pass
	return flag

if __name__ == '__main__':
	pass