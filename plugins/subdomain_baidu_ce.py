#coding:utf-8

from lib.common import requests_headers,requests_proxies
import requests,json

def baidu_ce(key_domain):
	'''
	Get key_domain list from ce.baidu.com.
	'''

	headers = requests_headers()
	proxies = requests_proxies()
	domains = []
	api_url = 'http://ce.baidu.com/index/getRelatedSites?site_address=%s' % key_domain
	try:
		r = requests.get(url=api_url,headers=headers,timeout=10,proxies=proxies,verify=False).content
		ce_json = json.loads(r)
		json_result = ce_json['data']
		for j_domain in json_result:
			domain = j_domain['domain']
			if domain not in domains:
				# print '[+] Get ce baidu domain > ' + domain
				domains.append(domain)
	except Exception,e:
		# print traceback.format_exc()
		pass
	return domains

if __name__ == '__main__':
	pass