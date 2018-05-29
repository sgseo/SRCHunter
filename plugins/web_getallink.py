#coding:utf-8

from lib.common import *

def getallink(url,content):
	'''
	Get response all link
	'''
	links,emails,ips,check = [],[],[],[]
	tags = ['a','A','link','script','area','iframe','form']# img
	tos = ['href','src','action']
	if url[-1:] == '/':
		url = url[:-1]
	try:
		print '[*] Now regex alllinks,emails,ips'
		emails_source = email_regex(str(content))
		ips = ip_regex(str(content))
		# print '[*] Now regex urls'
		# urls = url_regex(content)
		for tag in tags:
			for to in tos:
				link = re.findall(r'<%s.*?%s="(.*?)"' % (tag,to),str(content))
				for i in link:
					if i not in check and filter_list(module=i,filter_list=links_filter) and i != '':
						check.append(i)
						if '://' in i:
							i = i.replace(' ','')
							if str(urlparse.urlparse(i).path) in ['/',''] and str(urlparse.urlparse(i).query) in ['/','']:
								link_flag = '<a href="'+i+'" target=_blank />'+urlparse.urlparse(str(i)).netloc+'</a>'
							else:
								link_flag = '<a href="'+i+'" target=_blank />'+quote(urlparse.urlparse(str(i)).path+urlparse.urlparse(str(i)).query)[:25]+'</a>'
						elif '//' in i:
							if str(urlparse.urlparse(i).path) in ['/',''] and str(urlparse.urlparse(i).query) in ['/','']:
								link_flag = '<a href="http:'+i+'" target=_blank />'+urlparse.urlparse(str(i)).netloc+'</a>'
							else:
								link_flag = '<a href="http:'+i+'" target=_blank />'+quote(urlparse.urlparse(str(i)).path+urlparse.urlparse(str(i)).query)[:25]+'</a>'							
						else:
							link_flag = '<a href="'+url+'/'+i+'" target=_blank />'+quote(i)[:25]+'</a>'
							check.append(url + i)
						links.append(link_flag)
	except Exception,e:
		# print traceback.format_exc()()
		print '[!] Get regex link error'
		pass
	emails_handle = [email[-30:] for email in set(emails_source)]# Filter too lang email
	for email_check in emails_handle:
		if filter_list(module=email_check,filter_list=emails_filter):# loading@2x.gif/png
			emails.append(email_check)
	ips = [ip for ip in set(ips)]
	if len(links) > 10:
		# Click more_links to get detail result
		mainDiv = ranStr()
		childDiv = ranStr()
		return check,u'''<div id="%s" style="color:red" onclick="document.all.%s.style.display=(document.all.%s.style.display =='none')?'':'none'">[more_links]</div><div id="%s" style="display:none">%s</div>'''%(mainDiv,childDiv,childDiv,childDiv,'<br />'.join(links)),'<br />'.join(emails),'<br />'.join(ips)
	else:
		return check,links,'<br />'.join(emails),'<br />'.join(ips)

if __name__ == '__main__':
	pass