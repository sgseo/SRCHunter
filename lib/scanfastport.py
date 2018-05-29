#coding:utf-8

from lib.common import *

from plugins.web_getitle import getitle
from plugins.web_getallink import getallink

def checkFast(url,target,module):
	'''
	Main requests function no Dirscan
	'''
	output_file = report_filename(target,module)
	url = url_handle(url)
	try:
		if url not in filter_urls and filter_list(module=url,filter_list=sub_filter_list):
			filter_urls.append(url)
			print '[*] Now scanning: ' + url
			ip,open_ports = url,[]
			try:
				ip = url2ip(url)
				if not is_internal_ip(ip) and ip not in filter_ips.keys():# filter internal_ip | str(ip) not in filter_ips and
					print '[+] Get url2ip: ' + ip
					open_ports = portscan(ip)
					write_file(str(ip)+','+str(open_ports).replace('[','').replace(']',''),handle_ext(output_file)+portscan_opens_file)
					if len(open_ports) > openports_maxnum:
						print '[!] Maybe got port waf'
						write_file(ip,handle_ext(output_file)+portscan_maxnum_file)
						open_ports = []
				else:
					open_ports = filter_ips[ip]
			except Exception,e:
				# print traceback.format_exc()
				write_file(url,handle_ext(output_file)+url2ip_error_file)
				pass
			print '[+] Get open ports: ' + str(open_ports)
			if open_ports == []:#or 80 not in open_ports
				print '[!] Get open port lists None. Just scan default port'
				try:
					newtitle,code,lenth,content = '','','',''
					try:
						newtitle,code,lenth,content = getitle(url)
					except Exception,e:
						# print traceback.format_exc()
						pass
					if code in range(200,405):
						try:
							print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)
						except:pass
						write_file(url,handle_ext(output_file)+'/%s_alive_urls.txt' % handle_ext_old(target)) # save alive `host:port` to dirsearch
						alllink,alllinks,emails,ips = [],[],[],[]
						if title_filter not in newtitle and filter_list(module=newtitle,filter_list=title_filter_list):
							try:
								alllink,alllinks,emails,ips = getallink(url,content)
							except Exception,e:
								# print traceback.format_exc()
								pass
							try:
								write_file('<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;b</td><td><font color="blue">%s</font></td><td><ul><li>%s</li><li>%s</li><ul/></td></tr>\n\n' % (url,url,ip,code,newtitle,lenth,alllinks,emails,ips),output_file)
							except Exception,e:
								# print traceback.format_exc()
								print '[!] output_error'
								write_file(url,handle_ext(output_file)+output_error_file)
								pass
						else:
							print '[!] Filter title'
							write_file(url,handle_ext(output_file)+title_filter_file)
				except Exception,e:
					# print traceback.format_exc()
					pass
			else:
				for port in open_ports:
					if port not in filter_ports:
						if url[-1:] == '/':
							url = url[:-1]
						newurl = url + ':' + str(port)
						if newurl not in filter_urls:
							filter_urls.append(newurl)
							if newurl.split(':')[-1] == '80':
								newurl = newurl.replace('https://','http://')
							if newurl.split(':')[-1] == '443':
								newurl = newurl.replace(':443','').replace('http://','https://')
							print '[*] Scan new_url: ' + newurl
							try:
								newtitle,code,lenth,content = '','','',''
								try:
									newtitle,code,lenth,content = getitle(newurl)
								except Exception,e:
									# print traceback.format_exc()
									pass
								if code in range(200,405):
									try:
										print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)
									except:pass
									write_file(newurl,handle_ext(output_file)+'/%s_alive_urls.txt' % handle_ext_old(target))
									alllink,alllinks,emails,ips = [],[],[],[]
									if title_filter not in newtitle and filter_list(module=newtitle,filter_list=title_filter_list):
										try:
											alllink,alllinks,emails,ips = getallink(newurl,content)
										except Exception,e:
											# print traceback.format_exc()
											pass
										try:
											write_file('<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;b</td><td><font color="blue">%s</font></td><td><ul><li>%s</li><li>%s</li><ul/></td></tr>\n\n' % (newurl,newurl,ip,code,newtitle,lenth,alllinks,emails,ips),output_file)
										except Exception,e:
											# print traceback.format_exc()
											print '[!] output_error'
											write_file(newurl,handle_ext(output_file)+output_error_file)
											pass
									else:
										print '[!] Filter title'
										write_file(newurl,handle_ext(output_file)+title_filter_file)
							except Exception,e:
								# print traceback.format_exc()
								pass
					else:
						write_file(ip,handle_ext(output_file)+'/%s_%s.txt' % (handle_ext_old(target),str(port)))
						pass
		else:
			print '[!] Filter sub'
			write_file(url,handle_ext(output_file)+sub_filter_file)
	except Exception,e:
		# print traceback.format_exc()
		pass