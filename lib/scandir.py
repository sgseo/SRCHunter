#coding:utf-8

from lib.config import filter_urls,filter_ips,filter_ports,title_filter,sub_filter_list,title_filter_list
from lib.config import baidu_engine,github_engine,baidu_dir_engine
from lib.config import link_maxnum,dirpaths_maxnum,openports_maxnum
from lib.config import output_error_file,title_filter_file,portscan_maxnum_file,url2ip_error_file,sub_filter_file,portscan_opens_file

from lib.common import report_filename,filter_list,url_handle,handle_ext,handle_ext_old,write_file
from lib.common import url2ip,is_internal_ip,scandir_again

from plugins.portscan_tcp import portscan

from plugins.web_getitle import getitle
from plugins.web_getallink import getallink
from plugins.web_weakfile import weakfile
from plugins.web_baidu_check import baidu_check
from plugins.web_github_check import github_check
from plugins.web_dirscan import dirscan
from plugins.web_baidu_dir import baidu_dir

import urlparse,traceback

def checkDir(url,target,module):
	'''
	Main requests function with Portscan && Dirscan
	'''
	output_file = report_filename(target,module)
	url = url_handle(url)
	try:
		if url not in filter_urls and filter_list(module=url,filter_list=sub_filter_list):
			filter_urls.append(url)
			ip,open_ports,baidu_status,github_status = url,[],[],[]
			print '[*] Now scanning: ' + url
			if module in ['autoscan','dirscan','single']:# Handle c_ip scan
				if baidu_engine:
					print '[*] Check Baidu site: %s' % urlparse.urlparse(url).hostname
					baidu_status = baidu_check(url)
				if github_engine:
					print '[*] Check Github status: %s' % urlparse.urlparse(url).hostname
					github_status = github_check(url)
			try:
				ip = url2ip(url)
				if not is_internal_ip(ip) and ip not in filter_ips.keys() and ip != '':# filter internal_ip
					print '[+] Get url2ip: ' + ip
					open_ports = portscan(ip)
					filter_ips[ip] = open_ports
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
				try:
					newtitle,code,lenth,content = '','','',''
					try:
						newtitle,code,lenth,content = getitle(url)
					except Exception,e:
						# print traceback.format_exc()
						pass
					if code in range(200,405) and code != 401:# add Do not scan 401 status_code
						try:
							print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)
						except:pass
						write_file(url,handle_ext(output_file)+'/%s_alive_urls.txt' % handle_ext_old(target))
						if title_filter not in newtitle and filter_list(module=newtitle,filter_list=title_filter_list):
							alllink,alllinks,emails,ips = [],[],[],[]
							try:
								alllink,alllinks,emails,ips = getallink(url,content)
							except Exception,e:
								# print traceback.format_exc()
								pass
							dirpaths = []
							try:
								dir_urls = scandir_again(url,alllink)
								if len(dir_urls) < link_maxnum:
									for dir_url in dir_urls:
										dirpaths += weakfile(dir_url)
							except Exception,e:
								# print traceback.format_exc()
								pass
							if len(dirpaths) > dirpaths_maxnum:
								dirpaths = ["more_path"]
							weakuri = []
							try:
								weakuri = dirscan(url)
							except Exception,e:
								# print traceback.format_exc()
								pass
							baidu_dirs = ''
							if baidu_dir_engine and module in ['autoscan','dirscan','single']:
								try:
									baidu_dirs = baidu_dir(command = 'site:%s'%urlparse.urlparse(url).hostname,key_domain = urlparse.urlparse(url).hostname)
								except Exception,e:
									# print traceback.format_exc()
									pass
							weakuri = baidu_status + github_status + weakuri
							try:
								write_file('<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;b</td><td>%s</td><td><font color="blue">%s%s</font></td><td><ul><li>%s</li><li>%s</li><ul/></td></tr>\n\n' % (url,url,ip,code,newtitle,lenth,[dirpath_key for dirpath_key in set(dirpaths + weakuri)],alllinks,baidu_dirs,emails,ips),output_file)
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
				count_flag = 0
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
								if code in range(200,405) and code != 401:# add Do not scan 401 status_code
									try:
										print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)
									except:pass
									write_file(newurl,handle_ext(output_file)+'/%s_alive_urls.txt' % handle_ext_old(target))
									if title_filter not in newtitle and filter_list(module=newtitle,filter_list=title_filter_list):
										alllink,alllinks,emails,ips = [],[],[],[]
										try:
											alllink,alllinks,emails,ips = getallink(newurl,content)
										except Exception,e:
											# print traceback.format_exc()
											pass
										dirpaths = []
										try:
											dir_urls = scandir_again(newurl,alllink)
											if len(dir_urls) < link_maxnum:# Pass num
												for dir_url in dir_urls:
													dirpaths += weakfile(dir_url)
										except Exception,e:
											# print traceback.format_exc()
											pass
										if len(dirpaths) > dirpaths_maxnum:# Check num
											dirpaths = ["more_path"]
										weakuri = []
										try:
											weakuri = dirscan(newurl)
										except Exception,e:
											# print traceback.format_exc()
											pass
										baidu_dirs = ''
										if baidu_dir_engine and module in ['autoscan','dirscan','single'] and count_flag < 1:
											count_flag += 1
											try:
												baidu_dirs = baidu_dir(command = 'site:%s'%urlparse.urlparse(newurl).hostname,key_domain = urlparse.urlparse(newurl).hostname)
											except Exception,e:
												# print traceback.format_exc()
												pass
										weakuri = baidu_status + github_status + weakuri
										try:
											write_file('<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;b</td><td>%s</td><td><font color="blue">%s%s</font></td><td><ul><li>%s</li><li>%s</li><ul/></td></tr>\n\n' % (newurl,newurl,ip,code,newtitle,lenth,[dirpath_key for dirpath_key in set(dirpaths + weakuri)],alllinks,baidu_dirs,emails,ips),output_file)
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