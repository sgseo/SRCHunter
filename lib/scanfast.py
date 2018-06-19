#coding:utf-8

from lib.common import report_filename,url_handle,filter_list,write_file,handle_ext,scandir_again

from lib.config import baidu_engine,github_engine,baidu_dir_engine
from lib.config import title_filter,title_filter_list
from lib.config import link_maxnum,dirpaths_maxnum
from lib.config import output_error_file,title_filter_file

from plugins.web_getitle import getitle
from plugins.web_getallink import getallink
from plugins.web_weakfile import weakfile
from plugins.web_baidu_check import baidu_check
from plugins.web_github_check import github_check
from plugins.web_dirscan import dirscan
from plugins.web_baidu_dir import baidu_dir

import urlparse,traceback

def fastDir(newurl,target,module):
	'''
	FastDir scan without portscan
	'''
	output_file = report_filename(target,module)
	newurl = url_handle(newurl)
	ip,baidu_status,github_status = '',[],[]
	print '[*] Scan new_url: ' + newurl
	if baidu_engine:
		print '[*] Check Baidu site: %s' % urlparse.urlparse(newurl).hostname
		baidu_status = baidu_check(newurl)
	if github_engine:
		print '[*] Check Github status: %s' % urlparse.urlparse(newurl).hostname
		github_status = github_check(newurl)
	try:
		newtitle,code,lenth,content = '','','',''
		try:
			newtitle,code,lenth,content = getitle(url=newurl)
		except Exception,e:
			# print traceback.format_exc()
			pass
		if code in range(200,405) and code != 401:# add Do not scan 401 status_code
			try:
				print '[+] Get title: %s,status_code: %s,content lenth: %s' % (newtitle,code,lenth)
			except:pass
			alllink,alllinks,emails,ips = [],[],[],[]
			if title_filter not in newtitle and filter_list(module=newtitle,filter_list=title_filter_list):
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
				baidu_dirs = ''
				if baidu_dir_engine:
					try:
						baidu_dirs = baidu_dir(command = 'site:%s'%urlparse.urlparse(newurl).hostname,key_domain = urlparse.urlparse(newurl).hostname)
					except Exception,e:
						# print traceback.format_exc()
						pass
				weakuri = []
				try:
					weakuri = dirscan(newurl)
				except Exception,e:
					# print traceback.format_exc()
					pass
				weakuri = baidu_status + github_status + weakuri
				try:
					write_file('<tr><td><a href="%s" target=_blank />%s</a></td><td>%s</td><td><font color="blue">%s</font></td><td><font color="red">%s</font></td><td>%s&nbsp;b</td><td>%s</td><td><font color="blue">%s%s</font></td><td><ul><li>%s</li><li>%s</li><ul/></td></tr>\n\n' % (newurl,newurl,ip,code,newtitle,lenth,[dirpath_key for dirpath_key in set(dirpaths + weakuri)],baidu_dirs,alllinks,emails,ips),output_file)
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