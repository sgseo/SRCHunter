#coding:utf-8

from lib.common import *

from lib.scanModule import *
from plugins.subdomain_all import *

from lib.cmdparser import cmdLineParser
args = cmdLineParser()

# Automatic completion
from lib.complete import complete_use

# -s
if args.search:
	complete_use(args.search)

# -u
if args.single:
	checkDir(args.single,target=args.single,module='single')
	output_filename = report_filename(target=args.single,argmodule='single')
	result_paging(filename=output_filename,module='')

# -f
if args.fastscan:
	handle_cmd = complete_use(args.fastscan)
	domains = open_file(targets_path + handle_cmd)
	print '[+] Get %d task.' % len(domains)
	for domain in domains:
		checkFast(domain,target=handle_cmd,module='fastscan')
	output_filename = report_filename(target=handle_cmd,argmodule='fastscan')
	portscan_opens_handle = ip_counter(filename=handle_ext(output_filename)+portscan_opens_file)
	write_file(portscan_opens_handle,'%s%s_cip.txt'%(targets_path,'.'.join(handle_cmd.split('.')[:-1])))
	result_paging(filename=output_filename,module='fast')
	# thread_run(domains,args_target=handle_cmd,module='fastscan',scanfunc=checkFast)

# -d
if args.dirscan:
	handle_cmd = complete_use(args.dirscan)
	domains = open_file(targets_path + handle_cmd)
	print '[+] Get %d task.' % len(domains)
	# thread_run(domains,args_target=handle_cmd,module='dirscan',scanfunc=checkDir)
	for domain in domains:
		checkDir(domain,target=handle_cmd,module='dirscan')
	output_filename = report_filename(target=handle_cmd,argmodule='dirscan')
	portscan_opens_handle = ip_counter(filename=handle_ext(output_filename)+portscan_opens_file)
	write_file(portscan_opens_handle,'%s%s_cip.txt'%(targets_path,'.'.join(handle_cmd.split('.')[:-1])))
	result_paging(filename=output_filename,module='')

# -fu
if args.fasturlscan:
	fastDir(args.fasturlscan,target=args.fasturlscan,module='fasturlscan')

# -fd
if args.fastdirscan:
	handle_cmd = complete_use(args.fastdirscan)
	domains = open_file(targets_path + handle_cmd)
	print '[+] Get %d task.' % len(domains)
	# thread_run(domains,args_target=handle_cmd,module='fastdirscan',scanfunc=fastDir)
	for domain in domains:
		fastDir(domain,target=handle_cmd,module='fastdirscan')
	output_filename = report_filename(target=handle_cmd,argmodule='fastdirscan')
	result_paging(filename=output_filename,module='')

# -cf
if args.cfastscan:
	if check_ip(args.cfastscan) and not is_internal_ip(args.cfastscan):
		ip_list = c_ip(args.cfastscan)
		ip_list = get_ac_ip(ip_list)
		print '[+] Get %d task.' % len(ip_list)
		# thread_run(ip_list,args_target=args.cfastscan,module='cfastscan',scanfunc=checkFast)
		for ip in ip_list:
			checkFast(ip,target=args.cfastscan,module='cfastscan')
		output_filename = report_filename(target=args.cfastscan,argmodule='cfastscan')
		result_paging(filename=output_filename,module='fast')

# -cd
if args.cdirscan:
	if check_ip(args.cdirscan) and not is_internal_ip(args.cdirscan):
		ip_list = c_ip(args.cdirscan)
		ip_list = get_ac_ip(ip_list)
		print '[+] Get %d task.' % len(ip_list)
		# thread_run(ip_list,args_target=args.cdirscan,module='cdirscan',scanfunc=checkDir)
		for ip in ip_list:
			checkDir(ip,target=args.cdirscan,module='cdirscan')
		output_filename = report_filename(target=args.cdirscan,argmodule='cdirscan')
		result_paging(filename=output_filename,module='')

# -cl
if args.clistscan:
	handle_cmd = complete_use(args.clistscan)
	ips = open_file(targets_path + handle_cmd)
	print '[+] Get max %d task.' % (len(ips)*255)
	for ip in ips:
		if check_ip(ip) and not is_internal_ip(ip):
			ip_list = c_ip(ip)
			ip_list = get_ac_ip(ip_list)
			print '[+] Get %d task.' % len(ip_list)
			# thread_run(ip_list,args_target=args.clistscan,module='clistscan',scanfunc=checkDir)
			for target_ip in ip_list:
				checkDir(target_ip,target=handle_cmd,module='clistscan')
			output_filename = report_filename(target=handle_cmd,argmodule='clistscan')
			result_paging(filename=output_filename,module='')

# -a
if args.autoscan:
	baidu_ce_domains = baidu_ce(args.autoscan)
	print '[+] Get baidu_ce_domains : %d' % len(baidu_ce_domains)
	findsub_domains = findsubdomain(args.autoscan)
	print '[+] Get findsub_domains : %d' % len(findsub_domains)
	ilinks_domains = ilinks(args.autoscan)
	print '[+] Get ilinks_domains : %d' % len(ilinks_domains)
	domains_api = list(set(baidu_ce_domains + findsub_domains + ilinks_domains))
	print '[+] Get All api sub domains : %d' % len(domains_api)
	if github_engine:
		github_domains = github_site(subdoamin = args.autoscan,key_domain = args.autoscan)
		if len(github_domains) == 0:
			print '[!] Can not get github site result. \n[*] Default try again'
			github_domains = github_site(subdoamin = args.autoscan,key_domain = args.autoscan)
		print '[+] First get %d task' % len(github_domains)
		for g_sub in github_domains:
			print '[*] Github second: %s' % g_sub
			github_site(subdoamin = g_sub,key_domain = args.autoscan)
		second_len_g = github_domainss
		print '[+] Second get %d task' % len(second_len_g)
		thrid_task_g = list(set(second_len_g + domains_api) - set(github_domains))
		print '[+] Thrid num : %d' % len(thrid_task_g)
		while len(thrid_task_g) > 0:
			for sub_g in thrid_task_g:
				print '<3>' + sub_g
				new_tar = github_site(subdoamin = sub_g,key_domain = args.autoscan)
				thrid_task_g += new_tar
				thrid_task_g.remove(sub_g)
		print '[+] Github get all %d task' % len(list(set(github_domainss + domains_api)))
		write_file(str(github_domainss),'%s%s_github.txt'%(targets_path,args.autoscan))
	if baidu_engine:
		baidu_domains = baidu_site(key_domain=args.autoscan)
		if len(baidu_domains) == 0:
			print '[!] Can not get baidu site result. \n[*] Default try again'
			baidu_domains = baidu_site(key_domain=args.autoscan)
		print '[+] First get %d task' % len(baidu_domains)
		for sub in baidu_domains:
			print '<2>' + sub
			sub = sub.replace('.'+args.autoscan,'')
			baidu_site(key_domain=args.autoscan,sub_domain=sub)
		print '[+] Second get %d task' % len(baidu_domainss)
		thrid_task = list(set(baidu_domainss) - set(baidu_domains))
		print '[+] Thrid num : %d' % len(thrid_task)
		while len(thrid_task) > 0:
			for t_sub in thrid_task:
				print '<3>' + t_sub
				t_subs = t_sub.replace('.'+args.autoscan,'')
				new_tar_b = baidu_site(key_domain=args.autoscan,sub_domain=t_subs)
				thrid_task += new_tar_b
				thrid_task.remove(t_sub)
		last_task = list(set(baidu_domainss))
		last_tasks = list(set(domains_api+last_task+github_domainss))
		print '[+] Last baidu site task : %d' % len(last_task)
		while len(last_tasks) > 0:
			for subss in last_tasks:
				print '<4>' + subss
				last_b = baidu_site(command = 'site:%s'%subss,key_domain = args.autoscan)
				last_tasks += last_b
				last_tasks.remove(subss)
	domain_result = list(set(baidu_domainss + github_domainss + domains_api))
	print '[+] All auto task : %d' % len(domain_result)
	write_file(str(domain_result),'%s%s_auto.txt'%(targets_path,args.autoscan))
	for domain in domain_result:
		checkDir(domain,target=args.autoscan,module='dirscan')
# -al
# 
# 