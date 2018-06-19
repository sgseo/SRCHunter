#coding:utf-8

from lib.common import report_filename,result_paging,open_file,handle_ext,write_file
from lib.common import ip_counter,c_ip,check_ip,is_internal_ip
from lib.config import targets_path,portscan_opens_file
from lib.scanModule import *

from lib.cmdparser import cmdLineParser
args = cmdLineParser()

# Automatic completion
from lib.complete import complete_use

from plugins.portscan_icmp import get_ac_ip

# -s
if args.search:
	complete_use(args.search)

# -a
if args.autoscan:
	domain_result = autoSub(target=args.autoscan)
	print '[+] All auto task : %d' % len(domain_result)
	for domain in domain_result:
		checkDir(domain,target=args.autoscan,module='autoscan')	

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