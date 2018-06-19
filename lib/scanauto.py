#coding:utf-8

from lib.config import github_engine,baidu_engine,api_engine,github_domainss,baidu_domainss
from plugins.subdomain_all import *

def autoSub(target):
	domains_api = []
	if api_engine:
		baidu_ce_domains = baidu_ce(target)
		print '[+] Get baidu_ce_domains : %d' % len(baidu_ce_domains)
		findsub_domains = findsubdomain(target)
		print '[+] Get findsub_domains : %d' % len(findsub_domains)
		ilinks_domains = ilinks(target)
		print '[+] Get ilinks_domains : %d' % len(ilinks_domains)
		domains_api = list(set(baidu_ce_domains + findsub_domains + ilinks_domains))
		print '[+] Get All api sub domains : %d' % len(domains_api)
	if github_engine:
		github_domains = github_site(subdoamin = target,key_domain = target)
		if len(github_domains) == 0:
			print '[!] Can not get github site result. \n[*] Default try again'
			github_domains = github_site(subdoamin = target,key_domain = target)
		print '[+] First get %d task' % len(github_domains)
		for g_sub in github_domains:
			print '[*] Github second: %s' % g_sub
			github_site(subdoamin = g_sub,key_domain = target)
		second_len_g = github_domainss
		print '[+] Second get %d task' % len(second_len_g)
		thrid_task_g = list(set(second_len_g + domains_api) - set(github_domains))
		print '[+] Thrid num : %d' % len(thrid_task_g)
		while len(thrid_task_g) > 0:
			for sub_g in thrid_task_g:
				print '<3>' + sub_g
				new_tar = github_site(subdoamin = sub_g,key_domain = target)
				thrid_task_g += new_tar
				thrid_task_g.remove(sub_g)
		print '[+] Github get all %d task' % len(list(set(github_domainss + domains_api)))
	if baidu_engine:
		baidu_domains = baidu_site(key_domain=target)
		if len(baidu_domains) == 0:
			print '[!] Can not get baidu site result. \n[*] Default try again'
			baidu_domains = baidu_site(key_domain=target)
		print '[+] First get %d task' % len(baidu_domains)
		for sub in baidu_domains:
			print '<2>' + sub
			sub = sub.replace('.'+target,'')
			baidu_site(key_domain=target,sub_domain=sub)
		print '[+] Second get %d task' % len(baidu_domainss)
		thrid_task = list(set(baidu_domainss) - set(baidu_domains))
		print '[+] Thrid num : %d' % len(thrid_task)
		while len(thrid_task) > 0:
			for t_sub in thrid_task:
				print '<3>' + t_sub
				t_subs = t_sub.replace('.'+target,'')
				new_tar_b = baidu_site(key_domain=target,sub_domain=t_subs)
				thrid_task += new_tar_b
				thrid_task.remove(t_sub)
		last_task = list(set(baidu_domainss))
		last_tasks = list(set(domains_api+last_task+github_domainss))
		print '[+] Last baidu site task : %d' % len(last_task)
		while len(last_tasks) > 0:
			for subss in last_tasks:
				print '<4>' + subss
				last_b = baidu_site(command = 'site:%s'%subss,key_domain = target)
				last_tasks += last_b
				last_tasks.remove(subss)
	domain_result = list(set(baidu_domainss + github_domainss + domains_api))
	return domain_result