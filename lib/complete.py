#coding:utf-8

import os
from config import targets_path

def load_file(path):
	'''
	Return File
	'''
	filter_func = lambda file:(True,False)['__init__' in file or 'pyc' in file or 'bat' in file]
	dir_exploit = filter(filter_func,os.listdir(path))# root_path
	return dir_exploit

def complete_use(text):
	'''
	Load targets filename
	'''
	completions = []
	ListPlugins = load_file(targets_path)
	if not text:
		completions = plugins
	else:
		try:
			completions = [p for p in ListPlugins if p.startswith(text)]
			print '[+] Get keyword list: ' + str(completions) + '\n[*] Default list[0] -> %s' % completions[0]
		except Exception,e:
			# print traceback.format_exc()
			pass
	if len(completions) > 0:
		return completions[0]
	else:
		print '[!] Can not get targets list'
		print ListPlugins
		return

if __name__ == '__main__':
	pass