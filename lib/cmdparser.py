#coding:utf-8

import argparse
import sys
from config import version

def cmdLineParser():
	'''
usage: python SRCHunter.py -a target.com

<mail>: SRCHunter@cnnetarmy.com

ENGINE:
  -s SEARCH        Search targets
  -a AUTOSCAN      Subdmoain port + dir scan
  -u SINGLE        Target port + dir scan
  -f FASTSCAN      List port - dir scan
  -d DIRSCAN       List port + dir scan
  -fu FASTURLSCAN  Target dir - port scan
  -fd FASTDIRSCAN  List dir - port scan
  -cf CFASTSCAN    C_Target port - dir scan
  -cd CDIRSCAN     C_Target port + dir scan
  -cl CLISTSCAN    C_List port + dir scan

SYSTEM:
  -h, --help       show help message
  -v, --version    current version
	'''
	parser = argparse.ArgumentParser(description=u'<mail>: SRCHunter@cnnetarmy.com',usage='python SRCHunter.py -a target.com',add_help=False)#

	engine = parser.add_argument_group('ENGINE')

	engine.add_argument('-s',
		dest='search',
		default=False,
		help=u'Search targets')
	engine.add_argument('-a',
		dest='autoscan',
		default=False,
		help=u'Subdmoain port + dir scan')#,'--auto'
	engine.add_argument('-u',
		dest='single',
		default=False,
		help=u'Target port + dir scan')#,'--url'
	engine.add_argument('-f',
		dest='fastscan',
		default=False,
		help=u'List port - dir scan')#,'--fast'
	engine.add_argument('-d',
		dest='dirscan',
		default=False,
		help=u'List port + dir scan')#,'--dir'
	engine.add_argument('-fu',
		dest='fasturlscan',
		default=False,
		help=u'Target dir - port scan')#,'--fasturl'
	engine.add_argument('-fd',
		dest='fastdirscan',
		default=False,
		help=u'List dir - port scan')#,'--fastdir'
	engine.add_argument('-cf',
		dest='cfastscan',
		default=False,
		help=u'C_Target port - dir scan')#,'--cfast'
	engine.add_argument('-cd',
		dest='cdirscan',
		default=False,
		help=u'C_Target port + dir scan')#,'--cdir'
	engine.add_argument('-cl',
		dest='clistscan',
		default=False,
		help=u'C_List port + dir scan')#,'--clist'

	system = parser.add_argument_group('SYSTEM')

	system.add_argument('-h',
		'--help',
		action='help',
		help=u'show help message')
	system.add_argument('-v',
		'--version',
		version=version,
		action='version',
		help=u'current version')
	if len(sys.argv) == 1:
		sys.argv.append('-h')
	args = parser.parse_args()
	return args

if __name__ == '__main__':
	pass
	# args = cmdLineParser()
	# print args