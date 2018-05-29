#coding:utf-8

# Project name
app_name = 'SRCHunter'

# Project version
version = '3.0'

# Filter ports list
filter_ports = [21,22,23,25,53,110,111,135,139,143,\
389,445,465,587,843,873,993,995,1080,1433,1521,1723,\
2181,2375,3306,3389,5432,5631,5900,6379,11211,27017,50070]# 5984

# Big ports list
big_ports = [10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,\
10180,10215,10243,10554,10566,10616,10617,10621,10626,10628,10629,10778,11110,\
11111,11211,11300,11967,12000,12174,12265,12345,13456,13579,13722,13782,13783,\
14000,14147,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,\
16010,16012,16016,16018,16080,16113,16992,16993,17000,17877,17988,18040,18081,\
18101,18245,18888,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,\
20031,20221,20222,20547,20828,21025,21379,21571,22222,22939,23023,23424,23502,\
24444,24800,25105,25565,25734,25735,26214,27000,27015,27016,27017,27352,27353,\
27355,27356,27715,28015,28017,28201,30000,30718,30951,31038,31337,32400,32764,\
32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,\
32781,32782,32783,32784,32785,33333,33354,33899,34571,34572,34573,35500,37777,\
38292,40193,40911,41511,42510,44176,44442,44443,44444,44501,44818,45100,47808,\
48080,48899,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,\
49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50070,50070,\
50090,50100,50300,50389,50500,50636,50800,51103,51106,51493,52673,52822,52848,\
52869,53413,54045,54138,54321,54328,55055,55056,55443,55553,55554,55555,55600,\
56737,56738,57294,57797,58080,60000,60020,60443,61532,61900,62078,63331,64623,\
64680,64738,65000,65129,65389]

# Filter url list
filter_urls = []

# Filter ip dict
filter_ips = {}

# Global logged in cookie
cookie = ''

# Global Referer
referer = 'http://www.cnnetarmy.com'

# Baidu engine ON / OFF
baidu_engine = False# True

# Github engine ON / OFF
github_engine = False

# Baidu Dirscan engine ON / OFF
baidu_dir_engine = False

# Filter internal ip
filter_internal_ip = True

# big ports ON / OFF
check_big_ports = True

# Baidu_site result
baidu_domainss = []

# Github url result
github_domainss = []

# Subdomains filter string | Module (-a)
sub_filter = '.cnnetarmy.'

# Subdomains filter list
sub_filter_list = ['.whoam1.','.cnnetarmy.','.SRCHunter.']

# Title filter string
title_filter = 'SRCHunter'# baidu|mogujie|weibo|jd|...

# Title filter list
title_filter_list = ['SRCHunter','Cnnetarmy']#u'中文'

# Proxies http
http_proxies = ''# 127.0.0.1:1080 shadowsocks | socks5://127.0.0.1:1080

# Proxies https
https_proxies = ''# 127.0.0.1:8080 BurpSuite

# Github sudomain filter
github_sub_filter = ['github','<','>','/','{','}','?','=','@',' ','*',';',']','[',':']

# Allinks filter
links_filter = ['.png','javascript','.svg','.jpg','.js','.css','/css?',\
'.gif','.jpeg','.ico','.swf','.mpg','mailto:','data:image']

# Email name filter
emails_filter = ['.png','.svg','.jpg','.gif','.css','.js']

# Portscan thread number
portscan_thread_num = 100# 800

# Port min
port_min = 1

# Port max
port_max = 1000# 65535

# C ip list min
c_min = 1

# C ip list max
c_max = 255

# The filter for max openports
openports_maxnum = 90

# Link maxnum
link_maxnum = 50

# Dirpaths maxnum
dirpaths_maxnum = 15

# Thread number
threadnum = 2

# Month days bak number
month_bak_num = 3

# Dirscan payloads
dir_payloads = False

# IP count min
ip_count_min = 1

# Dirscan payloads file
dir_payloads_file = './payloads/dirscan_payloads.txt'

# Targets list
targets_path = './targets/'

# Report Path
report_path = './report/'

# Portscan maxnum file 
portscan_maxnum_file = '/portscan_maxnum.txt'

# Portscan open file
portscan_opens_file = '/portscan_opens.csv'

# Url2ip error file
url2ip_error_file = '/url2ip_error.txt'

# Output error file
output_error_file = '/output_error.txt'

# Title filter file
title_filter_file = '/title_filter.txt'

# Sub filter file
sub_filter_file = '/sub_filter.txt'

# Github check login
github_account = ''# srchunter

# Github logged in cookie
github_cookie = '_ga=GA1.2.605058324.1525746109; _octo=GH1.1.1636350760.1525746110; _gat=1; \
tz=Asia%2FShanghai; user_session=cEznaHgVk-tieVAXWimhPQ_H9XP7q8D_ZcoJ40GqQ-gWd2ya; \
__Host-user_session_same_site=cEznaHgVk-tieVAXWimhPQ_H9XP7q8D_ZcoJ40GqQ-gWd2ya; logged_in=yes; \
dotcom_user=opayload; _gh_sess=RDVVcUwzUmdLOXZxdFlCalhRbzhNMkg3S0wrZXhsWktmQ3N0cExENTdnRnRJU3V0\
d0R0Z3hkV3JwdUtHRTNxdWVQUWRHMUdhNG1VK1B2YjZPOHVVVkhXNUc3Q0wxdzFZbHZ4SVo5b2l5eThBRC9OREFyVUtqWm9\
lOUFkRzRMdEttUzUxWHFaalZDVlg5YkFlQUVnUk5XRnljWGJuN3ZjVjFFT3I1MEhJT2pFZi9ESFlmbkZzUlIzdG9pRTFNWX\
pNeUJ4bFdacDl2d01aL1VwQVVEQkd1eEgrMmFOSDgwTXFja0ppbEJCdkhMOD0tLUV3YXZ0Z3dIQnpMbHl4dnQzSS9PN2c9P\
Q%3D%3D--198ff900cd43a9c8672a6c712fe166f37a79301d'

# Report Dirscan data
str_d = '''
<meta charset='UTF-8'>
<title>SRCHunter Report</title>
<style>td,h1 {color: #FFF;text-align:center;}a:link {color: #0C0;text-decoration: none;}\
body {font-family:Georgia,serif;background-color: #000;}</style>
<h1>SRCHunter Report Data</h1>
<table border="1" cellpadding="3" cellspacing="0" style="width: 80%;margin:auto">
<tr>
<td><b><font color="blue">Url</font></b></td>
<td><b>Ip</b></td>
<td><b><font color="blue">Code</font></b></td>
<td><b><font color="red">Title</font></b></td>
<td><b>Length</b></td>
<td><b><font color="red">Dirscan</font></b></td>
<td><b><font color="blue">Allinks</font></b></td>
<td><b>Emails/Ips</b></td>
</tr>

'''

# Report Fastscan data
str_f = '''
<meta charset='UTF-8'>
<title>SRCHunter Report</title>
<style>td,h1 {color: #FFF;text-align:center;}a:link {color: #0C0;text-decoration: none;}\
body {font-family:Georgia,serif;background-color: #000;}canvas{display: block;}</style>
<h1>SRCHunter Report Data</h1>
<table border="1" cellpadding="3" cellspacing="0" style="width: 80%;margin:auto">
<tr>
<td><b><font color="blue">Url</font></b></td>
<td><b>Ip</b></td>
<td><b><font color="blue">Code</font></b></td>
<td><b><font color="red">Title</font></b></td>
<td><b>Length</b></td>
<td><b><font color="blue">Allinks</font></b></td>
<td><b>Emails/Ips</b></td>
</tr>

'''

# Result paging fastscan
str_paging_f ='''
<meta charset='UTF-8'>
<title>SRCHunter Report</title>
<style>td,h1 {color: #FFF;text-align:center;}a:link {color: #0C0;text-decoration: none;}\
body {font-family:Georgia,serif;background-color: #000;}.center{text-align:center;color: #FFF;}</style>
<h1>SRCHunter Report Data</h1>
<table border="1" cellpadding="3" cellspacing="0" style="width: 80%;margin:auto" id="table1">
<tbody id="table2">
<tr>
<td><b><font color="blue">Url</font></b></td>
<td><b>Ip</b></td>
<td><b><font color="blue">Code</font></b></td>
<td><b><font color="red">Title</font></b></td>
<td><b>Length</b></td>
<td><b><font color="blue">Allinks</font></b></td>
<td><b>Emails/Ips</b></td>
</tr>
@flag@
</tbody>
</table>
<div class="center">
<span id="spanFirst">First</span> &nbsp;|&nbsp; 
<span id="spanPre">Prev<<</span> &nbsp;&nbsp;
<span id="spanPageNum"></span>/
<span id="spanTotalPage"></span> &nbsp;&nbsp;
<span id="spanNext">Next>></span> &nbsp;|&nbsp;
<span id="spanLast">Last</span>
</div>
<script type="text/javascript" src="../../static/js/paging.js"></script>
'''

# Result paging dirscan
str_paging_d ='''
<meta charset='UTF-8'>
<title>SRCHunter Report</title>
<style>td,h1 {color: #FFF;text-align:center;}a:link {color: #0C0;text-decoration: none;}\
body {font-family:Georgia,serif;background-color: #000;}.center{text-align:center;color: #FFF;}</style>
<h1>SRCHunter Report Data</h1>
<table border="1" cellpadding="3" cellspacing="0" style="width: 80%;margin:auto" id="table1">
<tbody id="table2">
<tr>
<td><b><font color="blue">Url</font></b></td>
<td><b>Ip</b></td>
<td><b><font color="blue">Code</font></b></td>
<td><b><font color="red">Title</font></b></td>
<td><b>Length</b></td>
<td><b><font color="red">Dirscan</font></b></td>
<td><b><font color="blue">Allinks</font></b></td>
<td><b>Emails/Ips</b></td>
</tr>
@flag@
</tbody>
</table>
<div class="center">
<span id="spanFirst">First</span> &nbsp;|&nbsp; 
<span id="spanPre">Prev<<</span> &nbsp;&nbsp;
<span id="spanPageNum"></span>/
<span id="spanTotalPage"></span> &nbsp;&nbsp;
<span id="spanNext">Next>></span> &nbsp;|&nbsp;
<span id="spanLast">Last</span>
</div>
<script type="text/javascript" src="../../static/js/paging.js"></script>
'''

# User agent list
user_agent = ['Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0',
'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0',
'Mozilla/5.0 (Windows; U; Windows NT 5.1 ; x64; en-US; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre',
'Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60','Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14',
'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)',
'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr; rv:1.9.2.4) Gecko/20100523 Firefox/3.6.4 ( .NET CLR 3.5.30729)',
'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5']