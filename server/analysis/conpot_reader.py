import json, os
from itertools import islice
import re
from urllib2 import Request, urlopen
from pymongo import MongoClient

mongo_db_host = 'localhost'


lastlineread = '/opt/analysis/conpot_lastlineread.txt'
conpotlog = '/opt/files/incoming/conpot.log'
conpot_templog = '/opt/analysis/conpot_templog.txt'
conpot_connections = '/opt/analysis/conpot_connections.txt'
unique_ipaddresses = '/opt/analysis/unique_ipaddresses.txt'
ipaddresses = '/opt/analysis/ipaddresses.txt'

# Load Investigate API Key from investigate_token.txt:
with open('/opt/analysis/investigate_api_key') as API_KEY:
    token = API_KEY.read()

headers = {
  'Authorization': 'Bearer ' + token
}


def write_append(filename,line):
		writefile = open(filename,'a')
		writefile.write(line)
		writefile.close()

def write_overwrite(filename,line):
		writefile = open(filename,'w')
		writefile.write(line)
		writefile.close()

def write_lastline_after_processing():
		f = open(conpotlog,'r')
		count = 0
		for line in open(conpotlog, "r"):
			#data = json.loads(line)
			#if 'eventid' in data:
			count += 1
		write_overwrite(lastlineread, str(count))

def IP_query_OpenDNS_investigate(ip):

    #print '\nOrganizational inforrmation on IP addresses that were seen connecting to the SSH Honeypot:\n'
	try:
		request = Request('https://investigate.api.opendns.com/bgp_routes/ip/' + ip + '/as_for_ip.json', headers=headers)
		response_body = urlopen(request).read()
		values = json.loads(response_body)

		cidr = values[0]['cidr']
		creation_date = values[0]['creation_date']
		asn = values[0]['asn']
		description = values[0]['description']

		ip_info =  str(ip) + '|' + str(asn) + '|' +  str(description) + '|' +  str(creation_date)
		return(ip_info)
	except:
		return('')

def seek_to_line(f, n):
		for ignored_line in islice(f, n - 1):
			pass # skip n-1 lines

def first_run():
		# In case the program has never been run before, this will create the 'lastline.txt' file that keeps a record of what line we're at in the log file.
	        if not os.path.isfile(lastlineread):
	                cmd = 'echo \"1\" > ' + lastlineread
	                os.system(cmd)


def seek_to_last_line():
	for line in open(lastlineread,'r'):
		lastline = int(line.strip())

		f = open(conpotlog,'r')
		seek_to_line(f, lastline)
		for line in f:
			write_append(conpot_templog,line)

		# Update the 'lastline.txt' with the line we're on
		write_lastline_after_processing()


def finduniquelines(line):
	print line
	uline = set(line)
	for item in uline:
		return uline

def put_conpot_connections_into_mongodb():
		connection = MongoClient(mongo_db_host)
		db = connection.conpot.successfulconnections

		conpotconnections = {}
		for eachline in open(conpot_connections):
			try:
				time,ip,source,asn,org,created = eachline.strip().split('|')
				conpotsuccess = {'time':time, 'ip':ip, 'source':source,'asn':asn,'org':org,'created':created}
				db.insert(conpotsuccess)
			except:
				conpotsuccess = ''
	
			

def process_file():
		
	for line in open(conpot_templog, "r"):
		data = json.loads(line)
		
		message = data['message'].split(',')
		datetime = message[0]
		restofmessage = message[1:]

		ip_regex = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', str(restofmessage))
		eachline = str(ip_regex)[1:-1].strip('\n')
		# find and remove empty lines:
		if re.match(r'^\s*$', eachline):
			continue
		else:
			
			separateparts = eachline.split(',')
			ip_addresses = str(separateparts[0])
			write_append(ipaddresses,ip_addresses +'\n')

	os.system('sort -u ipaddresses.txt > unique_ipaddresses.txt')

	with open(unique_ipaddresses,'r') as ips:
		for eachline in ips:
			ip = eachline.strip().replace('\'','')
			investigate_ip = IP_query_OpenDNS_investigate(ip)
			completeline = datetime + '|' + ip + '|' + investigate_ip
			write_append(conpot_connections,completeline + '\n')

def remove_files():
		os.system('rm ' + conpot_templog)
		os.system('rm ' + conpot_connections)
		os.system('rm ' + unique_ipaddresses)
		os.system('rm ' + ipaddresses)

first_run()
seek_to_last_line()
process_file()
put_conpot_connections_into_mongodb()
remove_files()
