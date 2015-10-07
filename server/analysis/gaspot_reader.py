#!/usr/bin/python
import json, os
from itertools import islice
import re
from urllib2 import Request, urlopen
from pymongo import MongoClient

mongo_db_host = 'localhost'

gaspotlog = '/opt/files/incoming/gaspot.log'
lastlineread = '/opt/analysis/gaspot_lastlineread.txt'
gaspot_templog = '/opt/analysis/gaspot_templog.txt'
gaspot_connections = '/opt/analysis/gaspot_connections.txt'
unique_ipaddresses = '/opt/analysis/unique_ipaddresses.txt'
ipaddresses = '/opt/analysis/ipaddresses.txt'

# Load Investigate API Key from investigate_token.txt:
with open('/opt/analysis/investigate_api_key.txt') as API_KEY:
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
		f = open(gaspotlog,'r')
		count = 0
		for line in open(gaspotlog, "r"):
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

		ip_info =  str(asn) + '|' +  str(description) + '|' +  str(creation_date)
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

		f = open(gaspotlog,'r')
		seek_to_line(f, lastline)
		for line in f:
			write_append(gaspot_templog,line)

		# Update the 'lastline.txt' with the line we're on
		write_lastline_after_processing()


def finduniquelines(line):
	print line
	uline = set(line)
	for item in uline:
		return uline

def put_gaspot_connections_into_mongodb():
		connection = MongoClient(mongo_db_host)
		db = connection.gaspot.connections

		gaspotconnections = {}
		for eachline in open(gaspot_connections):
			try:
				time,command,ip,asn,org,created = eachline.strip().split('|')
				gaspotsuccess = {'time':time, 'command':command, 'ip':ip, 'asn':asn,'org':org,'created':created}
				db.insert(gaspotsuccess)
			except:
				gaspotsuccess = ''

def process_file():
		
	for line in open(gaspot_templog, "r"):
		data = json.loads(line)
		message = data['message']
		if 'Command' in message:
			try:
				_time = message.split(' - ')[0]
				time = _time.split('{\"message\":\"')
				time = str(time).replace('[u\'\', u\'','').replace('\']','').replace('[u\'','')
				_command = message.split(' - ')[1]
				command = _command.split(':')[0]
				_ip = message.split(': ')[1]
				ip = _ip.split('\"')[0]
		
				line = str(time) + '|' + str(command) + '|' +  str(ip)
			except:
				line = ''

			write_append(ipaddresses, line + '\n')
	if os.path.isfile(ipaddresses):	
		os.system('sort -u ' + ipaddresses + ' > ' + unique_ipaddresses)

	for line in open(unique_ipaddresses,'r'):
		try:
			time,command,ip = line.split('|')
			time =  time.strip()
			command = command.strip()
			ip = ip.strip()
			investigated_ip = IP_query_OpenDNS_investigate(ip)

			asn, org, createdate = investigated_ip.split('|')
			entry =  time + '|' + command + '|' + ip + '|' + asn + '|' + org + '|' + createdate
			write_append(gaspot_connections,entry + '\n')
		except:
			entry = ''

def remove_files():
		os.system('rm ' + gaspot_templog)
		os.system('rm ' + gaspot_connections)
		os.system('rm ' + unique_ipaddresses)
		os.system('rm ' + ipaddresses)

first_run()
seek_to_last_line()
process_file()
put_gaspot_connections_into_mongodb()
remove_files()
