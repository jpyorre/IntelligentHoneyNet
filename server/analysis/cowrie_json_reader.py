#! /usr/bin/python

# This runs on the server. It takes the cowrie.log file that's transferred from honeypots, reads through it and saves GET requests performed to a file. It also queries OpenDNS Investigate to find out ASN information on the IP addresses that connected in.

import json
import collections
from urllib2 import Request, urlopen
import shutil, os, datetime
from itertools import islice
from urlparse import urlparse
from pymongo import MongoClient

mongo_db_host = 'localhost'

file_timestamp = datetime.datetime.now().strftime("%s") #Used when renaming the log file after processing
cowrie_log_file = '/opt/files/incoming/cowrie.json'
lastlineread = '/opt/analysis/cowrie_json_lastline.txt'
temp_log = '/opt/analysis/cowrie_json_processing.json' 
Successful_Connections_file = '/opt/analysis/SSH_Successful_Connections.txt'
Unsuccessful_Connections_file = '/opt/analysis/SSH_Unsuccessful_Connections.txt'

# Functions to write files:    
def write_append(filename,line):
    writefile = open(filename,'a')
    writefile.write(line)
    writefile.write('\n')
    writefile.close()

def write_temp_log_file(filename,line):
        writefile = open(filename,'a')
        writefile.write(line)
        writefile.close()

def write_last_line_read(filename, line):
    writefile = open(filename,'w')
    writefile.write(line)
    writefile.close()

# Load Investigate API Key from investigate_token.txt:
with open('/opt/analysis/investigate_api_key.txt') as API_KEY:
    token = API_KEY.read()

headers = {
  'Authorization': 'Bearer ' + token
}

# Get information on a list of IP addresses (ASN, organization, creation date), from OpenDNS Investigate:
def query_OpenDNS_investigate(ip):
    #print '\nOrganizational inforrmation on IP addresses that were seen connecting to the SSH Honeypot:\n'
    request = Request('https://investigate.api.opendns.com/bgp_routes/ip/' + ip + '/as_for_ip.json', headers=headers)
    response_body = urlopen(request).read()
    values = json.loads(response_body)

    cidr = values[0]['cidr']
    creation_date = values[0]['creation_date']
    asn = values[0]['asn']
    description = values[0]['description']

    ip_info = str(asn) + '|' +  str(description) + '|' +  str(creation_date)
    return(ip_info)

def write_lastline_after_processing():
    f = open(cowrie_log_file,'r')
    count = 0
    for line in open(cowrie_log_file, "r"):
        #data = json.loads(line)
        #if 'eventid' in data:
        count += 1
    write_last_line_read(lastlineread,str(count))


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
        lastline = int(line)

        f = open(cowrie_log_file,'r')
        seek_to_line(f, lastline)
        for line in f:
            write_temp_log_file(temp_log,line)

        # Update the 'lastline.txt' with the line we're on
        write_lastline_after_processing()

def process_file():

# For removing duplicate entries:
    unique_ips= set()
    log_counter= collections.Counter()
    log_store= collections.defaultdict(list)
    
    for line  in open(temp_log, 'r'):
        #data = json.loads(line)
        try:
	    data = json.loads(line)
            ssh_id = data['session']
            log_counter[ssh_id]+=1
            log_store[ssh_id].append(data)
            unique_ips.add(data["src_ip"])
        except:
            continue

    for k, v in log_store.items():

        for item in v:
            timestamp = item['timestamp']

            if 'src_ip' in item:
                src_ip = item['src_ip']
            else:
                src_ip = "No source IP"

            if 'username' in item:
                username = item['username']
            else:
                username = "No username"

            if 'password' in item:
                password = item['password']
            else:
                password = "No password"

            if 'session' in item:
                session = item['session']

            # This sends the IP address to query_OpenDNS_investigate() and assigns the response to ip_asn_info.
            try:
                ip_asn_info = query_OpenDNS_investigate(src_ip)
            except:
                continue

            # Set up the line for printing to file:
            entry =  str(timestamp) + '|' + str(src_ip) + '|' + str(username) + '|' + str(password) + '|' + str(ip_asn_info)

            # Some entries aren't relevant here:
            if password == 'No password':
                continue
            
            # Save the successful and unsuccessful connections to separate files:
            else:
                if 'succeeded' in item['format']:
                    write_append(Successful_Connections_file,entry)

                else:
                    write_append(Unsuccessful_Connections_file,entry)

def put_ssh_successful_connections_into_mongodb():
    connection = MongoClient(mongo_db_host)
    db = connection.ssh.successfulconnections

    sshsuccess = {}
    if os.path.isfile(Successful_Connections_file):
        for eachline in open(Successful_Connections_file):
		try:
                	time,source,user,password,asn,org,created = eachline.strip().split('|')
                	sshsuccess = {'time':time,'source':source,'user':user,'password':password,'asn':asn,'org':org,'created':created}
                	db.insert(sshsuccess)
		except:
	    		sshsuccess = ''

def put_ssh_unsuccessful_connections_into_mongodb():
    connection = MongoClient(mongo_db_host)
    db = connection.ssh.unsuccessfulconnections

    sshunsuccessful = {}
    if os.path.isfile(Unsuccessful_Connections_file):
        for eachline in open(Unsuccessful_Connections_file):
		try:
                	time,source,user,password,asn,org,created = eachline.strip().split('|')
                	sshunsuccessful = {'time':time,'source':source,'user':user,'password':password,'asn':asn,'org':org,'created':created}
                	db.insert(sshunsuccessful)
		except:
	    		sshunsuccessful = ''

def remove_files():
    if os.path.isfile(temp_log):
        os.system('rm ' + temp_log)
    if os.path.isfile(Unsuccessful_Connections_file):
        os.system('rm ' + Unsuccessful_Connections_file)
    if os.path.isfile(Successful_Connections_file):
        os.system('rm ' + Successful_Connections_file)

first_run()
seek_to_last_line()
process_file()
put_ssh_successful_connections_into_mongodb()
put_ssh_unsuccessful_connections_into_mongodb()
remove_files()
