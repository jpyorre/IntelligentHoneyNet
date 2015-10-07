#! /usr/bin/python

# This takes the cowrie.log file that's transferred from honeypots, reads through it and saves GET requests performed to a file. It also queries OpenDNS Investigate to find out ASN information on the IP addresses that connected in.

import json
import collections
from urllib2 import Request, urlopen
import shutil, os, datetime
from itertools import islice
from urlparse import urlparse
from pymongo import MongoClient

mongo_db_host = 'localhost'
file_timestamp = datetime.datetime.now().strftime("%s") #Used when renaming the log file after processing
cowrie_log_file = '/opt/files/incoming/cowrie.log'
lastlineread = '/opt/analysis/cowrie_log_lastline.txt'
SSH_get_requests = '/opt/analysis/SSH_get_requests.txt'
host_callouts = '/opt/analysis/SSH_Host_callouts.txt'
SSH_get_requests_temp = '/opt/analysis/SSH_get_requests_temp.txt'
host_info = '/opt/analysis/host_info_temp.txt'
IP_addresses = '/opt/analysis/ip_addresses.txt'
Domains = '/opt/analysis/domains.txt'
ip_investigated = '/opt/analysis/ip_investigated.txt'
domain_investigated = '/opt/analysis/domain_investigated.txt'
temp_log = '/opt/analysis/cowrie_log_processing.json'    

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

def write_hosts():
    if os.path.isfile(SSH_get_requests_temp):
        with open(SSH_get_requests_temp) as data:
            for eachline in data:
                if eachline.startswith('Host: '):
                    host = eachline[6:].strip()
                    # Check if it's an IP address or a domain:
                    write_append(host_info,host)

def first_run():
    # In case the program has never been run before, this will create the 'lastline.txt' file that keeps a record of what line we're at in the log file.
        if not os.path.isfile(lastlineread):
                cmd = 'echo \"1\" > ' + lastlineread
                os.system(cmd)

def seek_to_line(f, n):
    for ignored_line in islice(f, n - 1):
        pass # skip n-1 lines

def seek_to_last_line():
    for line in open(lastlineread,'r'):
        lastline = int(line.strip())

        f = open(cowrie_log_file,'r')
        seek_to_line(f, lastline)
        for line in f:
            write_temp_log_file(temp_log,line)

        # Update the 'lastline.txt' with the line we're on
        write_lastline_after_processing()

def write_lastline_after_processing():
    f = open(cowrie_log_file,'r')
    count = 0
    for line in open(cowrie_log_file, "r"):
        count += 1
    write_last_line_read(lastlineread,str(count))


#####################################################################
# OpenDNS Investigate API functions
#####################################################################
# Load Investigate API Key from investigate_token.txt:
with open('/opt/analysis/investigate_api_key.txt') as API_KEY:
    token = API_KEY.read()

headers = {
  'Authorization': 'Bearer ' + token
}

# Get information on a list of IP addresses (ASN, organization, creation date), from OpenDNS Investigate:
def IP_query_OpenDNS_investigate(ip):

    #print '\nOrganizational inforrmation on IP addresses that were seen connecting to the SSH Honeypot:\n'
    request = Request('https://investigate.api.opendns.com/bgp_routes/ip/' + ip + '/as_for_ip.json', headers=headers)
    response_body = urlopen(request).read()
    values = json.loads(response_body)
    try:
        cidr = values[0]['cidr']
        creation_date = values[0]['creation_date']
        asn = values[0]['asn']
        description = values[0]['description']

        ip_info =  str(ip) + '|' + str(asn) + '|' +  str(description) + '|' +  str(creation_date)
        return(ip_info)
    except:
        return('No IP Address')

# Get whois information on a list of domains
def domain_query_OpenDNS_investigate(domain):

    try:
        request = Request('https://investigate.api.opendns.com/whois/' + domain + '.json', headers=headers)
        response_body = urlopen(request).read()
        values = json.loads(response_body)

        regstreet = (values['registrantStreet'])
        regcity = (values['registrantCity'])
        regstate = (values['registrantState'])
        regcountry = (values['registrantCountry'])
        reg_address = str(regstreet) + ', ' + str(regcity) + ', ' + str(regstate) + ', ' + str(regcountry)
        #regcontactname = (values['registrant_contact_name'])
        regemail = (values['emails'])
       # registrantorg = (values['registrant_contact_organization'])
        created = (values['created'])
        expiration = (values['expires'])
        updated = (values['updated'])
        registrar = (values['registrarName'])
        nameServers = (values['nameServers'][0])

        domain_info = domain + '|' + registrar + '|' + created + '|' + expiration + '|' + updated
        return(domain_info)

    except:
        return('No Domain')
#####################################################################
# END OpenDNS Investigate API functions
#####################################################################

def valid_ip(address):
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if b >= 0 and b<=255]
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False

def separate_IP_and_domains():
    if os.path.isfile(host_info):
        with open(host_info,'r') as f:
            for d in f:
                domain = d.rstrip()
                
                # Look at the domain. If it's an IP address, write the IP to a file. If not, write to the domains.txt file.  
                if valid_ip(domain) == True:
                    write_append(IP_addresses,domain)
                else:
                    write_append(Domains,domain)

def investigate_ips():
    if os.path.isfile(IP_addresses):
        with open(IP_addresses) as ipaddress:
            uniqueipset = set(ipaddress)
            for ip in uniqueipset:
                ip = ip.strip()
                investigated_ip = IP_query_OpenDNS_investigate(ip)
                write_append(ip_investigated,investigated_ip)

def investigate_domains():
    if os.path.isfile(Domains):
        with open(Domains) as domainlist:
            uniquedomainset = set(domainlist)
            for domain in uniquedomainset:
                domain = domain.strip().strip('\\')
                investigated_domain = domain_query_OpenDNS_investigate(domain)
                write_append(domain_investigated,investigated_domain)
            
# Process through the file, saving the unique entries.
def process_file():
    for line in open(temp_log, "r"):
        data = json.loads(line)
        try:
            message = data['message']
            if 'GET' in message:
                urls = urlparse(message)
                lines = message.replace('\\r','').replace('\'','').replace('\\n','\n')            
                write_append(SSH_get_requests_temp,lines)   
        except:
            continue   

# TO DO: modify to save to csv files for downloading.
def write_everything():
    if os.path.isfile(ip_investigated):
        for line in open(ip_investigated):
             write_append(host_callouts,line.strip())
    if os.path.isfile(domain_investigated):
        for line in open(domain_investigated):
             write_append(host_callouts,line.strip())
    if os.path.isfile(SSH_get_requests_temp):
        for line in open(SSH_get_requests_temp):
            write_append(SSH_get_requests,line.strip())

def put_ipcallouts_into_mongodb():
    connection = MongoClient(mongo_db_host)
    db = connection.ssh.ipcallouts

    ipcallout = {}
    if os.path.isfile(ip_investigated):
        for eachline in open(ip_investigated):
            host,asn,org,created = eachline.strip().split('|')
            ipcallout = {'host':host,'asn':asn,'org':org,'created':created}
            db.insert(ipcallout)

def put_domaincallouts_into_mongodb():
    connection = MongoClient(mongo_db_host)
    db = connection.ssh.domaincallouts

    domaincallout = {}
    if os.path.isfile(domain_investigated):
        for eachline in open(domain_investigated):
		try:
            		domain,registrar,created,expiration,updated = eachline.strip().split('|')
            		domaincallout = {'domain':domain,'registrar':registrar,'created':created,'expiration':expiration,'updated':updated}
            		db.insert(domaincallout)
		except:
			domaincallout = ''

# Not active yet because I have to figure out how to organize this 
#def put_SSH_GET_REQUESTS_into_mongodb():
#    connection = MongoClient(mongo_db_host)
#    db = connection.ssh.getrequests

#    getrequest = {}
#    if os.path.isfile(SSH_get_requests):
#    	for eachline in open(SSH_get_requests):
#        		getrequest_paragraph = eachline.strip()
#        		getrequest = {'request':request}
#        		db.insert(getrequest)

def remove_files():
    if os.path.isfile(SSH_get_requests_temp):
        os.system('rm ' + SSH_get_requests_temp)
    if os.path.isfile(IP_addresses):
        os.system('rm ' + IP_addresses)
    if os.path.isfile(Domains):
        os.system('rm ' + Domains)
    if os.path.isfile(temp_log):
        os.system('rm ' + temp_log)
    if os.path.isfile(domain_investigated):
        os.system('rm ' + domain_investigated)
    if os.path.isfile(host_info):
        os.system('rm ' + host_info)
    if os.path.isfile(ip_investigated):
        os.system('rm ' + ip_investigated)
    if os.path.isfile(SSH_get_requests):
	# This is a workaround until I can figure out how to parse this file for the database:
        os.system('cat ' + SSH_get_requests + ' >> /var/www/intel/intel/static/SSH_get_requests.txt')
    	os.system('rm ' + SSH_get_requests)
    if os.path.isfile(host_callouts):
        os.system('rm ' + host_callouts)
        
###################################################################    
first_run()
seek_to_last_line()
process_file()
write_hosts()
separate_IP_and_domains()
investigate_ips()
investigate_domains()
write_everything()
put_ipcallouts_into_mongodb()
put_domaincallouts_into_mongodb()
#put_SSH_GET_REQUESTS_into_mongodb()   # Not active yet because I have to figure out how to organize this part.
remove_files()
