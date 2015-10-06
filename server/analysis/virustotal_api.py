#!/usr/bin/python
import hashlib, json, requests
from pprint import pprint as pp
import os
from pymongo import MongoClient
import json
import urllib,urllib2

malware_from_honeypots = '/opt/files/incoming/malware_from_honeypots.txt'
vt_results = '/opt/analysis/vt_results.txt'
notprocessed = '/opt/analysis/vt_notprocessed.txt'
alreadyprocessed = '/opt/analysis/vt_alreadyprocessed.txt'
unique_not_processed = '/opt/analysis/vt_unique_not_processed.txt'

MONGODB_HOST = 'localhost'
connection = MongoClient(MONGODB_HOST)
COLLECTION_NAME = 'results'
VT_DBS_NAME = 'virustotal'
collection = connection[VT_DBS_NAME][COLLECTION_NAME]

with open('virustotal_api_key.txt') as API_KEY:
    API_key = API_KEY.read().strip('\n')

def write_vt_results(line):
        writefile = open(vt_results,'a')
        writefile.write(line +'\n')
        writefile.close()

def writeappend(filename,line):
        writefile = open(filename,'a')
        writefile.write(str(line) +'\n')
        writefile.close()

def check_if_in_db(sha256):
	vtresults = collection.find()
	for line in vtresults:
		sections = line['link'].split('/')
		sha_in_db = sections[4]
		if sha256 == sha_in_db:
			#print "Already in database: \n\t" + sha256
			writeappend(alreadyprocessed,sha256)
		else:
			#print sha256
			writeappend(notprocessed,sha256)

def put_VTResults_into_mongodb():
	vtresults = {}
	if os.path.isfile(vt_results):
		for eachline in open(vt_results):
			scandate,scanratio,variant,link = eachline.strip().split('|')
			result = {'scandate':scandate,'scanratio':scanratio,'variant':variant,'link':link}
			vtresults_db = connection.virustotal.results
			vtresults_db.insert(result)

def get_VT_report(sha256):
	url = "https://www.virustotal.com/vtapi/v2/file/report"
	parameters = {"resource": sha256,"apikey": API_key}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	_json = response.read()
	info = json.loads(_json)
	try:
		link = info['permalink']
       		positives = info['positives']
		total = info['total']
       		scandate = info['scan_date']
		av_info = info['scans']
		
		# Get and format information from AV vendors:
		avresults = []
		for item in av_info:
			detected = av_info[item]['detected']
			result = av_info[item]['result']
			scandate = av_info[item]['update']
			version = av_info[item]['version']
	
			if detected == True:
				avresults.append(result)

		avresults = str(avresults).replace('[u\'','').replace('\', u\'',',').replace('\']','')
		line = str(scandate) + '|' + str(positives) + '\\' + str(total) + '|' + str(avresults) + '|' + str(link)
		write_vt_results(line)
	except:
		line = ''

def remove_files():
	if os.path.isfile(vt_results):
		os.system('rm ' + vt_results)
	if os.path.isfile(notprocessed):
		os.system('rm ' + notprocessed)
	if os.path.isfile(alreadyprocessed):
		os.system('rm ' + alreadyprocessed)
	if os.path.isfile(unique_not_processed):
		os.system('rm ' + unique_not_processed)
	os.system('echo '' > ' + malware_from_honeypots)

def main():
	os.system('chmod 777 /opt/files/incoming/malware_from_honeypots.txt')

	# open the file like this and skip the first line because it has a newline
	lines = open(malware_from_honeypots,'r').readlines()
	for eachline in lines[1:]:
		try:
			data = json.loads(eachline)
			filename,sha256,source = data['message'].split(',')
			check_if_in_db(sha256)
			writeappend(notprocessed,sha256)
		except:
			data = ''

	os.system('sort -u ' + notprocessed + ' > ' + unique_not_processed)
	
	with open(unique_not_processed) as new_shaw_256:
		for sha in new_shaw_256:
			sha256 = sha.strip()
			get_VT_report(sha256)
	put_VTResults_into_mongodb()
	remove_files()

main()