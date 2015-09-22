#!/usr/bin/python
import hashlib, json, requests
from pprint import pprint as pp
import os
from pymongo import MongoClient
import json
import urllib,urllib2

fileinfo = []

host = 'www.virustotal.com'
VT_API_base_uri = 'https://www.virustotal.com/vtapi/v2/'
malware_from_honeypots = '/opt/files/incoming/malware_from_honeypots.txt'
mongodb_host = 'localhost'
vt_results = '/opt/analysis/vt_results.txt'

with open('/opt/analysis/virustotal_api_key.txt') as API_KEY:
    API_key = API_KEY.read().strip('\n')

def put_VTResults_into_mongodb():
	connection = MongoClient(mongodb_host)
	
	vtresults_db = connection.virustotal.results

	vtresults = {}
	for eachline in open(vt_results):
		scandate,scanratio,variant,link = eachline.strip().split('|')
		result = {'scandate':scandate,'scanratio':scanratio,'variant':variant,'link':link}
		vtresults_db = connection.virustotal.results
		vtresults_db.insert(result)

	#novtresults = {}
	#for eachline in open(no_vtresults):
	#	sha5,filename,text = eachline.strip().split('|')
	#	noresult = {'sha256':sha256,'filename':filename,'text':text}
	#	novtresults_db.insert(noresult)

def write_vt_results(line):
	writefile = open(vt_results,'a')
	writefile.write(line +'\n')
	writefile.close()

def write_no_vt_results(line):
	writefile = open(no_vtresults,'a')
	writefile.write(line +'\n')
	writefile.close()


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
	os.system('rm ' + vt_results)
	os.system('echo '' > /opt/files/incoming/malware_from_honeypots.txt')

# open the file like this and skip the first line because it has a newline
lines = open(malware_from_honeypots,'r').readlines()
for eachline in lines[1:]:
		data = json.loads(eachline)
		filename,sha256,source = data['message'].split(',')
		sha256 = sha256.strip('\n')
		get_VT_report(sha256)
put_VTResults_into_mongodb()
remove_files()
