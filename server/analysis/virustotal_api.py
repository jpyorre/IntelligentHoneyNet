import hashlib, json, requests
from pprint import pprint as pp
import os
from pymongo import MongoClient
import json

fileinfo = []

host = 'www.virustotal.com'
VT_API_base_uri = 'https://www.virustotal.com/vtapi/v2/'
malware_from_honeypots = 'malware_from_honeypots.txt'
mongodb_host = 'localhost'
vt_results = 'vt_results.txt'
no_vtresults = 'no_vtresults.txt'

with open('/opt/analysis/virustotal_api_key.txt') as API_KEY:
    API_key = API_KEY.read()

def put_VTResults_into_mongodb():
	connection = MongoClient(mongodb_host)
	
	novtresults_db = connection.virustotal.noresults

	vtresults = {}
	for eachline in open(vt_results):
		md5,vendor,result,updated,version = eachline.strip().split('|')
		result = {'vendor':vendor,'result':result,'updated':updated,'version':version}
		vtresults_db = connection.virustotal.results.md5
		vtresults_db.insert(result)

	novtresults = {}
	for eachline in open(no_vtresults):
		md5,filename,text = eachline.strip().split('|')
		noresult = {'md5':md5,'filename':filename,'text':text}
		novtresults_db.insert(noresult)

def write_vt_results(line):
	writefile = open(vt_results,'a')
	writefile.write(line +'\n')
	writefile.close()

def write_no_vt_results(line):
	writefile = open(no_vtresults,'a')
	writefile.write(line +'\n')
	writefile.close()


def get_VT_report():
	params = {'resource': md5, 'apikey': API_key}
	response = requests.get(VT_API_base_uri + 'file/report', params=params)
	json_response = response.json()
	not_in_vt = 'The requested resource is not among the finished, queued or pending scans'
	if not_in_vt in json_response['verbose_msg']:
		line = str(md5) + '|' + str(filename) + '|' + 'Not found in VirusTotal'
		write_no_vt_results(line)
	else:
		link = json_response['permalink']
		hits = json_response['positives']
		scan_date = json_response['scan_date']

		av_info = json_response['scans']

		# Get and format information from AV vendors:
		for item in av_info:
			detected = av_info[item]['detected']
			result = av_info[item]['result']
			update = av_info[item]['update']
			version = av_info[item]['version']
			line = str(md5) + '|' + str(item) + '|' + str(result) + '|' + str(update) + '|' + str(version)
			write_vt_results(line)

def remove_files():
	os.system('rm ' + vt_results)
	os.system('rm ' + no_vtresults)

for line in open(malware_from_honeypots, "r"):
		data = json.loads(line)
		filename,md5,source = data['message'].split(',')
		print filename + '|' + md5 + '|' + source
		get_VT_report()
put_VTResults_into_mongodb()
remove_files()