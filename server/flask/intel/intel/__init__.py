from flask import Flask
from flask import render_template
from pymongo import MongoClient
import json
from bson import json_util
from bson.json_util import dumps
from flask import Blueprint
import csv

app = Flask(__name__)

MONGODB_HOST = 'localhost'
MONGODB_PORT = 27017
SSH_DBS_NAME = 'ssh'
VT_DBS_NAME = 'virustotal'
CONPOT_DBS_NAME = 'conpot'
GASPOT_DBS_NAME = 'gaspot'

@app.route("/")
def index():
	return render_template("index.html")

@app.route("/ssh/ipcallouts")
def ip_callouts():
	connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
	COLLECTION_NAME = 'ipcallouts'
	collection = connection[SSH_DBS_NAME][COLLECTION_NAME]
	FIELDS = {'host': True, 'asn': True, 'org': True, 'created': True, '_id': False }
	callouts = collection.find(projection=FIELDS)

        # Write CSV:
        with open ('/var/www/intel/intel/static/ssh_IP_callouts.csv', 'w') as outfile:
                csvwriter = csv.writer(outfile)
                _header = "IP Address called out to|ASN|Organization that owns the IP|IP Creation Date"
                header = _header.split("|")
                csvwriter.writerow(header)
                for field in callouts:
                        ip = field['host']
                        asn = field['asn']
                        org = field['org']
                        if field['created'] == "None":
                                created = "No Data"
                        else:
                                created = field['created']
                        _line = ip+"|"+asn+"|"+org+"|"+created
                        line = _line.split("|")
                        csvwriter.writerow(line)

	connection.close()
	callouts = collection.find(projection=FIELDS)
	return render_template('ipcallouts.html', data = callouts)

@app.route("/ssh/domaincallouts")
def domain_callouts():
	connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
	COLLECTION_NAME = 'domaincallouts'
	collection = connection[SSH_DBS_NAME][COLLECTION_NAME]
	FIELDS = {'domain': True, 'registrar': True, 'created': True, 'expiration': True, 'updated': True, '_id': False }
	callouts = collection.find(projection=FIELDS)

	# Write CSV:
	with open ('/var/www/intel/intel/static/ssh_domain_callouts.csv', 'w') as outfile:
        	csvwriter = csv.writer(outfile)
	        _header = "Domain called out to|Registrar for the Domain|Domain Creation Date|Domain Expiration Date|Last Update to the Domain"
       	 	header = _header.split("|")
        	csvwriter.writerow(header)
        	for field in callouts:
               		domain = field['domain']
                	registrar = field['registrar']
                	expiration = field['expiration']
                	updated = field['updated']
                	if field['created'] == "None":
                        	created = "No Data"
                	else:
                        	created = field['created']
                	_line = domain+"|"+registrar+"|"+created+"|"+expiration+"|"+updated
                	line = _line.split("|")
                	csvwriter.writerow(line)

	connection.close()
	callouts = collection.find(projection=FIELDS)
	return render_template('domaincallouts.html', data = callouts)


@app.route("/ssh/successfulconnections")
def successfulconnections():
	connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
	COLLECTION_NAME = 'successfulconnections'
	collection = connection[SSH_DBS_NAME][COLLECTION_NAME]
	FIELDS = {'time': True, 'source': True, 'user': True, 'password': True, 'asn': True, 'org': True, 'created': True, '_id': False }
	successfulssh = collection.find(projection=FIELDS).sort('time',-1)

	# Create CSV
	with open ('/var/www/intel/intel/static/ssh_successful_connections.csv', 'w') as outfile:
		csvwriter = csv.writer(outfile)
		_header = "Time of Attack|Attacker IP|Username|Password|ASN (Attacker IP)|Attacker IP Organizational Information|Attacker IP Created"
		header = _header.split("|")
		csvwriter.writerow(header)
		for field in successfulssh:
			time = field['time']
			host = field['source']
			username = field['user']
			password = field['password']
			asn = field['asn']
			organization = field['org']
			if field['created'] == "None":
				created = "No Data"
			else:
				created = field['created']
			_line = time+"|"+host+"|"+username+"|"+password+"|"+asn+"|"+organization+"|"+created
			line = _line.split("|")
			csvwriter.writerow(line)

	successfulssh = collection.find(projection=FIELDS).sort('time',-1)
	connection.close()
	return render_template('successfulconnections.html', data = successfulssh)


@app.route("/ssh/unsuccessfulconnections")
def unsuccessfulconnections():
	connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
	COLLECTION_NAME = 'unsuccessfulconnections'
	collection = connection[SSH_DBS_NAME][COLLECTION_NAME]
	FIELDS = {'time': True, 'source': True, 'user': True, 'password': True, 'asn': True, 'org': True, 'created': True, '_id': False }
	unsuccessfulssh = collection.find(projection=FIELDS).sort('time',-1)

        # Create CSV
        with open ('/var/www/intel/intel/static/ssh_unsuccessful_connections.csv', 'w') as outfile:
                csvwriter = csv.writer(outfile)
                csvwriter = csv.writer(outfile)
                _header = "Time of Attack|Attacker IP|Username|Password|ASN (Attacker IP)|Attacker IP Organizational Information|Attacker IP Created"
                header = _header.split("|")
                csvwriter.writerow(header)
                for field in unsuccessfulssh:
                        time = field['time']
                        host = field['source']
                        username = field['user']
                        password = field['password']
                        asn = field['asn']
                        organization = field['org']
                        if field['created'] == "None":
                                created = "No Data"
                        else:
                                created = field['created']
                        _line = time+"|"+host+"|"+username+"|"+password+"|"+asn+"|"+organization+"|"+created
                        line = _line.split("|")
                        csvwriter.writerow(line)

	unsuccessfulssh = collection.find(projection=FIELDS).sort('time',-1)
	connection.close()
	return render_template('unsuccessfulconnections.html', data = unsuccessfulssh)


@app.route("/malware/virustotal/results")
def vtresults():
	connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
	COLLECTION_NAME = 'results'
	collection = connection[VT_DBS_NAME][COLLECTION_NAME]
	FIELDS = {'scandate': True, 'scanratio': True, 'variant': True, 'link': True, '_id': False }
	vtresults = collection.find(projection=FIELDS).sort('scandate',-1)
	#vtresults = collection.find(projection=FIELDS).distinct('variant')

        # Write CSV:
        with open ('/var/www/intel/intel/static/Virust_Total_Results.csv', 'w') as outfile:
                csvwriter = csv.writer(outfile)
                _header = "Scan Date|Ratio|Malware Names|Link on VirusTotal"
                header = _header.split("|")
                csvwriter.writerow(header)
                for field in vtresults:
                        date = field['scandate']
                        ratio = field['scanratio']
                        name = field['variant']
                        link = field['link']
                        _line = date+"|"+ratio+"|"+name+"|"+link
                        line = _line.split("|")
                        csvwriter.writerow(line)

	connection.close()
	vtresults = collection.find(projection=FIELDS).sort('scandate',-1)
	return render_template('vtresults.html', data = vtresults)


@app.route("/malware/virustotal/noresults")
def novtresults():
	connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
	COLLECTION_NAME = 'noresults'
	collection = connection[VT_DBS_NAME][COLLECTION_NAME]
	FIELDS = {'md5': True, 'filename': True, 'text': True, '_id': False }
	vtnoresults = collection.find(projection=FIELDS)

	connection.close()
	return render_template('novtresults.html', data = vtnoresults)

@app.route("/conpot/connections")
def conpotconnections():
	connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
	COLLECTION_NAME = 'successfulconnections'
	collection = connection[CONPOT_DBS_NAME][COLLECTION_NAME]
	FIELDS = {'time': True, 'ip': True, 'source': True, 'asn': True, 'org': True, 'created': True,'_id': False }
	conpotconnections = collection.find(projection=FIELDS).sort('time',-1)

        # Write CSV:
        with open ('/var/www/intel/intel/static/ConPot_Connections.csv', 'w') as outfile:
                csvwriter = csv.writer(outfile)
                _header = "Time|Host|ASN|Organization|Created"
                header = _header.split("|")
                csvwriter.writerow(header)
                for field in conpotconnections:
                        time = field['time']
                        host = field['ip']
                        asn = field['asn']
			org = field['org']
                        if field['created'] == "None":
                                created = "No Data"
                        else:
                                created = field['created']
                        _line = time+"|"+host+"|"+asn+"|"+org+"|"+created
                        line = _line.split("|")
                        csvwriter.writerow(line)

	connection.close()
	conpotconnections = collection.find(projection=FIELDS).sort('time',-1)
	return render_template('conpotconnections.html', data = conpotconnections)

@app.route("/gaspot/connections")
def gaspotconnections():
        connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
        COLLECTION_NAME = 'connections'
        collection = connection[GASPOT_DBS_NAME][COLLECTION_NAME]
        FIELDS = {'time': True, 'command': True, 'ip': True, 'asn': True, 'org': True, 'created': True,'_id': False }
	gaspotconnects = collection.find(projection=FIELDS).distinct("ip")
        gaspotconnections = collection.find(projection=FIELDS).sort('time',-1)
	# CSV Download code:

	with open ('/var/www/intel/intel/static/gaspot_connections.csv', 'w') as outfile:
		csvwriter = csv.writer(outfile)

		_header = "Time of Attack|Attacker IP|Command Entered by Attacker|ASN (Attacker IP)|Attacker IP Organizational Information|Attacker IP Created"
		header = _header.split("|")
		csvwriter.writerow(header)

		for field in gaspotconnections:
			time = field['time']
			host = field['ip']
			command = field['command']
			asn = field['asn']
			organization = field['org']
			if field['created'] == "None":
				created = "No Data"
			else:
				created = field['created']
	
			_line = time+"|"+host+"|"+command+"|"+asn+"|"+organization+"|"+created
			line = _line.split("|")
			csvwriter.writerow(line)
	
	gaspotconnections = collection.find(projection=FIELDS).sort('time',-1)
	connection.close()
        return render_template('gaspotconnections.html', data = gaspotconnections)



if __name__ == "__main__":
	#app.run()
	app.run(host='0.0.0.0',port=5000,debug=True)
