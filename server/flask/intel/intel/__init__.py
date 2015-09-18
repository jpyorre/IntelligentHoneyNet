from flask import Flask
from flask import render_template
from pymongo import MongoClient
import json
from bson import json_util
from bson.json_util import dumps
from flask import Blueprint

app = Flask(__name__)

MONGODB_HOST = 'localhost'
MONGODB_PORT = 27017
SSH_DBS_NAME = 'ssh'
VT_DBS_NAME = 'virustotal'
CONPOT_DBS_NAME = 'conpot'

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

	connection.close()
	return render_template('ipcallouts.html', data = callouts)

@app.route("/ssh/domaincallouts")
def domain_callouts():
	connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
	COLLECTION_NAME = 'domaincallouts'
	collection = connection[SSH_DBS_NAME][COLLECTION_NAME]
	FIELDS = {'domain': True, 'registrar': True, 'created': True, 'expiration': True, 'updated': True, '_id': False }
	callouts = collection.find(projection=FIELDS)

	connection.close()
	return render_template('domaincallouts.html', data = callouts)


@app.route("/ssh/successfulconnections")
def successfulconnections():
	connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
	COLLECTION_NAME = 'successfulconnections'
	collection = connection[SSH_DBS_NAME][COLLECTION_NAME]
	FIELDS = {'time': True, 'source': True, 'user': True, 'password': True, 'asn': True, 'org': True, '_id': False }
	callouts = collection.find(projection=FIELDS)

	connection.close()
	return render_template('successfulconnections.html', data = callouts)


@app.route("/ssh/unsuccessfulconnections")
def unsuccessfulconnections():
	connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
	COLLECTION_NAME = 'unsuccessfulconnections'
	collection = connection[SSH_DBS_NAME][COLLECTION_NAME]
	FIELDS = {'time': True, 'source': True, 'user': True, 'password': True, 'asn': True, 'org': True, '_id': False }
	callouts = collection.find(projection=FIELDS)

	connection.close()
	return render_template('unsuccessfulconnections.html', data = callouts)


@app.route("/malware/virustotal/results")
def vtresults():
	connection = MongoClient(MONGODB_HOST, MONGODB_PORT)
	COLLECTION_NAME = 'results'
	collection = connection[VT_DBS_NAME][COLLECTION_NAME]
	FIELDS = {'md5': True, 'vendor': True, 'result': True, 'updated': True, 'version': True, '_id': False }
	vtresults = collection.find(projection=FIELDS)
	connection.close()
	
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
	conpotconnections = collection.find(projection=FIELDS)

	connection.close()
	return render_template('conpotconnections.html', data = conpotconnections)

if __name__ == "__main__":
	app.run()
	#app.run(host='0.0.0.0',port=5000,debug=True)
