#Plays the log files (which show what the attackers were up to when connected) sitting in the /opt/cowrie/log/tty/ folder and saves them to ssh_replaylogs.txt, which is then sent via logstash to the server for further processing.

#! /usr/bin/python
import os

ssh_tty_log_dir = '/opt/cowrie/log/tty/'

replayfilenames = []

def load_file_list():
	global replayfilenames
	replayfilenames = os.listdir(ssh_tty_log_dir)

load_file_list()

# ssh binaries:

for filename in replayfilenames:

	if filename != '.gitignore':
		if '.log' in filename:
			playlogs_cmd = 'python /opt/cowrie/utils/playlog.py -m 0 /opt/cowrie/log/tty/' + filename.strip() + ' > /opt/sshreplays/' + filename.strip('.log') + '.txt'
			os.system(playlogs_cmd)
			#os.system('rm /opt/cowrie/log/tty/' + filename)
  
