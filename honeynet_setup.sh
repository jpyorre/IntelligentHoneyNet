#! /bin/bash

# Used to get the architecture for the installation of ElasticSearch and Kibana:
getarchitecture(){
        architecture=0
        echo "Are you running on 32 bit or 64 bit architecture? Enter 32 or 64"
        read architecture
        if [ $architecture -eq 32 ]
                then es_architecture="export JAVA_HOME=/usr/lib/jvm/java-7-openjdk-i386/" && kibana="https://download.elastic.co/kibana/kibana/kibana-4.1.1-linux-x86.tar.gz"
        elif [ $architecture -eq 64 ]
                then es_architecture="export JAVA_HOME=/usr/lib/jvm/java-7-openjdk-amd64/" && kibana="https://download.elastic.co/kibana/kibana/kibana-4.1.1-linux-x64.tar.gz"
        else
                getarchitecture;
        fi
}

getarchitecture;

HPN=$(dirname "$0")
DIR="$HPN/HoneyNet_Installer/"


# Make directories:
mkdir -p /opt/files/incoming /opt/analysis /usr/local/certs/sslcerts/ /var/www/intel /opt/cronscripts
chown nobody:nogroup /opt/files/incoming

# Copy analysis scripts:
cp $HPN/server/analysis/* /opt/analysis/ && chmod 755 /opt/analysis/* && cp -r $HPN/client /opt/

# cp webserver:
cp -r $HPN/server/flask/intel /var/www/ && chown -R www-data:www-data /var/www/intel

# Make some utilities for troubleshooting logstash when you need to add new things:

cat > /usr/bin/editlogstashconf.sh<<EOF
#!/bin/bash
sudo vim /etc/logstash/conf.d/server.conf
EOF

cat > /usr/bin/restartlogstash.sh<<EOF
#!/bin/bash
sudo service logstash restart
EOF

cat > /usr/bin/statuslogstash.sh<<EOF
#!/bin/bash
sudo service logstash status
EOF

cat > /usr/bin/taillogstashlog.sh<<EOF
#!/bin/bash
tail -f /var/log/logstash/logstash.log
EOF

cat > /usr/bin/testlogstash.sh<<EOF
#!/bin/bash
/usr/local/src/logstash-1.5.4/bin/logstash -f /etc/logstash/conf.d/client.conf --configtest
EOF
chmod 755 /usr/bin/editlogstashconf.sh
chmod 755 /usr/bin/restartlogstash.sh
chmod 755 /usr/bin/statuslogstash.sh
chmod 755 /usr/bin/taillogstashlog.sh
chmod 755 /usr/bin/testlogstash.sh

# Stuff we need for various parts of this installation:
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10
echo 'deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen' | tee /etc/apt/sources.list.d/mongodb.list
apt-get update && apt-get install build-essential libffi-dev apache2 redis-server stunnel4 supervisor openjdk-7-jdk curl libgeoip-dev mongodb-org git apache2-utils libapache2-mod-wsgi python-dev ntp -y

# Update the date (seems to have been a problem during my testing - my vm's were not udpating their date and time)
echo "This might hang for about 5 seconds:"
service ntp stop && /usr/sbin/ntpdate pool.ntp.org && service ntp start

cd /usr/local/src && wget https://bootstrap.pypa.io/get-pip.py && python get-pip.py

pip install flask-mongoengine pymongo flask-bootstrap requests


####### STUNNEL CONFIG #######
# stunnel is listening for connections on port 6378 on all interfaces and will send connections from there to 127.0.0.1:6379

#Generage a certificate for stunnel:
cd /etc/stunnel && openssl genrsa -out key.pem 2048 && openssl req -new -x509 -key key.pem -out cert.pem -days 2095 -subj "/C=US/ST=CA/L=Oakland/O=Honeynet/OU=Honeynet/CN=Honeynet CA/emailAddress=nonei@tld.com" && cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4

cat > /etc/stunnel/stunnel.conf<<EOF
cert = /etc/stunnel/stunnel.pem

[redis]
accept = 6378
connect = 127.0.0.1:6379

[logstash-filetransfer]
accept = 6781
connect = 127.0.0.1:6782

EOF

####### END STUNNEL CONFIG #######

####### LOGSTASH CONFIG #######


cd /usr/local/src && wget https://download.elastic.co/logstash/logstash/packages/debian/logstash_1.5.3-1_all.deb && dpkg -i logstash_1.5.3-1_all.deb

cd /etc/logstash && curl -O "http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz" && gunzip GeoLiteCity.dat.gz
cat > /etc/logstash/conf.d/server.conf<<EOF
input {

    if ( [type] == "SSH" or [type] == "GasPot" or [type] == "Conpot" ) {
      redis {
          host => "localhost"
          type => "redis-input"
          data_type => "list"
          key => "honeynet"
      }
    }

    if ( [type] == "ssh_intel" or [type] == "GasPot" or [type] == "ssh_intel2" or [type] == "conpot_intel" or [type] == "malware_from_honeypots" or [type] == "ssh_replaylogs" ) {
    tcp {
        mode => "server"
        codec => json_lines
        port => "6782"
  }

        }
}

filter {

# Conpot honeypot
#
  if [type] == "conpot" {
    grok {
       match => [ "message", "%{YEAR:year}-%{MONTHNUM:month}-%{MONTHDAY:day} %{TIME:time} : %{IP:srcip} \t%{DATA:srcport} \t %{IP:dstip} \t %{DATA:request_protocol} \t %{DATA:response_code} \t %{DATA:sensor_id} \t '%{DATA:request_raw}' " ]
    }
    
    mutate {
       add_field => [ "source-ip", "%{srcip}" ]
    }
    date {
      match => [ "timestamp" , "yyyy-MM-dd HH:mm:ss" ]
    }
  }

# GasPot honeypot
if [type] == "GasPot" {
  grok {
  match => [ "message", "Connection from : %{IP:src-ip}" ]
  }
  mutate {
  add_field => [ "source-ip", "%{src-ip}" ]
  }
}

# Cowrie honeypot
if [type] == "SSH" {

if ( [message] =~ "SSHService ssh-userauth on HoneyPotTransport" ) {

  grok {
  match => [ "message", "%{YEAR:year}-%{MONTHNUM:month}-%{MONTHDAY:day} %{TIME:time}%{ISO8601_TIMEZONE} \[SSHService ssh-userauth on HoneyPotTransport,%{DATA:ssh-session},%{IP:src-ip}" ]

  }
  mutate {
        add_field => [ "source-ip", "%{src-ip}" ]
  }
    }
}

# GEO DATA:
if ( [type] == "SSH" or [type] == "GasPot" ) {

geoip {
      source => "src-ip"
      target => "geoip"
      database => "/etc/logstash/GeoLiteCity.dat"
      add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
      add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
    }
    mutate {
      convert => [ "[geoip][coordinates]", "float"]
    }
}
}

output {
        if ( [type] == "SSH" or [type] == "GasPot" or [type] == "Conpot" ) {
    elasticsearch {
                cluster => "honeynet"
                bind_host => "127.0.0.1"
                }
    }

    if [type] == "ssh_intel" {
        file {
                codec => json
                path => "/opt/files/incoming/cowrie.json"
        }
    }
    if [type] == "GasPot" {
  file {
    path => "/opt/files/incoming/gaspot.log"
  }
    }

    if [type] == "ssh_intel2" {
        file {
                path => "/opt/files/incoming/cowrie.log"
        }       
    }   

    if [type] == "conpot_intel" {
        file {
                path => "/opt/files/incoming/conpot.log"
        }
    }
    
    if [type] == "malware_from_honeypots" {
        file {
                path => "/opt/files/incoming/malware_from_honeypots.txt"
        }
    }

    if [type] == "ssh_replaylogs" {
        file {
                path => "/opt/files/incoming/ssh_replaylogs.txt"
        }
    }

}

EOF

# Supervisor for logstash:
cat > /etc/supervisor/conf.d/logstash.conf <<EOF
[program:logstash]
command=/opt/startlogstash.sh
directory=/opt/
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

cat > /opt/startlogstash.sh <<EOF
#! /bin/bash
service logstash start
EOF

chmod 755 /opt/startlogstash.sh

chown logstash:logstash /opt/files/incoming/

####### END LOGSTASH CONFIG #######

####### ELASTICSEARCH CONFIG #######
# For 32 bit: export JAVA_HOME=/usr/lib/jvm/java-7-openjdk-i386/
# For 64 bit: export JAVA_HOME=/usr/lib/jvm/java-7-openjdk-amd64/
# handled in the beginning with the getarchitecture function

# Install elasticsearch:
cd /usr/local/src && wget https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-1.7.1.deb && echo $es_architecture && dpkg -i elasticsearch-1.7.1.deb && update-rc.d elasticsearch defaults 95 10

sed -i 's/#cluster.name: elasticsearch/cluster.name: honeynet/g' /etc/elasticsearch/elasticsearch.yml
sed -i 's/#node.name: "Franz Kafka"/node.name: "HNServer"/g' /etc/elasticsearch/elasticsearch.yml
sed -i 's/#network.host: 192.168.0.1/network.host: localhost/g' /etc/elasticsearch/elasticsearch.yml
####### END ELASTICSEARCH CONFIG #######


####### KIBANA CONFIG #######
# Kibana and apache
# 64 bit: https://download.elastic.co/kibana/kibana/kibana-4.1.1-linux-x64.tar.gz
# 32 bit: https://download.elastic.co/kibana/kibana/kibana-4.1.1-linux-x86.tar.gz
# handled in the beginning with the getarchitecture function

cd /var/www/ && wget $kibana && tar -zxf kibana* && rm *.gz && mv kibana* kibana && chown -R www-data:www-data kibana

# limit access to kibana to local connections only. This is so we can proxy through apache and use https
# The host to bind the server to.
sed -i 's/host: "0.0.0.0"/host: "127.0.0.1"/g' /var/www/kibana/config/kibana.yml

# DEPRECATED Set kibana to be able to read files owned by root:
#usermod -a -G adm logstash

# Setup kibana to start at boot
cat > /opt/kibana_start.sh <<EOF
#!/bin/sh
sh /var/www/kibana/bin/kibana
EOF

chmod 755 /opt/kibana_start.sh

cat > /etc/supervisor/conf.d/kibana.conf <<EOF
[program:kibana]
command=/opt/kibana_start.sh
directory=/var/www/kibana
stdout_logfile=/opt/kibana.out
stderr_logfile=/opt/kibana.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

####### END KIBANA CONFIG #######


####### SSL CONFIG #######
# generate ssl keys:
# Generate and copy to /usr/local/certs/sslcerts/
cd /usr/local/certs/sslcerts/

# Create server key and certificate signing request:
openssl req -new -out csr.key -passout pass:honeynet -subj "/C=US/ST=CA/L=Oakland/O=Honeynet/OU=Honeynet/CN=Honeynet CA/emailAddress=nonei@tld.com"

# Remove the Passphrase
openssl rsa -in privkey.pem -passin pass:honeynet -out server.key

# Sign certificate:
openssl x509 -req -days 3600 -in csr.key -signkey server.key -out server.crt
####### SSL CONFIG #######


####### APACHE CONFIG #######

# You have to run htpasswd to set up a user who can access the kibana interface:

#sudo htpasswd -c /opt/.htpasswd-private username
chown www-data:www-data /var/www/intel

rm /etc/apache2/sites-enabled/000-default*
cat > /etc/apache2/sites-enabled/kibana.conf<<EOF
<VirtualHost *:80>
    ProxyPreserveHost On
    ProxyPass / http://localhost:5601/
    <Location />
        Order allow,deny
        Allow from all
#        AuthName 'Kibana'
#        AuthType Basic
#        AuthUserFile /opt/.htpasswd-private
#        Require valid-user
#        AllowOverride None
   </Location>

</VirtualHost>
EOF

cat > /etc/apache2/sites-enabled/intel.conf<<EOF
<VirtualHost *:443>
                ServerName intel
                ServerAdmin admin@intel
                WSGIScriptAlias / /var/www/intel/intel.wsgi
                <Directory /var/www/intel/intel/>
                        Order allow,deny
                        Allow from all
                </Directory>
                Alias /static /var/www/intel/intel/static
                <Directory /var/www/intel/intel/static/>
                        Order allow,deny
                        Allow from all
                </Directory>
                ErrorLog ${APACHE_LOG_DIR}/error.log
                LogLevel warn
                CustomLog ${APACHE_LOG_DIR}/access.log combined
     SSLEngine on
     SSLOptions +StrictRequire
     SSLCertificateFile /usr/local/certs/sslcerts/server.crt
     SSLCertificateKeyFile /usr/local/certs/sslcerts/server.key
</VirtualHost>
EOF

a2enmod proxy_http && a2enmod ssl

####### END APACHE CONFIG #######

####### CRON CONFIG (for analysis scripts) #######
cat > /opt/cronscripts/conpotanalyzer.sh<<EOF
#!/bin/sh
python /opt/analysis/conpot_reader.py
EOF

cat > /opt/cronscripts/malwareanalyzer.sh<<EOF
#!/bin/sh
python /opt/analysis/virustotal_api.py
EOF

cat > /opt/cronscripts/cowrie_log_analysis.sh<<EOF
#!/bin/sh
python /opt/analysis/cowrie_log_analysis.py
EOF

cat > /opt/cronscripts/gaspot_log_analysis.sh<<EOF
#!/bin/sh
python /opt/analysis/gaspot_reader.py
EOF

chmod 755 /opt/cronscripts/conpotanalyzer.sh
chmod 755 /opt/cronscripts/malwareanalyzer.sh
chmod 755 /opt/cronscripts/cowrie_log_analysis.sh
chmod 755 /opt/cronscripts/gaspot_log_analysis.sh

(crontab -u root -l; echo "*/4 * * * * /opt/cronscripts/conpotanalyzer.sh" ) | crontab -u root -
(crontab -u root -l; echo "*/11 * * * * /opt/cronscripts/malwareanalyzer.sh" ) | crontab -u root -
(crontab -u root -l; echo "*/8 * * * * /opt/cronscripts/cowrie_log_analysis.sh" ) | crontab -u root -
(crontab -u root -l; echo "*/14 * * * * /opt/cronscripts/gaspot_log_analysis.sh" ) | crontab -u root -

####### END CRON CONFIG #######

####### START SERVICES #######
supervisorctl update
service stunnel4 restart
service redis-server restart
service elasticsearch restart
service apache2 restart

###############################################################
# CREATE CLIENT CONFIG (it will be saved to /opt/Honeynet_client_configuration.sh)



# Get the stunnel.pem
echo "cat > /etc/stunnel/stunnel.pem << EOF" > /opt/Honeynet_client_configuration.sh
cat /etc/stunnel/stunnel.pem >> /opt/Honeynet_client_configuration.sh
echo "EOF" >> /opt/Honeynet_client_configuration.sh

echo "chmod 600 /etc/stunnel/stunnel.pem" >> /opt/Honeynet_client_configuration.sh

cat >> /opt/Honeynet_client_configuration.sh<<ENDOFCLIENTSCRIPT

echo "What's the IP address or hostname of the HoneyPot Server?"
read SERVER

add-apt-repository -y ppa:honeynet/nightly
apt-get update
apt-get -y install python-dev openssl python-openssl python-pyasn1 python-twisted git python-pip authbind python-software-properties patch libglib2.0-dev libssl-dev libcurl4-openssl-dev libreadline-dev libsqlite3-dev libtool automake autoconf build-essential subversion git-core flex bison pkg-config libgc-dev libgc1c2 sqlite3 python-geoip sqlite libnl-3-dev libnl-genl-3-dev libnl-nf-3-dev libnl-route-3-dev supervisor stunnel4 openjdk-7-jdk curl authbind python-dev openssl git libsmi2ldbl libsmi2-common python-dev libxml2-dev python-lxml libxslt-dev libmysqlclient-dev dionaea ntp

# Update the date (seems to have been a problem during my testing - my vm's were not udpating their date and time)
echo "This might hang for about 5 seconds:"
service ntp stop && /usr/sbin/ntpdate pool.ntp.org && service ntp start

pip install --upgrade distribute
pip install virtualenv

HPN=$(dirname "$0")
DIR="$HPN/HoneyNet_Installer/"

# make directories:
mkdir -p /opt/transfer /opt/conpot /opt/cronscripts /opt/analysis /opt/sshreplays /var/dionaea/wwwroot /var/dionaea/binaries /var/dionaea/log /var/dionaea/bistreams

# Copy analysis scripts:
cp $HPN/client/analysis/* /opt/analysis/ && chmod 755 /opt/analysis/*

# make some needed files so they can be chowned correctly:
touch /opt/malware_from_honeypots && chown logstash:logstash /opt/malware_from_honeypots

# Make some utilities for troubleshooting logstash when you need to add new things:

cat > /usr/bin/editlogstashconf.sh<<EOF
#!/bin/bash
sudo vim /etc/logstash/conf.d/client.conf
EOF

cat > /usr/bin/restartlogstash.sh<<EOF
#!/bin/bash
sudo service logstash restart
EOF

cat > /usr/bin/statuslogstash.sh<<EOF
#!/bin/bash
sudo service logstash status
EOF

cat > /usr/bin/taillogstashlog.sh<<EOF
#!/bin/bash
tail -f /var/log/logstash/logstash.log
EOF

cat > /usr/bin/testlogstash.sh<<EOF
#!/bin/bash
/usr/local/src/logstash-1.5.4/bin/logstash -f /etc/logstash/conf.d/client.conf --configtest
EOF

chmod 755 /usr/bin/editlogstashconf.sh
chmod 755 /usr/bin/restartlogstash.sh
chmod 755 /usr/bin/statuslogstash.sh
chmod 755 /usr/bin/taillogstashlog.sh
chmod 755 /usr/bin/testlogstash.sh

####### sshd_config mod #######
# Modify sshd so it accepts connections on port 2222 instead of 22. Cowrie (the ssh honeypot will accept on 22). 
#When connecting for administrative purposes, you'll have to go to ssh -p 2223 username@host or you'll get caught by the honeypot
sed -i 's/Port 22/Port 2223/g' /etc/ssh/sshd_config && reload ssh
####### End sshd_config mod #######

####### STUNNEL CONFIG #######
# Create stunnel.conf. Config for the stunnel for reddis data to transfer to server:
cat > /etc/stunnel/stunnel.conf << EOF
cert = /etc/stunnel/stunnel.pem
client = yes
[reddis]
accept = 127.0.0.1:6379
connect = REPLACEME:6378

[logstash-filetransfer]
accept = 6782
connect = REPLACEME:6781

EOF

#Change ENABLED=0 to ENABLED=1 in /etc/default/stunnel4:
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4

sed -i "s/REPLACEME/$SERVER/g" /etc/stunnel/stunnel.conf

####### END STUNNEL CONFIG #######

####### LOGSTASH CONFIG #######

# Folder to output log files to:
sudo chown logstash:logstash /opt/transfer/

# Install logstash:
cd /usr/local/src && wget https://download.elastic.co/logstash/logstash/packages/debian/logstash_1.5.3-1_all.deb && dpkg -i logstash_1.5.3-1_all.deb

# Set up logstash client config file for sending data from ssh honeypot to elasticsearch on the server

cat > /etc/logstash/conf.d/client.conf << EOF
input {
    file {
        type => "SSH"
        path => "/opt/cowrie/log/cowrie.log"
        start_position => "beginning"
        }

    file {
        type => "Conpot"
        path => "/opt/conpot/conpot.log"
        start_position => "beginning"
        }

    file {
        type => "conpot_intel"
        path => "/opt/conpot/conpot.log"
        start_position => "beginning"
        }

    file {
        type => "ssh_intel"
        path => "/opt/cowrie/log/cowrie.json"
        codec => json
# sincedb_path => "/dev/null"
        start_position => "beginning"
        }

    file {
        type => "ssh_intel2"
        path => "/opt/cowrie/log/cowrie.log"
        start_position => "beginning"
        }
    
    file {
        type => "GasPot"
        path => "/opt/GasPot/all_attempts.log"
#        sincedb_path => "/dev/null"
        start_position => "beginning"
        }

    file {
        type => "malware_from_honeypots"
        path => "/opt/malware_from_honeypots.txt"
        start_position => "beginning"
        }

    file {
        type => "ssh_replaylogs"
        path => "/opt/ssh_replaylogs.txt"
        start_position => "beginning"
        }

    
}
output {
    if [type] == "SSH" or [type] == "GasPot" or [type] == "Conpot" {
        redis {
            host => "127.0.0.1"
            port => "6379"
            data_type => "list"
            key => "honeynet"
        }
    }

    if [type] == "ssh_intel" or [type] == "GasPot" or [type] == "ssh_intel2" or [type] == "conpot_intel" or [type] == "malware_from_honeypots" or [type] == "ssh_replaylogs" {
        tcp {
                host => "127.0.0.1"
                port => "6782"
    codec => json_lines
        }
    
}
}
EOF


# Supervisor for logstash:
cat > /etc/supervisor/conf.d/logstash.conf <<EOF
[program:logstash]
command=/opt/startlogstash.sh
directory=/opt/
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

cat > /opt/startlogstash.sh <<EOF
#! /bin/bash
service logstash start
EOF

chmod 755 /opt/startlogstash.sh

####### END LOGSTASH CONFIG #######


####### COWRIE INSTALLATION #######
#based off Kippo ssh honeypot

# Create cowrie user
useradd cowrie -U 

# Get the Cowrie source
cd /opt && git clone https://github.com/micheloosterhof/cowrie.git

# Configure Cowrie
cd /opt/cowrie && mv cowrie.cfg.dist cowrie.cfg && sed -i 's/hostname = svr03/hostname = payroll/g' cfgowrie.cfg && sed -i 's/ssh_version_string = SSH-2.0-OpenSSH_5.1p1 Debian-5/ssh_version_string = OpenSSH_5.9p1 Debian-5ubuntu1.4, OpenSSL 1.0.1 14 Mar 2012/g' cowrie.cfg

touch /opt/cowrie/log/cowrie.json
touch /opt/malware_from_honeypots.txt
chown nobody:nogroup /opt/cowrie/log/cowrie.json
chown nobody:nogroup /opt/cowrie/log/cowrie.log

chmod 777 /opt/cowrie/log/cowrie.json
chmod 777 /opt/cowrie/log/cowrie.log
chmod 777 /opt/malware_from_honeypots.txt

# Fix permissions for cowrie and set up authbind port
chown -R cowrie /opt/cowrie

# Setup cowrie to start at boot
cat > /opt/cowrie/start.sh <<EOF
#!/bin/sh
su cowrie -c "twistd -l log/cowrie.log --pidfile cowrie.pid cowrie"
EOF

chmod +x /opt/cowrie/start.sh

# Set up supervisor conf file:

cat > /etc/supervisor/conf.d/cowrie.conf <<EOF
[program:cowrie]
command=/opt/cowrie/start.sh
directory=/opt/cowrie
stdout_logfile=/opt/cowrie/log/cowrie.out
stderr_logfile=/opt/cowrie/log/cowrie.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

####### END COWRIE INSTALLATION #######

####### GasPot Honeypot #######

cd /opt/ && git clone https://github.com/sjhilt/GasPot.git && cd GasPot && mv config.ini.dist config.ini
touch /opt/GasPot/all_attempts.log && chmod 777 /opt/GasPot/all_attempts.log

# Config for supervisor.
cat > /etc/supervisor/conf.d/gaspot.conf <<EOF
[program:gaspot]
command=/usr/bin/python /opt/GasPot/GasPot.py
directory=/opt/GasPot
stdout_logfile=/opt/GasPot/gaspot.log
stderr_logfile=/opt/GasPot/gaspot.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

####### END GasPot Honeypot #######

####### CONPOT Honeypot #######
pip install six gevent pysnmp
pip install python-dateutil --upgrade
cd /opt/conpot
virtualenv env
. env/bin/activate
pip install -U setuptools
pip install -e git+https://github.com/glastopf/conpot.git#egg=conpot-dev
pip install -e git+https://github.com/glastopf/modbus-tk.git#egg=modbus-tk==0.4

cat > /etc/supervisor/conf.d/conpot.conf <<EOF
[program:conpot]
command=/opt/conpot/env/bin/python /opt/conpot/env/bin/conpot --template default -l /opt/conpot/conpot.log
directory=/opt/conpot
stdout_logfile=/var/log/conpot.out
stderr_logfile=/var/log/conpot.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

####### END CONPOT Honeypot #######

####### DIONAEA Honeypot #######
add-apt-repository -y ppa:honeynet/nightly && apt-get update
apt-get install -y dionaea
cp /etc/dionaea/dionaea.conf.dist /etc/dionaea/dionaea.conf
chown -R nobody:nogroup /var/dionaea 
chown nobody:nogroup /var/dionaea/bistreams

sed -i 's/var\/dionaea\///g' /etc/dionaea/dionaea.conf
sed -i 's/log\//\/var\/dionaea\/log\//g' /etc/dionaea/dionaea.conf
sed -i 's/levels = "all"/levels = "warning,error"/1' /etc/dionaea/dionaea.conf
sed -i 's/mode = "getifaddrs"/mode = "manual"/1' /etc/dionaea/dionaea.conf
sed --in-place='.bak' 's/addrs = { eth0 = \["::"\] }/addrs = { eth0 = ["::", "0.0.0.0"] }/' /etc/dionaea/dionaea.conf

# Config for supervisor.
cat > /etc/supervisor/conf.d/dionaea.conf <<EOF
[program:dionaea]
command=dionaea -c /etc/dionaea/dionaea.conf -w /var/dionaea -u nobody -g nogroup
directory=/var/dionaea
stdout_logfile=/var/log/dionaea.out
stderr_logfile=/var/log/dionaea.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

####### END DIONAEA Honeypot #######

####### CRON CONFIG (for client analysis scripts) #######
cat > /opt/cronscripts/getmalwareinfo.sh<<EOF
#!/bin/sh
python /opt/analysis/get_malware_info.py
EOF

cat > /opt/cronscripts/readtty.sh<<EOF
#!/bin/sh
python /opt/analysis/readtty.py
EOF


chmod 755 /opt/cronscripts/getmalwareinfo.sh
chmod 755 /opt/cronscripts/readtty.sh

(crontab -u root -l; echo "*/5 * * * * /opt/cronscripts/getmalwareinfo.sh" ) | crontab -u root -
(crontab -u root -l; echo "*/7 * * * * /opt/cronscripts/readtty.sh" ) | crontab -u root -

####### END CRON CONFIG #######

# Set IPTABLES to forward all port 22 traffic to 2222
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
apt-get install iptables-persistent -y

# Start up services:
/etc/init.d/stunnel4 start
supervisorctl update

clear
echo "You need to do one manual configuration:
sudo vim (or whatever editor) /etc/stunnel/stunnel.conf

Change the REPLACEME parts to the IP or domain name of the honeypot server.

cert = /etc/stunnel/stunnel.pem
client = yes
[reddis]
accept = 127.0.0.1:6379
connect = REPLACEME:6378

[logstash-filetransfer]
accept = 6782
connect = REPLACEME:6781

Then type: sudo service stunnel4 restart
"



ENDOFCLIENTSCRIPT

cd /opt/ && tar -czf HoneyNet_Client_Installer.tar.gz client/ Honeynet_client_configuration.sh
rm -rf client && rm Honeynet_client_configuration.sh

clear

echo "The server installation is complete. Copy the HoneyNet_Client_Installer.tar.gz from this directory (/opt/HoneyNet_Client_Installer.tar.gz) to any and all clients you want to set up as honeypots. 

Important: 
Add your API keys to:
OpenDNS Investigate: /opt/analysis/investigate_api_key.txt
Virus Total: /opt/analysis/virustotal_api_key.txt

Some basic information:

1: Intel can be found at https://yourserverip/ (attackers have to attack your honeypots first and then data will being to populate in there)

2: A kibana interface is set up at http://yourserverip/. You can make a dashboard there to show all the stuff.

Questions: Visit the github page or email jpyorre @ gmail . com
"