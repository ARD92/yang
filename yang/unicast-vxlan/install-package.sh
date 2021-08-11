# Install required packages 
apt-get update
apt-get install -y 
apt-get -y install mosquitto
apt-get -y install mosquitto-clients

# Install pip modules
pip3 install paho-mqtt
pip3 install pyroute2

# load yang
/usr/libexec/ui/yang-pkg add -i vxlan -m unicast-vxlan.yang -norestart

# Start services 
/usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf &
/usr/libexec/ui-pubd -N &
cp unicast-vxlan.py /var/db/scripts/jet
python3 /var/db/scripts/jet/unicast-vxlan.py &
