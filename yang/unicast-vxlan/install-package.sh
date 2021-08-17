#----------------------#
# setup unicast-vxlan  #
#----------------------#

# Load base mgd configs
cli -c 'configure;set system root-authentication encrypted-password "$6$asEwH$A3JDiygMWPzpG7KS0o7MAQgmIg/JEvDED0.tI4fPENi./dOUeMpwrDwTpnlpsfl0ozfAFkE1jOK/7J2eWWlbp.";set system commit xpath;set system commit constraints direct-access;set system commit notification configuration-diff-format xml;set system scripts language python3;commit'

# Install required packages 
apt-get update
apt-get install -y 
apt-get -y install mosquitto
apt-get -y install mosquitto-clients

# Install pip modules
pip3 install paho-mqtt
pip3 install pyroute2

# Daemonize and Start services 
#mkdir -p /etc/runit/mqtt/
#cp run-mqtt /etc/runit/mqtt/run
#chmod +x /etc/runit/mqtt
#ln -s /etc/runit/mqtt/ /etc/service/mqtt

/usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf &
/usr/libexec/ui-pubd -N &

cp unicast-vxlan.py /var/db/scripts/jet
chmod +x /var/db/scripts/jet/unicast-vxlan.py
mkdir -p /etc/runit/unicast-vxlan/
cp run-unicast-vxlan /etc/runit/unicast-vxlan/run
chmod +x /etc/runit/unicast-vxlan/run
ln -s /etc/runit/unicast-vxlan/ /etc/service/unicast-vxlan

# load yang package
/usr/libexec/ui/yang-pkg add -i vxlan -m unicast-vxlan.yang -norestart
cli -c "restart management"
