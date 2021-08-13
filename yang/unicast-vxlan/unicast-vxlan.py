#!/usr/bin/env python3
__author__ = "Aravind Prabhakar"

#  YOU MUST ACCEPT THE TERMS OF THIS DISCLAIMER TO USE THIS SOFTWARE.
#
#  JUNIPER IS WILLING TO MAKE THE INCLUDED SCRIPTING SOFTWARE AVAILABLE TO YOU
#  ONLY UPON THE CONDITION THAT YOU ACCEPT ALL OF THE TERMS CONTAINED IN THIS
#  DISCLAIMER. PLEASE READ THE TERMS AND CONDITIONS OF THIS DISCLAIMER CAREFULLY.
#
#  THE SOFTWARE CONTAINED IN THIS FILE IS PROVIDED "AS IS".  JUNIPER MAKES NO
#  WARRANTIES OF ANY KIND WHATSOEVER WITH RESPECT TO SOFTWARE. ALL EXPRESS OR
#  IMPLIED CONDITIONS, REPRESENTATIVES AND WARRANTIES, INCLUDING ANY WARRANTY
#  OF NON-INFRINGEMENT OR WARRANTY OF MERCHANTABILITY OR FITNESS FOR A
#  PARTICULAR PURPOSE, ARE HEREBY DISCLAIMED AND EXCLUDED TO THE EXTENT
#  ALLOWED BY APPLICABLE LAW.
#
#  IN NO EVENT WILL JUNIPER BE LIABLE FOR ANY LOST REVENUE, PROFIT OR DATA, OR
#  FOR DIRECT, SPECIAL, INDIRECT, CONSEQUENTIAL, INCIDENTAL OR PUNITIVE DAMAGES
#  HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY ARISING OUT OF THE
#  USE OF OR INABILITY TO USE THE SOFTWARE, EVEN IF JUNIPER HAS BEEN ADVISED OF
#  THE POSSIBILITY OF SUCH DAMAGES.
#

#  Author       : aprabh@juniper.net                                      
#  Version      : 1.0                                                    
#  Date         : 2021-08-10                                               
#  Description  : Config script for handling unicast vxlan yang model
#                 This would be a stopgap solution until the feature 
#                 comes in natively within cRPD. Log will be saved under 
#                 /var/log/unicast-vxlan.log


import os
import sys
import atexit
import signal
import socket
import json
import logging
import jxmlease
import paho.mqtt.client as mqtt
from logging import handlers

# MQTT related params
MQTT_PORT = 1883
MQTT_IP = socket.gethostbyname(socket.gethostname())
MQTT_HOST = ""
MQTT_TIMEOUT = 10
INTF = {}

Logrotate = logging.handlers.RotatingFileHandler(
    filename='/var/log/unicast-vxlan.log',
    mode='a',
    maxBytes=10240,
    backupCount=10,
    encoding=None,
    delay=0
)

logging.basicConfig(format='%s(name)s - %(levelname)s - %(message)s', level=logging.DEBUG, handlers=[Logrotate])

def find(xml):
    mapp = {}
    logging.debug(xml)
    logging.debug(50*"-")
    root = jxmlease.parse(xml)
    logging.debug(root)

    # deleting from top level hierarchy
    try:
        if root["vxlan"] == "":
            delVxlan("all")

        # single element handling
        elif isinstance(root['vxlan']['interface'],dict) and root['vxlan'] != "":
            if len(root['vxlan']['interface']) > 1:
                vxlanname = root['vxlan']['interface']['name']
                vni = root['vxlan']['interface']['vni']
                remoteip = root['vxlan']['interface']['remote-ip']
                ipprefix = root['vxlan']['interface']['ip-prefix']
                underlayintf = root['vxlan']['interface']['interface']
                dstport = root['vxlan']['interface']['destination-port']
                addVxlan(vxlanname, vni, ipprefix, remoteip, underlayintf, dstport)
            else:
                delVxlan(root['vxlan']['interface']['name'])

        # multiple element handling
        elif isinstance(root['vxlan']['interface'],list):
            for i in root['vxlan']['interface']:
                if len(i) > 1:
                    vxlanname = i['name']
                    vni = i['vni']
                    remoteip = i['remote-ip']
                    ipprefix = i['ip-prefix']
                    underlayintf = i['interface']
                    dstport = i['destination-port']
                    addVxlan(vxlanname, vni, ipprefix, remoteip, underlayintf, dstport)
                else:
                    delVxlan(i['name'])

    except KeyError:
        logging.info("blank commit occured, passing")
"""
Handling vxlan interface addition
"""
def addVxlan(ifname, vni, prefix, remoteip, underlayintf, dstport):
    """
    WIP: use pyroute2 native netlink libs
    ip.link("add",
            ifname="vx101",
            kind="vxlan",
            vxlan_link=ip.link_lookup(ifname="eth0")[0],
            vxlan_id=101,
            vxlan_group='239.1.1.1',
            vxlan_ttl=16)
    ip.link("set", index=x, state="up")
    """
    logging.info("Adding vxlan interface {}".format(ifname))
    os.popen('ip link add {} type vxlan id {} dev {} dstport {}'.format(ifname,vni, underlayintf, dstport))
    os.popen('ip link set up {}'.format(ifname))
    os.popen('ip addr add {} dev {}'.format(prefix, ifname))
    os.popen('bridge fdb append to 00:00:00:00:00:00 dst {} dev {}'.format(remoteip, ifname))

    # persist information in case script restarts to bring data back into memory
    INTF[ifname] = vni
    with open('/var/db/INTF-STORE.json','w') as f2:
        f2.write(json.dumps(INTF, indent=4))

"""
Handling Vxlan interface deletion
"""
def delVxlan(ifname):
    try:
        if ifname == "all":
            logging.info("deleting all vxlan interfaces")
            if len(INTF) != 0:
                for k,v in list(INTF.items()):
                    logging.info("Deleting vxlan interface {}".format(k))
                    os.popen('ip link set down {}'.format(k))
                    os.popen('ip link del {}'.format(k))
                    INTF.pop(k)
        else:
            logging.info("Deleting vxlan interface {}".format(ifname))
            os.popen('ip link set down {}'.format(ifname))
            os.popen('ip link del {}'.format(ifname))
            INTF.pop(ifname)

        with open('/var/db/INTF-STORE.json','w') as f4:
            f4.write(json.dumps(INTF, indent=4))

    except Error as e:
        logging.info(e)



def on_connect(client, userdata, flags, rc):
    print("connected with result code ", rc)
    client.subscribe("/junos/events/genpub/+", 1)


def on_message(client, userdata, msg):
    commit_data=json.loads(msg.payload)
    #print(commit_data)
    process_payload(commit_data)


def process_payload(commit_data):
    if "commit-patch" in commit_data:
        data = commit_data["commit-patch"]
        logging.debug(data)
        find(data)

def run():
    global INTF
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_IP, MQTT_PORT, MQTT_TIMEOUT)
    print("connected to ",MQTT_IP)
    try:
        if not INTF:
            with open('/var/db/INTF-STORE.json') as f0:
                fdata = json.load(f0)
            if fdata:
                INTF = fdata
    except:
        f2 = open('/var/db/INTF-STORE.json','a+')
        f2.close()
        pass

    client.loop_forever()


if __name__ == '__main__':
    run()
