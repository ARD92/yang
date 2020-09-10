#!/usr/bin/env python
__author__ = "Aravind Prabhakar"

'''
# Contact: Aravind Prabhakar <aprabh@juniper.net>
set system commit xpath
set system commit constraints direct-access
set system commit notification configuration-diff-format xml
set system scripts language python

'''
import grpc
import os
import sys
import atexit
import signal
import socket
import json
import logging
import paho.mqtt.client as mqtt

# import prpd IDLs
sys.path.append("/home/proto")
import authentication_service_pb2
import authentication_service_pb2_grpc
import prpd_common_pb2
import prpd_common_pb2_grpc 
import jnx_addr_pb2
import jnx_addr_pb2_grpc
import bfd_service_pb2
import bfd_service_pb2_grpc

from authentication_service_pb2 import *
from authentication_service_pb2_grpc import *
from prpd_common_pb2 import *
from prpd_common_pb2_grpc import *
from jnx_addr_pb2 import *
from jnx_addr_pb2_grpc import *
from bfd_service_pb2 import *
from bfd_service_pb2_grpc import *

from bs4 import BeautifulSoup as bs

#JSD Params for PRPD
DEFAULT_JSD_HOST = '10.102.144.96'
DEFAULT_JSD_PORT = 32767
DEFAULT_CLIENT_ID = '03424'
JET_TIMEOUT = 10000
USER = 'root'
PASSWORD = 'juniper123'

#MQTT related Params
MQTT_PORT = 1883
MQTT_IP = socket.gethostbyname(socket.gethostname())
MQTT_HOST = ''
MQTT_TIMEOUT = 10

BFD_SESSION_STORE = dict()

logging.basicConfig(filename='bfd_echolite.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)

#gRPC session
def stubAuth(DEFAULT_JSD_HOST, DEFAULT_JSD_PORT, USER, PASSWORD, DEFAULT_CLIENT_ID, JET_TIMEOUT):
    channel = grpc.insecure_channel('%s:%d' %(DEFAULT_JSD_HOST,DEFAULT_JSD_PORT))
    stub = authentication_service_pb2_grpc.LoginStub(channel)
    login_response = stub.LoginCheck(authentication_service_pb2.LoginRequest(
                                                                user_name=USER, 
                                                                password=PASSWORD,
                                                                client_id=DEFAULT_CLIENT_ID
                                                                ),
                                     JET_TIMEOUT
                                    )
    print(login_response.result)
    bfd = bfd_service_pb2_grpc.BFDStub(channel)
    try:
        result = bfd.Initialize(InitializeRequest())
        print(result.status)
        logging.info(result.status)
    except:
        print("Initialization Failed: ")
        logging.error("BFD JET Initialization failed")
    return bfd, channel


# BFD related function definitions
def sessionReq(**kwargs):
    if 'laddr' in kwargs:
        laddr = kwargs["laddr"]
    if 'raddr' in kwargs:
        raddr = kwargs["raddr"]
    if 'intf' in kwargs:
        intf = kwargs["intf"]
    if 'ri' in kwargs:
        ri = kwargs["ri"]
    if 'timer' in kwargs:
        timer = kwargs["timer"]
 
    laddr = NetworkAddress( 
                inet=IpAddress(addr_string=laddr)
                )
    raddr = NetworkAddress(
                inet=IpAddress(addr_string=raddr)
                )

    if 'ri' not in kwargs.keys():
        ri = 'default'
    # local discriminator and session_id should be 0 for Add request 
    session_key = SessionKey(session_id=0,
                    local_address=laddr,
                    remote_address=raddr,
                    interface_name=intf,
                    instance_name=ri ,
                    local_discriminator=0 
                    )       
    # add authentication=Authentication()  if you need BFD auth 
    session_param = SessionParameters(
                        minimum_echo_rx_interval=int(timer),
                        minimum_echo_tx_interval=int(timer)
                    )
    # Type ECHO_LITE = 1 and mode SINGLE_HOP=1 
    session_req = SessionRequest(
                    key=session_key,
                    params=session_param,
                    type=2,
                    mode=1,
                    )
    logging.info("session params are: {}".format(session_req))
    return session_req


def sessionAdd(bfd, sessionreq):
    sadd = bfd.SessionAdd(sessionreq)
    print("Session Added", sadd.status, sadd.session_id)
    logging.info("session added status {}".format(sadd.status))
    logging.info("Session Addded ID: {}".format(sadd.session_id)),
    return(sadd.status, sadd.session_id)


def sessionDel(bfd,sid):
    sdel = SessionRequest(key=SessionKey(session_id=sid))
    response = bfd.SessionDelete(sdel)
    print("session deleted", response.status)
    logging.info("Session Deleted: {}".format(sdel))


def ProcessSubStream(substream):
    for ev in substream:
        print(" ******* Notification *******  ")
        print(type(ev))
        print(ev)
        #print(ev.session_id, ev.session_state)
        print (" ************************** ")
    print("end of stream")


def subscribeNotif(bfd):
    subscribe = SubscribeRequest()
    eventStream = bfd.Subscribe(subscribe, timeout=10000)
    subThr =  threading.Thread(target=ProcessSubStream, args=(eventStream, ))
    subThr.start()
    print("BFD subscribed")


def on_connect(client, userdata, flags, rc):
    print("connected with result code ", rc)
    client.subscribe("/junos/events/genpub/+", 1)


def on_message(client, userdata, msg):
    commit_data=json.loads(msg.payload)
    process_payload(commit_data)


# find where operation occures, if top level or under sessions
def find(xml):
   mapp = {}
   xml = bs(xml, 'lxml')
   if xml.echolite["nc:operation"]:
       mapp["root"] = xml.echolite["nc:operation"]
       logging.info("Operation {} occured at top level".format( xml.echolite["nc:operation"]))
       return mapp
   else:
       total = []
       sessions = xml.echolite.findAll('session')
       for session in sessions:
           if session["nc:operation"]:
               logging.info("Operation {} occured at sessions level ".format( xml.echolite["nc:operation"]))
               mapp["session:{}".session.findChild('name').text] = session["nc:operation"]
               total.append(mapp) 
       print(mapp)
       logging.info(mapp) 
       return(total)


def process_payload(commit_data):
    if "commit-patch" in commit_data:
        data = commit_data["commit-patch"]
        out = find(data)
        xml = bs(data, 'lxml')
        bfd, channel = stubAuth(DEFAULT_JSD_HOST, DEFAULT_JSD_PORT, USER, PASSWORD, DEFAULT_CLIENT_ID, JET_TIMEOUT)
        if isinstance(out, dict) and out["root"] == 'create':
            print("adding all sessions created")
            for session in xml.echolite.findAll('session'):
                children = session.findChildren()
                param = {}
                for child in children:
                    if child.name == 'local-address':
                        param['laddr'] = child.text
                    elif child.name == 'remote-address':
                        param['raddr'] = child.text
                    elif child.name == 'local-interface':
                        param['intf'] = child.text
                    elif child.name == 'timer':
                        param['timer'] = child.text
                    elif child.name == 'instance':
                        param['ri'] = child.text
                    elif child.name == 'name':
                        param['session_name'] = child.text
                session_req = sessionReq(**param)
                try:
                    status, sid = sessionAdd(bfd, session_req)
                    if status == 0:
                        BFD_SESSION_STORE[session_name]=sid
                except:
                    print("Received Exception")
            channel.close()
            #write to file so that we can use to delete session accordingly 

        elif isinstance(out, dict) and out["root"] == 'delete':
            print(" Root delete")
            try:
                for sid in BFD_SESSION_STORE.values():
                    sessionDel(bfd,sid)
                channel.close()
            except:
                print("Exception block: ", e)

        else:#isinstance(out, list):
            #add/del only sessions which has been created/del
            for ses in out:
                name = ses.keys()[0][8:]
                oper = ses.values()[0]
                if oper == 'delete':
                    sid = BFD_SESSION_STORE["name"]
                    sessionDel(bfd,sid)
                    BFD_SESSION_STORE.pop(sid)
                elif oper == 'create':
                    siblings = xml.echolite.find('name', text=name)
                    siblings = siblings.findNextSiblings()
                    param = {}
                    for child in siblings:
                        if child.name == 'local-address':
                            param['laddr'] = child.text
                        if child == 'remote-address':
                            param['raddr'] = child.text
                        if child.name == 'local-interface':
                            param['intf'] = child.text
                        if child.name == 'timer':
                            param['timer'] = child.text
                        if child.name == 'instance':
                            param['ri'] = child.text
                  
                    session_req = sessionReq(**param)
                    status, sid = sessionAdd(bfd, session_req)
                    if status == 0:
                        BFD_SESSION_STORE[name]=sid
                    else:
                        logging.info(status, sid)
                        print(status, sid)
            channel.close()  
        print(BFD_SESSION_STORE)

def run(): 
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_IP, MQTT_PORT, MQTT_TIMEOUT)
    print("connected to ", MQTT_IP)
    client.loop_forever()

if __name__ == '__main__':
    run() 
