#!/usr/bin/env python
__author__ = "aprabh@juniper.net"
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
#
#  Author        : Aravind Prabhakar
#  E-mail        : aprabh@juniper.net

# Version: 1.1
# Firewall.yang version: 1.1

# This script takes the custom firewall yang model and generates IPtable rules accordingly upon commit of the config.
# For this script to work, the below has to be enabled on cMGD/cRPD
# 
# set system commit xpath
# set system commit constraints direct-access
# set system commit notification configuration-diff-format xml
# set system scripts language python
# 
# This has been tested only for iptables v1.6
# root@9174dce90317:/home# iptables --version
# iptables v1.6.0
 
# To do:
#     1. no custom chains supported at the moment. 
#     2. use python-iptables module instead of calling subprocess/popen (investigate)
#     3. Currently the order of rules is based on the order of keys. There is no concept of modifying the order by inserting one policy before other. we can use replace flag to handle this scenario.
#        example: iptables -R/-I INPUT 2 -s 5.5.5.5 -j DROP(insert the values from bottom)
#     4. instead of calling iptables everytime, use the iptable batch process
#     5. Add iptable logging to different file (emulate traceoptions)
#     6. add firstfrag, lastfraf, fragmore to fragments (-m frag --fragfirst/fraglast/fragmore)
#     7. SIMPLIFY CODE!!! the data structures are a MESS.(flatten it first then handle firewall_Create and delete). Passing except blocks is BAD! 
#     8. Instead of converting to dictionary handle xml directly using lxml. handling orderedDict in python3 is slightly different. 
#
# V1.0
#     1. 5 tuple from and then such as DROP, REJECT
#     2. different chain support
# 
# V1.1
#     1. Added DSCP, TOS, Classify, Packet markings, NAT, table selection
#     2. Created different functions for firewall create, delete
#     3. port range and multiple port support
#     4. config sync using file handlers
#
# V2
#     1. complete model change to accomodate reordering of rules and custom chains
#
# Known limitations:
#     1. --tcp-flags currently matches against all. If requirement is there, add specific flag selection as well to match against.
#     2. configuraiton "deactivate" isn't supported.@inactivate case is not handled in this script. only config deletion works
#        ex: iptables -A OUTPUT -p TCP -j DROP --tcp-flags ALL SYN,RST -m mac --mac-source OrderedDict([(u'@inactive', u'inactive'), ('#text', u'00:01:02:03:04:05')])
#     3. Except conditions not supported yet. (i.e. ex: !-f matches all except fragments )    
#
# Logging Errors:
#     1. All iptable Errors can be noticed in dmesg
#     2. /var/log/ukern.log can also be used to notice LOG targets. Dmesg would also read from the same.


import sys, os, time, atexit, signal
import socket
import json
import xmltodict
import paho.mqtt.client as mqtt
from daemon import daemon
from collections import OrderedDict

MQTT_PORT = 1883
MQTT_IP = socket.gethostbyname(socket.gethostname())
MQTT_HOST = ''
MQTT_TIMEOUT = 600
PID=OrderedDict()


def on_connect(client, userdata, flags, rc):
    client.subscribe("/junos/events/genpub/+", 1)

def on_message(client, userdata, msg):
    commit_data=json.loads(msg.payload)
    process_payload(commit_data)

"""
Flatten is used to flatten out dictionaries
for easy accessibility of each key, value
current not being used
"""

def flatten_order(mydict):
    new_dict = {}
    for key,value in mydict.items():
            if isinstance(value,OrderedDict):
                _dict = {':'.join([key, _key]):_value for _key, _value in flatten_order(value).items()}
                new_dict.update(_dict)
            else:
                new_dict[key]=value
    return new_dict

"""
The below function finds the operation hierarchy.
1. Returns 'create' or 'delete' if in present in global level.
2. return a list of dictionaries with [{ policy name: (operation,index,term_index) }] 
   if occurence is in per policy level.
3. The count value is used to find respective index of the policy in order to grab the 
   correct then and from condition.
4. if a single policy is added or deleted, then the function returns { policy name: (operation,index) } 
   instead of a list.
"""
def find(diction):
   oper={}
   count=0
   count_term=0
   for k,v in diction.items():
       if '@nc:operation' in k:
           print("operation present globally")
           return(diction[k])

       elif k == 'policy' and isinstance(diction["policy"], dict):
           #returns with index 1 because only one item has to be processed.
           #This would be decremented by 1 during calls as list index starts from 0
           print("policy is a dict")
           if '@nc:operation' in diction["policy"]:
               #print("operation present in policy")
               oper["policy"] = diction["policy"]["name"]
               oper["oper"] = diction["policy"]["@nc:operation"]
               oper["index"] = 1
               return(oper)
           
           # Occurs within nat/filter/mangle/raw table
           if '@nc:operation' in diction["policy"][diction["policy"].keys()[1]]:
               #print("operation in table")
               oper["policy"] = diction["policy"]["name"]
               oper["oper"] = diction["policy"][diction["policy"].keys()[1]]["@nc:operation"]
               oper["index"] = 1
               oper["table"] = diction["policy"].keys()[1]
               return(oper)
           
           # Occurs within INPUT/OUTPUT/FORWARD/PREROUTING/POSTROUTING chain
           if '@nc:operation' in diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]:
               #print("operation in chain")
               oper["policy"] = diction["policy"]["name"]
               oper["oper"] = diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["@nc:operation"]
               oper["index"] = 1
               oper["table"] = diction["policy"].keys()[1]
               oper["chain"] = diction["policy"][diction["policy"].keys()[1]].keys()[0]
               return(oper)
           
           # Occurs within terms. If term is a list i.e. multiple terms exists in a chain within a table 
           if isinstance(diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"],list):
               #print("entering multiple terms and single policy")
               oper_list = []
               for i in diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"]:
                   if(('@nc:operation' in i) and (i["@nc:operation"] == "create")):
                       key = i["@yang:key"][8:]
                       key = key[:-3:]
                       oper["policy"] = diction["policy"]["name"]
                       oper["oper"] = i["@nc:operation"]
                       oper["index_term"] = count_term
                       oper["term"] = i["name"]
                       oper[i["@yang:insert"]] = key
                       count_term=count_term+1
                       oper_list.append(oper)
                       oper = {}
                   elif(('@nc:operation' in i) and (i["@nc:operation"] == "delete")):
                       # @yang:insert and @yang:key isnt present. would be present only in create
                       oper["policy"] = diction["policy"]["name"]
                       oper["oper"] = i["@nc:operation"]
                       oper["index_term"] = count_term
                       oper["term"] = i["name"]
                       count_term = count_term+1
                       oper_list.append(oper)
                       oper = {}
               return(oper_list)
            
           # If a single term exists within a chain within a table
           else:
               if (('@nc:operation' in diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"]) and (diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"]["@nc:operation"] == 'create')):
                   #print(" Entering single term single policy")
                   key = diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"]["@yang:key"][8:]
                   key = key[:-3:]
                   oper["policy"] = diction["policy"]["name"]
                   oper["oper"] = diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"]["@nc:operation"]
                   oper["index"] = 1
                   oper["term"] = diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"]["name"]
                   oper[diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"]["@yang:insert"]] = key
                   return(oper)

               elif(('@nc:operation' in diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"]) and (diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"]["@nc:operation"] == 'delete')):
                       oper["policy"] = diction["policy"]["name"]
                       oper["oper"] = diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"]["@nc:operation"]
                       oper["index"] = 1
                       oper["term"] = diction["policy"][diction["policy"].keys()[1]][diction["policy"][diction["policy"].keys()[1]].keys()[0]]["term"]["name"]
                       return(oper)
           
           # If multiple operations exists within a policy (table delete and new table create) add below
           # output of keys would be [name, filter(old), raw(new)]

       # If Policy is a list
       elif k=='policy'  and isinstance(diction["policy"],list):
	   #import pdb; pdb.set_trace()
           #print("entering policy in list")
           oper_list = []
           for i in diction["policy"]:
               if '@nc:operation' in i:
                   #print("Entering case1: global level ")
                   oper["policy"] = i["name"]
                   oper["oper"] = i["@nc:operation"]
                   oper["index"] = count
               # Occurs in table (Filter/Nat/Mangle/Raw) level
	       try:
                   if '@nc:operation' in i[i.keys()[1]]:
                       #print("Entering case2: table level")
                       oper["policy"] = i["name"]
                       oper["oper"] = i[i.keys()[1]]["@nc:operation"]
                       oper["index"] = count
                       oper_list.append(oper)
	       except:
	           pass
               # Occurs in chain level (INPUT/OUTPUT/PREROUTING/POSTROUTING/FORWARD)
	       try:
                   if '@nc:operation' in i[i.keys()[2]][i[i.keys()[2]].keys()[0]]:
                       #print("Entering case3: chain level")
                       oper["policy"] = i["name"]
                       oper["oper"] = i[i.keys()[2]][i[i.keys()[2]].keys()[0]]["@nc:operation"]
                       oper["index"] = count
                       oper_list.append(oper)
               except:
                   pass
               # Occurs in term level. Term can be a list or a single value               
	       try: 
                   if isinstance(i[i.keys()[2]][i[i.keys()[2]].keys()[0]]["term"],list):
                       #print("entering case4: term level- list")
                       for j in i[i.keys()[2]][i[i.keys()[2]].keys()[0]]["term"]:
                           if '@nc:operation' in j:
                               oper["policy"] = i["name"]
                               oper["oper"] = j["@nc:operation"]
                               oper["index"] = count
                               oper["index_term"] = count_term
                               oper["term"] = j["name"]
                               count_term=count_term+1
               except:
	           pass
               # if a single term exists within a list of policies
	       try:
                   if '@nc:operation' in i[i.keys()[2]][i[i.keys()[2]].keys()[0]]["term"]:
                       oper["policy"] = i["name"]
                       oper["oper"] = i[i.keys()[2]][i[i.keys()[2]].keys()[0]]["term"]["nc:operation"]
                       oper["index"] = count
                       oper["term"] = i[i.keys()[2]][i[i.keys()[2]].keys()[0]]["term"]["name"]
               except:
	           pass
               # if inserting term in one policy and creating new policy altogether then table appears on index 1 i.e. i[i.keys()[1]]
               # This condition hasnt been added
	       try:
	           if '@nc:operation' in i[i.keys()[1]][i[i.keys()[1]].keys()[0]]["term"]:
		       oper["policy"] = i["name"]
		       oper["oper"] = i[i.keys()[1]][i[i.keys()[1]].keys()[0]]["term"]["@nc:operation"]
                       oper["index"] = count
                       oper["term"] = i[i.keys()[1]][i[i.keys()[1]].keys()[0]]["term"]["name"]
	       except:
	           pass	
               oper_list.append(oper)
               oper={}
               count=count+1
           return(oper_list)
        
"""
Process the respective payload by converting xml to dict format.
choose the correct operation by validating what the find function returns:.
pmap is a dictionary of policyname:[from{index 0}, then{index 1}]  
"""
def process_payload(commit_data):
    pmap=OrderedDict()
    if "commit-patch" in commit_data:
        data_json = xmltodict.parse(commit_data["commit-patch"])
        print(data_json)
        if "firewall" in data_json:
            oper = find(data_json["firewall"])
            print(oper, type(oper))
            if oper == 'create':
                #import pdb; pdb.set_trace()
                # case 1: policy is a list with single/multi term
                if isinstance(data_json["firewall"]["policy"],list):
                    for i in data_json["firewall"]["policy"]:
                        if isinstance(i[i.keys()[1]][i[i.keys()[1]].keys()[0]]["term"],list):
                            #print("policy is a list with multiple terms")
                            for j in i[i.keys()[1]][i[i.keys()[1]].keys()[0]]["term"]:
                                pmap[i["name"]]=[]
                                pmap[i["name"]].append(j["from"])
                                pmap[i["name"]].append(j["then"])
                                pmap[i["name"]].append(i.keys()[1])
                                pmap[i["name"]].append(i[i.keys()[1]].keys()[0])
                                pmap[i["name"]].append(j["name"])
                                firewall_create(pmap[i["name"]],i["name"])
                        else:
                            #print("policy is a list with a single term")
                            pmap[i["name"]]=[]
                            pmap[i["name"]].append(i[i.keys()[1]][i[i.keys()[1]].keys()[0]]["term"]["from"])
                            pmap[i["name"]].append(i[i.keys()[1]][i[i.keys()[1]].keys()[0]]["term"]["then"])
                            pmap[i["name"]].append(i.keys()[1])
                            pmap[i["name"]].append(i[i.keys()[1]].keys()[0])
                            pmap[i["name"]].append(i[i.keys()[1]][i[i.keys()[1]].keys()[0]]["term"]["name"])
                            firewall_create(pmap[i["name"]],i["name"])
                

                # case2 :  Single policy, single term
                if "then" in data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0]]["term"]:
                    #print("case1")
                    pmap[data_json["firewall"]["policy"]["name"]]=[]
                    pmap[data_json["firewall"]["policy"]["name"]].append(
                                                                    data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0]]["term"]["from"]
                                                                    )
                    pmap[data_json["firewall"]["policy"]["name"]].append(
                                                                    data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0]]["term"]["then"]
                                                                    )
                    pmap[data_json["firewall"]["policy"]["name"]].append(data_json["firewall"]["policy"].keys()[1])
                    pmap[data_json["firewall"]["policy"]["name"]].append(data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0])
                    pmap[data_json["firewall"]["policy"]["name"]].append(
                                                                    data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0]]["term"]["name"]
                                                                    )
                    firewall_create(pmap[data_json["firewall"]["policy"]["name"]],data_json["firewall"]["policy"]["name"])


                # case 3: single policy, multiple terms added first 
                elif isinstance(data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0]]["term"],list):
                    #print("single policy multiple terms")
                    for i in data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0]]["term"]:
                        pmap[data_json["firewall"]["policy"]["name"]]=[]
                        pmap[data_json["firewall"]["policy"]["name"]].append(i["from"])
                        pmap[data_json["firewall"]["policy"]["name"]].append(i["then"])
                        pmap[data_json["firewall"]["policy"]["name"]].append(data_json["firewall"]["policy"].keys()[1])
                        pmap[data_json["firewall"]["policy"]["name"]].append(data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0])
                        pmap[data_json["firewall"]["policy"]["name"]].append(i["name"])
                        firewall_create(pmap[data_json["firewall"]["policy"]["name"]],data_json["firewall"]["policy"]["name"])


            # global delete. Delete everting under PID 
            elif oper=="delete":
                firewall_delete(None,None)


            # create/delete single policy with  single/multiple term
            elif isinstance(oper,dict):
                # create/delete a policy
                # create a single term 
                if (oper["oper"] == "create" and len(oper)>4):
                    #print("entering create individual terms")
                    pmap[oper["policy"]]=[]
                    pmap[oper["policy"]].append(
                            data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0]]["term"]["from"]
                            )
                    pmap[oper["policy"]].append(
                            data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0]]["term"]["then"]
                            )
                    pmap[oper["policy"]].append(data_json["firewall"]["policy"].keys()[1])
                    pmap[oper["policy"]].append(data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0])
                    pmap[oper["policy"]].append(oper["term"])
                    firewall_create(pmap[oper["policy"]],oper["policy"])

                elif (oper["oper"] == "create" and len(oper)<4):
                    #print("no term detected, so creating new policy")
                    pmap[oper["policy"]]=[]
                    if "then" in data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]].keys()[0]]["term"]:
                        pmap[oper["policy"]].append(
                                data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]].keys()[0]]["term"]["from"]
                                )
                        pmap[oper["policy"]].append(
                                data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]].keys()[0]]["term"]["then"]
                                )
                        pmap[oper["policy"]].append(data_json["firewall"]["policy"].keys()[2])
                        pmap[oper["policy"]].append(data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]].keys()[0])
                        pmap[oper["policy"]].append(
                                data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]].keys()[0]]["term"]["name"]
                                )
                        firewall_create(pmap[oper["policy"]],oper["policy"])

                    elif isinstance(data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]].keys()[0]]["term"],list):
                        #print("addition of policy with multiple terms")
                        for i in data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]].keys()[0]]["term"]:
                            pmap[oper["policy"]]=[]
                            pmap[oper["policy"]].append(i["from"])
                            pmap[oper["policy"]].append(i["then"])
                            pmap[oper["policy"]].append(data_json["firewall"]["policy"].keys()[2])
                            pmap[oper["policy"]].append(data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[2]].keys()[0])
                            pmap[oper["policy"]].append(i["name"])
                            firewall_create(pmap[oper["policy"]],oper["policy"])
                
                # delete single policy or single term 
                elif (oper["oper"] == "delete"):
                    if "term" in oper.keys():
                        # delete specific term in a policy
                        firewall_delete(oper["policy"],oper["term"])
                    else:
                        # delete all terms in a policy including the policy
                        firewall_delete(oper["policy"],None)
            
            # create/delete multiple terms appending to exisiting policy 
            elif isinstance(oper, list):
                #print("entering list of multiple terms")
                #import pdb; pdb.set_trace()
                for i in oper:
		    try:
                        if i["oper"] == "create" and len(i) > 3:
                            # multiple terms adding
                            pmap[i["policy"]]=[]
                            pmap[i["policy"]].append(
                                    data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0]]["term"][i["index_term"]]["from"]
                                    )
                            pmap[i["policy"]].append(
                                    data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]][data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0]]["term"][i["index_term"]]["then"]
                                    )
                            pmap[i["policy"]].append(data_json["firewall"]["policy"].keys()[1])
                            pmap[i["policy"]].append(data_json["firewall"]["policy"][data_json["firewall"]["policy"].keys()[1]].keys()[0])
                            pmap[i["policy"]].append(i["term"])
                            #print(pmap)
                            firewall_create(pmap[i["policy"]],i["policy"])
                    except:
		        pass
                    try:
                        if i["oper"] == "create" and isinstance(data_json["firewall"]["policy"],list):
                            if len(i) > 3:
                                pmap[i["policy"]]=[]
                                pmap[i["policy"]].append(
                                        data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[1]][data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[1]].keys()[0]]["term"]["from"]
                                        )
                                pmap[i["policy"]].append(
                                        data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[1]][data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[1]].keys()[0]]["term"]["then"]
                                        )
                                pmap[i["policy"]].append(data_json["firewall"]["policy"][i["index"]].keys()[1])
                                pmap[i["policy"]].append(data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[1]].keys()[0])
                                pmap[i["policy"]].append(i["term"])
                                firewall_create(pmap[i["policy"]],i["policy"])
                    except:
                        pass
                    try:
                        if i["oper"] == "create" and len(i) < 4:
                            # single term
                            try:
                                if "then" in data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]][data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]].keys()[0]]["term"]:
                                    pmap[i["policy"]]=[]
                                    pmap[i["policy"]].append(data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]][data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]].keys()[0]]["term"]["from"])
                                    pmap[i["policy"]].append(data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]][data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]].keys()[0]]["term"]["then"])
                                    pmap[i["policy"]].append(data_json["firewall"]["policy"][i["index"]].keys()[2])
                                    pmap[i["policy"]].append(data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]].keys()[0])
                                    pmap[i["policy"]].append(data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]][data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]].keys()[0]]["term"]["name"])
                                    firewall_create(pmap[i["policy"]],i["policy"])
                            except:
                                pass
                            #multiple terms
                            try:
                                if isinstance(data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]][data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]].keys()[0]]["term"],list):
                                    for j in data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]][data_json["firewall"]["policy"][    i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]].keys()[0]]["term"]:
                                        pmap[i["policy"]]=[]
                                        pmap[i["policy"]].append(j["from"])
                                        pmap[i["policy"]].append(j["then"])
                                        pmap[i["policy"]].append(data_json["firewall"]["policy"][i["index"]].keys()[2])
                                        pmap[i["policy"]].append(data_json["firewall"]["policy"][i["index"]][data_json["firewall"]["policy"][i["index"]].keys()[2]].keys()[0])
                                        pmap[i["policy"]].append(j["name"])
                                        firewall_create(pmap[i["policy"]],i["policy"])
                            except:
                                pass 
                    except:
                        pass
                    
	            # delete multiple terms  
                    if i["oper"] == "delete":
                        if "term" in i.keys():
                            firewall_delete(i["policy"],i["term"])
                        else:
                            firewall_delete(i["policy"],None)

"""
Create iptable rules based on from and then conditions.
"""
def firewall_create(contents,name):
    rule = "iptables "
    print(50*"-")
    if contents[3]:
        rule = rule + "-A {} ".format(contents[3])
    if contents[2]:
        rule = rule + "-t {} ".format(contents[2])
    if "sourceIp" in contents[0]:
        # add IPV6 support (-4 for ipv4 and -6 for ipv6) 
        rule = rule + "-s {} ".format(contents[0]["sourceIp"])
    if "protocol" in contents[0]:
        rule = rule + "-p {} ".format(contents[0]["protocol"])
    if "destIp" in contents[0]:
        # add IPV6 support (-4 for ipv4 and -6 for ipv6)
        rule = rule + "-d {} ".format(contents[0]["destIp"])
    if "sourcePort" in contents[0]:
        if isinstance(contents[0]["sourcePort"],list):
            sval =  ','.join(str(val) for val in contents[0]["sourcePort"])
            rule = rule + "-m multiport " +"--source-port {} ".format(sval) 
        else:
            rule = rule + "--sport {} ".format(contents[0]["sourcePort"])
    if "destPort" in contents[0]:
        if isinstance(contents[0]["destPort"],list):
            dval = ','.join(str(val) for val in contents[0]["destPort"])
            rule = rule + "-m multiport "+ "--destination-port {} ".format(dval)
        else:
            rule = rule + "--dport {} ".format(contents[0]["destPort"])
    if "length" in contents[0]:
        rule = rule + "-m length --length {} ".format(contents[0]["length"])
    if "rate-limit-packets" in contents[0]:
        rule = rule + "-m limit "
        if "limit-packets" in contents[0]["rate-limit-packets"]:
            rule = rule + "--limit {} ".format(contents[0]["rate-limit-packets"]["limit-packets"])
        if "limit-burst" in contents[0]["rate-limit-packets"]:
            rule = rule + "--limit-burst {} ".format(contents[0]["rate-limit-packets"]["limit-burst"])
    if contents[1]:
        if contents[1].keys()[0] == "LOG":
            rule = rule + "-j {} ".format(contents[1].keys()[0])
            if "logLevel" in contents[1]["LOG"]:
                rule = rule + "--log-level {} ".format(contents[1]["LOG"]["logLevel"])
            if "logPrefix" in contents[1]["LOG"]:
                rule = rule + "--log-prefix {} ".format(contents[1]["LOG"]["logPrefix"])
        else:
            rule = rule + "-j {} ".format(contents[1].keys()[0])
    if "fragment" in contents[0]:
        rule = rule + "-f "
    if "tcp-flags" in contents[0]:
        # currently we from flags to ALL and not specific flag matches
        tcpval = ','.join(str(val) for val in contents[0]["tcp-flags"].keys())
        rule = rule + "--tcp-flags ALL {} ".format(tcpval)
    if "icmp-type" in contents[0]:
        rule = rule + "--icmp-type {} ".format(contents[0]["icmp-type"])
    if "connState" in contents[0]:
        if isinstance(contents[0]["connState"],dict):
            sval =  ','.join(str(val) for val in contents[0]["connState"].keys())
            rule = rule + "-m state --state {} ".format(sval)
        else:
            rule = rule + "-m state --state {} ".format(contents[0]["connState"].keys()[0])
    if "mac" in contents[0]:
        rule = rule + "-m mac --mac-source {} ".format(contents[0]["mac"])
    if "input_interface" in contents[0]:
        rule = rule + "--in-interface {} ".format(contents[0]["input_interface"])
    if "output_interface" in contents[0]:
        rule = rule + "--out-interface {} ".format(contents[0]["output_interface"])
    if "to-destination" in contents[0]:
        rule = rule + "--to-destination {} ".format(contents[0]["to-destination"])
    if "to-source" in contents[0]:
        rule = rule + "--to-source {} ".format(contents[0]["to-source"])
    if "ttl" in contents[0]:
        rule = rule + "-m ttl  --ttl {} ".format(contents[0]["ttl"])
    if "connlimit" in contents[0]:
        rule = rule + "-m connlimit --connlimit-above {} ".format(contents[0]["connlimit"])
    ##### The below conditions are to be evaluated last because they depend on action described as well #####
    if "max-seg-size" in contents[0]:
        # 1. -m tcpmss -mss 1400
        # 2. --set-mss 1400 -j TCPMSS
        if contents[1].keys()[0] == "TCPMSS":
            rule = rule + "--set-mss {} ".format(contents[0]["max-seg-size"])
        else:
            rule = rule +"-m tcpmss --mss {} ".format(contents[0]["max-seg-size"])
    if "set-class" in contents[0]:
        rule = rule + "--set-class {} ".format(contents[0]["set-class"])
    if "set-tos" in contents[0]:
        #1. -m tos --tos 0x19
        #2. -j TOS --set-tos 0x19
        if contents[1].keys()[0] == "TOS":
            rule = rule + "--set-tos {} ".format(contents[0]["set-tos"])
        else:
            rule = rule + "-m tos --tos {} ".format(contents[0]["set-tos"])
    if "DSCP" in contents[0]:
        #1. -m dscp --dscp
        #2. -m dscp --dscp-class
        #3. -j DSCP --set-dscp
        #4. -j DSCP --set-dscp-class
        if contents[1].keys()[0] == "DSCP":
            if "set-dscp" in contents[0]["DSCP"]:
                rule = rule + "--set-dscp {} ".format(contents[0]["DSCP"]["set-dscp"])
            if "set-dscp-class" in contents[0]["DSCP"]:
                rule = rule + "--set-dscp-class {} ".format(contents[0]["DSCP"]["set-dscp-class"])
        else:
            rule = rule + "-m dscp "
            if "set-dscp" in contents[0]["DSCP"]:
                rule = rule + "--dscp {} ".format(contents[0]["DSCP"]["set-dscp"])
            if "set-dscp-class" in contents[0]["DSCP"]:
                rule = rule + "--dscp-class {} ".format(contents[0]["DSCP"]["set-dscp-class"])
    if "packetMark" in contents[0]:
        #1. -j MARK --set-mark 2
        #2.  -m mark --mark 1
        if contents[1].keys()[0] == "MARK":
            rule = rule + "--set-mark {} ".format(contents[0]["packetMark"])
        else:
            rule = rule + "-m mark --mark {} ".format(contents[0]["packetMark"])
    print(rule)
    # create map between policy name and rule
    PID[str(name)+"_term_"+contents[4]]=rule
    os.popen(rule)
    os.popen('iptables-save -c > /home/iptables-save')
    with open('iptables-save.json','w') as f2:
        f2.write(json.dumps(PID, indent=4))


"""
Delete Iptable rules.
Each policy name is stored with name: chain map, this map has to be reffered to delete the correct chain rule..
if operation occurs globally, then it would flush all rules from the map PID.
"""
def firewall_delete(name,term):
    print("entering firewall_delete")
    print(name, term)
    if name is None:
        #pkey = PID.keys()
        for i in PID.keys():
            rule = PID[i]
            rule = rule.replace("A","D",1)
            os.popen(rule)
            print("deleted: {} ").format(rule)
            #remove the rule from mapping and write it back to file
            PID.pop(i)

    elif ((name is not None) and (term is None)):
        print("name not none and term is none")
        for i in PID.keys():
            if i.startswith(name):
                rule = PID[i]
                rule = rule.replace("A","D",1)
                print("deleted {} ").format(rule)
                os.popen(rule)
                PID.pop(i)
    else:
        rule = PID[name+"_term_"+term]
        rule = rule.replace("A","D",1)
        os.popen(rule)
        print("deleted {} ").format(rule)
        PID.pop(name+"_term_"+term)

    os.popen('iptables-save -c > /home/iptables-save')
    with open('iptables-save.json', 'w') as f4:
        f4.write(json.dumps(PID, indent=4))

def run():
    global PID
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    print('MQTT client is created and ready to connect')
    f1 = open('/home/log.txt', 'a+')
    f1.write("MQTT client is created and ready to connect" + "\n")

    client.connect(MQTT_IP, MQTT_PORT, MQTT_TIMEOUT)

    print("connected to ", MQTT_IP)
    f1.write("connected to " + MQTT_IP + "\n")
    f1.close()
    
    """
    create file to store PID dictionary. if file already exists, then load values into PID.
    This ensures that if the script is killed but config exists within MGD, respective values
    are copied back to memory to handle processes accordingly
    """
    try:
        #print(PID)
        if not PID:
            with open('iptables-save.json') as f0:
                fdata = json.load(f0)
            if fdata:
                PID = fdata
                #print(PID)
    except:
        f2 = open('iptables-save.json','a+')
        f2.close()
        pass

    client.loop_forever()

"""
command to start the daemon application is `python <name>.py start`, similarly to restart and stop the application.
run() fucntion will be executed in a dameon mode when you run this python script with start argument
"""
run()

if __name__ == "__main__":
    file_name = os.path.basename(__file__)
    daemon = daemon("/daemon_pids/" + file_name[:-3] + ".pid", run)

    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        else:
            print("Unknown command")
            sys.exit(2)
        print("program ended")
        sys.exit(0)
    else:
        print("usage: %s start|stop|restart" % sys.argv[0])
        sys.exit(2)
