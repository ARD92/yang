'''
Author: Aravind Prabhakar
Contact: aprabh@juniper.net
Action script for server/vm details 
'''

import jcs
import sys
import os
import subprocess

sys.path.append("/var/db/scripts/action")
sys.path.append("/var/db/scripts/import")

args = {'list': None}

for arg in args.keys():
    if arg in sys.argv:
        index = sys.argv.index(arg)
        args[arg] = sys.argv[index+1]

if args["list"] == "ram":
    out = subprocess.Popen(['free', '-h'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    jcs.output(out.communicate()[0])

if args["list"] == "hdd":
    out = subprocess.Popen(['df', '-h'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    jcs.output(out.communicate()[0])

if args["list"] == "vmstats":
    out = subprocess.Popen(['vmstat'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

if args["list"] == "cpu":
    out = subprocess.Popen(['iostat', '-c'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

if args["list"] == "meminfo"
   out = subprocess.Popen(['more', '/proc/meminfo'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

if args["list"] == "softirq"
   out = subprocess.Popen(['more', '/proc/softirq'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
