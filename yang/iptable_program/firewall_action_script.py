import jcs
import sys
import os
import subprocess

args = {'chain': None, 'lookup-ip-rules':None, 'table':None}

for arg in args.keys():
    if arg in sys.argv:
        index = sys.argv.index(arg)
        args[arg] = sys.argv[index+1]

if (args["lookup-ip-rules"] == "lookup-ip-rules") and (args["chain"] is None and args["table"] is None):
    out = subprocess.Popen(['ip', 'rule', 'show'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    jcs.output(out.communicate()[0])

if args["table"] == "filter" and not args["chain"]:
    out = subprocess.Popen(['iptables', '-L', '-t', 'filter'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    jcs.output(out.communicate()[0])
if args["table"] == "filter" and args["chain"] == "chain":
    out = subprocess.Popen(['iptables', '--list-rules', '-t', 'filter'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    jcs.output(out.communicate()[0])

if args["table"] == "mangle" and not args["chain"]:
    out = subprocess.Popen(['iptables', '-L', '-t', 'mangle'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    jcs.output(out.communicate()[0])
if args["table"] == "mangle" and args["chain"] == "chain":
    out = subprocess.Popen(['iptables', '--list-rules', '-t', 'mangle'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    jcs.output(out.communicate()[0])

if args["table"] == "nat" and not args["chain"]:
    out = subprocess.Popen(['iptables', '-L', '-t', 'nat'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    jcs.output(out.communicate()[0])
if args["table"] == "nat" and args["chain"] == "chain":
    out = subprocess.Popen(['iptables', '--list-rules', '-t', 'nat'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    jcs.output(out.communicate()[0])

if args["table"] == "raw" and not args["chain"]:
    out = subprocess.Popen(['iptables', '-L', '-t', 'raw'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    jcs.output(out.communicate()[0])
if args["table"] == "raw" and args["chain"] == "chain":
    out = subprocess.Popen(['iptables', '--list-rules', '-t', 'raw'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    jcs.output(out.communicate()[0])
