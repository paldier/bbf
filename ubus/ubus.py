#!/usr/bin/python

#      This program is free software: you can redistribute it and/or modify
#      it under the terms of the GNU General Public License as published by
#      the Free Software Foundation, either version 2 of the License, or
#      (at your option) any later version.
#
#      Copyright (C) 2019 iopsys Software Solutions AB
#		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os, re, sys, time, json, getopt, getpass
from collections import OrderedDict
from pexpect import pxssh
from shutil import copyfile

def removefile( filename ):
	try:
		os.remove(filename)
	except OSError:
		pass

def securemkdir( folder ):
	try:
		os.mkdir(folder)
	except:
		pass

def printopenobj( obj ):
	fp = open('./.ubus_tmp', 'a')
	print >> fp, "\"%s\" : {" % obj
	fp.close()

def printopenfile():
	fp = open('./.ubus_tmp', 'a')
	print >> fp, "{"
	fp.close()

def printclosefile():
	fp = open('./.ubus_tmp', 'a')
	print >> fp, "}"
	fp.close()

def removelastline():
	file_r = open("./.ubus_tmp")
	lines = file_r.readlines()
	lines = lines[:-1]
	file_r.close()
	file_w = open("./.ubus_tmp",'w')
	file_w.writelines(lines)
	file_w.close()
	printclosefile ()

def copy_data_in_file( data):
	file_r = open("./.tmp.json", 'a')
	print >> file_r, "%s" % data
	file_r.close()

def replace_data_in_file( data_in, data_out ):
	file_r = open("./.ubus_tmp", "rt")
	file_w = open("./.ubus_tmp_1", "wt")
	text = ''.join(file_r).replace(data_in, data_out)
	file_w.write(text)
	file_r.close()
	file_w.close()
	copyfile("./.ubus_tmp_1", "./.ubus_tmp")
	removefile("./.ubus_tmp_1")

def updatejsontmpfile():
	replace_data_in_file ("}\n", "},\n")
	replace_data_in_file ("},\n},", "}\n},")
	replace_data_in_file ("}\n},\n},", "}\n}\n},")
	replace_data_in_file ("}\n},\n}\n},", "}\n}\n}\n},")
	replace_data_in_file ("}\n},\n}\n}\n},", "}\n}\n}\n}\n},")
	replace_data_in_file ("}\n}\n}\n},\n}\n},", "}\n}\n}\n}\n}\n},")
	replace_data_in_file ("}\n}\n}\n}\n}\n}\n},", "}\n}\n}\n}\n}\n}\n},")
	replace_data_in_file ("}\n}\n}\n},\n}\n}\n}\n},", "}\n}\n}\n}\n}\n}\n}\n}")

def get_type_field( data ):
	if isinstance(data,bool):
		return "boolean"
	elif isinstance(data,(float, int)):
		return "integer"
	elif isinstance(data,list):
		return "array"
	else:
		return "string"

def read_json( data, parse ):
	for x in data:
		if isinstance(data[x],dict):
			if parse == 0:
				read_json (data[x], 1)
				break
			else:
				printopenobj(x)
				read_json (data[x], 1)
				printclosefile()
		elif isinstance(data[x],list):
			for element in data[x]:
				if isinstance(element,dict):
					printopenobj(x)
					read_json (element, 1)
					printclosefile()
				else:
					type_field = get_type_field(element)
					printopenobj(x)
					fp = open('./.ubus_tmp', 'a')
					print >> fp,  "\"description\": \"TODO\","
					print >> fp,  "\"list\": \"true\","
					print >> fp,  "\"type\": \"%s\"" % type_field
					fp.close()
					printclosefile()
				break
		else:
			type_field = get_type_field(data[x])
			printopenobj(x)
			fp = open('./.ubus_tmp', 'a')
			print >> fp,  "\"description\": \"TODO\","
			print >> fp,  "\"type\": \"%s\"" % type_field
			fp.close()
			printclosefile()


def generate_output( data, parse ):
	removefile("./.tmp.json")
	copy_data_in_file(data)

	file = open("./.tmp.json")
	data = json.loads(file.read(), object_pairs_hook=OrderedDict)
	file.close()	

	read_json (data, parse)

def generate_in_out_put( root_object, obj, line ):
	fp = open('./.ubus_tmp', 'a')
	print >> fp,  "\"description\": \"TODO\","
	in_args = re.search('{(.+?)}', line)
	if in_args:
		found = in_args.group(1)
		lst = found.split(",")
		stringcount = len(lst)
		print >> fp,  "\"input\": {"
		for idx, value in enumerate(lst):
			in_arg = value.split(":")
			print >> fp,  "%s: {" % in_arg[0]
			print >> fp,  "\"description\": \"TODO\","
			print >> fp,  "\"type\": %s" % in_arg[1].lower()
			print >> fp,  "}"
		print >> fp,  "}"
	else:
		print >> fp,  "\"input\": {},"

	if root_object == "system" and obj == "reboot" or \
	   root_object == "juci.system" and (obj == "reboot" or obj == "defaultreset" or obj == "report") or \
	   root_object == "router.dropbear" and obj == "get_ssh_keys" or \
	   root_object == "network.wireless" or \
	   root_object == "network.device" and (obj == "set_alias" or obj == "set_state") or \
	   root_object == "session" and obj == "list" or \
	   root_object == "network.interface" and (obj == "up" or obj == "down" or obj == "renew" or obj == "prepare" or obj == "notify_proto" or obj == "remove" or obj == "set_data"):
		print >> fp,  "\"output\": {}"
		fp.close()
	else:
		if ((root_object == "router.wireless" or root_object == "wifix") and obj == "status") or \
		   ((root_object == "router.wireless" or root_object == "wifix") and obj == "assoclist") or \
		   ((root_object == "router.wireless" or root_object == "wifix") and obj == "stas") or \
		   ((root_object == "router.wireless" or root_object == "wifix") and obj == "stations"):
			command1 = "uci get wireless.@wifi-iface[0].device"
			s.sendline (command1)
			s.prompt()
			device = s.before.split('\n',1)[1];
			device_name = device.translate(None, ' \n\t\r')
			command = "ubus call %s %s \'{\"vif\":\"%s\"}\'" % (root_object, obj, device_name)
		elif root_object == "network.interface":
			command = "ubus call %s.lan %s" % (root_object, obj)				
		else:
			command = "ubus call %s %s" % (root_object, obj)
		s.sendline (command)
		s.prompt()
		data = s.before.split('\n',1)[1];
		print "****************************************************************************"
		print "command = %s" % command
		print "data = %s" % data
		print "****************************************************************************"
		parse = 1
		if root_object == "network.device" and obj == "status" or \
		   root_object == "router.graph" and obj == "iface_traffic" or \
		   root_object == "router.port" and obj == "status" or \
		   root_object == "router.network" and obj == "clients" or \
		   root_object == "router.network" and obj == "dump" or \
		   (root_object == "router.wireless" or root_object == "wifix") and obj == "temperature" or \
		   (root_object == "router.wireless" or root_object == "wifix") and obj == "stas" or \
		   (root_object == "router.wireless" or root_object == "wifix") and obj == "radios":
			parse = 0
		if ("Command failed" in data.split("\n", 1)[0]) or (data == ""):
			print >> fp,  "\"output\": {}"
			fp.close()
		else:
			print >> fp,  "\"output\": {"
			fp.close()
			generate_output(data, parse)
			printclosefile()

def convert_object( line ):
	found = ""
	m = re.search('\'(.+?)\'', line)
	if m:
		found = m.group(1)
		if "network.interface." in found:
			return found
		else:
			printopenobj(found)

	return found	

def convert_param( root_object, line ):
	m = re.search('\"(.+?)\":{', line)
	if m:
		obj = m.group(1)
		printopenobj(obj)
		generate_in_out_put(root_object, obj, line)
		printclosefile()

def removetmpfiles():
	removefile("./.ubus_tmp")
	removefile("./.tmp.json")

def generatejsonfromdata( data, gendir ):
	first_object = 0
	root_object = ""

	securemkdir(gendir)
	removetmpfiles()
	printopenfile()

	lines = data.split ('\n')
	for line in lines :
		if "@" in line:
			if first_object != 0:
				printclosefile()
			root_object = convert_object(line)
			if "network.interface." in root_object:
				first_object = 0
			else:
				first_object = 1
			continue
		else:
			if "network.interface." in root_object:
				continue
			convert_param(root_object, line)

	printclosefile()
	printclosefile()
	updatejsontmpfile ()
	removelastline ()

	file_r = open("./.ubus_tmp", "r")
	obj = json.load(file_r, object_pairs_hook=OrderedDict)
	dump = json.dumps(obj, indent=2)
	file_r.close()

	try:
		json_file = open(gendir + "/ubus.json", "a")
		print >> json_file, "%s" % dump
		json_file.close()
	except:
		pass

	removetmpfiles()

def printusage():
	print "Usage:"
	print ""
	print sys.argv[0] + " -h{hostname} -u{user} -p{password}"
	print "Example:"
	print sys.argv[0] + " -h 192.168.1.1 -u root -p 10pD3v"
	print ""
	print "Or you can run the tool directly using " + sys.argv[0]
	print "then enter your Hostname, Username and Password"
	print "Example:"
	print sys.argv[0]
	print "Enter your Hostname: 192.168.1.1"
	print "Enter your Username: root"
	print "Enter your Password: 10pD3v"

### main ###
try:
	optlist, args = getopt.getopt(sys.argv[1:], 'h:u:p:', ['help','?'])
except Exception, e:
	print str(e)
	printusage()
	exit(1)

options = dict(optlist)
if len(args) > 1:
	printusage()
	exit(1)

if [elem for elem in options if elem in ['-?','--?','--help']]:
        printusage()
	exit(1)

if '-h' in options:
	host = options['-h']
else:
	host = raw_input('Enter your Hostname: ')
if '-u' in options:
	user = options['-u']
else:
	user = raw_input('Enter your Username: ')
if '-p' in options:
	password = options['-p']
else:
	password = getpass.getpass('Enter your Password: ')

## Login via SSH
try:
	s = pxssh.pxssh()
	s.login (host, user, password)
	print "SSH session login successful"
	command = "ubus -v list"
	s.sendline (command)
	s.prompt()
	data = s.before.split("\n",1)[1];
	gendir = "source_" + time.strftime("%Y-%m-%d_%H-%M-%S")
	print "Start Generation of JSON file"
	print "Please wait..."
	generatejsonfromdata(data, gendir)
	s.logout()

except pxssh.ExceptionPxssh as e:
	print("SSH session failed on login.")
	print(e)

if (os.path.isdir(gendir)):
	print "JSON file generated under \"./%s\"" % gendir
else:
	print "No JSON file generated!"

