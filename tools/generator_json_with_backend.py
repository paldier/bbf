#!/usr/bin/python

#      This program is free software: you can redistribute it and/or modify
#      it under the terms of the GNU General Public License as published by
#      the Free Software Foundation, either version 2 of the License, or
#      (at your option) any later version.
#
#      Copyright (C) 2019 iopsys Software Solutions AB
#		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>


import os, sys, time, re, json
import xml.etree.ElementTree as xml
from collections import OrderedDict
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

def getname( objname ):
	global model_root_name
	OBJSname = objname
	if (objname.count('.') > 1 and (objname.count('.') != 2 or objname.count('{i}') != 1) ):
		OBJSname = objname.replace(dmroot1.get('name'), "", 1)
	OBJSname = OBJSname.replace("{i}", "")
	OBJSname = OBJSname.replace(".", "")
	if (objname.count('.') == 1):
		model_root_name = OBJSname
		OBJSname = "Root" + OBJSname
		return OBJSname
	if (objname.count('.') == 2 and objname.count('{i}') == 1):
		model_root_name = OBJSname
		OBJSname = "Services" + OBJSname
		return OBJSname
	return OBJSname;

def getparamtype( dmparam ):
	ptype = None
	for s in dmparam:
		if s.tag == "syntax":
			for c in s:
				if c.tag == "list":
					ptype = "string"
					break
				if c.tag == "dataType":
					reftype = c.get("ref")
					if "StatsCounter" in reftype:
						ptype = "unsignedInt"
						break
					ptype = "string"
					break
				ptype = c.tag
				break
			break
	if ptype == None:
		ptype = "__NA__"
	return ptype

def getparamrange( dmparam ):
	min = None
	max = None
	for s in dmparam:
		if s.tag == "syntax":
			for c in s:
				for o in c:
					if o.tag == "range":
						min = o.get("minInclusive")
						max = o.get("maxInclusive")
						break
	if min == None:
		min = ""
	if max == None:
		max = ""
	return min, max

def getparamunit( dmparam ):
	unit = None
	for s in dmparam:
		if s.tag == "syntax":
			for c in s:
				for o in c:
					if o.tag == "units":
						unit = o.get("value")
						break
	if unit == None:
		unit = ""
	return unit

def getparamvalues( dmparam ):
	hasvalues = 0
	values = ""
	for s in dmparam:
		if s.tag == "syntax":
			for c in s:
				if c.tag == "string":
					for a in c:
						if a.tag == "enumeration":
							hasvalues = 1
							for x in c.findall('enumeration'):
								if values:
									values = "%s, \"%s\"" % (values, x.get('value'))
								else:
									values = "\"%s\"" % x.get('value')
							break
				
			break
	return hasvalues, values

listmapping = []
def generatelistfromfile(dmobject):
	obj = dmobject.get('name').split(".")
	if "tr-104" in sys.argv[1]:
		pathfilename = "../dmtree/tr104/voice_services.c"
	else:
		pathfilename = "../dmtree/tr181/" + obj[1].lower() + ".c"
	exists = os.path.isfile(pathfilename)
	if exists:
		filec = open(pathfilename, "r")
		for linec in filec:
			if "/*#" in linec:
				listmapping.append(linec)
	else:
	    pass

def getparammapping(dmobject, dmparam):
	hasmapping = 0
	mapping = ""
	if "tr-104" in sys.argv[1]:
		param = "Device.Services." + dmobject.get('name') + dmparam.get('name')
	else:
		param = dmobject.get('name') + dmparam.get('name')
	for value in listmapping:
		if param in value:
			hasmapping = 1
			comment = value.split("!")
			mapping = comment[1]
			mapping = mapping.replace("*/\n", "")
			break

	return hasmapping, mapping

def getobjmapping(dmobject):
	hasmapping = 0
	mapping = ""
	if "tr-104" in sys.argv[1]:
		obj = "Device.Services." + dmobject.get('name')
	else:
		obj = dmobject.get('name')
	for value in listmapping:
		comment = value.split("!")
		mapping = comment[0]
		mapping = mapping.replace("/*#", "")
		if obj == mapping:
			hasmapping = 1
			mapping = comment[1]
			mapping = mapping.replace("*/\n", "")
			break

	return hasmapping, mapping

def objhaschild (parentname, level, check_obj):
	hasobj = 0
	if check_obj == 0:
		model = model2
	else:
		model = model1
	for c in model:
		objname = c.get('name')
		if c.tag == "object" and parentname in objname and (objname.count('.') - objname.count('{i}')) == level:
			hasobj = 1
			break;
	return hasobj

def objhasparam (dmobject):
	hasparam = 0
	for c in dmobject:
		if c.tag == "parameter":
			hasparam = 1
			break;
	return hasparam

def printopenobject (obj):
	fp = open('./.json_tmp', 'a')
	if "tr-104" in sys.argv[1]:
		print >> fp, "\"Device.Services.%s\" : {" % obj.get('name')
	else:
		print >> fp, "\"%s\" : {" % obj.get('name')
	fp.close()

def printopenfile ():
	fp = open('./.json_tmp', 'a')
	print >> fp, "{"
	fp.close()

def printclosefile ():
	fp = open('./.json_tmp', 'a')
	print >> fp, "}"
	fp.close()

def printOBJMaPPING (mapping):
	fp = open('./.json_tmp', 'a')
	comment = mapping.split(":")
	config = comment[1].split("/")
	if comment[0] == "UCI":
		type = "uci"
	elif comment[0] == "UBUS":
		type = "ubus"
	else:
		type = "cli"
	print >> fp, "\"mapping\": {"
	print >> fp, "\"type\": \"%s\"," % type
	print >> fp, "\"%s\": {" % type
	if comment[0] == "UCI":
		print >> fp, "\"file\": \"%s\"," % config[0]
		print >> fp, "\"section\": {"
		print >> fp, "\"type\": \"%s\"" % config[1]
		print >> fp, "},"
		print >> fp, "\"dmmapfile\": \"%s\"" % config[2]
	print >> fp, "}"
	print >> fp, "}"
	fp.close()

def printPARAMMaPPING (mapping):
	fp = open('./.json_tmp', 'a')
	lst = mapping.split("&")
	count = len(lst)
	print >> fp, "\"mapping\": ["
	for i in range(count):
		comment = lst[i].split(":")
		config = comment[1].split("/")
		if comment[0] == "UCI":
			type = "uci"
		elif comment[0] == "UBUS":
			type = "ubus"
		else:
			type = "cli"
		print >> fp, "{"
		print >> fp, "\"type\": \"%s\"," % type
		print >> fp, "\"%s\": {" % type

		if comment[0] == "UCI":
			print >> fp, "\"file\": \"%s\"," % config[0]
			print >> fp, "\"section\": {"
			var = config[1].split(",")
			if len(var) == 1:
				print >> fp, "\"type\": \"%s\"" % var[0]
			elif len(var) > 1 and "@i" in var[1]:
				print >> fp, "\"type\": \"%s\"," % var[0]
				print >> fp, "\"index\": \"%s\"" % var[1]
			elif len(var) > 1:
				print >> fp, "\"type\": \"%s\"," % var[0]
				print >> fp, "\"name\": \"%s\"" % var[1]		
			print >> fp, "}"
			if len(var) > 1:
				print >> fp, "\"option\": {"
				print >> fp, "\"name\": \"%s\"" % config[2]
				print >> fp, "}"
		elif comment[0] == "UBUS":
			print >> fp, "\"object\": \"%s\"," % config[0]
			print >> fp, "\"method\": \"%s\"," % config[1]
			print >> fp, "\"args\": {"
			if config[2] != "":
				args = config[2].split(",")
				print >> fp, "\"%s\": \"%s\"" % (args[0], args[1])
			print >> fp, "}"
			print >> fp, "\"key\": \"%s\"" % config[3]

		else:
			print >> fp, "\"command\": \"%s\"," % config[0]
			print >> fp, "\"args\": \"%s\"" % config[1]

		print >> fp, "}"
		print >> fp, "}"
	print >> fp, "]"
	print >> fp, "}"
	fp.close()

def removelastline ():
	file = open("./.json_tmp")
	lines = file.readlines()
	lines = lines[:-1]
	file.close()
	w = open("./.json_tmp",'w')
	w.writelines(lines)
	w.close()
	printclosefile ()

def replace_data_in_file( data_in, data_out ):
	file_r = open("./.json_tmp", "rt")
	file_w = open("./.json_tmp_1", "wt")
	text = ''.join(file_r).replace(data_in, data_out)
	file_w.write(text)
	file_r.close()
	file_w.close()
	copyfile("./.json_tmp_1", "./.json_tmp")
	removefile("./.json_tmp_1")

def updatejsontmpfile ():
	replace_data_in_file ("}\n", "},\n")
	replace_data_in_file ("},\n},", "}\n},")
	replace_data_in_file ("}\n},\n},", "}\n}\n},")
	replace_data_in_file ("}\n},\n}\n},", "}\n}\n}\n},")
	replace_data_in_file ("}\n},\n}\n}\n},", "}\n}\n}\n}\n},")
	replace_data_in_file ("}\n}\n}\n},\n}\n},", "}\n}\n}\n}\n}\n},")
	replace_data_in_file ("}\n}\n}\n}\n}\n}\n},", "}\n}\n}\n}\n}\n}\n},")
	replace_data_in_file ("},\n]", "}\n]")

def removetmpfiles():
	removefile("./.json_tmp")
	removefile("./.json_tmp_1")

def printOBJ( dmobject, hasobj, hasparam, bbfdm_type ):
	hasmapping, mapping = getobjmapping(dmobject)
	if (dmobject.get('name')).endswith(".{i}."):
		fbrowse = "true"
	else:
		fbrowse = "false"

	fp = open('./.json_tmp', 'a')
	print >> fp,  "\"type\" : \"object\","
	print >> fp,  "\"protocols\" : [%s]," % bbfdm_type
	if (dmobject.get('access') == "readOnly"):
		print >> fp,  "\"access\" : false,"	
	else:
		print >> fp,  "\"access\" : true,"
	if hasparam or hasobj:
		print >> fp,  "\"array\" : %s," % fbrowse
	else:
		print >> fp,  "\"array\" : %s" % fbrowse
	fp.close()
	if hasmapping:
		printOBJMaPPING (mapping)

def printPARAM( dmparam, dmobject, bbfdm_type ):
	hasmapping, mapping = getparammapping(dmobject, dmparam)
	ptype = getparamtype(dmparam)
	min, max = getparamrange(dmparam)
	unit = getparamunit(dmparam)
	hasvalues, values = getparamvalues(dmparam)
	if (dmparam.get('access') == "readOnly"):
		access = "false"
	else:
		access = "true"

	fp = open('./.json_tmp', 'a')
	print >> fp,  "\"%s\" : {" % dmparam.get('name')
	print >> fp,  "\"type\" : \"%s\"," % ptype
	print >> fp,  "\"protocols\" : [%s]," % bbfdm_type
	if min != "" and max != "":
		print >> fp,  "\"range\" : {"
		print >> fp,  "\"min\" : \"%s\"," % min
		print >> fp,  "\"max\" : \"%s\"" % max
		print >> fp,  "},"
	elif min != "" and max == "":
		print >> fp,  "\"range\" : {"
		print >> fp,  "\"min\" : \"%s\"" % min
		print >> fp,  "},"
	elif min == "" and max != "":
		print >> fp,  "\"range\" : {"
		print >> fp,  "\"max\" : \"%s\"" % max
		print >> fp,  "},"
	if unit != "":
		print >> fp,  "\"unit\" : \"%s\"," % unit
	print >> fp,  "\"read\" : true,"
	if hasvalues and hasmapping:
		print >> fp,  "\"write\" : %s," % access
		print >> fp,  "\"values\": [%s]," % values
		fp.close()
		printPARAMMaPPING(mapping)
	elif hasvalues and hasmapping == 0:
		print >> fp,  "\"write\" : %s," % access
		print >> fp,  "\"values\": [%s]" % values
		print >> fp,  "}"
		fp.close()
	elif hasvalues == 0 and hasmapping:
		print >> fp,  "\"write\" : %s," % access
		fp.close()
		printPARAMMaPPING(mapping)
	else:
		print >> fp,  "\"write\" : %s" % access
		print >> fp,  "}"
		fp.close()

def printusage():
	if "tr-181" in sys.argv[1]:
		print "Usage: " + sys.argv[0] + " <tr-181 cwmp xml data model> <tr-181 usp xml data model> [Object path]"
		print "Examples:"
		print "  - " + sys.argv[0] + " tr-181-2-13-0-cwmp-full.xml tr-181-2-13-0-usp-full.xml Device."
		print "    ==> Generate the json file of the sub tree Device. in tr181.json"
	else:
		print "Usage: " + sys.argv[0] + " <xml data model> [Object path]"
		print "Examples:"
		print "  - " + sys.argv[0] + " tr-104-1-1-0-full.xml VoiceService."
		print "    ==> Generate the json file of the sub tree VoiceService. in tr104.json"
		print "  - " + sys.argv[0] + " tr-106-1-2-0-full.xml Device."
		print "    ==> Generate the json file of the sub tree Device. in tr106.json"

	print ""
	print "Example of xml data model file: https://www.broadband-forum.org/cwmp/tr-181-2-13-0-cwmp-full.xml"

def getobjectpointer( objname ):
	obj = None
	for c in model1:
		if c.tag == "object" and (c.get('name') == objname or c.get('name') == (objname + "{i}.")):
			obj = c
			break
	return obj

def chech_each_obj_with_other_obj(model1, model2):
	for c in model2:
		if c.tag == "object":
			found = 0
			for obj in model1:
				if obj.tag == "object" and (obj.get('name') == c.get('name')):
					found = 1
					break;
			if found == 0:
				if c.get('name').count(".") - (c.get('name')).count("{i}.") != 2:
					continue
				dmlevel = (c.get('name')).count(".") - (c.get('name')).count("{i}.") + 1
				printopenobject(c)
				object_parse_childs(c, dmlevel, 0, 0)
				printclosefile ()

def check_if_obj_exist_in_other_xml_file( objname ):
	obj = None
	found = 0
	for c in model2:
		if c.tag == "object" and (c.get('name') == objname.get('name')):
			obj = c
			found = 1
			break
	return obj, found

def chech_current_param_exist_in_other_obj(obj, c):
	bbfdm_type = ""
	for param in obj:
		if param.tag == "parameter" and param.get('name') == c.get('name'):
			bbfdm_type = "\"cwmp\", \"usp\""
			break
	if bbfdm_type == "" and "cwmp" in sys.argv[1]:
		bbfdm_type =  "\"cwmp\""
	elif bbfdm_type == "" and "usp" in sys.argv[1]:
		bbfdm_type =  "\"usp\""
	return bbfdm_type

def chech_obj_with_other_obj(obj, dmobject):
	for c in obj:
		exist = 0
		if c.tag == "parameter":
			for param in dmobject:
				if param.tag == "parameter" and c.get('name') == param.get('name'):
					exist = 1
					break
			if exist == 0 and "cwmp" in sys.argv[1]:
				printPARAM(c, obj, "\"usp\"")
			elif exist == 0 and "usp" in sys.argv[1]:
				printPARAM(c, obj, "\"cwmp\"")

def object_parse_childs(dmobject, level, generatelist, check_obj):
	if generatelist == 0 and (dmobject.get('name')).count(".") == 2:
		generatelistfromfile(dmobject)
	if check_obj ==1 and "tr-181" in sys.argv[1]:
		obj, exist = check_if_obj_exist_in_other_xml_file(dmobject) 

	hasobj = objhaschild(dmobject.get('name'), level, check_obj)
	hasparam = objhasparam(dmobject)

	if check_obj == 1 and "tr-181" in sys.argv[1] and exist == 0:
		printOBJ(dmobject, hasobj, hasparam, "\"cwmp\"")
	elif check_obj == 0 and "tr-181" in sys.argv[1]:
		printOBJ(dmobject, hasobj, hasparam, "\"usp\"")
	else:
		printOBJ(dmobject, hasobj, hasparam, "\"cwmp\", \"usp\"")

	if hasparam:
		for c in dmobject:
			if c.tag == "parameter":
				if check_obj == 1 and "tr-181" in sys.argv[1] and exist == 1:
					bbfdm_type = chech_current_param_exist_in_other_obj(obj, c)
				elif check_obj == 1 and "tr-181" in sys.argv[1] and exist == 0:
					bbfdm_type = "\"cwmp\""
				elif check_obj == 0:
					bbfdm_type = "\"usp\""
				else:
					bbfdm_type = "\"cwmp\", \"usp\""
				printPARAM(c, dmobject, bbfdm_type)

	if check_obj == 1 and "tr-181" in sys.argv[1] and exist == 1:
		chech_obj_with_other_obj(obj, dmobject)

	if hasobj and check_obj:
		for c in model1:
			objname = c.get('name')
			if c.tag == "object" and dmobject.get('name') in objname and (objname.count('.') - objname.count('{i}')) == level:
				printopenobject(c)
				object_parse_childs(c, level+1, 0, 1)
				printclosefile ()

	if hasobj and check_obj == 0:
		for c in model2:
			objname = c.get('name')
			if c.tag == "object" and dmobject.get('name') in objname and (objname.count('.') - objname.count('{i}')) == level:
				printopenobject(c)
				object_parse_childs(c, level+1, 0, 0)
				printclosefile ()

	return;

def generatejsonfromobj(pobj, pdir):
	generatelist = 0
	securemkdir(pdir)
	removetmpfiles()
	dmlevel = (pobj.get('name')).count(".") - (pobj.get('name')).count("{i}.") + 1
	if (pobj.get('name')).count(".") == 1:
		generatelist = 0
	else:
		generatelistfromfile(pobj)
		generatelist = 1
	printopenfile ()
	printopenobject(pobj)
	object_parse_childs(pobj, dmlevel, generatelist, 1)
	if "tr-181" in sys.argv[1] and Root.count(".") == 1:
		chech_each_obj_with_other_obj(model1, model2)

	if "tr-181" in sys.argv[1] and pobj.get("name").count(".") == 1:
		dmfp = open(pdir + "/tr181.json", "a")
	elif "tr-104" in sys.argv[1] and pobj.get("name").count(".") == 2:
		dmfp = open(pdir + "/tr104.json", "a")
	elif "tr-106" in sys.argv[1] and pobj.get("name").count(".") == 1:
		dmfp = open(pdir + "/tr106.json", "a")
	else:
		dmfp = open(pdir + "/" +  (getname(pobj.get('name'))).lower() + ".json", "a")

	printclosefile ()
	printclosefile ()
	updatejsontmpfile ()
	removelastline ()

	f = open("./.json_tmp", "r")
	obj = json.load(f, object_pairs_hook=OrderedDict)
	dump = json.dumps(obj, indent=4)
	tabs = re.sub('\n +', lambda match: '\n' + '\t' * (len(match.group().strip('\n')) / 4), dump)

	try:
		print >> dmfp, "%s" % tabs
		dmfp.close()
	except:
		pass

	removetmpfiles()


### main ###
if "tr-181" in sys.argv[1]:
	if len(sys.argv) < 4:
		printusage()
		exit(1)
else:
	if len(sys.argv) < 3:
		printusage()
		exit(1)

if (sys.argv[1]).lower() == "-h" or (sys.argv[1]).lower() == "--help":
	printusage()
	exit(1)

is_service_model = 0
model_root_name = "Root"

tree1 = xml.parse(sys.argv[1])
xmlroot1 = tree1.getroot()
model1 = xmlroot1

for child in model1:
	if child.tag == "model":
		model1 = child

if model1.tag != "model":
	print "Wrong %s XML Data model format!" % sys.argv[1]
	exit(1)

dmroot1 = None
for c in model1:
	if c.tag == "object" and c.get("name").count(".") == 1:
		dmroot1 = c
		break;

#If it is service data model
if dmroot1 == None:
	is_service_model = 1
	for c in model1:
		if c.tag == "object" and c.get("name").count(".") == 2:
			dmroot1 = c
			break;

if dmroot1 == None:
	print "Wrong %s XML Data model format!" % sys.argv[1]
	exit(1)

if "tr-181" in sys.argv[1]:
	tree2 = xml.parse(sys.argv[2])
	xmlroot2 = tree2.getroot()
	model2 = xmlroot2

	for child in model2:
		if child.tag == "model":
			model2 = child

	if model2.tag != "model":
		print "Wrong %s XML Data model format!" % sys.argv[2]
		exit(1)

	dmroot2 = None
	for c in model2:
		if c.tag == "object" and c.get("name").count(".") == 1:
			dmroot2 = c
			break;

	if dmroot2 == None:
		print "Wrong %s XML Data model format!" % sys.argv[2]
		exit(1)

if "tr-181" in sys.argv[1]:
	gendir = "tr181_" + time.strftime("%Y-%m-%d_%H-%M-%S")
elif "tr-104" in sys.argv[1]:
	gendir = "tr104_" + time.strftime("%Y-%m-%d_%H-%M-%S")
elif "tr-106" in sys.argv[1]:
	gendir = "tr106_" + time.strftime("%Y-%m-%d_%H-%M-%S")
else:
	gendir = "source_" + time.strftime("%Y-%m-%d_%H-%M-%S")

if "tr-181" in sys.argv[1]:
	Root = sys.argv[3]
	objstart = getobjectpointer(Root)
else:
	Root = sys.argv[2]
	objstart = getobjectpointer(Root)

if objstart == None:
	print "Wrong Object Name! %s" % Root
	exit(1)

generatejsonfromobj(objstart, gendir)

if (os.path.isdir(gendir)):
	print "Json file generated under \"./%s\"" % gendir
else:
	print "No json file generated!"

