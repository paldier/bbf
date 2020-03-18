#!/usr/bin/python

# Copyright (C) 2020 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os, sys, time, re, json
import xml.etree.ElementTree as xml
from collections import OrderedDict
from shutil import copyfile

listTypes = ["string",
			 "unsignedInt",
			 "unsignedLong",
			 "int",
			 "long",
			 "boolean",
			 "dateTime",
			 "hexBinary",
			 "base64"]

listdataTypes = ["string", 
				 "unsignedInt", 
				 "unsignedLong", 
				 "int",
				 "long",
				 "boolean",
				 "dateTime",
				 "hexBinary",
				 "base64",
				 "IPAddress",
				 "IPv4Address",
				 "IPv6Address",
				 "IPPrefix",
				 "IPv4Prefix",
				 "IPv6Prefix",
				 "MACAddress",
				 "decimal",
				 "IoTDeviceType",
				 "IoTLevelType",
				 "IoTUnitType",
				 "IoTEnumSensorType",
				 "IoTEnumControlType"]

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
	return OBJSname

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

def getMinMaxEnumerationUnitPatternparam(paramtype, c):
	paramvalrange = None
	paramenum = None
	paramunit = None
	parampattern = None
	if paramtype == "string" or paramtype == "hexBinary" or paramtype == "base64":
		for cc in c:
			if cc.tag == "size":
				if paramvalrange == None:
					paramvalrange = "%s,%s" % (cc.get("minLength"), cc.get("maxLength"))
				else:
					paramvalrange = "%s;%s,%s" % (paramvalrange, cc.get("minLength"), cc.get("maxLength"))
			if cc.tag == "enumeration":
				if paramenum == None:
					paramenum = "\"%s\"" % cc.get('value')
				else:
					paramenum = "%s, \"%s\"" % (paramenum, cc.get('value'))
			if cc.tag == "pattern":
				if parampattern == None and cc.get('value') != "":
					parampattern = "\"%s\"" % cc.get('value')
				elif cc.get('value') != "":
					parampattern = "%s,\"%s\"" % (parampattern, cc.get('value'))

	elif paramtype == "unsignedInt" or paramtype == "int" or paramtype == "unsignedLong" or paramtype == "long":
		for cc in c:
			if cc.tag == "range":
				if paramvalrange == None:
					paramvalrange = "%s,%s" % (cc.get("minInclusive"), cc.get("maxInclusive"))
				else:
					paramvalrange = "%s;%s,%s" % (paramvalrange, cc.get("minInclusive"), cc.get("maxInclusive"))
			if cc.tag == "units":
				paramunit = cc.get("value")

	return paramvalrange, paramenum, paramunit, parampattern


def getparamdatatyperef( datatyperef ):
	paramvalrange = None
	paramenum = None
	paramunit = None
	parampattern = None
	for d in xmlroot1:
		if d.tag == "dataType" and d.get("name") == datatyperef:
			if d.get("base") != "" and d.get("base") != None and d.get("name") == "Alias":
				paramvalrange, paramenum, paramunit, parampattern = getparamdatatyperef(d.get("base"))
			else:
				for dd in d:
					if dd.tag in listTypes:
						paramvalrange, paramenum, paramunit, parampattern = getMinMaxEnumerationUnitPatternparam(dd.tag, dd)
						break
					if dd.tag == "size":
						if paramvalrange == None:
							paramvalrange = "%s,%s" % (dd.get("minLength"), dd.get("maxLength"))
						else:
							paramvalrange = "%s;%s,%s" % (paramvalrange, dd.get("minLength"), dd.get("maxLength"))
					if dd.tag == "enumeration":
						if paramenum == None:
							paramenum = "\"%s\"" % dd.get('value')
						else:
							paramenum = "%s, \"%s\"" % (paramenum, dd.get('value'))
					if dd.tag == "pattern" and dd.get('value') != "":
						if parampattern == None:
							parampattern = "\"%s\"" % dd.get('value')
						elif dd.get('value') != "":
							parampattern = "%s,\"%s\"" % (parampattern, dd.get('value'))
				break

	return paramvalrange, paramenum, paramunit, parampattern

def getparamlist( dmparam ):
	minItem = None
	maxItem = None
	maxsize = None
	minItem = dmparam.get("minItems")
	maxItem = dmparam.get("maxItems")
	for cc in dmparam:
		if cc.tag == "size":
			maxsize = cc.get("maxLength")

	return minItem, maxItem, maxsize

def getparamoption( dmparam ):
	datatype = None
	paramvalrange = None
	paramenum = None
	paramunit = None
	parampattern = None
	listminItem = None
	listmaxItem = None
	listmaxsize = None
	islist = 0
	for s in dmparam:
		if s.tag == "syntax":
			for c in s:
				if c.tag == "list":
					islist = 1
					listminItem, listmaxItem, listmaxsize = getparamlist(c)
					for c in s:
						datatype = c.tag if c.tag in listdataTypes else None
						if datatype != None:
							paramvalrange, paramenum, paramunit, parampattern = getMinMaxEnumerationUnitPatternparam(datatype, c)
							break
						if c.tag == "dataType":
							datatype = c.get("ref")
							paramvalrange, paramenum, paramunit, parampattern = getparamdatatyperef(c.get("ref"))
							break

				if islist == 0:
					datatype = c.tag if c.tag in listdataTypes else None
					if datatype != None:
						paramvalrange, paramenum, paramunit, parampattern = getMinMaxEnumerationUnitPatternparam(datatype, c)
						break
					if c.tag == "dataType":
						datatype = c.get("ref")
						paramvalrange, paramenum, paramunit, parampattern = getparamdatatyperef(datatype)
						break
			break

	return islist, datatype, paramvalrange, paramenum, paramunit, parampattern, listminItem, listmaxItem, listmaxsize

listmapping = []
def generatelistfromfile(dmobject):
	obj = dmobject.get('name').split(".")
	if "tr-104" in sys.argv[1]:
		pathfilename = "../dmtree/tr104/voice_services.c"
		pathiopsyswrtfilename = "../dmtree/tr104/voice_services-iopsyswrt.c"
	elif obj[1] == "SoftwareModules" or obj[1] == "BulkData" :
		pathfilename = "../dmtree/tr157/" + obj[1].lower() + ".c"
		pathiopsyswrtfilename = "../dmtree/tr157/" + obj[1].lower() + "-iopsyswrt.c"
	else:
		pathfilename = "../dmtree/tr181/" + obj[1].lower() + ".c"
		pathiopsyswrtfilename = "../dmtree/tr181/" + obj[1].lower() + "-iopsyswrt.c"

	for x in range(0, 2):
		pathfile = pathfilename if x == 0 else pathiopsyswrtfilename
		exists = os.path.isfile(pathfile)
		if exists:
			filec = open(pathfile, "r")
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
	model = model2 if check_obj == 0 else model1
	for c in model:
		objname = c.get('name')
		if c.tag == "object" and parentname in objname and (objname.count('.') - objname.count('{i}')) == level:
			hasobj = 1
			break

	return hasobj

def objhasparam (dmobject):
	hasparam = 0
	for c in dmobject:
		if c.tag == "parameter":
			hasparam = 1
			break

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
	replace_data_in_file ("}\n}\n}\n},\n}\n}\n}\n},", "}\n}\n}\n}\n}\n}\n}\n},")
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
	islist, datatype, paramvalrange, paramenum, paramunit, parampattern, listminItem, listmaxItem, listmaxsize = getparamoption(dmparam)

	fp = open('./.json_tmp', 'a')
	print >> fp,  "\"%s\" : {" % dmparam.get('name')
	print >> fp,  "\"type\" : \"%s\"," % getparamtype(dmparam)
	print >> fp,  "\"read\" : true,"
	print >> fp,  "\"write\" : %s," % ("false" if dmparam.get('access') == "readOnly" else "true")
	print >> fp,  "\"protocols\" : [%s]," % bbfdm_type

	# create list
	if islist == 1:
		print >> fp,  "\"list\" : {"

	# add datatype
	print >> fp,  ("\"datatype\" : \"%s\"," % datatype) if (listmaxsize != None or listminItem != None or listmaxItem != None or paramvalrange != None or paramunit != None or paramenum != None or parampattern != None or (hasmapping and islist == 0)) else ("\"datatype\" : \"%s\"" % datatype)

	if islist == 1:
		# add maximum size of list
		if listmaxsize != None:
			print >> fp,  ("\"maxsize\" : %s," % listmaxsize) if (listminItem != None or listmaxItem != None or paramvalrange != None or paramunit != None or paramenum != None or parampattern != None) else ("\"maxsize\" : %s" % listmaxsize)

		# add minimun and maximum item values
		if listminItem != None and listmaxItem != None:
			print >> fp,  "\"item\" : {"
			print >> fp,  "\"min\" : %s," % listminItem
			print >> fp,  "\"max\" : %s" % listmaxItem
			print >> fp,  ("},") if (paramvalrange != None or paramunit != None or paramenum != None or parampattern != None) else ("}")
		elif listminItem != None and listmaxItem == None:
			print >> fp,  "\"item\" : {"
			print >> fp,  "\"min\" : %s" % listminItem
			print >> fp,  ("},") if (paramvalrange != None or paramunit != None or paramenum != None or parampattern != None) else ("}")
		elif listminItem == None and listmaxItem != None:
			print >> fp,  "\"item\" : {"
			print >> fp,  "\"max\" : %s" % listmaxItem
			print >> fp,  ("},") if (paramvalrange != None or paramunit != None or paramenum != None or parampattern != None) else ("}")

	# add minimun and maximum values
	if paramvalrange != None: 
		valranges = paramvalrange.split(";")
		print >> fp,  "\"range\" : ["
		for eachvalrange in valranges:
			valrange = eachvalrange.split(",")
			if valrange[0] != "None" and valrange[1] != "None":
				print >> fp,  "{"
				print >> fp,  "\"min\" : %s," % valrange[0]
				print >> fp,  "\"max\" : %s" % valrange[1]
				print >> fp,  ("},") if (eachvalrange == valranges[len(valranges)-1]) else ("}")
			elif valrange[0] != "None" and valrange[1] == "None":
				print >> fp,  "{"
				print >> fp,  "\"min\" : %s" % valrange[0]
				print >> fp,  ("},") if (eachvalrange == valranges[len(valranges)-1]) else ("}")
			elif valrange[0] == "None" and valrange[1] != "None":
				print >> fp,  "{"
				print >> fp,  "\"max\" : %s" % valrange[1]
				print >> fp,  ("},") if (eachvalrange == valranges[len(valranges)-1]) else ("}")
		print >> fp,  ("],") if (paramunit != None or paramenum != None or parampattern != None or (hasmapping and islist == 0)) else ("]")

	# add unit
	if paramunit != None: 
		print >> fp,  ("\"unit\" : \"%s\"," % paramunit) if (paramenum != None or parampattern != None or (hasmapping and islist == 0)) else ("\"unit\" : \"%s\"" % paramunit)

	# add enumaration
	if paramenum != None: 
		print >> fp,  ("\"enumerations\" : [%s]," % paramenum) if (parampattern != None or (hasmapping and islist == 0)) else ("\"enumerations\" : [%s]" % paramenum)

	# add pattern
	if parampattern != None:
		print >> fp,  ("\"pattern\" : [%s]," % parampattern.replace("\\", "\\\\")) if (hasmapping and islist == 0) else ("\"pattern\" : [%s]" % parampattern.replace("\\", "\\\\"))

	# close list
	if islist == 1:
		print >> fp,  ("},") if hasmapping else ("}")

	# add mapping
	if hasmapping:
		fp.close()
		printPARAMMaPPING(mapping)
	else:
		print >> fp,  "}"
		fp.close()

def printCOMMAND( dmparam, dmobject, bbfdm_type ):
	fp = open('./.json_tmp', 'a')
	print >> fp,  "\"%s\" : {" % dmparam.get('name')
	print >> fp,  "\"type\" : \"command\","
	inputfound = 0
	outputfound = 0
	for c in dmparam:
		if c.tag == "input":
			inputfound = 1
		elif c.tag == "output":
			outputfound = 1

	print >> fp, ("\"protocols\" : [\"usp\"],") if (inputfound or outputfound) else ("\"protocols\" : [\"usp\"]")

	for c in dmparam:
		if c.tag == "input":
			print >> fp,  "\"input\" : {"
			for param in c:
				if param.tag == "parameter":
					fp.close()
					printPARAM(param, dmobject, "\"usp\"")
			fp = open('./.json_tmp', 'a')
			print >> fp,  "}" if outputfound else "},"

		if c.tag == "output":
			print >> fp,  "\"output\" : {"
			for param in c:
				if param.tag == "parameter":
					fp.close()
					printPARAM(param, dmobject, "\"usp\"")
			fp = open('./.json_tmp', 'a')
			print >> fp,  "}"

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
					break
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
		if c.tag == "command":
			printCOMMAND(c, obj, "\"usp\"")

def object_parse_childs(dmobject, level, generatelist, check_obj):
	if generatelist == 0 and (dmobject.get('name')).count(".") == 2:
		generatelistfromfile(dmobject)
	if check_obj == 1 and "tr-181" in sys.argv[1]:
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
			if c.tag == "command":
				printCOMMAND(c, dmobject, "\"usp\"")

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

	return

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
		break

#If it is service data model
if dmroot1 == None:
	is_service_model = 1
	for c in model1:
		if c.tag == "object" and c.get("name").count(".") == 2:
			dmroot1 = c
			break

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
			break

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
