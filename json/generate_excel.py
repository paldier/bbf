#!/usr/bin/python

#      This program is free software: you can redistribute it and/or modify
#      it under the terms of the GNU General Public License as published by
#      the Free Software Foundation, either version 2 of the License, or
#      (at your option) any later version.
#
#      Copyright (C) 2019 iopsys Software Solutions AB
#		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os, sys, time, json, xlwt
from xlwt import Workbook 
from collections import OrderedDict

def removefile( filename ):
	try:
		os.remove(filename)
	except OSError:
		pass

def objhaschild( value ):
	if isinstance(value,dict):
		for k,v in value.items():
			if isinstance(v,dict):
				for k1,v1 in v.items():
					if k1 == "type" and v1 == "object":
						return 1
	return 0

def objhasparam( value ):
	if isinstance(value,dict):
		for k,v in value.items():
			if isinstance(v,dict):
				for k1,v1 in v.items():
					if k1 == "type" and v1 != "object":
						return 1
	return 0

def check_obj(dmobject):
	obj = dmobject.split(".")
	if dmobject.count('.') == 2:
		cmd = 'awk \'/DMOBJ tRoot_181_Obj/,/^{0}$/\' ../dmtree/tr181/device.c'
		res = os.popen(cmd).read()
		string = "\n{\"%s\"," % obj[1]
	else:
		array_name = ""
		if "Device.IP.Diagnostics." == dmobject:
			file = "../dmtree/tr181/ip.c"
		elif "Device.IP.Diagnostics." in dmobject:
			file = "../dmtree/tr143/diagnostics.c"
		else:
			file = "../dmtree/tr181/%s.c" % obj[1].lower()
		if(os.path.isfile(file)):
			dmobject = dmobject.replace(".{i}.", ".")
			count = dmobject.count('.')
			obj1 = dmobject.split(".")
			for i in range(count-2):
				array_name += obj1[i+1]
			cmd = 'awk \'/DMOBJ t%sObj/,/^{0}$/\' %s' % (array_name, file)
			res = os.popen(cmd).read()
			string = "\n{\"%s\"," % obj1[count - 1]
		else:
			return "false"

	if string in res:
		return "true"
	else:
		return "false"

def check_param(param, res):
	string = "\n{\"%s\"," % param
	if string in res:
		return "true"
	else:
		return "false"

def load_param(dmobject):
	if dmobject.count('.') == 1:
		cmd = 'awk \'/DMLEAF tRoot_181_Params/,/^{0}$/\' ../dmtree/tr181/device.c'
		res = os.popen(cmd).read()
	else:
		array_name = ""
		obj = dmobject.split(".")
		if "Device.IP.Diagnostics." in dmobject:
			file = "../dmtree/tr143/diagnostics.c"
		else:
			file = "../dmtree/tr181/%s.c" % obj[1].lower()
		if(os.path.isfile(file)):
			dmobject = dmobject.replace(".{i}.", ".")
			count = dmobject.count('.')
			obj1 = dmobject.split(".")
			for i in range(count-1):
				array_name += obj1[i+1]
			cmd = 'awk \'/DMLEAF t%sParams/,/^{0}$/\' %s' % (array_name, file)
			res = os.popen(cmd).read()
		else:
			res = ""

	if res == "":
		return "", 0
	else:
		return res, 1

def printOBJPARAM(obj, supported):
	fp = open('./.tmp', 'a')
	print >> fp,  "%s::%s" % (obj, supported)
	fp.close()

def printusage():
	print "Usage: " + sys.argv[0] + " <json data model>"
	print "Examples:"
	print "  - " + sys.argv[0] + " tr181.json"
	print "    ==> Generate excel file in tr181.xls"

def object_parse_childs( dmobject , value ):
	hasobj = objhaschild(value)
	hasparam = objhasparam(value)

	if dmobject.count('.') == 1:
		printOBJPARAM(dmobject, "true")
	else:
		supported = check_obj(dmobject)
		printOBJPARAM(dmobject, supported)		

	if hasparam:
		res, load = load_param(dmobject)
		if isinstance(value,dict):
			for k,v in value.items():
				if k == "mapping":
					continue
				if isinstance(v,dict):
					for k1,v1 in v.items():
						if k1 == "type" and v1 != "object":
							if load == "0":
								printOBJPARAM(dmobject + k, "false")
							else:
								supported = check_param(k, res)
								printOBJPARAM(dmobject + k, supported)
							break

	if hasobj:
		if isinstance(value,dict):
			for k,v in value.items():
				if isinstance(v,dict):
					for k1,v1 in v.items():
						if k1 == "type" and v1 == "object":
							object_parse_childs(k , v)

def generatecfromobj(pobj, pvalue):
	removefile("./.tmp")
	removefile("./tr181.xls")
	object_parse_childs(pobj, pvalue)

	wb = Workbook()
	sheet = wb.add_sheet('CWMP-USP')
	style0 = xlwt.easyxf('pattern: pattern solid, fore_colour yellow;''font: bold 1, color blue;''alignment: horizontal center;')
	style1 = xlwt.easyxf('pattern: pattern solid, fore_colour red;''font: bold 1, color black;''alignment: horizontal center;')
	style2 = xlwt.easyxf('pattern: pattern solid, fore_colour green;''font: bold 1, color black;''alignment: horizontal center;')
	sheet.write(0, 0, 'OBJ/PARAM', style0)
	sheet.write(0, 1, 'Status', style0)
	i = 0
	file = open("./.tmp", "r")
	for line in file:
		param = line.split("::")
		i += 1
		sheet.write(i, 0, param[0])
		if param[1] == "false\n":
			sheet.write(i, 1, "Not Supported", style1)
		else:
			sheet.write(i, 1, "Supported", style2)

	sheet.col(0).width = 1300*20
	sheet.col(1).width = 175*20
	wb.save('tr181.xls') 
	removefile("./.tmp")

### main ###
if len(sys.argv) < 2:
	printusage()
	exit(1)
	
if (sys.argv[1]).lower() == "-h" or (sys.argv[1]).lower() == "--help":
	printusage()
	exit(1)

model_root_name = "Root"
json_file = sys.argv[1]

with open(json_file) as file:
	data = json.loads(file.read(), object_pairs_hook=OrderedDict)

for i,(key,value) in enumerate(data.items()):
	objstart = key
	device = key.split(".")
	dmroot = device[0]

	if dmroot == None:
		print "Wrong JSON Data model format!"
		exit(1)

	generatecfromobj(objstart, value)


if (os.path.isfile("tr181.xls")):
	print "tr181.xls excel file generated"
else:
	print "No Excel file generated!"

