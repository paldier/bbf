#!/usr/bin/python

# Copyright (C) 2019 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

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

def getprotocols( value ):
	if isinstance(value, dict):
		for obj, val in value.items():
			if obj == "protocols" and isinstance(val, list):
				if len(val) == 2:
					return "CWMP+USP"
				elif val[0] == "usp":
					return "USP"
				else:
					return "CWMP"
	return "CWMP+USP"

def check_obj(dmobject):
	dmobject = dmobject.replace(".{i}.", ".")
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
		elif "Device.Services." in dmobject:
			file = "../dmtree/tr104/voice_services.c"
		elif "Device.SoftwareModules." in dmobject:
			file = "../dmtree/tr157/softwaremodules.c"
		elif "Device.BulkData." in dmobject:
			file = "../dmtree/tr157/bulkdata.c"
		else:
			file = "../dmtree/tr181/%s.c" % obj[1].lower()
		if(os.path.isfile(file)):
			count = dmobject.count('.')
			obj1 = dmobject.split(".")
			for i in range(count-2):
				array_name += obj1[i+1]
			cmd = 'awk \'/DMOBJ t%sObj/,/^{0}$/\' %s' % (array_name, file)
			res = os.popen(cmd).read()
			string = "\n{\"%s\"," % obj1[count - 1]
		else:
			return "No"

	if string in res:
		return "Yes"
	else:
		return "No"

def check_param(param, res):
	string = "\n{\"%s\"," % param
	if string in res:
		return "Yes"
	else:
		return "No"

def check_commands(param):
	cmd = 'awk \'/static struct op_cmd operate_helper/,/^};$/\' ../dmoperate.c'
	res = os.popen(cmd).read()
	param = param.replace(".{i}.", ".*.")
	param = param.replace("()", "")
	string = "\n\t{\"%s\"," % param
	if string in res:
		return "Yes"
	else:
		return "No"

def load_param(dmobject):
	if dmobject.count('.') == 1:
		cmd = 'awk \'/DMLEAF tRoot_181_Params/,/^{0}$/\' ../dmtree/tr181/device.c'
		res = os.popen(cmd).read()
	else:
		array_name = ""
		obj = dmobject.split(".")
		if "Device.IP.Diagnostics." in dmobject:
			file = "../dmtree/tr143/diagnostics.c"
		elif "Device.Time." in dmobject:
			file = "../dmtree/tr181/times.c"
		elif "Device.Services." in dmobject:
			file = "../dmtree/tr104/voice_services.c"
		elif "Device.SoftwareModules." in dmobject:
			file = "../dmtree/tr157/softwaremodules.c"
		elif "Device.BulkData." in dmobject:
			file = "../dmtree/tr157/bulkdata.c"
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

def printOBJPARAM(obj, supported, protocols, types):
	fp = open('./.tmp', 'a')
	print >> fp,  "%s::%s::%s::%s::" % (obj, protocols, supported, types)
	fp.close()

def printusage():
	print "Usage: " + sys.argv[0] + " <json data model>"
	print "Examples:"
	print "  - " + sys.argv[0] + " tr181.json"
	print "    ==> Generate excel file in tr181.xls"
	print "  - " + sys.argv[0] + " tr104.json"
	print "    ==> Generate excel file in tr104.xls"

def object_parse_childs( dmobject , value ):
	hasobj = objhaschild(value)
	hasparam = objhasparam(value)

	if dmobject.count('.') == 1:
		printOBJPARAM(dmobject, "Yes", "CWMP+USP", "object")
	else:
		supported = check_obj(dmobject)
		printOBJPARAM(dmobject, supported, getprotocols(value), "object")		

	if hasparam:
		res, load = load_param(dmobject)
		if isinstance(value,dict):
			for k,v in value.items():
				if k == "mapping":
					continue
				if isinstance(v,dict):
					param_proto = getprotocols(v)
					for k1,v1 in v.items():
						if k1 == "type" and v1 != "object":
							if "()" in k:
								supported = check_commands(dmobject + k)
								printOBJPARAM(dmobject + k, supported, param_proto, "operate")
							elif load == "0":
								printOBJPARAM(dmobject + k, "No", param_proto, "parameter")
							else:
								supported = check_param(k, res)
								printOBJPARAM(dmobject + k, supported, param_proto, "parameter")
							break

	if hasobj:
		if isinstance(value,dict):
			for k,v in value.items():
				if isinstance(v,dict):
					for k1,v1 in v.items():
						if k1 == "type" and v1 == "object":
							object_parse_childs(k , v)

def generatecfromobj(excel_file, pobj, pvalue):
	removefile("./.tmp")
	removefile("./"+excel_file)
	object_parse_childs(pobj, pvalue)

	wb = Workbook(style_compression=2)
	sheet = wb.add_sheet('CWMP-USP')
	xlwt.add_palette_colour("custom_colour_yellow", 0x10)
	xlwt.add_palette_colour("custom_colour_green", 0x20)
	xlwt.add_palette_colour("custom_colour_grey", 0x30)
	wb.set_colour_RGB(0x10, 255, 255, 153)
	wb.set_colour_RGB(0x20, 102, 205, 170)
	wb.set_colour_RGB(0x30, 153, 153, 153)

	style_title = xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_grey;''font: bold 1, color black;''alignment: horizontal center;')
	sheet.write(0, 0, 'OBJ/PARAM/OPERATE', style_title)
	sheet.write(0, 1, 'Protocols', style_title)
	sheet.write(0, 2, 'Supported', style_title)

	i = 0
	file = open("./.tmp", "r")
	for line in file:
		param = line.split("::")
		i += 1

		if param[3] == "object":
			style_name = xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_yellow')
			style = xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_yellow;''alignment: horizontal center;')
		elif param[3] == "operate":
			style_name = xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_green')
			style = xlwt.easyxf('pattern: pattern solid, fore_colour custom_colour_green;''alignment: horizontal center;')
		else:
			style_name = None
			style = xlwt.easyxf('alignment: horizontal center;')

		if style_name != None:
			sheet.write(i, 0, param[0], style_name)
		else:
			sheet.write(i, 0, param[0])

		sheet.write(i, 1, param[1], style)
		sheet.write(i, 2, param[2], style)

	sheet.col(0).width = 1300*20
	sheet.col(1).width = 175*20
	sheet.col(2).width = 175*20
	wb.save(excel_file) 
	removefile("./.tmp")

### main ###
if len(sys.argv) < 2:
	printusage()
	exit(1)
	
if (sys.argv[1]).lower() == "-h" or (sys.argv[1]).lower() == "--help":
	printusage()
	exit(1)

model_root_name = "Root"
if "tr181" in sys.argv[1]:
	excel_file = "tr181.xls"
elif "tr104" in sys.argv[1]:
	excel_file = "tr104.xls"

with open(sys.argv[1]) as file:
	data = json.loads(file.read(), object_pairs_hook=OrderedDict)

for obj, value in data.items():
	if obj == None:
		print "Wrong JSON Data model format!"
		exit(1)

	generatecfromobj(excel_file, obj, value)

if (os.path.isfile(excel_file)):
	print "%s excel file generated" % excel_file
else:
	print "No Excel file generated!"
