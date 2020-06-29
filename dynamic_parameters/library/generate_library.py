#!/usr/bin/python

# Copyright (C) 2020 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os
import sys
import time
import json
from collections import OrderedDict

arrtype = {
"string": "DMT_STRING",
"unsignedInt": "DMT_UNINT",
"unsignedLong": "DMT_UNLONG",
"int": "DMT_INT",
"long": "DMT_LONG",
"boolean": "DMT_BOOL",
"dateTime": "DMT_TIME",
"hexBinary": "DMT_HEXBIN",
"base64": "DMT_BASE64",
}

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

def getlastname( name ):
	lastname = name
	lastname = lastname.replace(".{i}", "")
	namelist = lastname.split('.')
	lastname = namelist[-1]
	if lastname == "":
		lastname = namelist[-2]
	return lastname;

def getname( objname ):
	OBJSname = objname
	if (objname.count('.') > 1 and (objname.count('.') != 2 or objname.count('{i}') != 1)):
		OBJSname = objname.replace("Device", "", 1)
	OBJSname = OBJSname.replace("{i}", "")
	OBJSname = OBJSname.replace(".", "")
	if (objname.count('.') == 1):
		OBJSname = "Device"
		return OBJSname
	return OBJSname;

def getoptionparam( value, option ):
	val = "false"
	if isinstance(value,dict):
		for k,v in value.items():
			if k == option:
				return v
	return val

def getprotocolsparam( value, option ):
	if isinstance(value,dict):
		for k,v in value.items():
			if k == option and isinstance(v, list):
				if len(v) == 2:
					return "BBFDM_BOTH"
				elif v[0] == "usp":
					return "BBFDM_USP"
				else:
					return "BBFDM_CWMP"
	return "BBFDM_BOTH"

def getparamtype( value ):
	ptype = None
	paramtype = getoptionparam(value, "type")
	ptype = arrtype.get(paramtype, None)
	if ptype == None:
		ptype = "__NA__"
	return ptype

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

def printheaderObjCommon( objname ):
	fp = open('./.objparamarray.c', 'a')
	print >> fp, "/* *** %s *** */" % objname
	fp.close()

def cprintheaderOBJS( objname ):
	fp = open('./.objparamarray.c', 'a')
	print >> fp,  "DMOBJ %s[] = {" % ("tdynamic" + getname(objname) + "Obj")
	print >> fp,  "/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/"
	fp.close()

def cprintheaderRootDynamicObj( ):
	fp = open('./.objroot.c', 'a')
	print >> fp, "/* ********** RootDynamicObj ********** */"
	print >> fp,  "LIB_MAP_OBJ tRootDynamicObj[] = {"
	print >> fp,  "/* parentobj, nextobject */"
	fp.close()

def cprintheaderRootDynamicOperate( ):
	fp = open('./.objroot.c', 'a')
	print >> fp, "/* ********** RootDynamicOperate ********** */"
	print >> fp,  "LIB_MAP_OPERATE tRootDynamicOperate[] = {"
	print >> fp,  "/* pathname, operation, type */"
	fp.close()

def printObjRootDynamic( dmobject ):
	commonname = getname(dmobject)
	fp = open('./.objroot.c', 'a')
	print >> fp,  "{\"%s\", %s}," % (dmobject, "tdynamic" + commonname + "Obj")
	fp.close()

def printOperateRootDynamic( dmobject, commonname , optype):
	fp = open('./.objroot.c', 'a')
	print >> fp,  "{\"%s\", %s, \"%s\"}," % (dmobject, "dynamic" + commonname + "Operate", optype)
	fp.close()

def printtailArrayRootDynamic( ):
	fp = open('./.objroot.c', 'a')
	print >> fp,  "{0}"
	print >> fp,  "};"
	print >> fp,  ""
	fp.close()

def hprintheaderOBJS( objname ):
	fp = open('./.objparamarray.h', 'a')
	print >> fp,  "DMOBJ %s[];" % ("tdynamic" + getname(objname) + "Obj")
	fp.close()

def cprinttopfile ( fp ):
	print >> fp, "/*"
	print >> fp, " * Copyright (C) 2020 iopsys Software Solutions AB"
	print >> fp, " *"
	print >> fp, " * This program is free software; you can redistribute it and/or modify"
	print >> fp, " * it under the terms of the GNU Lesser General Public License version 2.1"
	print >> fp, " * as published by the Free Software Foundation"
	print >> fp, " *"
	print >> fp, " *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>"
	print >> fp, " */"
	print >> fp, ""
	print >> fp, "#include <libbbfdm/dmbbf.h>"
	print >> fp, "#include <libbbfdm/dmcommon.h>"
	print >> fp, "#include <libbbfdm/dmuci.h>"
	print >> fp, "#include <libbbfdm/dmubus.h>"
	print >> fp, "#include <libbbfdm/dmjson.h>"
	print >> fp, "#include <libbbfdm/dmentry.h>"
	print >> fp, "#include <libbbfdm/dmoperate.h>"
	print >> fp, "#include \"example.h\""
	print >> fp, ""

def hprinttopfile ( fp ):
	print >> fp, "/*"
	print >> fp, " * Copyright (C) 2020 iopsys Software Solutions AB"
	print >> fp, " *"
	print >> fp, " * This program is free software; you can redistribute it and/or modify"
	print >> fp, " * it under the terms of the GNU Lesser General Public License version 2.1"
	print >> fp, " * as published by the Free Software Foundation"
	print >> fp, " *"
	print >> fp, " *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>"
	print >> fp, " */"
	print >> fp, ""
	print >> fp, "#ifndef __EXAMPLE_H"
	print >> fp, "#define __EXAMPLE_H"
	print >> fp, ""

def printmakefile ( fp ):
	print >> fp, "LIB_EXAMPLE := lib/libexample.so"
	print >> fp, ""
	print >> fp, "OBJS  := example.o"
	print >> fp, ""
	print >> fp, "PROG_CFLAGS = $(CFLAGS) -fstrict-aliasing"
	print >> fp, "PROG_LDFLAGS = $(LDFLAGS) -lbbfdm"
	print >> fp, "FPIC := -fPIC"
	print >> fp, ""
	print >> fp, ".PHONY: all"
	print >> fp, ""
	print >> fp, "%.o: %.c"
	print >> fp, "	$(CC) $(PROG_CFLAGS) $(FPIC) -c -o $@ $<"
	print >> fp, ""
	print >> fp, "all: $(LIB_EXAMPLE)"
	print >> fp, ""
	print >> fp, "$(LIB_EXAMPLE): $(OBJS)"
	print >> fp, "	$(shell mkdir -p lib)"
	print >> fp, "	$(CC) -shared -Wl,-soname,libexample.so $^ -o $@"
	print >> fp, ""
	print >> fp, "clean:"
	print >> fp, "	rm -f *.o"
	print >> fp, "	rm -f $(LIB_EXAMPLE)"
	print >> fp, ""

def hprintfootfile ( fp ):
	print >> fp, ""
	print >> fp, "#endif //__EXAMPLE_H"
	print >> fp, ""

def cprintAddDelObj( faddobj, fdelobj, name, mappingobj, dmobject ):
	fp = open('./.objadddel.c', 'a')
	print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char **instance)" % faddobj
	print >> fp, "{"
	print >> fp, "	//TODO"
	print >> fp, "	return 0;"
	print >> fp, "}"
	print >> fp, ""
	print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)" % fdelobj
	print >> fp, "{"
	print >> fp, "	switch (del_action) {"
	print >> fp, "		case DEL_INST:"
	print >> fp, "			//TODO"
	print >> fp, "			break;"
	print >> fp, "		case DEL_ALL:"
	print >> fp, "			//TODO"
	print >> fp, "			break;"
	print >> fp, "	}"
	print >> fp, "	return 0;"
	print >> fp, "}"
	print >> fp, ""
	fp.close()

def hprintAddDelObj( faddobj, fdelobj ):
	fp = open('./.objadddel.h', 'a')
	print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char **instance);" % faddobj
	print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);" % fdelobj
	fp.close()

def cprintBrowseObj( fbrowse, name, mappingobj, dmobject ):
	fp = open('./.objbrowse.c', 'a')
	print >> fp, "int %s(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)" % fbrowse
	print >> fp, "{"
	print >> fp, "	//TODO"
	print >> fp, "	return 0;"
	print >> fp, "}"
	print >> fp, ""
	fp.close()

def hprintBrowseObj( fbrowse ):
	fp = open('./.objbrowse.h', 'a')
	print >> fp, "int %s(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);" % fbrowse
	fp.close()

def cprintGetSetValue(getvalue, setvalue, mappingparam, instance, typeparam, parentname, dmparam):
	fp = open('./.getstevalue.c', 'a')
	print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)" % getvalue
	print >> fp, "{"
	print >> fp, "	//TODO"
	print >> fp, "	return 0;"
	print >> fp, "}"
	print >> fp, ""
	if setvalue != "NULL":
		print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)" % setvalue
		print >> fp, "{"
		print >> fp, "	switch (action)	{"
		print >> fp, "		case VALUECHECK:"
		print >> fp, "			break;"
		print >> fp, "		case VALUESET:"
		print >> fp, "			//TODO"
		print >> fp, "			break;"
		print >> fp, "	}"
		print >> fp, "	return 0;"
		print >> fp, "}"
		print >> fp, ""
	fp.close()

def hprintGetSetValue( getvalue, setvalue ):
	fp = open('./.getstevalue.h', 'a')
	print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);" % getvalue
	if setvalue != "NULL":
		print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);" % setvalue
	fp.close()

def cprintOperate( get_operate ):
	fp = open('./.operate.c', 'a')
	print >> fp, "opr_ret_t %s(struct dmctx *dmctx, char *path, char *input)" % ("dynamic" + get_operate + "Operate")
	print >> fp, "{"
	print >> fp, "	return SUCCESS;"
	print >> fp, "}"
	fp.close()

def cprintheaderPARAMS( objname ):
	fp = open('./.objparamarray.c', 'a')
	print >> fp,  "DMLEAF %s[] = {" % ("tdynamic" + getname(objname) + "Params")
	print >> fp,  "/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/"
	fp.close()

def hprintOperate( get_operate ):
	fp = open('./.operate.h', 'a')
	print >> fp, "opr_ret_t %s(struct dmctx *dmctx, char *path, char *input);" % ("dynamic" + get_operate + "Operate")
	fp.close()

def hprintheaderPARAMS( objname ):
	fp = open('./.objparamarray.h', 'a')
	print >> fp,  "DMLEAF %s[];" % ("tdynamic" + getname(objname) + "Params")
	fp.close()

def printPARAMline( parentname, dmparam, value ):
	commonname = getname(parentname) + "_" + dmparam
	ptype = getparamtype(value)
	getvalue = "getdynamic_" + commonname
	mappingparam = getoptionparam(value, "mapping")
	typeparam = getoptionparam(value, "type")
	bbfdm = getprotocolsparam(value, "protocols")
	accessparam = getoptionparam(value, "write")

	if accessparam:
		access = "&DMWRITE"
		setvalue = "setdynamic_" + commonname
	else:
		access = "&DMREAD"
		setvalue = "NULL"

	if parentname.endswith(".{i}."):
		instance = "TRUE"
	else:
		instance = "FALSE"

	cprintGetSetValue(getvalue, setvalue, mappingparam, instance, typeparam, parentname, dmparam)
	hprintGetSetValue(getvalue, setvalue)

	fp = open('./.objparamarray.c', 'a')
	print >> fp,  "{\"%s\", %s, %s, %s, %s, NULL, NULL, %s}," % (dmparam, access, ptype, getvalue, setvalue, bbfdm)
	fp.close()

def printtailArray( ):
	fp = open('./.objparamarray.c', 'a')
	print >> fp,  "{0}"
	print >> fp,  "};"
	print >> fp,  ""
	fp.close()

def printOBJline( dmobject, value ):
	commonname = getname(dmobject)
	hasobj = objhaschild(value)
	hasparam = objhasparam(value)
	accessobj = getoptionparam(value, "access")
	mappingobj = getoptionparam(value, "mapping")
	bbfdm = getprotocolsparam(value, "protocols")

	if accessobj:
		access = "&DMWRITE"
		faddobj = "adddynamicObj" + commonname
		fdelobj = "deldynamicObj" + commonname
		cprintAddDelObj(faddobj, fdelobj, (getlastname(dmobject)).lower(), mappingobj, dmobject)
		hprintAddDelObj(faddobj, fdelobj)
	else:
		access = "&DMREAD"
		faddobj = "NULL"
		fdelobj = "NULL"

	if dmobject.endswith(".{i}."):
		fbrowse = "browse" + commonname + "Inst"
		cprintBrowseObj(fbrowse, (getlastname(dmobject)).lower(), mappingobj, dmobject)
		hprintBrowseObj(fbrowse)
	else:
		fbrowse = "NULL"

	if hasobj:
		objchildarray = "tdynamic" + commonname + "Obj"
	else:
		objchildarray = "NULL"

	if hasparam:
		paramarray = "tdynamic" + commonname + "Params"
	else:
		paramarray = "NULL"

	fp = open('./.objparamarray.c', 'a')
	print >> fp,  "{\"%s\", %s, %s, %s, NULL, %s, NULL, NULL, NULL, %s, %s, NULL, %s}," % (getlastname(dmobject), access, faddobj, fdelobj, fbrowse, objchildarray, paramarray, bbfdm)
	fp.close()

def printusage():
	print "Usage: " + sys.argv[0] + " <json file>"
	print "Examples:"
	print "  - " + sys.argv[0] + " example.json"
	print "    ==> Generate the C code in example/ folder"

def object_parse_childs( dmobject , value, nextlevel ):
	hasobj = objhaschild(value)
	hasparam = objhasparam(value)

	if hasobj or hasparam:
		printheaderObjCommon(dmobject)

	if hasobj:
		cprintheaderOBJS(dmobject)
		hprintheaderOBJS(dmobject)

		if isinstance(value,dict):
			for k,v in value.items():
				if isinstance(v,dict):
					for k1,v1 in v.items():
						if k1 == "type" and v1 == "object":
							printOBJline(k, v)
							break
		printtailArray()

	if hasparam:
		cprintheaderPARAMS(dmobject)
		hprintheaderPARAMS(dmobject)
		if isinstance(value,dict):
			for k,v in value.items():
				if k == "mapping":
					continue
				if isinstance(v,dict):
					for k1,v1 in v.items():
						if k1 == "type" and v1 != "object":
							printPARAMline(dmobject, k, v)
							break
		printtailArray()

	if hasobj and nextlevel == 0:
		if isinstance(value,dict):
			for k,v in value.items():
				if isinstance(v,dict):
					for k1,v1 in v.items():
						if k1 == "type" and v1 == "object":
							object_parse_childs(k , v, 0)

def generatecfiles( pdir ):
	securemkdir(pdir)
	dmfpc = open(pdir + "/example" + ".c", "w")
	dmfph = open(pdir + "/example" + ".h", "w")
	makefile = open(pdir + "/Makefile", "w")

	cprinttopfile(dmfpc)
	hprinttopfile(dmfph)
	printmakefile(makefile)

	try:
		tmpf = open("./.objroot.c", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfpc.write(tmpd)
	except:
		pass
	try:
		tmpf = open("./.objparamarray.c", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfpc.write(tmpd)
	except:
		pass
	try:
		tmpf = open("./.objparamarray.h", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfph.write(tmpd)
		print >> dmfph,  ""
	except:
		pass
	try:
		exists = os.path.isfile("./.objbrowse.c")
		if exists:
			print >> dmfpc,  "/*************************************************************"
			print >> dmfpc,  " * ENTRY METHOD"
			print >> dmfpc,  "/*************************************************************/"
		tmpf = open("./.objbrowse.c", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfpc.write(tmpd)
	except:
		pass
	try:
		tmpf = open("./.objbrowse.h", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfph.write(tmpd)
		print >> dmfph,  ""
	except:
		pass
	try:
		exists = os.path.isfile("./.objadddel.c")
		if exists:
			print >> dmfpc,  "/*************************************************************"
			print >> dmfpc,  " * ADD & DEL OBJ"
			print >> dmfpc,  "/*************************************************************/"
		tmpf = open("./.objadddel.c", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfpc.write(tmpd)
	except:
		pass
	try:
		tmpf = open("./.objadddel.h", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfph.write(tmpd)
		print >> dmfph,  ""
	except:
		pass
	try:
		exists = os.path.isfile("./.getstevalue.c")
		if exists:
			print >> dmfpc,  "/*************************************************************"
			print >> dmfpc,  " * GET & SET PARAM"
			print >> dmfpc,  "/*************************************************************/"
		tmpf = open("./.getstevalue.c", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfpc.write(tmpd)
	except:
		pass
	try:
		tmpf = open("./.getstevalue.h", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfph.write(tmpd)
	except:
		pass
	try:
		exists = os.path.isfile("./.operate.c")
		if exists:
			print >> dmfpc,  "/*************************************************************"
			print >> dmfpc,  " * OPERATE"
			print >> dmfpc,  "/*************************************************************/"
		tmpf = open("./.operate.c", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfpc.write(tmpd)
	except:
		pass
	try:
		tmpf = open("./.operate.h", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfph.write(tmpd)
	except:
		pass
	hprintfootfile(dmfph)
	removetmpfiles()

def generatestartedobject( key , value ):
	obj_type = getoptionparam(value, "type")
	if obj_type == "operate":
	        op_type = getoptionparam(value, "optype")
		key = key.replace(".{i}.", ".*.")
		if key not in DictOperate:
			DictOperate[key] = op_type;
	else:
		key = key.replace(".{i}", "")
		obj = '.'.join(key.split(".")[0:key.count('.')-1]) + '.'
		if obj not in ListObjects:
			ListObjects.append(obj) 

def generateRootDynamicarray( ):
	cprintheaderRootDynamicObj()
	for x in ListObjects:
		printObjRootDynamic(x)
	printtailArrayRootDynamic()

	cprintheaderRootDynamicOperate()
	for x in DictOperate:
		commonname = getname(x)
		printOperateRootDynamic(x, commonname, DictOperate[x])
		cprintOperate(commonname)
		hprintOperate(commonname)
	printtailArrayRootDynamic()	

def removetmpfiles( ):
	removefile("./.objparamarray.c")
	removefile("./.objparamarray.h")
	removefile("./.objadddel.c")
	removefile("./.objadddel.h")
	removefile("./.objbrowse.c")
	removefile("./.objbrowse.h")
	removefile("./.getstevalue.c")
	removefile("./.getstevalue.h")
	removefile("./.operate.c")
	removefile("./.operate.h")
	removefile("./.objroot.c")

### main ###
if len(sys.argv) < 2:
	printusage()
	exit(1)
	
if (sys.argv[1]).lower() == "-h" or (sys.argv[1]).lower() == "--help":
	printusage()
	exit(1)

json_file = sys.argv[1]
gendir = "example"
removetmpfiles()

with open(json_file) as file:
	data = json.loads(file.read(), object_pairs_hook=OrderedDict)

ListObjects = []
DictOperate = {}
for i,(key,value) in enumerate(data.items()):
	generatestartedobject(key, value)

generateRootDynamicarray()

for x in ListObjects:
	printheaderObjCommon(x)
	cprintheaderOBJS(x)
	hprintheaderOBJS(x)
	for i,(key,value) in enumerate(data.items()):
		obj_type = getoptionparam(value, "type")
		if obj_type == "operate":
			continue
		objstart = key
		key = key.replace(".{i}", "")
		obj = '.'.join(key.split(".")[0:key.count('.')-1]) + '.'
		if x == obj:
			printOBJline(objstart, value)
	printtailArray()

for i,(key,value) in enumerate(data.items()):
	objstart = key
	device = key.split(".")
	if device[0] == None:
		print "Wrong JSON Data model format!"
		exit(1)
	object_parse_childs(objstart, value, 0)

generatecfiles(gendir)

if (os.path.isdir(gendir)):
	print "Source code generated under \"./%s\" folder" % gendir
else:
	print "No source code generated!"

