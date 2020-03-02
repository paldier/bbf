#!/usr/bin/python

# Copyright (C) 2020 iopsys Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>

import os, sys, time, json
from collections import OrderedDict

arrTypes = { "string": "DMT_STRING",
			"unsignedInt": "DMT_UNINT",
			"unsignedLong": "DMT_UNLONG",
			"int": "DMT_INT",
			"long": "DMT_LONG",
			"boolean": "DMT_BOOL",
			"dateTime": "DMT_TIME",
			"hexBinary": "DMT_HEXBIN",
			"base64": "DMT_BASE64"}

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
	return name.replace(".{i}", "").split('.')[-2];

def getname( objname ):
	global model_root_name
	OBJSname = objname
	if (objname.count('.') > 1 and (objname.count('.') != 2 or objname.count('{i}') != 1) ):
		OBJSname = objname.replace("Device", "", 1)
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

def getoptionparam( value, option ):
	if isinstance(value, dict):
		for obj, val in value.items():
			if obj == option:
				return val
	return None

def getarrayoptionparam( value, option ):
	if isinstance(value, dict):
		for obj, val in value.items():
			if obj == option and isinstance(val, list):
				return val
	return None

def getprotocolsparam( value, option ):
	if isinstance(value, dict):
		for obj, val in value.items():
			if obj == option and isinstance(val, list):
				if len(val) == 2:
					return "BBFDM_BOTH"
				elif val[0] == "usp":
					return "BBFDM_USP"
				else:
					return "BBFDM_CWMP"
	return "BBFDM_BOTH"

def getargsparam( value ):
	if isinstance(value, dict):
		for obj, val in value.items():
			return obj, val
	return None, None

def getparamtype( value ):
	paramtype = getoptionparam(value, "type")
	return arrTypes.get(paramtype, None)

def objhaschild( value ):
	if isinstance(value, dict):
		for obj, val in value.items():
			if isinstance(val, dict):
				for obj1, val1 in val.items():
					if obj1 == "type" and val1 == "object":
						return 1
	return 0

def objhasparam( value ):
	if isinstance(value, dict):
		for obj, val in value.items():
			if isinstance(val, dict):
				for obj1,val1 in val.items():
					if obj1 == "type" and val1 != "object":
						return 1
	return 0

def get_mapping_param( mappingobj ):
	type = getoptionparam(mappingobj, "type")
	if type == "uci":
		uciobj = getoptionparam(mappingobj, "uci")
		file = getoptionparam(uciobj, "file")
		sectionobj = getoptionparam(uciobj, "section")
		sectiontype = getoptionparam(sectionobj, "type")
		sectionname = getoptionparam(sectionobj, "name")
		sectionindex = getoptionparam(sectionobj, "index")
		optionobj = getoptionparam(uciobj, "option")
		optionname = getoptionparam(optionobj, "name")
		return type, file, sectiontype, sectionname, sectionindex, optionname
	elif type == "ubus":
		ubusobj = getoptionparam(mappingobj, "ubus")
		object = getoptionparam(ubusobj, "object")
		method = getoptionparam(ubusobj, "method")
		argsobj = getoptionparam(ubusobj, "args")
		arg1, arg2 = getargsparam(argsobj)
		key = getoptionparam(ubusobj, "key")
		return type, object, method, arg1, arg2, key
	else:
		cliobj = getoptionparam(mappingobj, "cli")
		command = getoptionparam(cliobj, "command")
		argsobj = getoptionparam(cliobj, "args")
		i = 0
		value = ""
		list_length = len(argsobj)
		while i < list_length:
			if value == "":
				value = "\"" + argsobj[i] + "\", "
			elif i == list_length-1:
				value = value + "\"" + argsobj[i] + "\""
			else:
				value = value + "\"" + argsobj[i] + "\", "
			i += 1
		return type, command, list_length, value, "", ""

def printGlobalstrCommon( str_exp ):
	if "tr104" in sys.argv[1]:
		common = "tr104/common.c"
	else:
		common = "tr181/common.c"
	fp = open(common, 'a')
	print >> fp, "%s" % str_exp
	fp.close()

def get_mapping_obj( mappingobj ):
	type = getoptionparam(mappingobj, "type")
	uciobj = getoptionparam(mappingobj, "uci")
	file = getoptionparam(uciobj, "file")
	sectionobj = getoptionparam(uciobj, "section")
	sectiontype = getoptionparam(sectionobj, "type")
	dmmapfile = getoptionparam(uciobj, "dmmapfile")
	return type, file, sectiontype, dmmapfile

def generate_validate_value(dmparam, value):
	validate_value = ""
	maxsizeparam = "NULL"
	itemminparam = "NULL"
	itemmaxparam = "NULL"
	rangeminparam = "NULL"
	rangemaxparam = "NULL"

	listparam = getoptionparam(value, "list")
	if listparam != None:
		datatypeparam = getoptionparam(listparam, "datatype")
		maxsizeparam = getoptionparam(listparam, "maxsize")
		if maxsizeparam == None: maxsizeparam = "NULL"
		itemparam = getoptionparam(listparam, "item")
		if itemparam != None:
			itemminparam = getoptionparam(itemparam, "min")
			if itemminparam == None: itemminparam = "NULL"
			itemmaxparam = getoptionparam(itemparam, "max")
			if itemmaxparam == None: itemmaxparam = "NULL"
		rangeparam = getoptionparam(listparam, "range")
		if rangeparam != None:
			rangeminparam = getoptionparam(rangeparam, "min")
			if rangeminparam == None: rangeminparam = "NULL"
			rangemaxparam = getoptionparam(rangeparam, "max")
			if rangemaxparam == None: rangemaxparam = "NULL"
		enumarationsparam = getarrayoptionparam(listparam, "enumerations")
		if enumarationsparam != None:
			list_enumarationsparam = enumarationsparam
			enum_length = len(list_enumarationsparam)
			enumarationsparam = dmparam if datatypeparam == "string" else datatypeparam
			str_enum = "char *%s[] = {" % enumarationsparam
			for i in range(enum_length):
				str_enum += "\"%s\", " % list_enumarationsparam[i]
			str_enum += "NULL};"
			printGlobalstrCommon(str_enum)
		else:
			enumarationsparam = "NULL"
		patternparam = getarrayoptionparam(listparam, "pattern")
		if patternparam != None:
			list_patternparam = patternparam
			pattern_length = len(list_patternparam)
			patternparam = dmparam if datatypeparam == "string" else datatypeparam
			str_pattern = "char *%s[] = {" % patternparam
			for i in range(pattern_length):
				str_pattern += "\"^%s$\", " % list_patternparam[i]
			str_pattern += "NULL};"
			printGlobalstrCommon(str_pattern)
		elif datatypeparam == "IPAddress":
			patternparam = "IPAddress"
		elif datatypeparam == "IPv6Address":
			patternparam = "IPv6Address"
		else:
			patternparam = "NULL"
		if datatypeparam == "unsignedInt":
			validate_value += "			if (dm_validate_unsignedInt_list(value, \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"))\n" % (itemminparam, itemmaxparam, maxsizeparam, rangeminparam, rangemaxparam)
		elif datatypeparam == "int":
			validate_value += "			if (dm_validate_int_list(value, \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"))\n" % (itemminparam, itemmaxparam, maxsizeparam, rangeminparam, rangemaxparam)
		else:
			validate_value += "			if (dm_validate_string_list(value, \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", %s, %s))\n" % (itemminparam, itemmaxparam, maxsizeparam, rangeminparam, rangemaxparam, enumarationsparam, patternparam)
	else:
		datatypeparam = getoptionparam(value, "datatype")
		rangeparam = getoptionparam(value, "range")
		if rangeparam != None:
			rangeminparam = getoptionparam(rangeparam, "min")
			if rangeminparam == None: rangeminparam = "NULL"
			rangemaxparam = getoptionparam(rangeparam, "max")
			if rangemaxparam == None: rangemaxparam = "NULL"
		enumarationsparam = getarrayoptionparam(value, "enumerations")
		if enumarationsparam != None:
			list_enumarationsparam = enumarationsparam
			enum_length = len(list_enumarationsparam)
			enumarationsparam = dmparam if datatypeparam == "string" else datatypeparam
			str_enum = "char *%s[] = {" % enumarationsparam
			for i in range(enum_length):
				str_enum += "\"%s\", " % list_enumarationsparam[i]

			str_enum += "NULL};"
			printGlobalstrCommon(str_enum)
		else:
			enumarationsparam = "NULL"
		patternparam = getarrayoptionparam(value, "pattern")
		if patternparam != None:
			list_patternparam = patternparam
			pattern_length = len(list_patternparam)
			patternparam = dmparam if datatypeparam == "string" else datatypeparam
			str_pattern = "char *%s[] = {" % patternparam
			for i in range(pattern_length):
				str_pattern += "\"^%s$\", " % list_patternparam[i]
			str_pattern += "NULL};"
			printGlobalstrCommon(str_pattern)
		elif datatypeparam == "IPAddress":
			patternparam = "IPAddress"
		elif datatypeparam == "IPv6Address":
			patternparam = "IPv6Address"
		else:
			patternparam = "NULL"
		if datatypeparam == "boolean":
			validate_value += "			if (dm_validate_boolean(value))\n"
		elif datatypeparam == "unsignedInt":
			validate_value += "			if (dm_validate_unsignedInt(value, \"%s\", \"%s\"))\n" % (rangeminparam, rangemaxparam)
		elif datatypeparam == "int":
			validate_value += "			if (dm_validate_int(value, \"%s\", \"%s\"))\n" % (rangeminparam, rangemaxparam)
		elif datatypeparam == "unsignedLong":
			validate_value += "			if (dm_validate_unsignedLong(value, \"%s\", \"%s\"))\n" % (rangeminparam, rangemaxparam)
		elif datatypeparam == "long":
			validate_value += "			if (dm_validate_long(value, \"%s\", \"%s\"))\n" % (rangeminparam, rangemaxparam)
		elif datatypeparam == "dateTime":
			validate_value += "			if (dm_validate_dateTime(value))\n"
		elif datatypeparam == "hexBinary":
			validate_value += "			if (dm_validate_hexBinary(value, \"%s\", \"%s\"))\n" % (rangeminparam, rangemaxparam)			
		else:
			validate_value += "			if (dm_validate_string(value, \"%s\", \"%s\", %s, %s))\n" % (rangeminparam, rangemaxparam, enumarationsparam, patternparam)
	validate_value += "				return FAULT_9007;"
	validate_value = validate_value.replace("\"NULL\"", "NULL")
	return validate_value

def printheaderObjCommon( objname ):
	fp = open('./.objparamarray.c', 'a')
	print >> fp, "/* *** %s *** */" % objname
	fp.close()

def cprintheaderOBJS( objname ):
	fp = open('./.objparamarray.c', 'a')
	print >> fp,  "DMOBJ %s[] = {" % ("t" + getname(objname) + "Obj")
	print >> fp,  "/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/"
	fp.close()

def hprintheaderOBJS( objname ):
	fp = open('./.objparamarray.h', 'a')
	print >> fp,  "extern DMOBJ %s[];" % ("t" + getname(objname) + "Obj")
	fp.close()

def cprinttopfile (fp, filename):
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
	print >> fp, "#include \"%s.h\"" % filename.lower()
	print >> fp, ""

def hprinttopfile (fp, filename):
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
	print >> fp, "#ifndef __%s_H" % filename.upper()
	print >> fp, "#define __%s_H" % filename.upper()
	print >> fp, ""
	print >> fp, "#include <libbbf_api/dmcommon.h>"
	print >> fp, ""

def hprintfootfile (fp, filename):
	print >> fp, ""
	print >> fp, "#endif //__%s_H" % filename.upper()
	print >> fp, ""

def cprintAddDelObj( faddobj, fdelobj, name, mappingobj, dmobject ):
	fp = open('./.objadddel.c', 'a')
	print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char **instance)" % faddobj
	print >> fp, "{"
	if mappingobj != None:
		type, file, sectiontype, dmmapfile = get_mapping_obj(mappingobj)
		if type == "uci":
			print >> fp, "	char *inst, *value, *v;"
			print >> fp, "	struct uci_section *dmmap = NULL, *s = NULL;"
			print >> fp, ""
			print >> fp, "	check_create_dmmap_package(\"%s\");" % dmmapfile
			print >> fp, "	inst = get_last_instance_bbfdm(\"%s\", \"%s\", \"%s\");" % (dmmapfile, sectiontype, name+"instance")
			print >> fp, "	dmuci_add_section_and_rename(\"%s\", \"%s\", &s, &value);" % (file, sectiontype)
			print >> fp, "	//dmuci_set_value_by_section(s, \"option\", \"value\");"
			print >> fp, ""
			print >> fp, "	dmuci_add_section_bbfdm(\"%s\", \"%s\", &dmmap, &v);" % (dmmapfile, sectiontype)
			print >> fp, "	dmuci_set_value_by_section(dmmap, \"section_name\", section_name(s));"
			print >> fp, "	*instance = update_instance_bbfdm(dmmap, inst, \"%s\");" % (name+"instance")
	else:
		print >> fp, "	//TODO"
	print >> fp, "	return 0;"
	print >> fp, "}"
	print >> fp, ""
	print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)" % fdelobj
	print >> fp, "{"
	if mappingobj != None:
		if type == "uci":
			print >> fp, "	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;"
			print >> fp, "	int found = 0;"
			print >> fp, ""
	print >> fp, "	switch (del_action) {"
	if mappingobj != None:
		if type == "uci":
			print >> fp, "		case DEL_INST:"
			print >> fp, "			get_dmmap_section_of_config_section(\"%s\", \"%s\", section_name((struct uci_section *)data), &dmmap_section);" % (dmmapfile, sectiontype)
			print >> fp, "			if (dmmap_section != NULL)"
			print >> fp, "				dmuci_delete_by_section(dmmap_section, NULL, NULL);"
			print >> fp, "			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);"
			print >> fp, "			break;"
			print >> fp, "		case DEL_ALL:"
			print >> fp, "			uci_foreach_sections(\"%s\", \"%s\", s) {" % (file, sectiontype)
			print >> fp, "				if (found != 0) {"
			print >> fp, "					get_dmmap_section_of_config_section(\"%s\", \"%s\", section_name(ss), &dmmap_section);" % (dmmapfile, sectiontype)
			print >> fp, "					if (dmmap_section != NULL)"
			print >> fp, "						dmuci_delete_by_section(dmmap_section, NULL, NULL);"
			print >> fp, "					dmuci_delete_by_section(ss, NULL, NULL);"
			print >> fp, "				}"
			print >> fp, "				ss = s;"
			print >> fp, "				found++;"
			print >> fp, "			}"
			print >> fp, "			if (ss != NULL) {"
			print >> fp, "				get_dmmap_section_of_config_section(\"%s\", \"%s\", section_name(ss), &dmmap_section);" % (dmmapfile, sectiontype)
			print >> fp, "				if (dmmap_section != NULL)"
			print >> fp, "					dmuci_delete_by_section(dmmap_section, NULL, NULL);"
			print >> fp, "				dmuci_delete_by_section(ss, NULL, NULL);"
			print >> fp, "			}"
			print >> fp, "			break;"
	else:
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
	# Open file
	fp = open('./.objbrowse.c', 'a')

	### Mapping Parameter
	if mappingobj != None:
		type, file, sectiontype, dmmapfile = get_mapping_obj(mappingobj)
		print >> fp, "/*#%s!%s:%s/%s/%s*/" % (dmobject, type.upper(), file, sectiontype, dmmapfile)

	print >> fp, "int %s(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)" % fbrowse
	print >> fp, "{"

	# Mapping exist
	if mappingobj != None:

		############################## UCI ########################################
		if type == "uci" :
			print >> fp, "	char *inst = NULL, *inst_last = NULL;"
			print >> fp, "	struct dmmap_dup *p;"
			print >> fp, "	LIST_HEAD(dup_list);"
			print >> fp, ""
			print >> fp, "	synchronize_specific_config_sections_with_dmmap(\"%s\", \"%s\", \"%s\", &dup_list);" % (file, sectiontype, dmmapfile)
			print >> fp, "	list_for_each_entry(p, &dup_list, list) {"
			print >> fp, "		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, p->dmmap_section, \"%s\", \"%s\");" % (name+"instance", name+"alias")
			print >> fp, "		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)"
			print >> fp, "			break;"
			print >> fp, "	}"
			print >> fp, "	free_dmmap_config_dup_list(&dup_list);"


		############################## UBUS ########################################
		elif type == "ubus" :
			print >> fp, "	"


	# Mapping doesn't exist
	else:
		print >> fp, "	//TODO"
	print >> fp, "	return 0;"
	print >> fp, "}"
	print >> fp, ""

	# Close file
	fp.close()

def hprintBrowseObj( fbrowse ):
	fp = open('./.objbrowse.h', 'a')
	print >> fp, "int %s(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);" % fbrowse
	fp.close()

def cprintGetSetValue(getvalue, setvalue, mappingparam, instance, typeparam, parentname, dmparam, value):
	# Open file
	fp = open('./.getstevalue.c', 'a')

	# Generate Validate value
	validate_value = ""
	if setvalue != "NULL":
		validate_value = generate_validate_value(dmparam, value)

	# Mapping exist
	if mappingparam != None:
		count = len(mappingparam)
		i = 0
		mapping = ""
		tmpgetvalue = ""
		tmpsetvalue = ""
		set_value = ""
		for element in mappingparam:
			type, res1, res2, res3, res4, res5 = get_mapping_param(element)
			get_value = ""
			i += 1


			############################## UCI ########################################
			if type == "uci":
				### Mapping Parameter
				if res3 != None:
					mapping = "%s:%s/%s,%s/%s" % (type.upper(), res1, res2, res3, res5)
				else:
					mapping = "%s:%s/%s,%s/%s" % (type.upper(), res1, res2, res4, res5)

				### GET VALUE Parameter
				if "NumberOfEntries" in dmparam:
					get_value += "	struct uci_section *s = NULL;\n"
					get_value += "	int cnt = 0;\n"
					get_value += "\n"
					get_value += "	uci_foreach_sections(\"%s\", \"%s\", s) {\n" % (res1, res2)
					get_value += "		cnt++;\n"
					get_value += "	}\n"
					get_value += "	dmasprintf(value, \"%d\", cnt);"
				elif instance == "TRUE":
					get_value += "	dmuci_get_value_by_section_string((struct uci_section *)data, \"%s\", value);" % res5
				else:
					get_value += "	dmuci_get_option_value_string(\"%s\", \"%s\", \"%s\", value);" % (res1, res3, res5)

				### SET VALUE Parameter
				set_value += "	switch (action)	{\n"
				set_value += "		case VALUECHECK:\n"
				set_value += "%s\n" % validate_value
				set_value += "			break;\n"
				set_value += "		case VALUESET:\n"
				if typeparam == "boolean":
					set_value += "			string_to_bool(value, &b);\n"
					if instance == "TRUE":
						set_value += "			dmuci_set_value_by_section((struct uci_section *)data, \"%s\", b ? \"1\" : \"0\");" % res5
					else:
						set_value += "			dmuci_set_value(\"%s\", \"%s\", \"%s\", b ? \"1\" : \"0\");" % (res1, res3, res5)
				elif instance == "TRUE":
					set_value += "			dmuci_set_value_by_section((struct uci_section *)data, \"%s\", value);" % res5
				else:
					set_value += "			dmuci_set_value(\"%s\", \"%s\", \"%s\", value);" % (res1, res3, res5)
			

			############################## UBUS ########################################
			elif type == "ubus":
				### Mapping Parameter
				if res3 != None and res4 != None:
					mapping = "%s:%s/%s/%s,%s/%s" % (type.upper(), res1, res2, res3, res4, res5)
				else:
					mapping = "%s:%s/%s//%s" % (type.upper(), res1, res2, res5)

				### GET VALUE Parameter
				get_value += "	json_object *res;\n"
				if res3 == None and res4 == None:
					get_value += "	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{}, 0, &res);\n" % (res1, res2)
				else:
					if i == 2 and res4 == "prev_value":
						get_value += "	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{{\"%s\", *value, String}}, 1, &res);\n" % (res1, res2, res3)

					elif i == 2 and res4 == "@Name":
						get_value += "	if (*value[0] == '\\0')\n"
						get_value += "	{\n"
						get_value += "	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{{\"%s\", section_name((struct uci_section *)data), String}}, 1, &res);\n" % (res1, res2, res3)
					elif res4 == "@Name":
						get_value += "	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{{\"%s\", section_name((struct uci_section *)data), String}}, 1, &res);\n" % (res1, res2, res3)
					else:
						get_value += "	dmubus_call(\"%s\", \"%s\", UBUS_ARGS{{\"%s\", \"%s\", String}}, 1, &res);\n" % (res1, res2, res3, res4)

				get_value += "	DM_ASSERT(res, *value = \"\");\n"
				option = res5.split(".")
				if "." in res5:
					if option[0] == "@Name":
						get_value += "	*value = dmjson_get_value(res, 2, section_name((struct uci_section *)data), \"%s\");" % (option[1])
					else:
						get_value += "	*value = dmjson_get_value(res, 2, \"%s\", \"%s\");" % (option[0], option[1])
				else:
					get_value += "	*value = dmjson_get_value(res, 1, \"%s\");" % option[0]
				if i == 2 and res4 == "@Name":
					get_value += "\n	}"

				### SET VALUE Parameter
				set_value += "	switch (action)	{\n"
				set_value += "		case VALUECHECK:\n"
				set_value += "%s\n" % validate_value
				set_value += "			break;\n"
				set_value += "		case VALUESET:\n"
				set_value += "			//TODO"


			############################## CLI ########################################
			elif type == "cli":
				### GET VALUE Parameter
				get_value += "	dmcmd(\"%s\", %s, %s);" % (res1, res2, res3)

			if count == 2 and i == 1:
				tmpmapping = mapping
				tmpgetvalue = get_value
				tmpsetvalue = set_value
			elif count == 2 and i == 2:
				print >> fp, "/*#%s!%s&%s*/" % (parentname+dmparam, tmpmapping, mapping)
				print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)" % getvalue
				print >> fp, "{"
				print >> fp, "%s" % tmpgetvalue
				print >> fp, "%s" % get_value
				print >> fp, "	return 0;"
				print >> fp, "}"
				print >> fp, ""
				if setvalue != "NULL":
					print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)" % setvalue
					print >> fp, "{"
					print >> fp, "%s" % tmpsetvalue
					print >> fp, "			break;"
					print >> fp, "	}"
					print >> fp, "	return 0;"
					print >> fp, "}"
					print >> fp, ""
			else:
				print >> fp, "/*#%s!%s*/" % (parentname+dmparam, mapping)
				print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)" % getvalue
				print >> fp, "{"
				print >> fp, "%s" % get_value
				print >> fp, "	return 0;"
				print >> fp, "}"
				print >> fp, ""
				if setvalue != "NULL":
					print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)" % setvalue
					print >> fp, "{"
					print >> fp, "%s" % set_value
					print >> fp, "			break;"
					print >> fp, "	}"
					print >> fp, "	return 0;"
					print >> fp, "}"
					print >> fp, ""
	

	# Mapping doesn't exist
	else:
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
			print >> fp, "%s" % validate_value
			print >> fp, "			break;"
			print >> fp, "		case VALUESET:"
			print >> fp, "			//TODO"
			print >> fp, "			break;"
			print >> fp, "	}"
			print >> fp, "	return 0;"
			print >> fp, "}"
			print >> fp, ""

	# Close file
	fp.close()

def hprintGetSetValue(getvalue, setvalue):
	fp = open('./.getstevalue.h', 'a')
	print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);" % getvalue
	if setvalue != "NULL":
		print >> fp, "int %s(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);" % setvalue
	fp.close()


def cprintheaderPARAMS( objname ):
	fp = open('./.objparamarray.c', 'a')
	print >> fp,  "DMLEAF %s[] = {" % ("t" + getname(objname) + "Params")
	print >> fp,  "/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/"
	fp.close()

def hprintheaderPARAMS( objname ):
	fp = open('./.objparamarray.h', 'a')
	print >> fp,  "extern DMLEAF %s[];" % ("t" + getname(objname) + "Params")
	fp.close()

def printPARAMline( parentname, dmparam, value ):
	commonname = getname(parentname) + "_" + dmparam
	ptype = getparamtype(value)
	getvalue = "get_" + commonname
	mappingparam = getoptionparam(value, "mapping")
	typeparam = getoptionparam(value, "type")
	bbfdm = getprotocolsparam(value, "protocols")
	accessparam = getoptionparam(value, "write")

	if accessparam:
		access = "&DMWRITE"
		setvalue = "set_" + commonname
	else:
		access = "&DMREAD"
		setvalue = "NULL"

	if parentname.endswith(".{i}."):
		instance = "TRUE"
	else:
		instance = "FALSE"

	cprintGetSetValue(getvalue, setvalue, mappingparam, instance, typeparam, parentname, dmparam, value)
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
		faddobj = "addObj" + commonname
		fdelobj = "delObj" + commonname
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
		objchildarray = "t" + commonname + "Obj"
	else:
		objchildarray = "NULL"

	if hasparam:
		paramarray = "t" + commonname + "Params"
	else:
		paramarray = "NULL"

	fp = open('./.objparamarray.c', 'a')
	print >> fp,  "{\"%s\", %s, %s, %s, NULL, %s, NULL, NULL, NULL, %s, %s, NULL, %s}," % (getlastname(dmobject), access, faddobj, fdelobj, fbrowse, objchildarray, paramarray, bbfdm)
	fp.close()

def printusage():
	print "Usage: " + sys.argv[0] + " <json data model>" + " [Object path]"
	print "Examples:"
	print "  - " + sys.argv[0] + " tr181.json"
	print "    ==> Generate the C code of all data model in tr181/ folder"
	print "  - " + sys.argv[0] + " tr104.json"
	print "    ==> Generate the C code of all data model in tr104/ folder"
	print "  - " + sys.argv[0] + " tr181.json" + " Device.DeviceInfo."
	print "    ==> Generate the C code of all data model in tr181/ folder"
	print "  - " + sys.argv[0] + " tr181.json" + " Device.WiFi."
	print "    ==> Generate the C code of all data model in tr181/ folder"
	print "  - " + sys.argv[0] + " tr104.json" + " Device.Services.VoiceService.{i}.Capabilities."
	print "    ==> Generate the C code of all data model in tr104/ folder"

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

def generatecfromobj( pobj, pvalue, pdir, nextlevel ):
	securemkdir(pdir)
	removetmpfiles()
	object_parse_childs(pobj, pvalue, nextlevel)
	
	dmfpc = open(pdir + "/" +  getname(pobj).lower() + ".c", "w")
	dmfph = open(pdir + "/" +  getname(pobj).lower() + ".h", "w")
	cprinttopfile(dmfpc, getname(pobj).lower())
	hprinttopfile(dmfph, getname(pobj).lower())
	try:
		tmpf = open("./.rootinclude.c", "r")
		tmpd = tmpf.read()
		tmpf.close()
		dmfpc.write(tmpd)
		print >> dmfpc,  ""
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
			print >> dmfpc,  "* ENTRY METHOD"
			print >> dmfpc,  "**************************************************************/"
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
			print >> dmfpc,  "* ADD & DEL OBJ"
			print >> dmfpc,  "**************************************************************/"
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
			print >> dmfpc,  "* GET & SET PARAM"
			print >> dmfpc,  "**************************************************************/"
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

	hprintfootfile (dmfph, getname(pobj).lower())
	removetmpfiles()
	

def removetmpfiles():
	removefile("./.objparamarray.c")
	removefile("./.objparamarray.h")
	removefile("./.objadddel.c")
	removefile("./.objadddel.h")
	removefile("./.objbrowse.c")
	removefile("./.objbrowse.h")
	removefile("./.getstevalue.c")
	removefile("./.getstevalue.h")
	removefile("./.rootinclude.c")

### main ###
if len(sys.argv) < 2:
	printusage()
	exit(1)
	
if (sys.argv[1]).lower() == "-h" or (sys.argv[1]).lower() == "--help":
	printusage()
	exit(1)

model_root_name = "Root"
json_file = sys.argv[1] # tr181.json

# load json file
with open(json_file) as file:
	data = json.loads(file.read(), object_pairs_hook=OrderedDict)

if "tr181" in sys.argv[1]: # TR181 JSON File
	gendir = "tr181"
elif "tr104" in sys.argv[1]: # TR104 JSON File 
	gendir = "tr104"
elif "tr106" in sys.argv[1]: # TR106 JSON File 
	gendir = "tr106"
else:
	gendir = "source_" + time.strftime("%Y-%m-%d_%H-%M-%S")

for obj, value in data.items():
	if obj == None:
		print "Wrong JSON Data model format!"
		exit(1)

	# Generate the object file if it is defined by "sys.argv[2]" argument
	if (len(sys.argv) > 2):
		if sys.argv[2] != obj:
			if isinstance(value, dict):
				for obj1, value1 in value.items():
					if obj1 == sys.argv[2]:
						if isinstance(value1, dict):
							for obj2, value2 in value1.items():
								if obj2 == "type" and value2 == "object":
									generatecfromobj(obj1, value1, gendir, 0)
									break
						break
			break

	# Generate the root object tree file if amin does not exist
	generatecfromobj(obj, value, gendir, 1)

	# Generate the sub object tree file if amin does not exist
	if isinstance(value, dict):
		for obj1, value1 in value.items():
			if isinstance(value1, dict):
				for obj2, value2 in value1.items():
					if obj2 == "type" and value2 == "object":
						generatecfromobj(obj1, value1, gendir, 0)

if (os.path.isdir(gendir)):
	print "Source code generated under \"./%s\" folder" % gendir
else:
	print "No source code generated!"

