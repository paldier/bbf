# README #
The libray **bbfdm** is an implementation of BBF(Broad Band Forum) data models. BBF data models includes a list of objects and parameters used for CPE management through remote control protocols such as : CWMP, USP, etc.

## Design of bbfdm ##
The root directory of bbfdm library is **“src”** which is structred as follow :
![structure](/pictures/structure.jpg)

## How to start with bbfdm ##
The bbfdm library offers a tool to generate templates of the source code from json files.

```plain
$ python convertor_json_to_c.py 
Usage: convertor_json_to_c.py <json data model>
Examples:
  - convertor_json_to_c.py tr181.json
    ==> Generate the C code of all data model in tr181/ folder
  - convertor_json_to_c.py tr104.json
    ==> Generate the C code of all data model in tr104/ folder
```
**Note:** Any developer can full the json file (**tr181.json** or **tr104.json**) with mapping field according to UCI, UBUS or CLI commands before generating the source code in C.

Find below the examples of **UCI**, **UBUS** or **CLI** commands:<br/>
**1. UCI command:**<br/>
- **@Name:** the section name of paraent object<br/>
- **@i:** is the number of instance object
```plain
    "mapping": [
        {
            "type": "uci", 
            "uci": {
                "file": "wireless", 
                "section": {
                    "type": "wifi-device", 
		    "name": "@Name",
                    "index": "@i-1"
                }, 
                "option": {
                    "name": "disabled"
                }
            }
        }
    ]
```

**2. UBUS command:**<br/>
- **@Name:** the section name of paraent object
```plain
    "mapping": [
        {
            "type": "ubus", 
            "ubus": {
                "object": "network.device", 
                "method": "status", 
                "args": {
	            "name": "@Name"
                }, 
                "key": "statistics.rx_bytes"
            }
        }
    ]
```

**3. CLI command:**<br/>
- **@Name:** the section name of paraent object<br/>
- **-i:** is the number of arguments command
```plain
    "mapping": [
        {
            "type" : "cli",
            "cli" : {
                "command" : "wlctl",
                "args" : [
                    "-i",
                    "@Name",
                    "bands"
                ]
            }
        }
    ]
```

After building the templates of C source code, a **tr181** or **tr104** folder will be generated under **json** folder that contains all files related a each object under root Device.

#### Object definition ###
![object](/pictures/obj.png)
Each object in the **DMOBJ** table contains the following arguments:

|     Argument        |                                                   Description                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `OBJ`               | A string of the object name. Example “Bridging”, “IP”, “DeviceInfo”, “WiFi” |
| `permission`        | The permission of the object. Could be **&DMREAD** or **&DMWRITE**. If it's `&DMWRITE` then we can add/delete instances of this object |
| `addobj`            | The function to add new instance under this object. This function will be triggered when the ACS/Controller call AddObject of this object |
| `delobj`            | The function to delete instance under this object. This function will be triggered when the ACS/Controller call DeleteObject of an instance of this object |
| `checkobj`          | The function to check if the object is allowed to appear in the tree. If it's `NULL` then the object has always appeared in the tree |
| `browseinstobj`     | This function allow to browse all instances under this object |
| `forced_inform`     | If it's set to `&DMFINFRM` that mean the object contains a force inform parameter in its subtree. The forced inform parameters are the parameter included in the inform message |
| `notification`      | The notification of the object. Could be **&DMACTIVE**, **&DMACTIVE** or **&DMNONE** |
| `nextdynamicobj`       | Pointer to the next of **DMOBJ** which contains a list of the child objects using json files and plugins(libraries) |
| `nextobj`           | Pointer to a **DMOBJ** array which contains a list of the child objects |
| `leaf`              | Pointer to a **DMLEAF** array which contains a list of the child objects |
| `linker`            | This argument is used for LowerLayer parameters or to make reference to other instance object in the tree |
| `bbfdm_type`        | The bbfdm type of the object. Could be **BBFDM_CWMP**, **BBFDM_USP** or **BBFDM_NONE**.If it's `BBFDM_NONE` then we can see this object in all protocols (CWMP, USP,...) |

#### Parameter definition ###
![parameter](/pictures/param.png)<br/>
Each parameter in the **DMLEAF** table contains the following arguments:

|     Argument        |                                                   Description                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `PARAM`             | A string of the parameter name. Example “Enable”, “Status”, “Name” |
| `permission`        | The permission of the parameter. Could be **&DMREAD** or **&DMWRITE**.If it's `&DMWRITE` then we can set a value for this parameter |
| `type`              | Type of the parameter: **DM_STRING**, **DM_BOOL**, **DM_UNINT**,... |
| `getvalue`          | The function which return the value of this parameter |
| `setvalue`          | The function which set the value of this parameter |
| `forced_inform`     | If this argument is set to `&DMFINFRM` that mean the parameter will be included in the list of parameter of inform message |
| `notification`      | The notification of the parameter. Could be **&DMACTIVE**, **&DMACTIVE** or **&DMNONE** |
| `bbfdm_type`        | The bbfdm type of the parameter. Could be **BBFDM_CWMP**, **BBFDM_USP** or **BBFDM_NONE**.If it's `BBFDM_NONE` then we can see this parameter in all protocols (CWMP, USP,...) |

## BBFDM API ##

The bbfdm API is used for GET/SET/ADD/Delete/Operate calls.

It includes list of `UCI` functions. The most used one are as follow:

**1. dmuci_get_option_value_string:** execute the uci get value
```plain
int dmuci_get_option_value_string(char *package, char *section, char *option, char **value)
```
**Argument:**
- **package:** package name
- **section:** section name
- **option:** option name
- **value:** the value of the returned option

**2. dmuci_get_value_by_section_string:** execute the uci get value
```plain
int dmuci_get_value_by_section_string(struct uci_section *s, char *option, char **value)
```
**Argument:**
- **section:** section name
- **option:** option name
- **value:** the value of the returned option

**3. uci_foreach_sections:** browse all sections by package and section type
```plain
#define uci_foreach_sections(package, stype, section)
```
**Argument:**
- **package:** package name
- **stype:** section type to browse
- **section:** return section pointer for each loop iteration

**NOTE: For others please refer to dmuci (.c and .h)**

It also includes list of `UBUS` functions as follow:

**1. dmubus_call:** execute the ubus call
```plain
int dmubus_call(char *obj, char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res)
```
**Argument:**
- **obj:** ubus obj
- **method:** ubus method
- **u_args:** ubus arguments
- **u_args_size:** number of ubus arguments
- **req_res:** the json message of the ubus call

**2. dmubus_call_set:** set the ubus call
```plain
int dmubus_call_set(char *obj, char *method, struct ubus_arg u_args[], int u_args_size);
```
**Argument:**
- **obj:** ubus obj
- **method:** ubus method
- **u_args: ubus** arguments
- **u_args_size:** number of ubus arguments

**NOTE: There are others API related to JSON and CLI command defined in dmjson, dmcommon (.c and .h).**

## TIPS ##
When developing a new parameters/features in the data model C source code, it's highly recommended to use the memory management functions of bbfdm allocate and free because it's freed at the end of each RPCs.<br/>
The list of memory management functions of bbfdm are:
```plain
dmmalloc(x)
dmcalloc(n, x)
dmrealloc(x, n)
dmstrdup(x)
dmasprintf(s, format, ...)
dmastrcat(s, b, m)
dmfree(x)
```

## Good To know ##
#### XML generator: ####
It is a generator of data model tree in XML format conform to BBF schema.
```plain
$ ./generate_xml_bbf.sh 
Start Generation of BBF Data Models...
Please wait...
Number of BBF Data Models objects is 196
Number of BBF Data Models parameters is 1393
End of BBF Data Models Generation
```

#### JSON generator: ####
It is a generator of json file from xml data model and C source code.
```plain
$ python generator_json_with_backend.py
Usage: generator_json_with_backend.py <tr-181 cwmp xml data model> <tr-181 usp xml data model> [Object path]
Examples:
  - generator_json_with_backend.py tr-181-2-12-0-cwmp-full.xml tr-181-2-12-0-usp-full.xml Device.
    ==> Generate the json file of the sub tree Device. in tr181.json
  - generator_json_with_backend.py tr-104-1-1-0-full.xml VoiceService.
    ==> Generate the json file of the sub tree VoiceService. in tr104.json
  - generator_json_with_backend.py tr-106-1-2-0-full.xml Device.
    ==> Generate the json file of the sub tree Device. in tr106.json

Example of xml data model file: https://www.broadband-forum.org/cwmp/tr-181-2-12-0-cwmp-full.xml
```

#### Excel generator: ####
It is a generator of excel sheet with supported and unsupported data model parameters.
```plain
$ python generate_excel.py
Usage: generate_excel.py <json data model>
Examples:
  - generate_excel.py tr181.json
    ==> Generate excel file in tr181.xls
  - generate_excel.py tr104.json
    ==> Generate excel file in tr104.xls
```

#### Load additional parameters at run time ####

The bbfdm library allows all applications installed on the box to import its own tr-181 data model parameters at run time in two formats: **JSON files** and **Plugin(library) files**.

#### `JSON Files:` ####

The application should bring its JSON file under **'/etc/bbfdm/json/'** path with **UCI** and **UBUS** mappings. The new added parameters will be automatically shown by icwmp and uspd/obuspa.

To build a new JSON file, you can use **example.json file** under **dynamic_parameters/json** folder to help you build it.

**1. Object without instance:**
```plain
"Device.CWMP.": {
    "type": "object", 
    "protocols": [
        "cwmp", 
        "usp"
    ], 
    "array": false
}
```

**2. Object with instace:**
- **UCI command:** uci show wireless | grep wifi-device
```plain
"Device.X_IOPSYS_EU_Radio.{i}.": {
    "type": "object", 
    "protocols": [
        "cwmp", 
        "usp"
    ], 
    "array": true,
    "mapping": {
        "type": "uci", 
        "uci": {
            "file": "wireless", 
            "section": {
                "type": "wifi-device"
            }, 
            "dmmapfile": "dmmap_wireless"
        }
    }
}
```

- **UBUS command:** ubus call dsl status | jsonfilter -e @.line
```plain
"Device.DSL.Line.{i}.": {
	"type": "object", 
	"protocols": [
		"cwmp", 
		"usp"
	], 
	"array": true,
	"mapping": {
		"type": "ubus", 
		"ubus": {
			"object": "dsl", 
			"method": "status", 
			"args": {}, 
			"key": "line"
		}
	}
}
```

**3. Parameter under object with instance:**
- **UCI command:** uci get wireless.@wifi-device[0].country

- **@i:** is the number of instance object

```plain
"Country": {
    "type": "string", 
    "protocols": [
        "cwmp", 
        "usp"
    ],
    "read": true, 
    "write": true, 
    "mapping": {
        "type" : "uci",
        "uci" : {
            "file" : "wireless",
            "section" : {
                "type": "wifi-device",
                "index": "@i-1"
            },
            "option" : {
                "name" : "country"
            }
        }
}
```
- **UBUS command (format 1):** ubus call network.interface status '{"interface":"lan"}' | jsonfilter -e @.device

- **@Name:** the section name of paraent object, in this example, the section name is "lan"
```plain
"SSID": {
    "type": "string", 
    "protocols": [
        "cwmp", 
        "usp"
    ],
    "read": true, 
    "write": false,
    "mapping": {
        "type" : "ubus",
        "ubus" : {
            "object" : "network.interface",
            "method" : "status",
            "args" : {
                "interface" : "@Name"
            },
            "key" : "device"
        }
    }
}
```

- **UBUS command (format 2):** ubus call wifi status | jsonfilter -e @.radios[0].noise
```plain
"Noise": {
    "type": "int", 
    "protocols": [
        "cwmp", 
        "usp"
    ],
    "read": true, 
    "write": false,
    "mapping": {
        "type" : "ubus",
        "ubus" : {
            "object" : "wifi",
            "method" : "status",
            "args" : {},
            "key" : "radios[i-1].noise"
        }
    }
}
```
**4. Parameter under object without instance:**
- **UCI command:** uci get cwmp.cpe.userid
```plain
"Username": {
    "type": "string", 
    "protocols": [
        "cwmp", 
        "usp"
    ],
    "read": true, 
    "write": true, 
    "mapping": {
        "type" : "uci",
        "uci" : {
            "file" : "cwmp",
            "section" : {
                "type": "cwmp",
                "name": "cpe"
            },
            "option" : {
                "name" : "userid"
            }
        }
    }
}
```
- **UBUS command (format 1):** ubus call system info | jsonfilter -e @.uptime
```plain
"Uptime": {
    "type": "unsignedInt", 
    "protocols": [
        "cwmp", 
        "usp"
    ],
    "read": true, 
    "write": false,
    "mapping": {
        "type" : "ubus",
        "ubus" : {
            "object" : "system",
            "method" : "info",
            "args" : {},
            "key" : "uptime"
        }
    }
}
```
- **UBUS command (format 2):** ubus call system info | jsonfilter -e @.memory.total
```plain
"Total": {
    "type": "unsignedInt", 
    "protocols": [
        "cwmp", 
        "usp"
    ],
    "read": true, 
    "write": false,
    "mapping": {
        "type" : "ubus",
        "ubus" : {
            "object" : "system",
            "method" : "info",
            "args" : {},
            "key" : "memory.total"
        }
    }
}
```
#### 

#### `Plugin(library) Files:` ####

The application should bring its plugin(library) file under **'/usr/lib/bbfdm/'** path that contains the sub tree of **Objects/Parameters** and the related functions **Get/Set/Add/Delete/Operate**. The new added objects, parameters and operates will be automatically shown by icwmp and uspd/obuspa.

To build a new library, you can use **example source code** under **dynamic_parameters/library** folder to help you build it.

Each library should contains two Root table named **“tRootDynamicObj”** and **“tRootDynamicOperate”** to define the parant path for each new object and operate.

#### RootDynamicObject definition ####
![object](/pictures/rootdynamicobj.png)

Each object in the **LIB_MAP_OBJ** table contains two arguments:

|     Argument        |                                                   Description                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `parentobj`         | A string of the parent object name. Example “Device.IP.Diagnostics.”, “Device.DeviceInfo”, “Device.WiFi.Radio.” |
| `nextobject`        | Pointer to a **DMOBJ** array which contains a list of the child objects. |

#### RootDynamicOperate definition ####
![object](/pictures/rootdynamincoperate.png)

Each operate in the **LIB_MAP_OPERATE** table contains two arguments:

|     Argument        |                                                   Description                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `pathname`         | A string of the path name operate. Example “Device.BBKSpeedTest”, “Device.WiFi.AccessPoint.*.X_IOPSYS_EU_Reset” |
| `operation`        | The function which return the status of this operate. |

For the other tables, they are defined in the same way as the [Object and Parameter](#object-definition) definition described above.

**Below are the steps for building of a new library using JSON file**

**1. Create the json file:**

Any developer should create a json file containing object requested as defined in the above section of **JSON Files**. You can find an example of json file **example.json** under **library** folder.

**2. Generate the source code:**

The bbfdm library offers a tool to generate templates of the library source code from json file. You can find the tool **generate_library.py** under **library** folder.

```plain
$ python generate_library.py 
Usage: generate_library.py <json file>
Examples:
  - generate_library.py example.json
    ==> Generate the C code in example/ folder
```

**3. Fill the functions of object/parameter:**

After building the templates of source code, a **test.c, test.h and Makefile** files will be generated under **test** folder that contains the functions related to each object, parameter and operate. Then, you have to fill each function with the necessary [bbfdm API](#bbfdm-api) defined above. You can find an example of source code **(example folder)** under **library** folder.

## Dependencies ##

To successfully build libbbfdm, the following libraries are needed:

| Dependency  | Link                                        | License        |
| ----------- | ------------------------------------------- | -------------- |
| libuci      | https://git.openwrt.org/project/uci.git     | LGPL 2.1       |
| libubox     | https://git.openwrt.org/project/libubox.git | BSD            |
| libubus     | https://git.openwrt.org/project/ubus.git    | LGPL 2.1       |
| libjson-c   | https://s3.amazonaws.com/json-c_releases    | MIT            |
| libtrace    | https://github.com/apietila/libtrace.git    | GPLv2          |
| libbbf_api  | https://dev.iopsys.eu/iopsys/bbf.git        | LGPL 2.1       |

