/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#ifndef __DM_COMMON_H
#define __DM_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dirent.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <regex.h>
#include <unistd.h>
#include <glob.h>
#include <limits.h>
#include <float.h>
#include <time.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/param.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <uci.h>
#include <libubox/blobmsg_json.h>
#include <libubox/list.h>
#include <json-c/json.h>

#include "dmbbf.h"
#include "dmuci.h"
#include "dmubus.h"
#include "dmjson.h"

extern char *Encapsulation[];
extern char *LinkType[];
extern char *BridgeStandard[];
extern char *BridgeType[];
extern char *VendorClassIDMode[];
extern char *DiagnosticsState[];
extern char *SupportedProtocols[];
extern char *InstanceMode[];
extern char *NATProtocol[];
extern char *Config[];
extern char *Target[];
extern char *ServerConnectAlgorithm[];
extern char *KeepAlivePolicy[];
extern char *DeliveryHeaderProtocol[];
extern char *KeyIdentifierGenerationPolicy[];
extern char *PreambleType[];
extern char *MFPConfig[];
extern char *DuplexMode[];
extern char *RequestedState[];
extern char *BulkDataProtocols[];
extern char *EncodingTypes[];
extern char *CSVReportFormat[];
extern char *RowTimestamp[];
extern char *JSONReportFormat[];
extern char *StaticType[];
extern char *ProtocolVersion[];
extern char *ServerSelectionProtocol[];
extern char *DHCPType[];
extern char *DropAlgorithm[];
extern char *SchedulerAlgorithm[];
extern char *DTMFMethod[];
extern char *ProfileEnable[];
extern char *PIN[];
extern char *DestinationAddress[];
extern char *RegulatoryDomain[];
extern char *ConformingAction[];
extern char *IPv4Address[];
extern char *IPv6Address[];
extern char *IPAddress[];
extern char *MACAddress[];
extern char *IPPrefix[];
extern char *IPv4Prefix[];
extern char *IPv6Prefix[];
extern char *SupportedOperatingChannelBandwidth[];
extern char *SupportedStandards[];

#define UPTIME "/proc/uptime"
#define DEFAULT_CONFIG_DIR "/etc/config/"
#define MAX_DHCP_LEASES 256
#define MAX_PROC_ROUTING 256
#define ROUTING_FILE "/proc/net/route"
#define DHCP_LEASES_FILE "/tmp/dhcp.leases"
#define DMMAP "dmmap"
#define DHCPSTATICADDRESS_DISABLED_CHADDR "00:00:00:00:00:01"
#define RANGE_ARGS (struct range_args[])

#define DM_ASSERT(X, Y) \
do { \
	if(!(X)) { \
		Y; \
		return -1; \
	} \
} while(0)

#define dmstrappendstr(dest, src) \
do { \
	int len = strlen(src); \
	memcpy(dest, src, len); \
	dest += len; \
} while(0)

#define dmstrappendchr(dest, c) \
do { \
	*dest = c; \
	dest += 1; \
} while(0)

#define dmstrappendend(dest) \
do { \
	*dest = '\0'; \
} while(0)


#define DMCMD(CMD, N, ...) \
do { \
	int mpp = dmcmd(CMD, N, ## __VA_ARGS__); \
	if (mpp) close (mpp); \
} while (0)

#define IPPING_PATH "/usr/share/bbfdm/functions/ipping_launch"
#define IPPING_STOP DMCMD("/bin/sh", 2, IPPING_PATH, "stop");
#define DOWNLOAD_DIAGNOSTIC_PATH "/usr/share/bbfdm/functions/download_launch"
#define DOWNLOAD_DUMP_FILE "/tmp/download_dump"
#define DOWNLOAD_DIAGNOSTIC_STOP DMCMD("/bin/sh", 2, DOWNLOAD_DIAGNOSTIC_PATH, "stop");
#define UPLOAD_DIAGNOSTIC_PATH "/usr/share/bbfdm/functions/upload_launch"
#define UPLOAD_DUMP_FILE "/tmp/upload_dump"
#define UPLOAD_DIAGNOSTIC_STOP DMCMD("/bin/sh", 2, UPLOAD_DIAGNOSTIC_PATH, "stop");
#define NSLOOKUP_PATH "/usr/share/bbfdm/functions/nslookup_launch"
#define NSLOOKUP_LOG_FILE "/tmp/nslookup.log"
#define NSLOOKUP_STOP DMCMD("/bin/sh", 2, NSLOOKUP_PATH, "stop");
#define TRACEROUTE_PATH "/usr/share/bbfdm/functions/traceroute_launch"
#define TRACEROUTE_STOP DMCMD("/bin/sh", 2, TRACEROUTE_PATH, "stop");
#define UDPECHO_PATH "/usr/share/bbfdm/functions/udpecho_launch"
#define UDPECHO_STOP DMCMD("/bin/sh", 2, UDPECHO_PATH, "stop");
#define SERVERSELECTION_PATH "/usr/share/bbfdm/functions/serverselection_launch"
#define SERVERSELECTION_STOP DMCMD("/bin/sh", 2, SERVERSELECTION_PATH, "stop");

#define sysfs_foreach_file(path,dir,ent) \
        if ((dir = opendir(path)) == NULL) return 0; \
        while ((ent = readdir (dir)) != NULL) \

enum notification_enum {
	notification_none,
	notification_passive,
	notification_active,
	notification_passive_lw,
	notification_ppassive_passive_lw,
	notification_aactive_lw,
	notification_passive_active_lw,
	__MAX_notification
};

enum strstructered_enum {
	STRUCTERED_SAME,
	STRUCTERED_PART,
	STRUCTERED_NULL
};

struct range_args {
	const char *min;
	const char *max;
};

struct proc_routing {
	char *iface;
	char *flags;
	char *refcnt;
	char *use;
	char *metric;
	char *mtu;
	char *window;
	char *irtt;
	char destination[16];
	char gateway[16];
	char mask[16];
};

struct routingfwdargs
{
	char *permission;
	struct uci_section *routefwdsection;
	struct proc_routing *proute;
	int type;
};

struct dmmap_dup
{
	struct list_head list;
	struct uci_section *config_section;
	struct uci_section *dmmap_section;
	void* additional_attribute;
};

struct dmmap_sect {
	struct list_head list;
	char *section_name;
	char *instance;
};

struct dm_args
{
	struct uci_section *section;
	struct uci_section *dmmap_section;
	char *name;
};

struct sysfs_dmsection {
	struct list_head list;
	char *sysfs_folder_path;
	char *sysfs_folder_name;
	struct uci_section *dm;
};

char *cut_fx(char *str, char *delimiter, int occurence);
pid_t get_pid(char *pname);
int check_file(char *path);
char *cidr2netmask(int bits);
bool is_strword_in_optionvalue(char *optionvalue, char *str);
int dmcmd(char *cmd, int n, ...);
int dmcmd_read(int pipe, char *buffer, int size);
void dmcmd_read_alloc(int pipe, char **value);
int dmcmd_no_wait(char *cmd, int n, ...);
int ipcalc(char *ip_str, char *mask_str, char *start_str, char *end_str, char *ipstart_str, char *ipend_str);
int ipcalc_rev_start(char *ip_str, char *mask_str, char *ipstart_str, char *start_str);
int ipcalc_rev_end(char *ip_str, char *mask_str, char *start_str, char *ipend_str, char *end_str);
int network_get_ipaddr(char **value, char *iface);
void update_section_list(char *config, char *section, char *option, int number, char *filter, char *option1, char *val1,  char *option2, char *val2);
int wan_remove_dev_interface(struct uci_section *interface_setion, char *dev);
void parse_proc_route_line(char *line, struct proc_routing *proute);
int strstructered(char *str1, char *str2);
int dmcommon_check_notification_value(char *value);
void hex_to_ip(char *address, char *ret);
void ip_to_hex(char *address, char *ret);
void free_dmmap_config_dup_list(struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap_filter(char *package, char *section_type,
					void *data, char *dmmap_package, char *dmmap_sec,
					char *proto, struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap_mcast_iface(char *package, char *section_type,
					void *data, char *dmmap_package, char *dmmap_sec, char *proto,
					struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap(char *package, char *section_type, char *dmmap_package, struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap_eq(char *package, char *section_type, char *dmmap_package,char* option_name, char* option_value, struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap_eq_no_delete(char *package, char *section_type, char *dmmap_package,char* option_name, char* option_value, struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap_cont(char *package, char *section_type, char *dmmap_package,char* option_name, char* option_value, struct list_head *dup_list);
void add_sysfs_sectons_list_paramameter(struct list_head *dup_list, struct uci_section *dmmap_section, char *file_name, char* filepath);
int synchronize_system_folders_with_dmmap_opt(char *sysfsrep, char *dmmap_package, char *dmmap_section, char *opt_name, char* inst_opt, struct list_head *dup_list);
void get_dmmap_section_of_config_section(char* dmmap_package, char* section_type, char *section_name, struct uci_section **dmmap_section);
void get_dmmap_section_of_config_section_eq(char* dmmap_package, char* section_type, char *opt, char* value, struct uci_section **dmmap_section);
void get_config_section_of_dmmap_section(char* package, char* section_type, char *section_name, struct uci_section **config_section);
void check_create_dmmap_package(char *dmmap_package);
int is_section_unnamed(char *section_name);
void delete_sections_save_next_sections(char* dmmap_package, char *section_type, char *instancename, char *section_name, int instance, struct list_head *dup_list);
void update_dmmap_sections(struct list_head *dup_list, char *instancename, char* dmmap_package, char *section_type);
unsigned char isdigit_str(char *str);
char *dm_strword(char *src, char *str);
char **strsplit(const char* str, const char* delim, size_t* numtokens);
char **strsplit_by_str(const char str[], char *delim);
char *get_macaddr_from_device(char *device_name);
char *get_macaddr(char *ifname);
char *get_device(char *ifname);
int is_elt_exit_in_str_list(char *str_list, char *elt);
void add_elt_to_str_list(char **str_list, char *elt);
void remove_elt_from_str_list(char **iface_list, char *ifname);
struct uci_section *get_dup_section_in_dmmap_opt(char *dmmap_package, char *section_type, char *opt_name, char *opt_value);
struct uci_section *get_dup_section_in_dmmap_eq(char *dmmap_package, char* section_type, char*sect_name, char *opt_name, char* opt_value);
int is_array_elt_exist(char **str_array, char *str, int length);
int get_shift_time_time(int shift_time, char *local_time, int size);
int get_shift_time_shift(char *local_time, char *shift);
int command_exec_output_to_array(char *cmd, char **output, int *length);
int copy_temporary_file_to_original_file(char *f1, char *f2);
struct uci_section *is_dmmap_section_exist(char* package, char* section);
struct uci_section *is_dmmap_section_exist_eq(char* package, char* section, char* opt, char* value);
int isfolderexist(char *folderpath);
char * dmmap_file_path_get(const char *dmmap_package);
int dm_read_sysfs_file(const char *file, char *dst, unsigned len);
int get_net_iface_sysfs(const char *uci_iface, const char *name, char **value);
int get_net_device_sysfs(const char *uci_iface, const char *name, char **value);
char *get_device_from_wifi_iface(const char *wifi_iface, const char *wifi_section);
int dm_time_format(time_t ts, char **dst);
bool match(const char *string, const char *pattern);
int dm_validate_string(char *value, int min_length, int max_length, char *enumeration[], int enumeration_size, char *pattern[], int pattern_size);
int dm_validate_boolean(char *value);
int dm_validate_unsignedInt(char *value, struct range_args r_args[], int r_args_size);
int dm_validate_int(char *value, struct range_args r_args[], int r_args_size);
int dm_validate_unsignedLong(char *value, struct range_args r_args[], int r_args_size);
int dm_validate_long(char *value, struct range_args r_args[], int r_args_size);
int dm_validate_dateTime(char *value);
int dm_validate_hexBinary(char *value, struct range_args r_args[], int r_args_size);
int dm_validate_string_list(char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], int enumeration_size, char *pattern[], int pattern_size);
int dm_validate_unsignedInt_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);
char *decode64(char *enc);
bool file_exists(const char *path);
int is_regular_file(const char *path);
char *stringToHex(char *text, int length);
char *replace_char(char *str, char find, char replace);
int is_vlan_termination_section(char *name);
int get_br_key_from_lower_layer(char *lower_layer, char *key, size_t s_key);
int get_igmp_snooping_interface_val(char *value, char *ifname, size_t s_ifname);
void sync_dmmap_bool_to_uci_list(struct uci_section *s, char *section, char *value, bool b);
void del_dmmap_sec_with_opt_eq(char *dmmap_file, char *section, char *option, char *value);
#endif
