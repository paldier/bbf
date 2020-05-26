/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "dmcommon.h"

char *array_notifcation_char[__MAX_notification] = {
	[notification_none] = "0",
	[notification_passive] = "1",
	[notification_active] = "2",
	[notification_passive_lw] = "3",
	[notification_ppassive_passive_lw] = "4",
	[notification_aactive_lw] = "5",
	[notification_passive_active_lw] = "6",
};

char *Encapsulation[] = {"LLC", "VCMUX"};
char *LinkType[] = {"EoA", "IPoA", "PPPoA", "CIP", "Unconfigured"};
char *BridgeStandard[] = {"802.1D-2004", "802.1Q-2005", "802.1Q-2011"};
char *BridgeType[] = {"ProviderNetworkPort", "CustomerNetworkPort", "CustomerEdgePort", "CustomerVLANPort", "VLANUnawarePort"};
char *VendorClassIDMode[] = {"Exact", "Prefix", "Suffix", "Substring"};
char *DiagnosticsState[] = {"None", "Requested", "Canceled", "Complete", "Error"};
char *SupportedProtocols[] = {"HTTP", "HTTPS"};
char *InstanceMode[] = {"InstanceNumber", "InstanceAlias"};
char *NATProtocol[] = {"TCP", "UDP", "TCP/UDP"};
char *Config[] = {"High", "Low", "Off", "Advanced"};
char *Target[] = {"Drop", "Accept", "Reject", "Return", "TargetChain"};
char *ServerConnectAlgorithm[] = {"DNS-SRV", "DNS", "ServerTable", "WebSocket"};
char *KeepAlivePolicy[] = {"ICMP", "None"};
char *DeliveryHeaderProtocol[] = {"IPv4", "IPv6"};
char *KeyIdentifierGenerationPolicy[] = {"Disabled", "Provisioned", "CPE_Generated"};
char *PreambleType[] = {"short", "long", "auto"};
char *MFPConfig[] = {"Disabled", "Optional", "Required"};
char *DuplexMode[] = {"Half", "Full", "Auto"};
char *RequestedState[] = {"Idle", "Active"};
char *BulkDataProtocols[] = {"Streaming", "File", "HTTP"};
char *EncodingTypes[] = {"XML", "XDR", "CSV", "JSON"};
char *CSVReportFormat[] = {"ParameterPerRow", "ParameterPerColumn"};
char *RowTimestamp[] = {"Unix-Epoch", "ISO-8601", "None"};
char *JSONReportFormat[] = {"ObjectHierarchy", "NameValuePair"};
char *StaticType[] = {"Static", "Inapplicable", "PrefixDelegation", "Child"};
char *ProtocolVersion[] = {"Any", "IPv4", "IPv6"};
char *ServerSelectionProtocol[] = {"ICMP", "UDP Echo"};
char *DHCPType[] = {"DHCPv4", "DHCPv6"};
char *DropAlgorithm[] = {"RED", "DT", "WRED", "BLUE"};
char *SchedulerAlgorithm[] = {"WFQ", "WRR", "SP"};
char *DTMFMethod[] = {"InBand", "RFC2833", "SIPInfo"};
char *ProfileEnable[] = {"Disabled", "Quiescent", "Enabled"};
char *SupportedOperatingChannelBandwidth[] = {"20MHz", "40MHz", "80MHz", "160MHZ", "80+80MHz", "Auto"};
char *SupportedStandards[] = {"a", "b", "g", "n", "ac", "ax"};

char *PIN[] = {"^\\d{4}|\\d{8}$"};
char *DestinationAddress[] = {"^\\d+/\\d+$"};
char *RegulatoryDomain[] = {"^[A-Z][A-Z][ OI]$"};
char *ConformingAction[] = {"^Null$", "^Drop$", "^[0-9]|[1-5][0-9]|6[0-3]$", "^:[0-7]$", "^([0-9]|[1-5][0-9]|6[0-3]):[0-7]$"};
char *IPv4Address[] = {"^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$"};
char *IPv6Address[] = {"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"};
char *IPAddress[] = {"^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$", "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"};
char *MACAddress[] = {"^([0-9A-Fa-f][0-9A-Fa-f]:){5}([0-9A-Fa-f][0-9A-Fa-f])$"};
char *IPPrefix[] = {"^/(3[0-2]|[012]?[0-9])$", "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])/(3[0-2]|[012]?[0-9])$"};
char *IPv4Prefix[] = {"^/(3[0-2]|[012]?[0-9])$", "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])/(3[0-2]|[012]?[0-9])$"};
char *IPv6Prefix[] = {}; //TODO

char *cut_fx(char *str, char *delimiter, int occurence)
{
	int i = 1;
	char *pch, *spch;
	pch = strtok_r(str, delimiter, &spch);
	while (pch != NULL && i < occurence) {
		i++;
		pch = strtok_r(NULL, delimiter, &spch);
	}
	return pch;
}

unsigned char dmisnumeric(char *nbr)
{
	if (*nbr == '\0')
		return 0;
	while (*nbr <= '9' && *nbr >= '0') {
		nbr++;
	}
	return ((*nbr) ? 0 : 1);
}

/* int strstructered(char *str1, char *str2)
 * Return:
 * STRUCTERED_SAME: if str1 is same of str2
 * STRUCTERED_PART: if str2 is part of str1
 * STRUCTERED_NULL: if str2 is not part of str1
 *
 */
int strstructered(char *str1, char *str2)
{
	char buf[16];
	int i = 0;
	for (; *str1 && *str2; str1++, str2++) {
		if (*str1 == *str2)
			continue;
		if (*str2 == '#') {
			i = 0;
			do {
				buf[i++] = *str1;
			} while (*(str1+1) && *(str1+1) != dm_delim && str1++);
			buf[i] = '\0';
			if (dmisnumeric(buf))
				continue;
		} else if (*str1 == '#') {
			i = 0;
			do {
				buf[i++] = *str2;
			} while (*(str2+1) && *(str2+1) != dm_delim && str2++);
			buf[i] = '\0';
			if (dmisnumeric(buf))
				continue;
		}
		return STRUCTERED_NULL;
	}
	if (*str1 == '\0' && *str2 == '\0')
		return STRUCTERED_SAME;
	else if (*str2 == '\0')
		return STRUCTERED_PART;
	return STRUCTERED_NULL;
}


pid_t get_pid(char *pname)
{
	DIR* dir;
	struct dirent* ent;
	char* endptr;
	char buf[512];

	if (!(dir = opendir("/proc"))) {
		return -1;
	}
	while((ent = readdir(dir)) != NULL) {
		long lpid = strtol(ent->d_name, &endptr, 10);
		if (*endptr != '\0') {
			continue;
		}
		snprintf(buf, sizeof(buf), "/proc/%ld/cmdline", lpid);
		FILE* fp = fopen(buf, "r");
		if (fp) {
			if (fgets(buf, sizeof(buf), fp) != NULL) {
				char* first = strtok(buf, " ");
				if (strstr(first, pname)) {
					fclose(fp);
					closedir(dir);
					return (pid_t)lpid;
				}
			}
			fclose(fp);
		}
	}
	closedir(dir);
	return -1;
}

int check_file(char *path)
{
	glob_t globbuf;
	if(glob(path, 0, NULL, &globbuf) == 0) {
		globfree(&globbuf);
		return 1;
	}
	return 0;
}

char *cidr2netmask(int bits)
{
	uint32_t mask;
	struct in_addr ip_addr;
	uint8_t u_bits = (uint8_t)bits;

	mask = ((0xFFFFFFFFUL << (32 - u_bits)) & 0xFFFFFFFFUL);
	mask = htonl(mask);
	ip_addr.s_addr = mask;
	return inet_ntoa(ip_addr);
}

bool is_strword_in_optionvalue(char *optionvalue, char *str)
{
	int len;
	char *s = optionvalue;
	while ((s = strstr(s, str))) {
		len = strlen(str); //should be inside while, optimization reason
		if(s[len] == '\0' || s[len] == ' ')
			return true;
		s++;
	}
	return false;
}

int dmcmd(char *cmd, int n, ...)
{
	va_list arg;
	int i, pid;
	static int dmcmd_pfds[2];
	char *argv[n+2];

	argv[0] = cmd;

	va_start(arg,n);
	for (i=0; i<n; i++)
	{
		argv[i+1] = va_arg(arg, char*);
	}
	va_end(arg);

	argv[n+1] = NULL;

	if (pipe(dmcmd_pfds) < 0)
		return -1;

	if ((pid = fork()) == -1)
		return -1;

	if (pid == 0) {
		/* child */
		close(dmcmd_pfds[0]);
		dup2(dmcmd_pfds[1], 1);
		close(dmcmd_pfds[1]);

		execvp(argv[0], (char **) argv);
		exit(ESRCH);
	} else if (pid < 0)
		return -1;

	/* parent */
	close(dmcmd_pfds[1]);

	int status;
	while (waitpid(pid, &status, 0) != pid)
	{
		kill(pid, 0);
		if (errno == ESRCH) {
			return dmcmd_pfds[0];
		}
	}

	return dmcmd_pfds[0];
}

int dmcmd_no_wait(char *cmd, int n, ...)
{
	va_list arg;
	int i, pid;
	char *argv[n+2];
	static char sargv[4][128];

	argv[0] = cmd;
	va_start(arg,n);
	for (i=0; i<n; i++)
	{
		strcpy(sargv[i], va_arg(arg, char*));
		argv[i+1] = sargv[i];
	}
	va_end(arg);

	argv[n+1] = NULL;

	if ((pid = fork()) == -1)
		return -1;

	if (pid == 0) {
		execvp(argv[0], (char **) argv);
		exit(ESRCH);
	} else if (pid < 0)
		return -1;
	return 0;
}

void dmcmd_read_alloc(int pipe, char **value)
{
	char buffer[64];
	ssize_t rxed;
	int t, len = 1;

	*value = NULL;
	while ((rxed = read(pipe, buffer, sizeof(buffer) - 1)) > 0) {
		t = len;
		len += rxed;
		*value = dmrealloc(*value, len);
		memcpy(*value + t - 1, buffer, rxed);
		*(*value + len -1) = '\0';
	}
	if (*value == NULL)
		*value = dmstrdup("");
}

int dmcmd_read(int pipe, char *buffer, int size)
{
	int rd;
	if (size < 2) return -1;
	if ((rd = read(pipe, buffer, (size-1))) > 0) {
		buffer[rd] = '\0';
		return (rd + 1);
	} else {
		buffer[0] = '\0';
		return -1;
	}
	return -1;
}

int ipcalc(char *ip_str, char *mask_str, char *start_str, char *end_str, char *ipstart_str, char *ipend_str)
{
	struct in_addr ip, mask, ups, upe;
	int start, end;

	inet_aton(ip_str, &ip);
	inet_aton(mask_str, &mask);

	start = atoi(start_str);

	ups.s_addr = htonl(ntohl(ip.s_addr & mask.s_addr) + start);
	strcpy(ipstart_str, inet_ntoa(ups));

	if (end_str) {
		end = atoi(end_str);
		upe.s_addr = htonl(ntohl(ups.s_addr) + end);
		strcpy(ipend_str, inet_ntoa(upe));
	}
	return 0;
}

int ipcalc_rev_start(char *ip_str, char *mask_str, char *ipstart_str, char *start_str)
{
	struct in_addr ip, mask, ups;
	int start;

	inet_aton(ip_str, &ip);
	inet_aton(mask_str, &mask);
	inet_aton(ipstart_str, &ups);

	start = ntohl(ups.s_addr) - ntohl(ip.s_addr & mask.s_addr);
	sprintf(start_str, "%d", start);
	return 0;
}

int ipcalc_rev_end(char *ip_str, char *mask_str, char *start_str, char *ipend_str, char *end_str)
{
	struct in_addr ip;
	struct in_addr mask;
	struct in_addr upe;
	int end;

	inet_aton(ip_str, &ip);
	inet_aton(mask_str, &mask);
	inet_aton(ipend_str, &upe);

	end = ntohl(upe.s_addr) - ntohl(ip.s_addr & mask.s_addr) - atoi(start_str);
	sprintf(end_str, "%d", end);
	return 0;
}

int network_get_ipaddr(char **value, char *iface)
{
	json_object *res, *jobj;
	char *ipv6_value = "";

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", iface, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
	*value = dmjson_get_value(jobj, 1, "address");
	jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-address");
	ipv6_value = dmjson_get_value(jobj, 1, "address");

	if((*value)[0] == '\0' || ipv6_value[0] == '\0') {
		if ((*value)[0] == '\0')
			*value = ipv6_value;
	} else if (ip_version == 6) {
		*value = ipv6_value;
		return 0;
	}
	return 0;
}

char *dmmap_file_path_get(const char *dmmap_package)
{
	char *path;
	int rc;

	rc = dmasprintf(&path, "/etc/bbfdm/%s", dmmap_package);
	if (rc == -1)
		return NULL;

	if (access(path, F_OK)) {
		/*
		 *File does not exist
		 **/
		FILE *fp = fopen(path, "w"); // new empty file
		if (fp)
			fclose(fp);
	}
	return path;
}

void update_section_list(char *config, char *section, char *option, int number, char *filter, char *option1, char *val1, char *option2, char *val2)
{
	char *add_value;
	struct uci_section *s = NULL;
	int i = 0;

	if (strcmp(config, DMMAP) == 0) {
		if (option) {
			uci_path_foreach_option_eq(bbfdm, config, section, option, filter, s) {
				return;
			}
		} else {
			uci_path_foreach_sections(bbfdm, config, section, s) {
				return;
			}
		}
		while (i < number) {
			DMUCI_ADD_SECTION(bbfdm, config, section, &s, &add_value);
			if (option)DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, option, filter);
			if (option1)DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, option1, val1);
			if (option2)DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, option2, val2);
			i++;
		}
	} else {
		if (option) {
			uci_foreach_option_eq(config, section, option, filter, s) {
				return;
			}
		} else {
			uci_foreach_sections(config, section, s) {
				return;
			}
		}
		while (i < number) {
			dmuci_add_section_and_rename(config, section, &s, &add_value);
			if (option)dmuci_set_value_by_section(s, option, filter);
			if (option1)dmuci_set_value_by_section(s, option1, val1);
			if (option2)dmuci_set_value_by_section(s, option2, val2);
			i++;
		}
	}
}

int wan_remove_dev_interface(struct uci_section *interface_setion, char *dev)
{
	char *ifname, new_ifname[64], *p, *pch = NULL, *spch = NULL;
	new_ifname[0] = '\0';
	p = new_ifname;
	dmuci_get_value_by_section_string(interface_setion, "ifname", &ifname);
	for (pch = strtok_r(ifname, " ", &spch); pch; pch = strtok_r(NULL, " ", &spch)) {
		if (!strstr(pch, dev)) {
			if (new_ifname[0] != '\0') {
				dmstrappendchr(p, ' ');
			}
			dmstrappendstr(p, pch);
		}
	}
	dmstrappendend(p);
	if (new_ifname[0] == '\0')
		dmuci_delete_by_section(interface_setion, NULL, NULL);
	else
		dmuci_set_value_by_section(interface_setion, "ifname", new_ifname);
	return 0;
}

int dmcommon_check_notification_value(char *value)
{
	int i;
	for (i = 0; i< __MAX_notification; i++) {
		if (strcmp(value, array_notifcation_char[i]) == 0)
			return 0;
	}
	return -1;
}

void parse_proc_route_line(char *line, struct proc_routing *proute)
{
	char *pch, *spch;

	proute->iface = strtok_r(line, " \t", &spch);
	pch = strtok_r(NULL, " \t", &spch);
	hex_to_ip(pch, proute->destination);
	pch = strtok_r(NULL, " \t", &spch);
	hex_to_ip(pch, proute->gateway);
	proute->flags = strtok_r(NULL, " \t", &spch);
	proute->refcnt = strtok_r(NULL, " \t", &spch);
	proute->use = strtok_r(NULL, " \t", &spch);
	proute->metric = strtok_r(NULL, " \t", &spch);
	pch = strtok_r(NULL, " \t", &spch);
	hex_to_ip(pch, proute->mask);
	proute->mtu = strtok_r(NULL, " \t", &spch);
	proute->window = strtok_r(NULL, " \t", &spch);
	proute->irtt = strtok_r(NULL, " \t\n\r", &spch);
}

void hex_to_ip(char *address, char *ret)
{
	int ip[4] = {0};

	sscanf(address, "%2x%2x%2x%2x", &(ip[0]), &(ip[1]), &(ip[2]), &(ip[3]));
	if (htonl(13) == 13) {
		sprintf(ret, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
	} else {
		sprintf(ret, "%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0]);
	}
}

void ip_to_hex(char *address, char *ret)
{
	int ip[4] = {0};

	sscanf(address, "%d.%d.%d.%d", &(ip[0]), &(ip[1]), &(ip[2]), &(ip[3]));
	sprintf(ret, "%02X%02X%02X%02X", ip[0], ip[1], ip[2], ip[3]);
}

/*
 * dmmap_config sections list manipulation
 */
void add_sectons_list_paramameter(struct list_head *dup_list, struct uci_section *config_section, struct uci_section *dmmap_section, void* additional_attribute)
{
	struct dmmap_dup *dmmap_config;

	dmmap_config = dmcalloc(1, sizeof(struct dmmap_dup));
	list_add_tail(&dmmap_config->list, dup_list);
	dmmap_config->config_section = config_section;
	dmmap_config->dmmap_section = dmmap_section;
	dmmap_config->additional_attribute = additional_attribute;
}

void dmmap_config_dup_delete(struct dmmap_dup *dmmap_config)
{
	list_del(&dmmap_config->list);
}

void free_dmmap_config_dup_list(struct list_head *dup_list)
{
	struct dmmap_dup *dmmap_config;
	while (dup_list->next != dup_list) {
		dmmap_config = list_entry(dup_list->next, struct dmmap_dup, list);
		dmmap_config_dup_delete(dmmap_config);
	}
}

/*
 * Function allows to synchronize config section with dmmap config
 */
struct uci_section *get_origin_section_from_config(char *package, char *section_type, char *orig_section_name)
{
	struct uci_section *s;

	uci_foreach_sections(package, section_type, s) {
		if (strcmp(section_name(s), orig_section_name) == 0) {
			return s;
		}
	}
	return NULL;
}

struct uci_section *get_dup_section_in_dmmap(char *dmmap_package, char *section_type, char *orig_section_name)
{
	struct uci_section *s;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, "section_name", orig_section_name, s) {
		return s;
	}

	return NULL;
}

struct uci_section *get_dup_section_in_dmmap_opt(char *dmmap_package, char *section_type, char *opt_name, char *opt_value)
{
	struct uci_section *s;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, opt_name, opt_value, s) {
		return s;
	}

	return NULL;
}

struct uci_section *get_dup_section_in_dmmap_eq(char *dmmap_package, char* section_type, char*sect_name, char *opt_name, char* opt_value)
{
	struct uci_section *s;
	char *v;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, "section_name", sect_name, s) {
		dmuci_get_value_by_section_string(s, opt_name, &v);
		if (strcmp(v, opt_value) == 0)
			return s;
	}
	return NULL;
}

void synchronize_specific_config_sections_with_dmmap_mcast_iface(char *package, char *section_type,
					void *data, char *dmmap_package, char *dmmap_sec, char *proto,
					struct list_head *dup_list)
{
	struct uci_section *s, *dmmap_sect, *d_sec, *stmp;
	char *v;
	char *s_name;

	dmmap_file_path_get(dmmap_package);
	uci_foreach_option_eq(package, section_type, "proto", proto, s) {
		if (strcmp(section_name(s), section_name((struct uci_section *)data)) != 0)
			continue;

		// The list snooping_interface and proxy_interface in the uci file corresponds to the
		// proxy_interface section in the dmmap. First, read the list of proxy interfaces
		// and update the dmmap section accordingly. The do the same exercise for the list
		// snooping_interface
		struct uci_list *proxy_iface = NULL;
		dmuci_get_value_by_section_list(s, "upstream_interface", &proxy_iface);
		if (proxy_iface != NULL) {
			struct uci_element *e;
			uci_foreach_element(proxy_iface, e) {
				char *p_ifname = dmstrdup(e->name);
				int found = 0;
				uci_path_foreach_option_eq(bbfdm, dmmap_package, dmmap_sec, "ifname",
						p_ifname, d_sec) {
					dmuci_get_value_by_section_string(d_sec, "section_name", &s_name);
					if (strcmp(s_name, section_name(s)) == 0) {
						add_sectons_list_paramameter(dup_list, s, d_sec, NULL);
						found = 1;
						break;
					}
				}

				if (found == 0) {
					// add entry in dmmap for this
					dmuci_add_section_bbfdm(dmmap_package, dmmap_sec, &d_sec, &v);
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, d_sec, "section_name",
							section_name(s));
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, d_sec, "ifname",
							p_ifname);
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, d_sec, "upstream",
							"1");
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, d_sec, "snooping_mode",
							"0");
					add_sectons_list_paramameter(dup_list, s, d_sec, NULL);
				}
			}
		}

		struct uci_list *snooping_iface = NULL;
		char *s_mode;
		dmuci_get_value_by_section_list(s, "downstream_interface", &snooping_iface);
		dmuci_get_value_by_section_string(s, "snooping_mode", &s_mode);
		if (snooping_iface != NULL) {
			struct uci_element *e;
			uci_foreach_element(snooping_iface, e) {
				char *s_ifname = dmstrdup(e->name);
				int found = 0;
				uci_path_foreach_option_eq(bbfdm, dmmap_package, dmmap_sec, "ifname",
						s_ifname, d_sec) {
					dmuci_get_value_by_section_string(d_sec, "section_name", &s_name);
					if (strcmp(s_name, section_name(s)) == 0) {
						add_sectons_list_paramameter(dup_list, s, d_sec, NULL);
						found = 1;
						break;
					}
				}

				if (found == 0) {
					// add entry in dmmap for this
					dmuci_add_section_bbfdm(dmmap_package, dmmap_sec, &d_sec, &v);
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, d_sec, "section_name",
							section_name(s));
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, d_sec, "ifname",
							s_ifname);
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, d_sec, "upstream",
							"0");
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, d_sec, "snooping_mode",
							s_mode);
					add_sectons_list_paramameter(dup_list, s, d_sec, NULL);
				}
			}
		}

		char *f_ifname;
		// There can be entries in the dmmap_mcast file that do not have an ifname set.
		// For such entries, now add to dup_list
		uci_path_foreach_option_eq(bbfdm, dmmap_package, dmmap_sec, "section_name",
				section_name(s), dmmap_sect) {
			dmuci_get_value_by_section_string(dmmap_sect, "ifname", &f_ifname);

			if (strcmp(f_ifname, "") == 0)
				add_sectons_list_paramameter(dup_list, s, dmmap_sect, NULL);
		}
	}

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, dmmap_sec, stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
	}
}

void synchronize_specific_config_sections_with_dmmap_filter(char *package, char *section_type, void *data,
							char *dmmap_package, char *dmmap_sec, char *proto,
							struct list_head *dup_list)
{
	struct uci_section *s, *dmmap_sect, *d_sec, *stmp;
	char *v;
	char *s_name;

	dmmap_file_path_get(dmmap_package);

	uci_foreach_option_eq(package, section_type, "proto", proto, s) {
		if (strcmp(section_name(s), section_name((struct uci_section *)data)) != 0)
			continue;
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		struct uci_list *l = NULL;

		dmuci_get_value_by_section_list(s, "filter", &l);
		if (l != NULL) {
			struct uci_element *e;
			uci_foreach_element(l, e) {
				char *ip_addr = dmstrdup(e->name);
				int found = 0;
				uci_path_foreach_option_eq(bbfdm, dmmap_package, dmmap_sec, "ipaddr",
						ip_addr, d_sec) {
					dmuci_get_value_by_section_string(d_sec, "section_name", &s_name);
					if (strcmp(s_name, section_name(s)) == 0) {
						add_sectons_list_paramameter(dup_list, s, d_sec, NULL);
						found = 1;
						break;
					}
				}

				if (found == 0) {
					// add entry in dmmap for this
					dmuci_add_section_bbfdm(dmmap_package, dmmap_sec, &d_sec, &v);
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, d_sec, "section_name",
							section_name(s));
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, d_sec, "ipaddr",
							ip_addr);
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, d_sec, "enable",
							"1");
					add_sectons_list_paramameter(dup_list, s, d_sec, NULL);
				}
			}
		}

		char *f_ip, *f_enable;
		// There can be entries in the dmmap_mcast file that do not have an IP address set.
		// For such entries, now add to dup_list
		uci_path_foreach_option_eq(bbfdm, dmmap_package, dmmap_sec, "section_name",
				section_name(s), dmmap_sect) {
			dmuci_get_value_by_section_string(dmmap_sect, "ipaddr", &f_ip);
			dmuci_get_value_by_section_string(dmmap_sect, "enable", &f_enable);

			if ((f_ip[0] == '\0') || (strcmp(f_enable, "0") == 0))
				add_sectons_list_paramameter(dup_list, s, dmmap_sect, NULL);
		}
	}

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, dmmap_sec, stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
	}
}

void synchronize_specific_config_sections_with_dmmap(char *package, char *section_type, char *dmmap_package, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	char *v;

	dmmap_file_path_get(dmmap_package);

	uci_foreach_sections(package, section_type, s) {
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, section_type, section_name(s))) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section_type, &dmmap_sect, &v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(s));
		}

		/* Change to fix multiple IP interface creation. */
		if (strcmp(package, "network") == 0  && strcmp(section_type, "interface") == 0 && strcmp(dmmap_package, "dmmap_network") == 0) {
			char *value;
			dmuci_get_value_by_section_string(s, "proto", &value);
			if (*value == '\0')
				continue;
		}

		/*
		 * Add system and dmmap sections to the list
		 */
		add_sectons_list_paramameter(dup_list, s, dmmap_sect, NULL);
	}

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section_type, stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
	}
}

void synchronize_specific_config_sections_with_dmmap_eq(char *package, char *section_type, char *dmmap_package,char* option_name, char* option_value, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	char *v;

	dmmap_file_path_get(dmmap_package);

	uci_foreach_option_eq(package, section_type, option_name, option_value, s) {
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, section_type, section_name(s))) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section_type, &dmmap_sect, &v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(s));
		}

		/*
		 * Add system and dmmap sections to the list
		 */
		add_sectons_list_paramameter(dup_list, s, dmmap_sect, NULL);
	}

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section_type, stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

void synchronize_specific_config_sections_with_dmmap_eq_no_delete(char *package, char *section_type, char *dmmap_package, char* option_name, char* option_value, struct list_head *dup_list)
{
	struct uci_section *s, *dmmap_sect;
	char *v;

	dmmap_file_path_get(dmmap_package);

	uci_foreach_option_eq(package, section_type, option_name, option_value, s) {
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, section_type, section_name(s))) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section_type, &dmmap_sect, &v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(s));
		}
	}

	dmmap_sect = NULL;
	s = NULL;
	uci_path_foreach_sections(bbfdm, dmmap_package, section_type, dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "section_name", &v);
		get_config_section_of_dmmap_section("network", "interface", v, &s);
		add_sectons_list_paramameter(dup_list, s, dmmap_sect, NULL);
	}
}

void synchronize_specific_config_sections_with_dmmap_cont(char *package, char *section_type, char *dmmap_package,char* option_name, char* option_value, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	char *v;

	dmmap_file_path_get(dmmap_package);

	uci_foreach_option_cont(package, section_type, option_name, option_value, s) {
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, section_type, section_name(s))) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section_type, &dmmap_sect, &v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(s));
		}

		/*
		 * Add system and dmmap sections to the list
		 */
		add_sectons_list_paramameter(dup_list, s, dmmap_sect, NULL);
	}

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section_type, stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

void add_sysfs_sectons_list_paramameter(struct list_head *dup_list, struct uci_section *dmmap_section, char *file_name, char* filepath)
{
	struct sysfs_dmsection *dmmap_sysfs;

	dmmap_sysfs = dmcalloc(1, sizeof(struct sysfs_dmsection));
	list_add_tail(&dmmap_sysfs->list, dup_list);
	dmmap_sysfs->dm = dmmap_section;
	dmmap_sysfs->sysfs_folder_name = dmstrdup(file_name);
	dmmap_sysfs->sysfs_folder_path = dmstrdup(filepath);
}

int synchronize_system_folders_with_dmmap_opt(char *sysfsrep, char *dmmap_package, char *dmmap_section, char *opt_name, char* inst_opt, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	DIR *dir;
	struct dirent *ent;
	char *v, *sysfs_rep_path, *instance= NULL;
	struct sysfs_dmsection *p, *tmp;
	LIST_HEAD(dup_list_no_inst);


	dmmap_file_path_get(dmmap_package);

	sysfs_foreach_file(sysfsrep, dir, ent) {
		if(strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name, "..")==0)
			continue;

		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		dmasprintf(&sysfs_rep_path, "%s/%s", sysfsrep, ent->d_name);
		if ((dmmap_sect = get_dup_section_in_dmmap_opt(dmmap_package, dmmap_section, opt_name, sysfs_rep_path)) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, dmmap_section, &dmmap_sect, &v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, opt_name, sysfs_rep_path);
		}

		dmuci_get_value_by_section_string(dmmap_sect, inst_opt, &instance);

		/*
		 * Add system and dmmap sections to the list
		 */

		if(instance == NULL || strlen(instance) <= 0)
			add_sysfs_sectons_list_paramameter(&dup_list_no_inst, dmmap_sect, ent->d_name, sysfs_rep_path);
		else
			add_sysfs_sectons_list_paramameter(dup_list, dmmap_sect, ent->d_name, sysfs_rep_path);
	}
	if (dir)
		closedir(dir);

	/*
	 * fusion two lists
	 */
	list_for_each_entry_safe(p, tmp, &dup_list_no_inst, list)
		list_move_tail(&p->list, dup_list);

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, dmmap_section, stmp, s) {
		dmuci_get_value_by_section_string(s, opt_name, &v);
		if (isfolderexist(v) == 0)
			dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
	}
	return 0;
}

void get_dmmap_section_of_config_section(char* dmmap_package, char* section_type, char *section_name, struct uci_section **dmmap_section)
{
	struct uci_section* s;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, "section_name", section_name, s) {
		*dmmap_section = s;
		return;
	}
	*dmmap_section = NULL;
}

void get_dmmap_section_of_config_section_eq(char* dmmap_package, char* section_type, char *opt, char* value, struct uci_section **dmmap_section)
{
	struct uci_section* s;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, opt, value, s) {
		*dmmap_section = s;
		return;
	}
	*dmmap_section = NULL;
}

void get_config_section_of_dmmap_section(char* package, char* section_type, char *section_name, struct uci_section **config_section)
{
	struct uci_section* s;

	uci_foreach_sections(package, section_type, s) {
		if (strcmp(section_name(s), section_name) == 0) {
			*config_section = s;
			return;
		}
	}
	*config_section = NULL;
}

void check_create_dmmap_package(char *dmmap_package)
{
	char *dmmap_file_path = dmmap_file_path_get(dmmap_package);
	dmfree(dmmap_file_path);
}

int is_section_unnamed(char *section_name)
{
	int i;

	if (strlen(section_name) != 9)
		return 0;
	if(strstr(section_name, "cfg") != section_name)
		return 0;
	for (i = 3; i < 9; i++) {
		if (!isxdigit(section_name[i]))
			return 0;
	}
	return 1;
}

void add_dmmap_list_section(struct list_head *dup_list, char* section_name, char* instance)
{
	struct dmmap_sect *dmsect;

	dmsect = dmcalloc(1, sizeof(struct dmmap_sect));
	list_add_tail(&dmsect->list, dup_list);
	dmasprintf(&dmsect->section_name, "%s", section_name);
	dmasprintf(&dmsect->instance, "%s", instance);
}

void delete_sections_save_next_sections(char* dmmap_package, char *section_type, char *instancename, char *section_name, int instance, struct list_head *dup_list)
{
	struct uci_section *s, *stmp;
	char *v = NULL, *lsectname = NULL, *tmp = NULL;
	int inst;

	dmasprintf(&lsectname, "%s", section_name);

	uci_path_foreach_sections(bbfdm, dmmap_package, section_type, s) {
		dmuci_get_value_by_section_string(s, instancename, &v);
		inst= atoi(v);
		if(inst>instance){
			dmuci_get_value_by_section_string(s, "section_name", &tmp);
			add_dmmap_list_section(dup_list, lsectname, v);
			dmfree(lsectname);
			lsectname= NULL;
			dmasprintf(&lsectname, "%s", tmp);
			dmfree(tmp);
			tmp= NULL;
		}
	}

	if(lsectname != NULL) dmfree(lsectname);

	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section_type, stmp, s) {
		dmuci_get_value_by_section_string(s, instancename, &v);
		inst= atoi(v);
		if(inst>=instance)
			dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
	}
}

void update_dmmap_sections(struct list_head *dup_list, char *instancename, char* dmmap_package, char *section_type)
{
	struct uci_section *dm_sect;
	char *v;
	struct dmmap_sect *p = NULL;

	list_for_each_entry(p, dup_list, list) {
		dmuci_add_section_bbfdm(dmmap_package, section_type, &dm_sect, &v);
		dmuci_set_value_by_section(dm_sect, "section_name", p->section_name);
		dmuci_set_value_by_section(dm_sect, instancename, p->instance);
	}
}

struct uci_section *is_dmmap_section_exist(char* package, char* section)
{
	struct uci_section *s;

	uci_path_foreach_sections(bbfdm, package, section, s) {
		return s;
	}
	return NULL;
}

struct uci_section *is_dmmap_section_exist_eq(char* package, char* section, char* opt, char* value)
{
	struct uci_section *s;

	uci_path_foreach_option_eq(bbfdm, package, section, opt, value, s) {
		return s;
	}
	return NULL;
}

unsigned char isdigit_str(char *str)
{
	if (!(*str)) return 0;
	while(isdigit(*str++));
	return ((*(str-1)) ? 0 : 1);
}

static inline int isword_delim(char c)
{
	if (c == ' ' ||
		c == ',' ||
		c == '.' ||
		c == '\t' ||
		c == '\v' ||
		c == '\r' ||
		c == '\n' ||
		c == '\0')
		return 1;
	return 0;
}

char *dm_strword(char *src, char *str)
{
	char *ret = src;
	if (src[0] == '\0')
		return NULL;
	int len = strlen(str);
	while ((ret = strstr(ret, str)) != NULL) {
		if ((ret == src && isword_delim(ret[len])) ||
			(ret != src && isword_delim(ret[len]) && isword_delim(*(ret - 1))))
			return ret;
		ret++;
	}
	return NULL;
}

char **strsplit(const char* str, const char* delim, size_t* numtokens)
{
	char *s = strdup(str);
	size_t tokens_alloc = 1;
	size_t tokens_used = 0;
	char **tokens = dmcalloc(tokens_alloc, sizeof(char*));
	char *token, *strtok_ctx;

	for (token = strtok_r(s, delim, &strtok_ctx);
		token != NULL;
		token = strtok_r(NULL, delim, &strtok_ctx)) {

		if (tokens_used == tokens_alloc) {
			tokens_alloc *= 2;
			tokens = dmrealloc(tokens, tokens_alloc * sizeof(char*));
		}
		tokens[tokens_used++] = dmstrdup(token);
	}
	if (tokens_used == 0) {
		dmfree(tokens);
		tokens = NULL;
	} else {
		tokens = dmrealloc(tokens, tokens_used * sizeof(char*));
	}
	*numtokens = tokens_used;
	FREE(s);
	return tokens;
}

char **strsplit_by_str(const char str[], char *delim)
{
	char *substr = NULL;
	size_t tokens_alloc = 1;
	size_t tokens_used = 0;
	char **tokens = dmcalloc(tokens_alloc, sizeof(char*));
	char *strparse = strdup(str);
	do {
		substr = strstr(strparse, delim);
		if (substr == NULL && (strparse == NULL || strparse[0] == '\0'))
			break;

		if (substr == NULL) {
			substr = strdup(strparse);
			tokens[tokens_used] = dmcalloc(strlen(substr)+1, sizeof(char));
			strcpy(tokens[tokens_used], strparse);
			FREE(strparse);
			break;
		}

		if (tokens_used == tokens_alloc) {
			if (strparse == NULL)
				tokens_alloc++;
			else
				tokens_alloc += 2;
			tokens = dmrealloc(tokens, tokens_alloc * sizeof(char*));
		}

		tokens[tokens_used] = dmcalloc(substr-strparse+1, sizeof(char));
		strncpy(tokens[tokens_used], strparse, substr-strparse);
		tokens_used++;
		FREE(strparse);
		strparse = strdup(substr+strlen(delim));
	} while (substr != NULL);
	FREE(strparse);
	return tokens;
}

char *get_macaddr_from_device(char *device_name)
{
	char *mac;

	if (device_name[0]) {
		char file[128];
		char val[32];

		snprintf(file, sizeof(file), "/sys/class/net/%s/address", device_name);
		dm_read_sysfs_file(file, val, sizeof(val));
		mac = dmstrdup(val);
	} else {
		mac = "";
	}
	return mac;
}

char *get_macaddr(char *interface_name)
{
	char *device = get_device(interface_name);
	char *mac;

	if (device[0]) {
		char file[128];
		char val[32];

		snprintf(file, sizeof(file), "/sys/class/net/%s/address", device);
		dm_read_sysfs_file(file, val, sizeof(val));
		mac = dmstrdup(val);
	} else {
		mac = "";
	}
	return mac;
}

char *get_device(char *interface_name)
{
	json_object *res;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface_name, String}}, 1, &res);
	return dmjson_get_value(res, 1, "device");
}

char *get_device_from_wifi_iface(const char *wifi_iface, const char *wifi_section)
{
	json_object *jobj;
	array_list *jarr;
	unsigned n = 0, i;
	const char *ifname = "";

	if (wifi_iface[0] == 0 || wifi_section[0] == 0)
		return "";

	dmubus_call("network.wireless", "status", UBUS_ARGS{{}}, 0, &jobj);
	if (jobj == NULL)
		return "";

	json_object_object_get_ex(jobj, wifi_iface, &jobj);
	json_object_object_get_ex(jobj, "interfaces", &jobj);

	jarr = json_object_get_array(jobj);
	if (jarr)
		n = array_list_length(jarr);

	for (i = 0; i < n; i++) {
		json_object *j_e = jarr->array[i];
		const char *sect;

		sect = __dmjson_get_string(j_e, "section");
		if (!strcmp(sect, wifi_section)) {
			ifname = __dmjson_get_string(j_e, "ifname");
			break;
		}
	}
	return (char *)ifname;
}

/*
 * Manage string lists
 */

int is_elt_exit_in_str_list(char *str_list, char *elt)
{
	char *pch, *spch, *list;
	list= dmstrdup(str_list);
	for (pch = strtok_r(list, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		if(strcmp(pch, elt) == 0)
			return 1;
	}
	return 0;
}

void add_elt_to_str_list(char **str_list, char *elt)
{
	if (*str_list == NULL || strlen(*str_list) == 0) {
		dmasprintf(str_list, "%s", elt);
		return;
	}
	char *list = dmstrdup(*str_list);
	dmfree(*str_list);
	*str_list = NULL;
	dmasprintf(str_list, "%s %s", list, elt);
}

void remove_elt_from_str_list(char **iface_list, char *ifname)
{
	char *list = NULL, *tmp = NULL, *pch = NULL, *spch = NULL;

	if (*iface_list == NULL || strlen(*iface_list) == 0)
		return;
	list = dmstrdup(*iface_list);
	dmfree(*iface_list);
	*iface_list = NULL;
	for (pch = strtok_r(list, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		if (strcmp(pch, ifname) == 0)
			continue;
		if (tmp == NULL)
			dmasprintf(iface_list, "%s", pch);
		else
			dmasprintf(iface_list, "%s %s", tmp, pch);
		if (tmp) {
			dmfree(tmp);
			tmp = NULL;
		}
		if(*iface_list){
			tmp = dmstrdup(*iface_list);
			dmfree(*iface_list);
			*iface_list = NULL;
		}
	}
	dmasprintf(iface_list, "%s", tmp);
}

int is_array_elt_exist(char **str_array, char *str, int length)
{
	int i;

	for (i = 0; i < length; i++){
		if (strcmp(str_array[i], str) == 0)
			return 1;
	}
	return 0;
}

int get_shift_time_time(int shift_time, char *local_time, int size)
{
	time_t t_time;
	struct tm *t_tm;

	t_time = time(NULL) + shift_time;
	t_tm = localtime(&t_time);
	if (t_tm == NULL)
		return -1;

	if (strftime(local_time, size, "%Y-%m-%dT%H:%M:%SZ", t_tm) == 0)
		return -1;

	return 0;
}

int get_shift_time_shift(char *local_time, char *shift)
{
	struct tm tm = {0};

	strptime(local_time,"%Y-%m-%dT%H:%M:%SZ", &tm);
	sprintf(shift, "%u", (unsigned int)(mktime(&tm) - time(NULL)));

	return 0;
}

int command_exec_output_to_array(char *cmd, char **output, int *length)
{
	FILE *fp;
	char out[1035];
	int i = 0;

	/* Open the command for reading. */
	fp = popen(cmd, "r");
	if (fp == NULL)
		return 0;

	/* Read the output line by line and store it in output array. */
	while (fgets(out, sizeof(out)-1, fp) != NULL)
		dmasprintf(&output[i++], "%s", out);

	*length = i;

	/* close */
	pclose(fp);

	return 0;
}

int isfolderexist(char *folderpath)
{
	DIR* dir = opendir(folderpath);
	if (dir) {
	    closedir(dir);
	    return 1;
	} else
		return 0;
}

int copy_temporary_file_to_original_file(char *f1, char *f2)
{
	FILE *fp, *ftmp;
	char buf[512];

	ftmp = fopen(f2, "r");
	if (ftmp == NULL)
		return 0;

	fp = fopen(f1, "w");
	if (fp == NULL) {
	  fclose(ftmp);
	  return 0;
	}

	while (fgets(buf, 512, ftmp) != NULL) {
		fprintf(fp, "%s", buf);
	}
	fclose(ftmp);
	fclose(fp);
	return 1;
}

static inline int char_is_valid(char c)
{
	return c >= 0x20 && c < 0x7f;
}

int dm_read_sysfs_file(const char *file, char *dst, unsigned len)
{
	char *content;
	int fd;
	int rlen;
	int i, n;
	int rc = 0;

	content = alloca(len);
	dst[0] = 0;

	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -1;

	rlen = read(fd, content, len - 1);
	if (rlen == -1) {
		rc = -1;
		goto out;
	}

	content[rlen] = 0;
	for (i = 0, n = 0; i < rlen; i++) {
		if (!char_is_valid(content[i])) {
			if (i == 0)
				continue;
			else
				break;
		}
		dst[n++] = content[i];
	}
	dst[n] = 0;

out:
	close(fd);
	return rc;
}

int get_net_device_sysfs(const char *device, const char *name, char **value)
{
	if (device && device[0]) {
		char file[256];
		char val[64];

		snprintf(file, sizeof(file), "/sys/class/net/%s/%s", device, name);
		dm_read_sysfs_file(file, val, sizeof(val));
		*value = dmstrdup(val);
	} else {
		*value = "0";
	}
	return 0;
}

int get_net_iface_sysfs(const char *uci_iface, const char *name, char **value)
{
	const char *device = get_device((char *)uci_iface);

	return get_net_device_sysfs(device, name, value);
}

int dm_time_format(time_t ts, char **dst)
{
	char time_buf[32] = { 0, 0 };
	struct tm *t_tm;

	*dst = "0001-01-01T00:00:00Z";

	t_tm = localtime(&ts);
	if (t_tm == NULL)
		return -1;

	if(strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", t_tm) == 0)
		return -1;

	*dst = dmstrdup(time_buf);
	return 0;
}

bool match(const char *string, const char *pattern)
{
	regex_t re;
	if (regcomp(&re, pattern, REG_EXTENDED) != 0) return 0;
	int status = regexec(&re, string, 0, NULL, 0);
	regfree(&re);
	if (status != 0) return false;
	return true;
}

static int dm_validate_string_length(char *value, int min_length, int max_length)
{
	if (((min_length > 0) && (strlen(value) < min_length)) || ((max_length > 0) && (strlen(value) > max_length)))
		return -1;
	return 0;
}

static int dm_validate_string_enumeration(char *value, char *enumeration[], int enumeration_size)
{
	int i;
	for (i = 0; i < enumeration_size; i++) {
		if (strcmp(enumeration[i], value) == 0)
			return 0;
	}
	return -1;
}

static int dm_validate_string_pattern(char *value, char *pattern[], int pattern_size)
{
	int i;
	for (i = 0; i < pattern_size; i++) {
		if (match(value, pattern[i]))
			return 0;
	}
	return -1;
}

int dm_validate_string(char *value, int min_length, int max_length, char *enumeration[], int enumeration_size, char *pattern[], int pattern_size)
{
	/* check size */
	if (dm_validate_string_length(value, min_length, max_length))
		return -1;

	/* check enumeration */
	if (enumeration && dm_validate_string_enumeration(value, enumeration, enumeration_size))
		return -1;

	/* check pattern */
	if (pattern && dm_validate_string_pattern(value, pattern, pattern_size))
		return -1;

	return 0;
}

int dm_validate_boolean(char *value)
{
	/* check format */
	if ((value[0] == '1' && value[1] == '\0') || (value[0] == '0' && value[1] == '\0')
		|| (strcmp(value, "true") == 0) || (strcmp(value, "false") == 0)) {
		return 0;
	}
	return -1;
}

int dm_validate_unsignedInt(char *value, struct range_args r_args[], int r_args_size)
{
	int i;

	/* check size for each range */
	for (i = 0; i < r_args_size; i++) {
		unsigned long val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtoul(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtoul(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		val = strtoul(value, &endval, 10);

		if ((*endval != 0) || (errno != 0)) return -1;

		/* check size */
		if ((r_args[i].min && val < minval) || (r_args[i].max && val > maxval) || (val < 0) || (val > (unsigned int)UINT_MAX))
			return -1;
	}

	return 0;
}

int dm_validate_int(char *value, struct range_args r_args[], int r_args_size)
{
	int i;

	/* check size for each range */
	for (i = 0; i < r_args_size; i++) {
		long val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtol(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtol(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		val = strtol(value, &endval, 10);

		if ((*endval != 0) || (errno != 0)) return -1;

		/* check size */
		if ((r_args[i].min && val < minval) || (r_args[i].max && val > maxval) || (val < INT_MIN) || (val > INT_MAX))
			return -1;
	}

	return 0;
}

int dm_validate_unsignedLong(char *value, struct range_args r_args[], int r_args_size)
{
	int i;

	/* check size for each range */
	for (i = 0; i < r_args_size; i++) {
		unsigned long val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtoul(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtoul(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		val = strtoul(value, &endval, 10);

		if ((*endval != 0) || (errno != 0)) return -1;

		/* check size */
		if ((r_args[i].min && val < minval) || (r_args[i].max && val > maxval) || (val < 0) || (val > (unsigned long)ULONG_MAX))
			return -1;
	}

	return 0;
}

int dm_validate_long(char *value, struct range_args r_args[], int r_args_size)
{
	int i;

	/* check size for each range */
	for (i = 0; i < r_args_size; i++) {
		long val = 0, minval = 0, maxval = 0;
		char *endval = NULL, *endmin = NULL, *endmax = NULL;

		if (r_args[i].min) minval = strtol(r_args[i].min, &endmin, 10);
		if (r_args[i].max) maxval = strtol(r_args[i].max, &endmax, 10);

		/* reset errno to 0 before call */
		errno = 0;

		val = strtol(value, &endval, 10);

		if ((*endval != 0) || (errno != 0)) return -1;

		/* check size */
		if ((r_args[i].min && val < minval) || (r_args[i].max && val > maxval))
			return -1;
	}

	return 0;
}

int dm_validate_dateTime(char *value)
{
	/* check format */
	struct tm tm;
	if (!(strptime(value, "%Y-%m-%dT%H:%M:%SZ", &tm)))
		return -1;
	return 0;
}

int dm_validate_hexBinary(char *value, struct range_args r_args[], int r_args_size)
{
	int i;

	/* check format */
	for (i = 0; i < strlen(value); i++) {
		if (!isxdigit(value[i]))
			return -1;
	}

	/* check size */
	for (i = 0; i < r_args_size; i++) {
		if ((r_args[i].min && r_args[i].max && (atoi(r_args[i].min) == atoi(r_args[i].max)) && (strlen(value) != 2 * atoi(r_args[i].max))) ||
			(r_args[i].min && !r_args[i].max && (strlen(value) < atoi(r_args[i].min))) ||
			(!r_args[i].min && r_args[i].max && (strlen(value) > atoi(r_args[i].max)))) {
			return -1;
		}
	}

	return 0;
}

static int dm_validate_size_list(int min_item, int max_item, int nbr_item)
{
	if (((min_item > 0) && (max_item > 0) && (min_item == max_item) && (nbr_item != 2 * max_item)) ||
		((min_item > 0) && (nbr_item < min_item)) ||
		((max_item > 0) && (nbr_item > max_item))) {
		return -1;
	}
	return 0;
}

int dm_validate_string_list(char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], int enumeration_size, char *pattern[], int pattern_size)
{
	char *pch, *pchr;
	int nbr_item = 0;

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size))
			return -1;

	/* copy data in buffer */
	char buf[strlen(value)+1];
	strncpy(buf, value, sizeof(buf) - 1);
	buf[strlen(value)] = '\0';

	/* for each value, validate string */
	for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
		if (dm_validate_string(pch, min, max, enumeration, enumeration_size, pattern, pattern_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (dm_validate_size_list(min_item, max_item, nbr_item))
		return -1;

	return 0;
}

int dm_validate_unsignedInt_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	char *pch, *pchr;
	int nbr_item = 0;

	/* check length of list */
	if ((max_size > 0) && (strlen(value) > max_size))
			return -1;

	/* copy data in buffer */
	char buf[strlen(value)+1];
	strncpy(buf, value, sizeof(buf) - 1);
	buf[strlen(value)] = '\0';

	/* for each value, validate string */
	for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
		if (dm_validate_unsignedInt(pch, r_args, r_args_size))
			return -1;
		nbr_item ++;
	}

	/* check size of list */
	if (dm_validate_size_list(min_item, max_item, nbr_item))
		return -1;

	return 0;
}

bool file_exists(const char* path)
{
	struct stat buffer;

	if(stat(path, &buffer) == 0)
		return true;
	else
		return false;
}

int is_regular_file(const char *path)
{
	if (path == NULL || strlen(path) == 0)
		return 0;

	struct stat path_stat;
	stat(path, &path_stat);
	return S_ISREG(path_stat.st_mode);
}

int get_base64char_value(char b64)
{
	char *base64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i;
	for (i = 0; i < 64; i++)
		if (base64C[i] == b64)
		return i;
	return -1;
}

char *decode64(char *enc)
{
	int i, j = 0;
	size_t decsize = strlen(enc)*6/8;
	char *dec = (char *)dmmalloc((decsize +1) * sizeof(char));

	for (i = 0; i < strlen(enc)-1; i++) {
		dec[j] = (get_base64char_value(enc[i]) << (j%3==0?2:(j%3==1?4:6))) + (get_base64char_value(enc[i+1]) >> (j%3==0?4:(j%3==1? 2:0)));
		if (j%3 == 2)
			i++;
		j++;
	}
	dec[j] = '\0';
	return dec;
}

char *stringToHex(char *text, int length)
{
	char *hex = NULL;
	int i, j;

	hex = (char *)dmcalloc(100, sizeof(char));

	for (i = 0, j = 0; i < length; ++i, j += 3) {
		sprintf(hex + j, "%02x", text[i] & 0xff);
		if (i < length-1)
			sprintf(hex + j + 2, "%c", ':');
	}
	return hex;
}

char *replace_char(char *str, char find, char replace)
{
	char *current_pos = strchr(str, find);
	while (current_pos) {
		*current_pos = replace;
		current_pos = strchr(current_pos, find);
	}
	return str;
}

int is_vlan_termination_section(char *name)
{
	struct uci_section *s;

	uci_foreach_sections("network", "interface", s) {

		// check ifname is not empty
		char *ifname;
		dmuci_get_value_by_section_string(s, "ifname", &ifname);
		if (*ifname == '\0')
			continue;

		// check if ifname list contains the device name
		if (strstr(ifname, name)) {
			char *type;
			// check type is not bridge

			dmuci_get_value_by_section_string(s, "type", &type);
			if (strcmp(type, "bridge") == 0)
				return 0;

			break;
		}
	}
	return 1;
}

void del_dmmap_sec_with_opt_eq(char *dmmap_file, char *section, char *option, char *value)
{
	struct uci_section *d_sec = NULL;
	struct uci_section *stmp = NULL;
	char *opt_val;

	uci_path_foreach_sections_safe(bbfdm, dmmap_file, section, stmp, d_sec) {
		dmuci_get_value_by_section_string(d_sec, option, &opt_val);
		if (strcmp(opt_val, value) == 0)
			dmuci_delete_by_section_unnamed_bbfdm(d_sec, NULL, NULL);
	}
}

void sync_dmmap_bool_to_uci_list(struct uci_section *s, char *section,
				char *value, bool b)
{
	struct uci_list *v = NULL;
	struct uci_element *e;
	char *val;

	dmuci_get_value_by_section_list(s, section, &v);
	if (v != NULL) {
		uci_foreach_element(v, e) {
			val = dmstrdup(e->name);
			if (strcmp(val, value) == 0) {
				if (!b) {
					// remove this entry
					dmuci_del_list_value_by_section(s, section, value);
				}

				// Further action is not required
				return;
			}
		}
	}

	// If control has reached this point, that means, either the entry was not found
	// in the list, hence, if b is true, add this entry to the list
	if (b) {
		dmuci_add_list_value_by_section(s, section, value);
	}
}

int get_br_key_from_lower_layer(char *lower_layer, char *key, size_t s_key)
{
	char *p = strstr(lower_layer, "Port");

	if (!p)
		return -1;

	/* Get the bridge_key. */
	int len = strlen(p);
	char new_if[250] = {0};
	int i;
	for (i = 0; i < strlen(lower_layer) - len; i++) {
		new_if[i] = lower_layer[i];
	}

	char br_key = new_if[strlen(new_if) - 2];

	snprintf(key, s_key, "%c", br_key);

	return 0;
}

int get_igmp_snooping_interface_val(char *value, char *ifname, size_t s_ifname)
{
	char lower_layer[250] = {0};

	if (value[strlen(value)-1] != '.')
		snprintf(lower_layer, sizeof(lower_layer), "%s.", value);
	else
		strncpy(lower_layer, value, sizeof(lower_layer) - 1);

	/* Check if the value is valid or not. */
	if (strncmp(lower_layer, "Device.Bridging.Bridge.", 23) != 0)
		return -1;

	char key[10] = {0};
	if (get_br_key_from_lower_layer(lower_layer, key, sizeof(key)) != 0)
		return -1;

	/* Find out bridge section name using bridge key. */
	struct uci_section *s = NULL;
	char *sec_name;
	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "interface", "bridge_instance", key, s) {
		dmuci_get_value_by_section_string(s, "section_name", &sec_name);
		break;
	}

	// Check if network uci file has this section, if yes, then
	// update the snooping interface with value as br-<section name>
	struct uci_section *intf_s = NULL;
	uci_foreach_sections("network", "interface", intf_s) {
		char  sec[20] = {0};
		strncpy(sec, section_name(intf_s), sizeof(sec) - 1);
		if (strncmp(sec, sec_name, sizeof(sec)) != 0)
			continue;

		char *type;
		dmuci_get_value_by_section_string(intf_s, "type", &type);
		if (*type == '\0' || strcmp(type, "bridge") != 0)
			continue;

		snprintf(ifname, s_ifname, "br-%s", sec_name);
		break;

	}

	return 0;
}
