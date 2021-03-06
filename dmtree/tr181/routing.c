/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "routing.h"

#define PROC_ROUTE6 "/proc/net/ipv6_route"

enum enum_route_type {
	ROUTE_STATIC,
	ROUTE_DYNAMIC,
	ROUTE_DISABLED
};

/********************************
 * init function
 ********************************/
static inline int init_args_ipv4forward(struct routingfwdargs *args, struct uci_section *s, char *permission, int type)
{
	args->permission = permission;
	args->routefwdsection = s;
	args->type = type;
	return 0;
}

static inline int init_args_ipv6forward(struct routingfwdargs *args, struct uci_section *s, char *permission, int type)
{
	args->permission = permission;
	args->routefwdsection = s;
	args->type = type;
	return 0;
}

/************************************************************************************* 
**** function related to get_object_router_ipv4forwarding ****
**************************************************************************************/
static bool is_proc_route_in_config(struct proc_routing *proute)
{
	struct uci_section *s;
	char *mask, *target, *gateway, *device;

	uci_foreach_option_eq("network", "route", "target", proute->destination, s) {
		dmuci_get_value_by_section_string(s, "netmask", &mask);
		if (mask[0] == '\0' || strcmp(proute->mask, mask) == 0)
			return true;
	}
	uci_foreach_option_eq("network", "route_disabled", "target", proute->destination, s) {
		dmuci_get_value_by_section_string(s, "netmask", &mask);
		if (mask[0] == '\0' || strcmp(proute->mask, mask) == 0)
			return true;
	}
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route_dynamic", s) {
		dmuci_get_value_by_section_string(s, "target", &target);
		dmuci_get_value_by_section_string(s, "gateway", &gateway);
		dmuci_get_value_by_section_string(s, "device", &device);
		if (strcmp(target, proute->destination) == 0 && strcmp(gateway, proute->gateway) == 0 && strcmp(device, proute->iface) == 0) {
			return true;
		}
	}
	return false;
}

static unsigned char is_proc_route6_in_config(char *ciface, char *cip, char *cgw)
{
	struct uci_section *s = NULL;
	char *ip, *gw, *v;
	json_object *jobj;

	uci_foreach_sections("network", "route6", s) {
		dmuci_get_value_by_section_string(s, "target", &ip);
		ip = (*ip) ? ip : "::/0";
		dmuci_get_value_by_section_string(s, "gateway", &gw);
		gw = (*gw) ? gw : "::";
		dmuci_get_value_by_section_string(s, "interface", &v);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", v, String}}, 1, &jobj);
		if (!jobj) return 0;
		v = dmjson_get_value(jobj, 1, "device");
		if (((*v != '\0' && strcmp(ciface, v) == 0) || ((*gw != ':' || *(gw+1) != ':') && strcmp(cgw, gw) == 0)) && strcmp(cip, ip) == 0) {
			return 1;
		}
	}
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route6_dynamic", s) {
		dmuci_get_value_by_section_string(s, "target", &ip);
		dmuci_get_value_by_section_string(s, "gateway", &gw);
		dmuci_get_value_by_section_string(s, "device", &v);
		if (((*v != '\0' && strcmp(ciface, v) == 0) || ((*gw != ':' || *(gw+1) != ':') && strcmp(cgw, gw) == 0)) && strcmp(cip, ip) == 0) {
			return 1;
		}
	}
	return 0;
}

static bool is_cfg_route_active(struct uci_section *s)
{
	FILE *fp;
	char line[MAX_PROC_ROUTING];
	struct proc_routing proute;
	char *dest, *mask;
	int lines = 0;

	dmuci_get_value_by_section_string(s, "target", &dest);
	dmuci_get_value_by_section_string(s, "netmask", &mask);

	fp = fopen(ROUTING_FILE, "r");
	if (fp != NULL) {
		while (fgets(line, MAX_PROC_ROUTING, fp) != NULL) {
			if (line[0] == '\n' || lines == 0) { /* skip the first line or skip the line if it's empty */
				lines++;
				continue;
			}
			parse_proc_route_line(line, &proute);
			if (strcmp(dest, proute.destination) == 0 &&
				(mask[0] == '\0' || strcmp(mask, proute.mask) == 0)) {
				fclose(fp) ;
				return true;
			}
		}
		fclose(fp) ;
	}
	return false;
}

static int get_forwarding_last_inst()
{
	char *rinst = NULL, *drinst = NULL, *dsinst = NULL, *tmp;
	int r = 0, dr = 0, ds = 0, max;
	struct uci_section *s;

	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route", s) {
		dmuci_get_value_by_section_string(s, "routeinstance", &tmp);
		if (tmp[0] == '\0')
			break;
		rinst = tmp;
	}
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route_disabled", s) {
		dmuci_get_value_by_section_string(s, "routeinstance", &tmp);
		if (tmp[0] == '\0')
			break;
		dsinst = tmp;
	}
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route_dynamic", s) {
		dmuci_get_value_by_section_string(s, "routeinstance", &tmp);
		if (tmp[0] == '\0')
			break;
		drinst = tmp;
	}
	if (rinst) r = atoi(rinst);
	if (dsinst) ds = atoi(dsinst);
	if (drinst) dr = atoi(drinst);
	max = (r>ds&&r>dr?r:ds>dr?ds:dr);
	return max;
}

static char *forwarding_update_instance_alias_bbfdm(int action, char **last_inst, void *argv[])
{
	char *instance, *alias;
	char buf[64] = {0};

	struct uci_section *s = (struct uci_section *) argv[0];
	char *inst_opt = (char *) argv[1];
	char *alias_opt = (char *) argv[2];
	bool *find_max = (bool *) argv[3];

	dmuci_get_value_by_section_string(s, inst_opt, &instance);
	if (instance[0] == '\0') {
		if (*find_max) {
			int m = get_forwarding_last_inst();
			snprintf(buf, sizeof(buf), "%d", m+1);
			*find_max = false;
		} else if (last_inst == NULL) {
			snprintf(buf, sizeof(buf), "%d", 1);
		} else {
			snprintf(buf, sizeof(buf), "%d", atoi(*last_inst)+1);
		}
		instance = dmuci_set_value_by_section_bbfdm(s, inst_opt, buf);
	}
	*last_inst = instance;
	if (action == INSTANCE_MODE_ALIAS) {
		dmuci_get_value_by_section_string(s, alias_opt, &alias);
		if (alias[0] == '\0') {
			snprintf(buf, sizeof(buf), "cpe-%s", instance);
			alias = dmuci_set_value_by_section_bbfdm(s, alias_opt, buf);
		}
		snprintf(buf, sizeof(buf), "[%s]", alias);
		instance = dmstrdup(buf);
	}
	return instance;
}

static int get_forwarding6_last_inst()
{
	char *rinst = NULL, *drinst = NULL, *tmp;
	int r = 0, dr = 0, max;
	struct uci_section *s;

	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route6", s) {
		dmuci_get_value_by_section_string(s, "route6instance", &tmp);
		if (tmp[0] == '\0')
			break;
		rinst = tmp;
	}
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route6_dynamic", s) {
		dmuci_get_value_by_section_string(s, "route6instance", &tmp);
		if (tmp[0] == '\0')
			break;
		drinst = tmp;
	}
	if (rinst) r = atoi(rinst);
	if (drinst) dr = atoi(drinst);
	max = r>dr?r:dr;
	return max;
}

static char *forwarding6_update_instance_alias_bbfdm(int action, char **last_inst, void *argv[])
{
	char *instance, *alias;
	char buf[64] = {0};

	struct uci_section *s = (struct uci_section *) argv[0];
	char *inst_opt = (char *) argv[1];
	char *alias_opt = (char *) argv[2];
	bool *find_max = (bool *) argv[3];

	dmuci_get_value_by_section_string(s, inst_opt, &instance);
	if (instance[0] == '\0') {
		if (*find_max) {
			int m = get_forwarding6_last_inst();
			snprintf(buf, sizeof(buf), "%d", m+1);
			*find_max = false;
		} else if (last_inst == NULL) {
			snprintf(buf, sizeof(buf), "%d", 1);
		} else {
			snprintf(buf, sizeof(buf), "%d", atoi(*last_inst)+1);
		}
		instance = dmuci_set_value_by_section_bbfdm(s, inst_opt, buf);
	}
	*last_inst = instance;
	if (action == INSTANCE_MODE_ALIAS) {
		dmuci_get_value_by_section_string(s, alias_opt, &alias);
		if (alias[0] == '\0') {
			snprintf(buf, sizeof(buf), "cpe-%s", instance);
			alias = dmuci_set_value_by_section_bbfdm(s, alias_opt, buf);
		}
		snprintf(buf, sizeof(buf), "[%s]", alias);
		instance = dmstrdup(buf);
	}
	return instance;
}

static int dmmap_synchronizeRoutingRouterIPv4Forwarding(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *stmp;
	struct proc_routing proute = {0};
	json_object *jobj;
	FILE* fp = NULL;
	char *target, *iface, *name, *instance, *str, line[MAX_PROC_ROUTING];
	int found, last_inst, lines;

	check_create_dmmap_package("dmmap_route_forwarding");
	uci_path_foreach_sections_safe(bbfdm, "dmmap_route_forwarding", "route_dynamic", stmp, s) {
		dmuci_get_value_by_section_string(s, "target", &target);
		dmuci_get_value_by_section_string(s, "device", &iface);
		found = 0;
		fp = fopen(ROUTING_FILE, "r");
		if ( fp != NULL) {
			lines = 0;
			while (fgets(line, MAX_PROC_ROUTING, fp) != NULL) {
				if (line[0] == '\n' || lines == 0) { /* skip the first line or skip the line if it's empty */
					lines++;
					continue;
				}
				parse_proc_route_line(line, &proute);
				if ((strcmp(iface, proute.iface) == 0) && strcmp(target, proute.destination) == 0) {
					found = 1;
					break;
				}
			}
			if (!found)
				dmuci_delete_by_section(s, NULL, NULL);
			fclose(fp);
		}
	}

	fp = fopen(ROUTING_FILE, "r");
	if ( fp != NULL) {
		lines = 0;
		while (fgets(line, MAX_PROC_ROUTING, fp) != NULL) {
			if (line[0] == '\n' || lines == 0) { /* skip the first line or skip the line if it's empty */
				lines++;
				continue;
			}
			parse_proc_route_line(line, &proute);
			if (is_proc_route_in_config(&proute))
				continue;
			iface = "";
			uci_foreach_sections("network", "interface", s) {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &jobj);
				if (!jobj) {
					fclose(fp);
					return 0;
				}
				str = dmjson_get_value(jobj, 1, "device");
				if (strcmp(str, proute.iface) == 0) {
					iface = section_name(s);
					break;
				}
			}
			last_inst = get_forwarding_last_inst();
			dmasprintf(&instance, "%d", last_inst+1);
			DMUCI_ADD_SECTION(bbfdm, "dmmap_route_forwarding", "route_dynamic", &s, &name);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "target", proute.destination);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "netmask", proute.mask);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "metric", proute.metric);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "gateway", proute.gateway);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "device", proute.iface);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "interface", iface);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "routeinstance", instance);
			dmfree(instance);
		}
		fclose(fp);
	}
	return 0;
}

static int dmmap_synchronizeRoutingRouterIPv6Forwarding(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *stmp;
	char buf[512], dev[32], ipstr[INET6_ADDRSTRLEN + 8], gwstr[INET6_ADDRSTRLEN + 8];
	char ipbuf[INET6_ADDRSTRLEN];
	unsigned int ip[4], gw[4];
	unsigned int flags, refcnt, use, metric, prefix;
	char *iface, *str, *target, *name, *instance;
	json_object *jobj;
	FILE* fp = NULL;
	int found, last_inst;

	check_create_dmmap_package("dmmap_route_forwarding");
	uci_path_foreach_sections_safe(bbfdm, "dmmap_route_forwarding", "route6_dynamic", stmp, s) {
		dmuci_get_value_by_section_string(s, "target", &target);
		dmuci_get_value_by_section_string(s, "device", &iface);
		fp = fopen(PROC_ROUTE6, "r");
		if (fp == NULL)
			return 0;

		found = 0;
		while (fgets(buf, 512, fp) != NULL) {
			if (*buf == '\n' || *buf == '\0')
				continue;
			sscanf(buf, "%8x%8x%8x%8x %x %*s %*s %8x%8x%8x%8x %x %x %x %x %31s", &ip[0], &ip[1], &ip[2], &ip[3],
					&prefix, &gw[0], &gw[1], &gw[2], &gw[3], &metric, &refcnt, &use, &flags, dev);
			if (strcmp(dev, "lo") == 0)
				continue;
			ip[0] = htonl(ip[0]);
			ip[1] = htonl(ip[1]);
			ip[2] = htonl(ip[2]);
			ip[3] = htonl(ip[3]);
			inet_ntop(AF_INET6, ip, ipbuf, INET6_ADDRSTRLEN);
			snprintf(ipstr, sizeof(ipstr), "%s/%u", ipbuf, prefix);
			if (strcmp(iface, dev) == 0 && strcmp(ipstr, target) == 0) {
				found = 1;
				break;
			}
		}
		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
		fclose(fp);
	}

	fp = fopen(PROC_ROUTE6, "r");
	if (fp == NULL)
		return 0;

	while (fgets(buf , 512 , fp) != NULL) {
		if (*buf == '\n' || *buf == '\0')
			continue;
		sscanf(buf, "%8x%8x%8x%8x %x %*s %*s %8x%8x%8x%8x %x %x %x %x %31s", &ip[0], &ip[1], &ip[2], &ip[3],
				&prefix, &gw[0], &gw[1], &gw[2], &gw[3], &metric, &refcnt, &use, &flags, dev);
		if (strcmp(dev, "lo") == 0)
			continue;
		ip[0] = htonl(ip[0]);
		ip[1] = htonl(ip[1]);
		ip[2] = htonl(ip[2]);
		ip[3] = htonl(ip[3]);
		gw[0] = htonl(gw[0]);
		gw[1] = htonl(gw[1]);
		gw[2] = htonl(gw[2]);
		gw[3] = htonl(gw[3]);
		inet_ntop(AF_INET6, ip, ipbuf, INET6_ADDRSTRLEN);
		snprintf(ipstr, sizeof(ipstr), "%s/%u", ipbuf, prefix);
		inet_ntop(AF_INET6, gw, gwstr, INET6_ADDRSTRLEN);
		if (is_proc_route6_in_config(dev, ipstr, gwstr))
			continue;
		iface = "";
		uci_foreach_sections("network", "interface", s) {
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &jobj);
			if (!jobj) {
				fclose(fp);
				return 0;
			}
			str = dmjson_get_value(jobj, 1, "device");
			if (strcmp(str, dev) == 0) {
				iface = section_name(s);
				break;
			}
		}
		last_inst = get_forwarding6_last_inst();
		dmasprintf(&instance, "%d", last_inst+1);
		DMUCI_ADD_SECTION(bbfdm, "dmmap_route_forwarding", "route6_dynamic", &s, &name);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "target", ipstr);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "gateway", gwstr);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "interface", iface);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "device", dev);
		snprintf(buf, sizeof(buf), "%u", metric);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "metric", buf);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "route6instance", instance);
		dmfree(instance);
	}
	fclose(fp);
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_router_nbr_entry(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_RoutingRouter_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_RoutingRouter_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_RoutingRouter_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Enabled";
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4ForwardingNumberOfEntries!UCI:network/route/*/
static int get_RoutingRouter_IPv4ForwardingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int cnt = 0;

	uci_foreach_sections("network", "route", s) {
		cnt++;
	}
	uci_foreach_sections("network", "route_disabled", s) {
		cnt++;
	}
	dmmap_synchronizeRoutingRouterIPv4Forwarding(ctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route_dynamic", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6ForwardingNumberOfEntries!UCI:network/route6/*/
static int get_RoutingRouter_IPv6ForwardingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int cnt = 0;

	uci_foreach_sections("network", "route6", s) {
		cnt++;
	}
	dmmap_synchronizeRoutingRouterIPv6Forwarding(ctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route6_dynamic", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

static int get_router_ipv4forwarding_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if(((struct routingfwdargs *)data)->type == ROUTE_DISABLED)
		*value = "0";
	else
		*value = "1";
	return 0;
}

static int set_router_ipv4forwarding_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				if (((struct routingfwdargs *)data)->type == ROUTE_STATIC)
					return 0;
				dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, NULL, "route");
			}
			else {
				if (((struct routingfwdargs *)data)->type == ROUTE_DISABLED)
					return 0;
				dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, NULL, "route_disabled");
			}
			return 0;
	}
	return 0;
}

static int get_router_ipv4forwarding_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if(((struct routingfwdargs *)data)->type == ROUTE_DISABLED) {
		*value = "Disabled";
	} else {
		if (is_cfg_route_active(((struct routingfwdargs *)data)->routefwdsection))
			*value = "Enabled";
		else
			*value = "Error";
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.DestIPAddress!UCI:network/route,@i-1/target*/
static int get_router_ipv4forwarding_destip(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "target", "0.0.0.0");
	return 0;
}

static int set_router_ipv4forwarding_destip(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "target", value);
			return 0;
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.DestSubnetMask!UCI:network/route,@i-1/netmask*/
static int get_router_ipv4forwarding_destmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "netmask", "255.255.255.255");
	return 0;
}

static int set_router_ipv4forwarding_destmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "netmask", value);
			return 0;
	}
	return 0;
}

static int get_router_ipv4forwarding_static_route(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct routingfwdargs *)data)->type != ROUTE_DYNAMIC)
		*value = "1";
	else
		*value = "0";

	return 0;
}

static int get_router_ipv4forwarding_forwarding_policy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "-1";
	return 0;
}

static int get_router_ipv4forwarding_origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct routingfwdargs *)data)->type != ROUTE_DYNAMIC)
		*value = "Static";
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.GatewayIPAddress!UCI:network/route,@i-1/gateway*/
static int get_router_ipv4forwarding_gatewayip(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "gateway", "0.0.0.0");
	return 0;
}

static int set_router_ipv4forwarding_gatewayip(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "gateway", value);
			return 0;
	}
	return 0;
}

static int get_router_ipv4forwarding_interface_linker_parameter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;

	if (((struct routingfwdargs *)data)->routefwdsection != NULL)
		dmuci_get_value_by_section_string(((struct routingfwdargs *)data)->routefwdsection, "interface", &linker);
	if (linker[0] != '\0') {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int set_router_ipv4forwarding_interface_linker_parameter(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker) {
				dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "interface", linker);
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.ForwardingMetric!UCI:network/route,@i-1/metric*/
static int get_router_ipv4forwarding_metric(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "metric", "0");
	return 0;
}

static int set_router_ipv4forwarding_metric(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "metric", value);
			return 0;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Enabled";
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6Forwarding.{i}.DestIPPrefix!UCI:network/route,@i-1/target*/
static int get_RoutingRouterIPv6Forwarding_DestIPPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "target", "::");
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_DestIPPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 49, NULL, 0, IPv6Prefix, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "target", value);
			return 0;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "-1";
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6Forwarding.{i}.NextHop!UCI:network/route,@i-1/gateway*/
static int get_RoutingRouterIPv6Forwarding_NextHop(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "gateway", "::");
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_NextHop(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPv6Address, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "gateway", value);
			return 0;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;

	if (((struct routingfwdargs *)data)->routefwdsection != NULL)
		dmuci_get_value_by_section_string(((struct routingfwdargs *)data)->routefwdsection, "interface", &linker);
	if (linker[0] != '\0') {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker) {
				dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "interface", linker);
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct routingfwdargs *)data)->type != ROUTE_DYNAMIC)
		*value = "Static";
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6Forwarding.{i}.ForwardingMetric!UCI:network/route,@i-1/metric*/
static int get_RoutingRouterIPv6Forwarding_ForwardingMetric(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "metric", "0");
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_ForwardingMetric(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "metric", value);
			return 0;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_ExpirationTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "9999-12-31T23:59:59Z";
	return 0;
}

static int get_RoutingRouteInformation_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_RoutingRouteInformation_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_RoutingRouteInformation_InterfaceSettingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	json_object *res, *route_obj;
	char *proto, *ip6addr;
	int entries = 0;

	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "proto", &proto);
		dmuci_get_value_by_section_string(s, "ip6addr", &ip6addr);
		if(strcmp(proto, "dhcpv6")==0 || ip6addr[0] != '\0') {
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
			while (res) {
				route_obj = dmjson_select_obj_in_array_idx(res, entries, 1, "route");
				if(route_obj) {
					entries++;
				}
				else
					break;
			}
		}
	}
	dmasprintf(value, "%d", entries);
	return 0;
}

static int get_RoutingRouteInformationInterfaceSetting_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *target, *mask, *nexthop, *gateway, *ip_target, buf[64];

	*value = "NoForwardingEntry";
	target = dmjson_get_value((struct json_object *)data, 1, "target");
	mask = dmjson_get_value((struct json_object *)data, 1, "mask");
	snprintf(buf, sizeof(buf), "%s/%s", target, mask);
	nexthop = dmjson_get_value((struct json_object *)data, 1, "nexthop");
	uci_foreach_sections("network", "route6", s) {
		dmuci_get_value_by_section_string(s, "target", &ip_target);
		dmuci_get_value_by_section_string(s, "gateway", &gateway);
		if(strcmp(ip_target, buf) == 0 && strcmp(nexthop, gateway) == 0) {
			*value = "ForwardingEntryCreated";
			return 0;
		}
	}
	return 0;
}

static int get_RoutingRouteInformationInterfaceSetting_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char buf[512], dev[32], ipstr[INET6_ADDRSTRLEN + 8], gwstr[INET6_ADDRSTRLEN + 8];
	char ipbuf[INET6_ADDRSTRLEN];
	unsigned int ip[4], gw[4], flags, refcnt, use, metric, prefix;
	char *source, *nexthop, *str, *iface = "";
	json_object *jobj;
	FILE* fp = NULL;

	source = dmjson_get_value((struct json_object *)data, 1, "source");
	nexthop = dmjson_get_value((struct json_object *)data, 1, "nexthop");
	fp = fopen(PROC_ROUTE6, "r");
	if (fp == NULL)
		return 0;

	while (fgets(buf , 512 , fp) != NULL) {
		if (*buf == '\n' || *buf == '\0')
			continue;
		sscanf(buf, "%8x%8x%8x%8x %x %*s %*s %8x%8x%8x%8x %x %x %x %x %31s", &ip[0], &ip[1], &ip[2], &ip[3],
				&prefix, &gw[0], &gw[1], &gw[2], &gw[3], &metric, &refcnt, &use, &flags, dev);
		if (strcmp(dev, "lo") == 0)
			continue;
		ip[0] = htonl(ip[0]);
		ip[1] = htonl(ip[1]);
		ip[2] = htonl(ip[2]);
		ip[3] = htonl(ip[3]);
		gw[0] = htonl(gw[0]);
		gw[1] = htonl(gw[1]);
		gw[2] = htonl(gw[2]);
		gw[3] = htonl(gw[3]);
		inet_ntop(AF_INET6, ip, ipbuf, INET6_ADDRSTRLEN);
		snprintf(ipstr, sizeof(ipstr), "%s/%u", ipbuf, prefix);
		inet_ntop(AF_INET6, gw, gwstr, INET6_ADDRSTRLEN);
		if((strcmp(source, ipstr) == 0) && (strcmp(nexthop, gwstr) == 0))
			break;
	}
	fclose(fp);
	uci_foreach_sections("network", "interface", s) {
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &jobj);
		if (!jobj) return 0;
		str = dmjson_get_value(jobj, 1, "device");
		if (strcmp(str, dev) == 0) {
			iface = section_name(s);
			break;
		}
	}
	if (iface[0] != '\0') {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), iface, value);
		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int get_RoutingRouteInformationInterfaceSetting_SourceRouter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((struct json_object *)data, 1, "source");
	return 0;
}

static int get_RoutingRouteInformationInterfaceSetting_RouteLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char local_time[32] = {0};
	char *valid = dmjson_get_value((struct json_object *)data, 1, "valid");
	*value = "0001-01-01T00:00:00Z";
	if (get_shift_time_time(atoi(valid), local_time, sizeof(local_time)) == -1)
		return 0;
	*value = dmstrdup(local_time);
	return 0;
}

/*************************************************************
* SET AND GET ALIAS FOR ROUTER OBJ
**************************************************************/
static int get_RoutingRouter_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "router_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_RoutingRouter_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "router_alias", value);
			return 0;
	}
	return 0;
}

static int get_router_ipv4forwarding_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	if(((struct routingfwdargs *)data)->type == ROUTE_DYNAMIC)
		dmmap_section= ((struct routingfwdargs *)data)->routefwdsection;
	else if (((struct routingfwdargs *)data)->type == ROUTE_STATIC)
		get_dmmap_section_of_config_section("dmmap_route_forwarding", "route", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
	else
		get_dmmap_section_of_config_section("dmmap_route_forwarding", "route_disabled", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "routealias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_router_ipv4forwarding_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if(((struct routingfwdargs *)data)->type == ROUTE_DYNAMIC)
				dmmap_section = ((struct routingfwdargs *)data)->routefwdsection;
			else if (((struct routingfwdargs *)data)->type == ROUTE_STATIC)
				get_dmmap_section_of_config_section("dmmap_route_forwarding", "route", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			else
				get_dmmap_section_of_config_section("dmmap_route_forwarding", "route_disabled", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "routealias", value);
			return 0;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	if(((struct routingfwdargs *)data)->type == ROUTE_DYNAMIC)
		dmmap_section = ((struct routingfwdargs *)data)->routefwdsection;
	else
		get_dmmap_section_of_config_section("dmmap_route_forwarding", "route6", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "route6alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if(((struct routingfwdargs *)data)->type == ROUTE_DYNAMIC)
				dmmap_section = ((struct routingfwdargs *)data)->routefwdsection;
			else
				get_dmmap_section_of_config_section("dmmap_route_forwarding", "route6", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "route6alias", value);
			return 0;
	}
	return 0;
}

static char *get_routing_perm(char *refparam, struct dmctx *dmctx, void *data, char *instance)
{
	return ((struct routingfwdargs *)data)->permission;
}

struct dm_permession_s DMRouting = {"0", &get_routing_perm};

/*************************************************************
* ADD DEL OBJ
**************************************************************/
static int add_ipv4forwarding(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	char *value, *v, instance[8];
	struct uci_section *s = NULL;
	struct uci_section *dmmap_route = NULL;
	int last_inst;

	check_create_dmmap_package("dmmap_route_forwarding");
	last_inst = get_forwarding_last_inst();
	snprintf(instance, sizeof(instance), "%d", last_inst);
	dmuci_add_section_and_rename("network", "route", &s, &value);
	dmuci_set_value_by_section(s, "metric", "0");
	dmuci_set_value_by_section(s, "interface", "lan");

	dmuci_add_section_bbfdm("dmmap_route_forwarding", "route", &dmmap_route, &v);
	dmuci_set_value_by_section(dmmap_route, "section_name", section_name(s));
	*instancepara = update_instance_bbfdm(dmmap_route, instance, "routeinstance");
	return 0;
}

static int delete_ipv4forwarding(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *dmmap_section = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_route_forwarding", "route", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct routingfwdargs *)data)->routefwdsection, NULL, NULL);

			get_dmmap_section_of_config_section("dmmap_route_forwarding", "route_disabled", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct routingfwdargs *)data)->routefwdsection, NULL, NULL);
			break;
		case DEL_ALL:
			return FAULT_9005;
		}
	return 0;
}

static int add_ipv6Forwarding(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	char *value, *v, instance[8];
	struct uci_section *s = NULL;
	struct uci_section *dmmap_route = NULL;
	int last_inst;

	check_create_dmmap_package("dmmap_route_forwarding");
	last_inst = get_forwarding6_last_inst();
	snprintf(instance, sizeof(instance), "%d", last_inst);
	dmuci_add_section_and_rename("network", "route6", &s, &value);
	dmuci_set_value_by_section(s, "metric", "0");
	dmuci_set_value_by_section(s, "interface", "lan");

	dmuci_add_section_bbfdm("dmmap_route_forwarding", "route6", &dmmap_route, &v);
	dmuci_set_value_by_section(dmmap_route, "section_name", section_name(s));
	*instancepara = update_instance_bbfdm(dmmap_route, instance, "route6instance");
	return 0;
}

static int delete_ipv6Forwarding(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *dmmap_section = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_route_forwarding", "route6", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			if (dmmap_section)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct routingfwdargs *)data)->routefwdsection, NULL, NULL);
			break;
		case DEL_ALL:
			return FAULT_9005;
		}
	return 0;
}

/*************************************************************
* SUB ENTRIES
**************************************************************/
static int browseRouterInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *r = NULL, *r_last = NULL;

	update_section_list(DMMAP,"router", NULL, 1, NULL, NULL, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap", "router", s) {
		r = handle_update_instance(1, dmctx, &r_last, update_instance_alias_bbfdm, 3, s, "router_instance", "router_alias");
		DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, r);
		break;
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.!UCI:network/route/dmmap_route_forwarding*/
static int browseIPv4ForwardingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *iroute = NULL, *iroute_last = NULL;
	struct uci_section *ss = NULL;
	bool find_max = true;
	struct routingfwdargs curr_routefwdargs = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "route", "dmmap_route_forwarding", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		init_args_ipv4forward(&curr_routefwdargs, p->config_section, "1", ROUTE_STATIC);
		iroute =  handle_update_instance(1, dmctx, &iroute_last, forwarding_update_instance_alias_bbfdm, 4, p->dmmap_section, "routeinstance", "routealias", &find_max);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_routefwdargs, iroute) == DM_STOP)
			goto end;
	}
	free_dmmap_config_dup_list(&dup_list);
	synchronize_specific_config_sections_with_dmmap("network", "route_disabled", "dmmap_route_forwarding", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		init_args_ipv4forward(&curr_routefwdargs, p->config_section, "1", ROUTE_DISABLED);
		iroute =  handle_update_instance(1, dmctx, &iroute_last, forwarding_update_instance_alias_bbfdm, 4, p->dmmap_section, "routeinstance", "routealias", &find_max);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_routefwdargs, iroute) == DM_STOP)
			goto end;
	}
	free_dmmap_config_dup_list(&dup_list);
	dmmap_synchronizeRoutingRouterIPv4Forwarding(dmctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route_dynamic", ss) {
		init_args_ipv4forward(&curr_routefwdargs, ss, "0", ROUTE_DYNAMIC);
		iroute =  handle_update_instance(1, dmctx, &iroute_last, forwarding_update_instance_alias_bbfdm, 4, ss, "routeinstance", "routealias", &find_max);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_routefwdargs, iroute) == DM_STOP)
			goto end;
	}
end:
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6Forwarding.{i}.!UCI:network/route6/dmmap_route_forwarding*/
static int browseIPv6ForwardingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *iroute = NULL, *iroute_last = NULL;
	struct uci_section *ss = NULL;
	bool find_max = true;
	struct routingfwdargs curr_route6fwdargs = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "route6", "dmmap_route_forwarding", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		init_args_ipv6forward(&curr_route6fwdargs, p->config_section, "1", ROUTE_STATIC);
		iroute =  handle_update_instance(1, dmctx, &iroute_last, forwarding6_update_instance_alias_bbfdm, 4, p->dmmap_section, "route6instance", "route6alias", &find_max);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_route6fwdargs, iroute) == DM_STOP)
			goto end;
	}
	free_dmmap_config_dup_list(&dup_list);
	dmmap_synchronizeRoutingRouterIPv6Forwarding(dmctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route6_dynamic", ss) {
		init_args_ipv6forward(&curr_route6fwdargs, ss, "0", ROUTE_DYNAMIC);
		iroute =  handle_update_instance(1, dmctx, &iroute_last, forwarding6_update_instance_alias_bbfdm, 4, ss, "route6instance", "route6alias", &find_max);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_route6fwdargs, iroute) == DM_STOP)
			goto end;
	}
end:
	return 0;
}

static int browseRoutingRouteInformationInterfaceSettingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	json_object *res, *route_obj;
	char *proto, *ip6addr, *idx, *idx_last = NULL;
	int id = 0, entries = 0;

	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "proto", &proto);
		dmuci_get_value_by_section_string(s, "ip6addr", &ip6addr);
		if(strcmp(proto, "dhcpv6")==0 || ip6addr[0] != '\0') {
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
			while (res) {
				route_obj = dmjson_select_obj_in_array_idx(res, entries, 1, "route");
				if(route_obj) {
					entries++;
					idx = handle_update_instance(3, dmctx, &idx_last, update_instance_without_section, 1, ++id);
					if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)route_obj, idx) == DM_STOP)
						break;
				}
				else
					break;
			}
		}
	}
	return 0;
}

/* *** Device.Routing. *** */
DMOBJ tRoutingObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Router", &DMREAD, NULL, NULL, NULL, browseRouterInst, NULL, NULL, NULL, tRoutingRouterObj, tRoutingRouterParams, NULL, BBFDM_BOTH},
{"RouteInformation", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tRoutingRouteInformationObj, tRoutingRouteInformationParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tRoutingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"RouterNumberOfEntries", &DMREAD, DMT_UNINT, get_router_nbr_entry, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Routing.Router.{i}. *** */
DMOBJ tRoutingRouterObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"IPv4Forwarding", &DMWRITE, add_ipv4forwarding, delete_ipv4forwarding, NULL, browseIPv4ForwardingInst, NULL, NULL, NULL, NULL, tRoutingRouterIPv4ForwardingParams, NULL, BBFDM_BOTH},
{"IPv6Forwarding", &DMWRITE, add_ipv6Forwarding, delete_ipv6Forwarding, NULL, browseIPv6ForwardingInst, NULL, NULL, NULL, NULL, tRoutingRouterIPv6ForwardingParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tRoutingRouterParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_RoutingRouter_Enable, set_RoutingRouter_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_RoutingRouter_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_RoutingRouter_Alias, set_RoutingRouter_Alias, NULL, NULL, BBFDM_BOTH},
{"IPv4ForwardingNumberOfEntries", &DMREAD, DMT_UNINT, get_RoutingRouter_IPv4ForwardingNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6ForwardingNumberOfEntries", &DMREAD, DMT_UNINT, get_RoutingRouter_IPv6ForwardingNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Routing.Router.{i}.IPv4Forwarding.{i}. *** */
DMLEAF tRoutingRouterIPv4ForwardingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMRouting, DMT_BOOL, get_router_ipv4forwarding_enable, set_router_ipv4forwarding_enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_router_ipv4forwarding_status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_router_ipv4forwarding_alias, set_router_ipv4forwarding_alias, NULL, NULL, BBFDM_BOTH},
{"StaticRoute", &DMREAD, DMT_BOOL, get_router_ipv4forwarding_static_route, NULL, NULL, NULL, BBFDM_BOTH},
{"DestIPAddress", &DMRouting, DMT_STRING, get_router_ipv4forwarding_destip, set_router_ipv4forwarding_destip, NULL, NULL, BBFDM_BOTH},
{"DestSubnetMask", &DMRouting, DMT_STRING, get_router_ipv4forwarding_destmask, set_router_ipv4forwarding_destmask, NULL, NULL, BBFDM_BOTH},
{"ForwardingPolicy", &DMREAD, DMT_INT, get_router_ipv4forwarding_forwarding_policy, NULL, NULL, NULL, BBFDM_BOTH},
{"GatewayIPAddress", &DMRouting, DMT_STRING, get_router_ipv4forwarding_gatewayip, set_router_ipv4forwarding_gatewayip, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMRouting, DMT_STRING, get_router_ipv4forwarding_interface_linker_parameter, set_router_ipv4forwarding_interface_linker_parameter, NULL, NULL, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_router_ipv4forwarding_origin, NULL, NULL, NULL, BBFDM_BOTH},
{"ForwardingMetric", &DMRouting, DMT_INT, get_router_ipv4forwarding_metric, set_router_ipv4forwarding_metric, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Routing.Router.{i}.IPv4Forwarding.{i}. *** */
DMLEAF tRoutingRouterIPv6ForwardingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMRouting, DMT_BOOL, get_RoutingRouterIPv6Forwarding_Enable, set_RoutingRouterIPv6Forwarding_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_RoutingRouterIPv6Forwarding_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_RoutingRouterIPv6Forwarding_Alias, set_RoutingRouterIPv6Forwarding_Alias, NULL, NULL, BBFDM_BOTH},
{"DestIPPrefix", &DMRouting, DMT_STRING, get_RoutingRouterIPv6Forwarding_DestIPPrefix, set_RoutingRouterIPv6Forwarding_DestIPPrefix, NULL, NULL, BBFDM_BOTH},
{"ForwardingPolicy", &DMRouting, DMT_INT, get_RoutingRouterIPv6Forwarding_ForwardingPolicy, set_RoutingRouterIPv6Forwarding_ForwardingPolicy, NULL, NULL, BBFDM_BOTH},
{"NextHop", &DMRouting, DMT_STRING, get_RoutingRouterIPv6Forwarding_NextHop, set_RoutingRouterIPv6Forwarding_NextHop, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMRouting, DMT_STRING, get_RoutingRouterIPv6Forwarding_Interface, set_RoutingRouterIPv6Forwarding_Interface, NULL, NULL, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_RoutingRouterIPv6Forwarding_Origin, NULL, NULL, NULL, BBFDM_BOTH},
{"ForwardingMetric", &DMRouting, DMT_INT, get_RoutingRouterIPv6Forwarding_ForwardingMetric, set_RoutingRouterIPv6Forwarding_ForwardingMetric, NULL, NULL, BBFDM_BOTH},
{"ExpirationTime", &DMREAD, DMT_TIME, get_RoutingRouterIPv6Forwarding_ExpirationTime, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Routing.RouteInformation. *** */
DMOBJ tRoutingRouteInformationObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"InterfaceSetting", &DMREAD, NULL, NULL, NULL, browseRoutingRouteInformationInterfaceSettingInst, NULL, NULL, NULL, NULL, tRoutingRouteInformationInterfaceSettingParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tRoutingRouteInformationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_RoutingRouteInformation_Enable, set_RoutingRouteInformation_Enable, NULL, NULL, BBFDM_BOTH},
{"InterfaceSettingNumberOfEntries", &DMREAD, DMT_UNINT, get_RoutingRouteInformation_InterfaceSettingNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Routing.RouteInformation.InterfaceSetting.{i}. *** */
DMLEAF tRoutingRouteInformationInterfaceSettingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Status", &DMREAD, DMT_STRING, get_RoutingRouteInformationInterfaceSetting_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMREAD, DMT_STRING, get_RoutingRouteInformationInterfaceSetting_Interface, NULL, NULL, NULL, BBFDM_BOTH},
{"SourceRouter", &DMREAD, DMT_STRING, get_RoutingRouteInformationInterfaceSetting_SourceRouter, NULL, NULL, NULL, BBFDM_BOTH},
{"RouteLifetime", &DMREAD, DMT_TIME, get_RoutingRouteInformationInterfaceSetting_RouteLifetime, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
