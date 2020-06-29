/*
 * dmoperate.c: Operate handler for uspd
 *
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Yashvardhan <y.yashvardhan@iopsys.eu>
 * Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __DMOPERATE_H__
#define __DMOPERATE_H__

#include "dmentry.h"
#include "dmdiagnostics.h"

#define SYSTEM_UBUS_PATH "system"
#define NETWORK_INTERFACE_UBUS_PATH "network.interface"
#define ICWMP_SCRIPT "/usr/sbin/icwmp"
#define VCF_FILE_TYPE "3"

extern struct op_cmd *dynamic_operate;

struct wifi_security_params {
	char node[255];
	char *param;
	char value[256];
};

struct file_server {
	char *url;
	char *user;
	char *pass;
};

struct neighboring_wiFi_diagnostic {
	char *radio;
	char *ssid;
	char *bssid;
	char *channel;
	char *frequency;
	char *encryption_mode;
	char *operating_frequency_band;
	char *supported_standards;
	char *operating_standards;
	char *operating_channel_bandwidth;
	char *signal_strength;
	char *noise;
};

struct ipping_diagnostics {
	char *host;
	char *interface;
	char *proto;
	char *nbofrepetition;
	char *timeout;
	char *datablocksize;
	char *dscp;
	char *success_count;
	char *failure_count;
	char *average_response_time;
	char *minimum_response_time;
	char *maximum_response_time;
	char *average_response_time_detailed;
	char *minimum_response_time_detailed;
	char *maximum_response_time_detailed;
};

struct traceroute_diagnostics {
	char *host;
	char *interface;
	char *proto;
	char *nboftries;
	char *timeout;
	char *datablocksize;
	char *dscp;
	char *maxhops;
	char *response_time;
	char *host_name;
	char *host_address;
	char *rttimes;
};

struct download_diagnostics {
	char *interface;
	char *download_url;
	char *dscp;
	char *ethernet_priority;
	char *proto;
	char *num_of_connections;
	char *enable_per_connection_results;
	char *romtime;
	char *bomtime;
	char *eomtime;
	char *test_bytes_received;
	char *total_bytes_received;
	char *total_bytes_sent;
	char *test_bytes_received_under_full_loading;
	char *total_bytes_received_under_full_loading;
	char *total_bytes_sent_under_full_loading;
	char *period_of_full_loading;
	char *tcp_open_request_time;
	char *tcp_open_response_time;
	char *per_conn_romtime;
	char *per_conn_bomtime;
	char *per_conn_eomtime;
	char *per_conn_test_bytes_received;
	char *per_conn_total_bytes_received;
	char *per_conn_total_bytes_sent;
	char *per_conn_period_of_full_loading;
	char *per_conn_tcp_open_request_time;
	char *per_conn_tcp_open_response_time;
};

struct upload_diagnostics {
	char *interface;
	char *upload_url;
	char *dscp;
	char *ethernet_priority;
	char *test_file_length;
	char *proto;
	char *num_of_connections;
	char *enable_per_connection_results;
	char *romtime;
	char *bomtime;
	char *eomtime;
	char *test_bytes_sent;
	char *total_bytes_received;
	char *total_bytes_sent;
	char *test_bytes_sent_under_full_loading;
	char *total_bytes_received_under_full_loading;
	char *total_bytes_sent_under_full_loading;
	char *period_of_full_loading;
	char *tcp_open_request_time;
	char *tcp_open_response_time;
	char *per_conn_romtime;
	char *per_conn_bomtime;
	char *per_conn_eomtime;
	char *per_conn_test_bytes_sent;
	char *per_conn_total_bytes_received;
	char *per_conn_total_bytes_sent;
	char *per_conn_period_of_full_loading;
	char *per_conn_tcp_open_request_time;
	char *per_conn_tcp_open_response_time;
};

struct udpecho_diagnostics {
	char *host;
	char *interface;
	char *port;
	char *nbofrepetition;
	char *timeout;
	char *datablocksize;
	char *dscp;
	char *inter_transmission_time;
	char *response_time;
	char *proto;
	char *success_count;
	char *failure_count;
	char *average_response_time;
	char *minimum_response_time;
	char *maximum_response_time;
};

struct serverselection_diagnostics {
	char *interface;
	char *protocol_version;
	char *proto;
	char *hostlist;
	char *port;
	char *nbofrepetition;
	char *timeout;
	char *fasthost;
	char *average_response_time;
	char *minimum_response_time;
	char *maximum_response_time;
};

struct nslookup_diagnostics {
	char *interface;
	char *hostname;
	char *dnsserver;
	char *timeout;
	char *nbofrepetition;
	char *success_count;
	char *status;
	char *answer_type;
	char *hostname_returned;
	char *ip_addresses;
	char *dns_server_ip;
	char *response_time;
};

struct deployment_unit_install {
	char *url;
	char *uuid;
	char *username;
	char *password;
	char *environment;
};

struct deployment_unit_update {
	char *url;
	char *username;
	char *password;
};

struct op_cmd {
	char *name;
	operation opt;
	char *type;
};

int add_dynamic_operate(char *path, operation operate, char *optype);
void operate_list_cmds(struct dmctx *dmctx);
opr_ret_t operate_on_node(struct dmctx *dmctx, char *path, char *input);

#endif
