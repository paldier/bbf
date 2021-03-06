/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "voice_services.h"

struct codec_args
{
	char *cdc;
	char *id;
	int enumid;
	struct uci_section *codec_section;
};

struct rtp_tos
{
	char *key;
	char *val;
};

struct cap_sip_codec
{
	int enumid;
	char *c1;
	char *c2;
	char *c3;
	char *c4;
	char *c5;
};

struct sip_args
{
	struct uci_section *sip_section;
	char *profile_num;
};

struct tel_args
{
	struct uci_section *tel_section;
	struct uci_section *sip_section;
	char *profile_num;
};

struct allow_sip_codec
{
	int enumid;
	char *id;
	char *allowed_cdc;
	char *priority_cdc;
	char *ptime_cdc;
};

struct line_codec_args
{
	int enumid;
	char *sip_id;
	char *cdc;
	char *id;
	char *priority_cdc;
	char *ptime_cdc;
	struct uci_section *sip_section;
	struct uci_section *codec_sec;
};

struct region
{
	char *country;
	char *id;
};

struct codec
{
	char *cdc;
	char *id;
	char *priority;
};

enum enum_cap_sip_codecs {
	SIP_CODEC_G723,
	SIP_CODEC_GSM,
	SIP_CODEC_ULAW,
	SIP_CODEC_ALAW,
	SIP_CODEC_G726AAL2,
	SIP_CODEC_ADPCM,
	SIP_CODEC_SLIN,
	SIP_CODEC_LPC10,
	SIP_CODEC_G729,
	SIP_CODEC_SPEEX,
	SIP_CODEC_ILBC,
	SIP_CODEC_G726,
	SIP_CODEC_G722,
	SIP_CODEC_SIREN7,
	SIP_CODEC_SIREN14,
	SIP_CODEC_SLIN16,
	SIP_CODEC_G719,
	SIP_CODEC_SPEEX16,
	SIP_CODEC_TESTLAW
};

#define MAX_ALLOWED_SIP_CODECS 20
int available_sip_codecs = 0;
struct allow_sip_codec allowed_sip_codecs[MAX_ALLOWED_SIP_CODECS];
char *codec_option_array[5] = {"codec0", "codec1", "codec2", "codec3", "codec4"};
struct cap_sip_codec capabilities_sip_codecs[] = {
	{SIP_CODEC_G723, "g723", "G.723.1", "6451", "30-300", "30"},
	{SIP_CODEC_GSM, "gsm", "GSM-FR", "13312", "20-300", "20"},
	{SIP_CODEC_ULAW, "ulaw", "G.711MuLaw","65536", "10-150", "20"},
	{SIP_CODEC_ALAW, "alaw", "G.711ALaw", "65536", "10-150", "20"},
	{SIP_CODEC_G726AAL2, "g726aal2","g726aal2 ", "32768", "10-300", "20"},
	{SIP_CODEC_ADPCM, "adpcm", "adpcm", "32768", "10-300", "20"},
	{SIP_CODEC_SLIN, "slin", "slin", "0", "10-70", "20"},
	{SIP_CODEC_LPC10, "lpc10", "lpc10", "2457", "20-20", "20"},
	{SIP_CODEC_G729, "g729", "G.729a", "8192", "10-230", "20"},
	{SIP_CODEC_SPEEX, "speex", "speex", "49152", "10-60", "20"},
	{SIP_CODEC_ILBC, "ilbc", "iLBC", "8192", "30-30", "30"},
	{SIP_CODEC_G726, "g726", "G.726", "32768", "10-300", "20"},
	{SIP_CODEC_G722, "g722", "G.722", "65536", "0-0", "0"},
	{SIP_CODEC_SIREN7, "siren7", "G.722.1", "32768", "0-0", "0"},
	{SIP_CODEC_SIREN14, "siren14", "siren14 ", "0", "0-0", "0"},
	{SIP_CODEC_SLIN16, "slin16", "slin16", "0", "0-0", "0"},
	{SIP_CODEC_G719, "g719", "g719", "0", "0-0", "0"},
	{SIP_CODEC_SPEEX16, "speex16", "speex16", "0", "0-0", "0"},
	{SIP_CODEC_TESTLAW, "testlaw", "testlaw", "0", "0-0", "0"}
};
struct region capabilities_regions[] = {
	{"au", "AU"},
	{"be", "BE"},
	{"br", "BR"},
	{"cl", "CL"},
	{"cn", "CN"},
	{"cz", "CZ"},
	{"dk", "DK"},
	{"fi", "FI"},
	{"fr", "FR"},
	{"de", "DE"},
	{"hu", "HU"},
	{"in", "IN"},
	{"it", "IT"},
	{"jp", "JP"},
	{"nl", "NL"},
	{"nz", "NZ"},
	{"us", "US"},
	{"es", "ES"},
	{"se", "SE"},
	{"ch", "CH"},
	{"no", "NO"},
	{"tw", "TW"},
	{"gb", "GB"},
	{"ae", "AE"},
	{"et", "ET"},
	{"t5", "T5"}
};
struct rtp_tos list_rtp_tos[] = {
	{"CS0", "0"},
	{"CS1", "32"},
	{"AF11", "40"},
	{"AF12", "48"},
	{"AF13", "56"},
	{"CS2", "64"},
	{"AF21", "72"},
	{"AF22", "80"},
	{"AF23", "88"},
	{"CS3", "96"},
	{"AF31", "104"},
	{"AF32", "112"},
	{"AF33", "120"},
	{"CS4", "128"},
	{"AF41", "136"},
	{"AF42", "144"},
	{"AF43", "152"},
	{"CS5", "160"},
	{"EF", "184"},
	{"CS6", "192"},
	{"CS7", "224"}
};

///////////////////////////////INIT ARGS//////////////////
static void wait_voice_service_up(void)
{
	json_object *res;
	int i = 0;
	while (i++ < 10) {
		dmubus_call("voice.asterisk", "status", UBUS_ARGS{}, 0, &res);
		if (res)
			return;
	}
}

static inline int init_allowed_sip_codecs()
{
	json_object *res = NULL;
	char id[16], priority[24], ptime[24];
	int i;
	available_sip_codecs = 0;
	dmubus_call("voice.asterisk", "codecs", UBUS_ARGS{}, 0, &res);
	if(res) {
		json_object_object_foreach(res, key, val) {
			UNUSED(val);
			for (i = 0; i < ARRAY_SIZE(capabilities_sip_codecs); i++) {
				if(strcmp(capabilities_sip_codecs[i].c1, key) == 0) {
					allowed_sip_codecs[available_sip_codecs].enumid = capabilities_sip_codecs[i].enumid;
					break;
				}
			}
			snprintf(id, sizeof(id), "%d", available_sip_codecs + 1);
			snprintf(priority, sizeof(priority), "priority_%s", key);
			snprintf(ptime, sizeof(ptime), "ptime_%s", key);
			allowed_sip_codecs[available_sip_codecs].id = dmstrdup(id);
			allowed_sip_codecs[available_sip_codecs].allowed_cdc = key;
			allowed_sip_codecs[available_sip_codecs].priority_cdc = dmstrdup(priority);
			allowed_sip_codecs[available_sip_codecs].ptime_cdc = dmstrdup(ptime);
			available_sip_codecs++;
		}
	}	
	return 0;
}

static int init_sip_args(struct sip_args *args, struct uci_section *section, char *profile_num)
{
	args->sip_section = section;
	args->profile_num = profile_num;
	return 0;
}

static int init_codec_args(struct codec_args *args, char *cdc, char *id, int enumid,  struct uci_section *s)
{
	args->cdc = dmstrdup(cdc);
	args->id = dmstrdup(id);
	args->enumid = enumid;
	args->codec_section = s;
	return 0;
}

static int fini_codec_args(struct codec_args *args)
{
	dmfree(args->cdc);
	dmfree(args->id);
	return 0;
}

static int init_line_code_args(struct line_codec_args *args, int i, struct uci_section *s, struct uci_section *codec_sec)
{
	args->cdc = allowed_sip_codecs[i].allowed_cdc;
	args->id = allowed_sip_codecs[i].id;
	args->sip_section = s;
	args->priority_cdc = allowed_sip_codecs[i].priority_cdc;
	args->enumid = allowed_sip_codecs[i].enumid;
	args->ptime_cdc = allowed_sip_codecs[i].ptime_cdc;
	args->codec_sec = codec_sec;
	return 0;
}

static int init_tel_args(struct tel_args *args, struct uci_section *section, struct uci_section *section2, char *instance)
{
	args->tel_section = section;
	args->sip_section = section2;
	args->profile_num = instance;
	return 0;
}

/**************************ADD/DEL OBJECT *********************************/
static int get_cfg_sipidx(void)
{
	char *si;
	int idx = 0, max = -1;
	struct uci_section *s = NULL;

	uci_foreach_sections("asterisk", "sip_service_provider", s) {
		si = section_name(s) + sizeof("sip") - 1;
		idx = atoi(si);
		if (idx > max)
			max = idx;
	}
	return (max + 1);
}

static int add_profile_object(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	struct uci_section *dmmap_voice_section = NULL;
	char sname[16], account[32], *instance, *v;
	
	check_create_dmmap_package("dmmap_asterisk");
	int sipidx = get_cfg_sipidx();
	snprintf(sname, sizeof(sname), "sip%d", sipidx);
	snprintf(account, sizeof(account), "Account %d", sipidx);
	dmuci_set_value("asterisk", sname, NULL, "sip_service_provider");
	dmuci_set_value("asterisk", sname, "name", account);
	dmuci_set_value("asterisk", sname, "enabled", "0");
	dmuci_set_value("asterisk", sname, "codec0", "ulaw");
	dmuci_set_value("asterisk", sname, "codec1", "alaw");
	dmuci_set_value("asterisk", sname, "codec2", "g729");
	dmuci_set_value("asterisk", sname, "codec3", "g726");
	dmuci_set_value("asterisk", sname, "cfim_on", "*21*");
	dmuci_set_value("asterisk", sname, "cfim_off", "#21#");
	dmuci_set_value("asterisk", sname, "cfbs_on", "*61*");
	dmuci_set_value("asterisk", sname, "cfbs_off", "#61#");
	dmuci_set_value("asterisk", sname, "call_return", "*69");
	dmuci_set_value("asterisk", sname, "redial", "*66");
	dmuci_set_value("asterisk", sname, "cbbs_key", "5");
	dmuci_set_value("asterisk", sname, "cbbs_maxretry", "5");
	dmuci_set_value("asterisk", sname, "cbbs_retrytime", "300");
	dmuci_set_value("asterisk", sname, "cbbs_waittime", "30");
	instance = get_last_instance_bbfdm("dmmap_asterisk", "sip_service_provider", "profileinstance");

	dmuci_add_section_bbfdm("dmmap_asterisk", "sip_service_provider", &dmmap_voice_section, &v);
	dmuci_set_value_by_section(dmmap_voice_section, "section_name", sname);
	*instancepara = update_instance_bbfdm(dmmap_voice_section, instance, "profileinstance");

	return 0;
}

static int delete_associated_line_instances(char *sip_id, char* profile_key)
{
	struct uci_section *s = NULL, *stmp = NULL;

	uci_foreach_option_eq("asterisk", "tel_line", "sip_account", sip_id, s) {
		dmuci_set_value_by_section(s, "sip_account", "-");
	}
	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_asterisk", "tel_line", "voice_profile_key", profile_key, stmp, s) {
		dmuci_delete_by_section(s, NULL, NULL);
	}
	return 0;
}

static int delete_profile_object(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s, *ss = NULL, *sss = NULL;
	struct sip_args *sipargs = (struct sip_args *)data;
	struct uci_section *dmmap_section;
	char *v= NULL;
	
	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(sipargs->sip_section), &dmmap_section);
			dmuci_get_value_by_section_string(dmmap_section, "profileinstance", &v);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);
			delete_associated_line_instances(section_name(sipargs->sip_section), v);
			dmuci_delete_by_section(sipargs->sip_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("asterisk", "sip_service_provider", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(ss), &dmmap_section);
					dmuci_get_value_by_section_string(dmmap_section, "profileinstance", &v);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					delete_associated_line_instances(section_name(ss), v);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(ss), &dmmap_section);
				dmuci_get_value_by_section_string(dmmap_section, "profileinstance", &v);
				if(dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				delete_associated_line_instances(section_name(ss), v);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			uci_foreach_sections("asterisk", "tel_line", sss) {
				dmuci_set_value_by_section(sss, "sip_account", "-");
			}
			break;
	}
	
	return 0;
}

static int get_voice_service_max_line()
{
	char *num_lines = NULL;

	db_get_value_string("hw", "board", "VoicePorts", &num_lines);
	if(num_lines)
		return atoi(num_lines);
	return 0;
}

static int get_line_max_instance(struct uci_section **tel_section)
{
	struct uci_section *s;
	int line_number, i = 0, found = 0;
	char *value;
	
	line_number = get_voice_service_max_line();
	
	uci_foreach_sections("asterisk", "tel_line", s) {
		i++;
		dmuci_get_value_by_section_string(s, "sip_account", &value);
		if (strcmp(value, "-") == 0) {
			found = 1;
			break;
		} else if (i >= line_number) {
			i = 0;
			break;
		}
	}
	if (found == 1)
		*tel_section = s;
	else {
		i = 0;
		*tel_section = NULL;
	}
	return i;
}

static char *update_vp_line_instance(struct uci_section *tel_s, char *sipx)
{
	struct uci_section *s = NULL, *dmmap_section = NULL, *dmmap_dup = NULL;
	int last_instance = 0, i_instance;
	char *instance, buf[16];

	get_dmmap_section_of_config_section("dmmap_asterisk", "tel_line", section_name(tel_s), &dmmap_section);
	if (dmmap_section)
		dmuci_get_value_by_section_string(dmmap_section, "lineinstance", &instance);
	if (instance[0] != '\0') {
		return instance;
	}
	uci_foreach_option_eq("asterisk", "tel_line", "sip_account", sipx, s) {
		get_dmmap_section_of_config_section("dmmap_asterisk", "tel_line", section_name(s), &dmmap_dup);
		dmuci_get_value_by_section_string(dmmap_dup, "lineinstance", &instance);
		if (instance[0] != '\0') {
			i_instance = atoi(instance);
			if ( i_instance > last_instance)
				last_instance = i_instance;
		}
	}
	snprintf(buf, sizeof(buf), "%d", last_instance + 1);
	instance = dmuci_set_value_by_section(dmmap_section, "lineinstance", buf);
	return instance;
}

static int add_line(struct uci_section *s, char *s_name)
{
	dmuci_set_value_by_section(s, "sip_account", s_name);
	return 0;
}

static int add_line_object(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{	
	char *value, *v, *voice_profile_key, call_lines[16] = {0};
	struct uci_section *s = NULL;
	struct sip_args *sipargs = (struct sip_args *)data;
	struct uci_section *dmmap_voice_line_section, *dmmap_section;

	check_create_dmmap_package("dmmap_asterisk");
	int i = get_line_max_instance(&s);
	if (i == 0)
		return FAULT_9004;
	add_line(s, section_name(sipargs->sip_section));
	dmuci_add_section_bbfdm("dmmap_asterisk", "tel_line", &dmmap_voice_line_section, &v);
	dmuci_set_value_by_section(dmmap_voice_line_section, "section_name", section_name(s));
	get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(sipargs->sip_section), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "profileinstance", &voice_profile_key);
	dmuci_set_value_by_section(dmmap_voice_line_section, "voice_profile_key", voice_profile_key);
	*instancepara = update_vp_line_instance(s, section_name(sipargs->sip_section));
	dmuci_get_value_by_section_string(sipargs->sip_section, "call_lines", &value);
	if (value[0] == '\0')
		snprintf(call_lines, sizeof(call_lines), "%d", i - 1);
	else
		snprintf(call_lines, sizeof(call_lines), "%s %d", value, i - 1);
	dmuci_set_value_by_section(sipargs->sip_section, "call_lines", call_lines);
	return 0;
}

static int delete_line(struct uci_section *line_section, struct uci_section *sip_section)
{
	char *line_section_name, *line_id, *value = NULL;
	char *pch, *spch, *call_lines, *p, new_call_lines[34] = {0};
	
	line_section_name = section_name(line_section);
	line_id = line_section_name + strlen(line_section_name) - 1;
	dmuci_set_value_by_section(line_section, "sip_account", "-");
	dmuci_set_value_by_section(line_section, "lineinstance", "");
	dmuci_set_value_by_section(line_section, "linealias", "");
	dmuci_get_value_by_section_string(sip_section, "call_lines", &value);
	call_lines = dmstrdup(value);
	pch = strtok_r(call_lines, " ", &spch);
	p = new_call_lines;
	while (pch != NULL) {
		if (strcmp(pch, line_id) != 0) {
			if (new_call_lines[0] == '\0') {
				dmstrappendstr(p, pch);
			} else {
				dmstrappendchr(p, ' ');
				dmstrappendstr(p, pch);
			}
		}
		pch = strtok_r(NULL, " ", &spch);
	}
	dmstrappendend(p);
	dmuci_set_value_by_section(sip_section, "call_lines", new_call_lines);
	return 0;
}

static int delete_line_object(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	char *s_name;
	struct uci_section *s;
	struct sip_args *sipargs;
	struct tel_args *bargs; //profile_num must be added to tel_args
	struct uci_section *dmmap_section = NULL;
	
	switch (del_action) {
		case DEL_INST:
			bargs = (struct tel_args *)data;
			get_dmmap_section_of_config_section("dmmap_asterisk", "tel_line", section_name(bargs->tel_section), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			delete_line(bargs->tel_section, bargs->sip_section);
			break;
		case DEL_ALL:
			sipargs = (struct sip_args *)data;
			s_name = section_name(sipargs->sip_section);
			uci_foreach_option_eq("asterisk", "tel_line", "sip_account", s_name, s) {
				get_dmmap_section_of_config_section("dmmap_asterisk", "tel_line", section_name(s), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				delete_line(s, sipargs->sip_section);
			}
			break;
	}

	return 0;
}
/**************************Function for root entry *************************/
static int get_max_profile_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "8";
	return 0;
}

static int get_max_line_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "6";
	return 0;
}

static int get_max_session_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "6";
	return 0;
}

static int get_signal_protocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "SIP";
	return 0;
}

static int get_regions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "AU, BE, BR, CL, CN, CZ, DK, FI, FR, DE, HU, IN, IT, JP, NL, NZ, US, ES, SE, CH, NO, TW, GB, AE, ET, T5";
	return 0;
}

static int get_true_value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_false_value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}
/*******************end root ***************************/

/**************SIP CAPABILITIES ************************/
static int get_sip_role (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "BackToBackUserAgents";
	return 0;
}

static int get_sip_extension(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "INVITE,ACK,CANCEL,OPTIONS,BYE,REFER,SUBSCRIBE,NOTIFY,INFO,PUBLISH";
	return 0;
}

static int get_sip_transport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "UDP,TCP,TLS";
	return 0;
}

static int get_sip_tls_auth_protocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "MD5";
	return 0;
}

static int get_sip_tls_enc_protocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "RC4,RC2,DES,3DES";
	return 0;
}

static int get_sip_tls_key_protocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "RSA,DSS";
	return 0;
}
/*******************Capabilities.Codecs.***********************************/
static int get_entry_id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct codec_args *codecs = (struct codec_args *)data;
	*value = dmstrdup(codecs->id);
	return 0;
}

static int get_capabilities_sip_codec(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	struct codec_args *cdcargs = (struct codec_args *)data;
	for (i = 0; i < ARRAY_SIZE(capabilities_sip_codecs); i++) {
		if (capabilities_sip_codecs[i].enumid == cdcargs->enumid) {
			*value = capabilities_sip_codecs[i].c2;
			break;
		}
	}
	return 0;
}

static int get_capabilities_sip_bitrate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	struct codec_args *cdcargs = (struct codec_args *)data;
	for (i = 0; i < ARRAY_SIZE(capabilities_sip_codecs); i++) {
		if (capabilities_sip_codecs[i].enumid == cdcargs->enumid) {
			*value = capabilities_sip_codecs[i].c3;
			break;
		}
	}
	return 0;
}

static int get_capabilities_sip_pperiod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	struct codec_args *cdcargs = (struct codec_args *)data;
	for (i = 0; i < ARRAY_SIZE(capabilities_sip_codecs); i++) {
		if (capabilities_sip_codecs[i].enumid == cdcargs->enumid) {
			*value = capabilities_sip_codecs[i].c4;
			break;
		}
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.Enable!UCI:asterisk/sip_service_provider,@i-1/enabled*/
static int get_voice_profile_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp;
	struct sip_args *sipargs = (struct sip_args *)data;
	
	dmuci_get_value_by_section_string(sipargs->sip_section, "enabled", &tmp);
	
	if(strcmp(tmp, "0") == 0)
		*value = "Disabled";
	else
		*value = "Enabled";
	return 0;
}

static int set_voice_profile_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct sip_args *sipargs = (struct sip_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProfileEnable, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if(strcmp(value, "Enabled") == 0)
				dmuci_set_value_by_section(sipargs->sip_section, "enabled", "1");
			else
				dmuci_set_value_by_section(sipargs->sip_section, "enabled", "0");
			return 0;
	}
	return 0;
}

static int set_voice_profile_reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if(b) {
				dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", "asterisk"}}, 1);
				return 0;
			}
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.Name!UCI:asterisk/sip_service_provider,@i-1/name*/
static int get_voice_profile_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	dmuci_get_value_by_section_string(sipargs->sip_section, "name", value);
	return 0;
}

static int set_voice_profile_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct sip_args *)data)->sip_section, "name", value);
			return 0;
	}
	return 0;
}

static int get_voice_profile_signalprotocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "SIP";
	return 0;
}

static int set_voice_profile_signaling_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.MaxSessions!UBUS:voice.asterisk/lines//num_lines*/
static int get_voice_profile_max_sessions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char *sub_channel = NULL, *num_lines = NULL;
	dmubus_call("voice.asterisk", "lines", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	sub_channel = dmjson_get_value(res, 1, "num_subchannels");
	num_lines =  dmjson_get_value(res, 1, "num_lines");
	dmasprintf(value, "%d", atoi(sub_channel) * atoi(num_lines)); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.NumberOfLines!UBUS:voice.asterisk/status//tel.@Name*/
static int get_voice_profile_number_of_lines(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int num = 0;
	json_object *res = NULL, *jobj = NULL;
	struct uci_section *b_section = NULL;
	struct sip_args *sipargs = (struct sip_args *)data;

	*value = "0";
	dmubus_call("voice.asterisk", "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	uci_foreach_option_eq("asterisk", "tel_line", "sip_account", section_name(sipargs->sip_section), b_section) {
		jobj = dmjson_get_obj(res, 2, "tel", section_name(b_section));
		if (jobj)
			num++;
	}
	dmasprintf(value, "%d", num); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.ProxyServer!UCI:asterisk/sip_advanced,SIP/sip_proxy*/
static int get_voice_profile_sip_proxyserver(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "sip_options", "sip_proxy", value);
	return 0;
}

static int set_voice_profile_sip_proxyserver(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "sip_proxy", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.ProxyServerTransport!UCI:asterisk/sip_service_provider,@i-1/transport*/
static int get_sip_proxy_server_transport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct sip_args *sipargs = (struct sip_args *)data;
		
	dmuci_get_value_by_section_string(sipargs->sip_section, "transport", value);
	return 0;
}

static int set_sip_proxy_server_transport(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct sip_args *sipargs = (struct sip_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(sipargs->sip_section, "transport", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.RegistrarServer!UCI:asterisk/sip_service_provider,@i-1/host*/
static int get_voice_profile_sip_registerserver(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	
	dmuci_get_value_by_section_string(sipargs->sip_section, "host", value);
	return 0;
}

static int set_voice_profile_sip_registerserver(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(sipargs->sip_section, "host", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.RegistrarServerPort!UCI:asterisk/sip_service_provider,@i-1/port*/
static int get_voice_profile_sip_registerserverport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct sip_args *)data)->sip_section, "port", "0");
	return 0;
}

static int set_voice_profile_sip_registerserverport(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(sipargs->sip_section, "port", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.RegistrarServerTransport!UCI:asterisk/sip_service_provider,@i-1/transport*/
static int get_sip_registrar_server_transport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	
	dmuci_get_value_by_section_string(sipargs->sip_section, "transport", value);
	return 0;
}

static int set_sip_registrar_server_transport(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct sip_args *sipargs = (struct sip_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(sipargs->sip_section, "transport", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.UserAgentDomain!UCI:asterisk/sip_service_provider,@i-1/domain*/
static int get_sip_user_agent_domain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	
	dmuci_get_value_by_section_string(sipargs->sip_section, "domain", value);
	return 0;
}

static int set_sip_user_agent_domain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(sipargs->sip_section, "domain", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.UserAgentPort!UCI:asterisk/sip_advanced,SIP/bindport*/
static int get_sip_user_agent_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "sip_options", "bindport", "0");
	return 0;
}

static int set_sip_user_agent_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "bindport", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.UserAgentTransport!UCI:asterisk/sip_service_provider,@i-1/transport*/
static int get_sip_user_agent_transport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct sip_args *)data)->sip_section, "transport", "udp");
	return 0;
}

static int set_sip_user_agent_transport(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcasecmp(value, "udp")==0) dmuci_set_value_by_section(sipargs->sip_section, "transport", "");
			else dmuci_set_value_by_section(sipargs->sip_section, "transport", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.OutboundProxy!UCI:asterisk/sip_service_provider,@i-1/outboundproxy*/
static int get_sip_outbound_proxy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	
	dmuci_get_value_by_section_string(sipargs->sip_section, "outboundproxy", value);
	return 0;
}

static int set_sip_outbound_proxy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(sipargs->sip_section, "outboundproxy", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.OutboundProxyPort!UCI:asterisk/sip_service_provider,@i-1/outboundproxyport*/
static int get_sip_outbound_proxy_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct sip_args *)data)->sip_section, "outboundproxyport", "0");
	return 0;
}

static int set_sip_outbound_proxy_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(sipargs->sip_section, "outboundproxyport", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.RegistrationPeriod!UCI:asterisk/sip_advanced,SIP/defaultexpiry*/
static int get_sip_registration_period(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "sip_options", "defaultexpiry", value);
	return 0;
}

static int set_sip_registration_period(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "defaultexpiry", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP.ReInviteExpires!UCI:asterisk/sip_advanced,SIP/registertimeout*/
static int get_sip_re_invite_expires(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "sip_options", "registertimeout", "1");
	return 0;
}

static int set_sip_re_invite_expires(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "registertimeout", value);
			return 0;
	}
	return 0;
}

static int get_sip_call_lines(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	
	dmuci_get_value_by_section_string(sipargs->sip_section, "call_lines", value);
	return 0;
}

static int set_sip_call_lines(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	
	switch (action) {
		case VALUECHECK:
			//TODO
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(sipargs->sip_section, "call_lines", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.DTMFMethod!UCI:asterisk/sip_advanced,SIP/dtmfmode*/
static int get_voice_profile_sip_dtmfmethod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp;
	
	dmuci_get_option_value_string("asterisk", "sip_options", "dtmfmode", &tmp);
	if (strcmp(tmp, "inband") == 0)
		*value = "InBand";
	else if (strcmp(tmp, "rfc2833") == 0)
		*value = "RFC2833";
	else if (strcmp(tmp, "info") == 0)
		*value = "SIPInfo";
	else
		*value = tmp;
	return 0;
}

static int set_voice_profile_sip_dtmfmethod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, DTMFMethod, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if(strcmp(value, "InBand") == 0)
				dmuci_set_value("asterisk", "sip_options", "dtmfmode", "inband");
			else if(strcmp(value, "RFC2833") == 0)
				dmuci_set_value("asterisk", "sip_options", "dtmfmode", "rfc2833");
			else if(strcmp(value, "SIPInfo") == 0)
				dmuci_set_value("asterisk", "sip_options", "dtmfmode", "info");
			return 0;
	}
	return 0;
}

static int get_sip_profile_region(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	
	dmuci_get_option_value_string("asterisk", "tel_options", "country", value);
	for (i = 0; i < ARRAY_SIZE(capabilities_regions); i++) {
		if(strcmp(*value, capabilities_regions[i].country) == 0){
			*value = capabilities_regions[i].id;
			return 0;
		}
	}
	return 0;
}

static int set_sip_profile_region(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int i;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			for (i = 0; i < ARRAY_SIZE(capabilities_regions); i++) {
				if(strcasecmp(value, capabilities_regions[i].id) == 0){
					dmuci_set_value("asterisk", "tel_options", "country", capabilities_regions[i].country);
					break;
				}
			}
			return 0;
		}
	return 0;
}

static int get_voice_service_serviceproviderinfo_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	
	dmuci_get_value_by_section_string(sipargs->sip_section, "provider_name", value);
	if(*value[0] == '\0') {
		dmuci_get_value_by_section_string(sipargs->sip_section, "domain", value);
	}
	return 0;
}

static int set_voice_service_serviceproviderinfo_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct sip_args *sipargs = (struct sip_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(sipargs->sip_section, "provider_name", value);
			return 0;
	}
	return 0;
}

static int get_sip_fax_t38_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct sip_args *sipargs = (struct sip_args *)data;
	dmuci_get_value_by_section_string(sipargs->sip_section, "is_fax", value);
	return 0;
}

static int set_sip_fax_t38_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct sip_args *)data)->sip_section, "is_fax", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_voice_service_vp_rtp_portmin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "sip_options", "rtpstart", "5000");
	return 0;
}

static int set_voice_service_vp_rtp_portmin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "rtpstart", value);
			return 0;
	}
	return 0;
}

static int get_voice_service_vp_rtp_portmax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "sip_options", "rtpend", "31000");
	return 0;
}

static int set_voice_profile_rtp_localportmax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "rtpend", value);
			return 0;
	}
	return 0;
}

static int get_voice_service_vp_rtp_dscp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	char *tmp;
	*value = "0";

	dmuci_get_option_value_string("asterisk", "sip_options", "tos_audio", &tmp);
	for (i = 0; i < ARRAY_SIZE(list_rtp_tos); i++) {
		if(strcmp(tmp, list_rtp_tos[i].key) == 0){
			*value = list_rtp_tos[i].val;
			break;
		}
	}
	return 0;
}

static int set_voice_service_vp_rtp_dscp(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int i;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			for (i = 0; i < ARRAY_SIZE(list_rtp_tos); i++) {
				if (strcmp(value, list_rtp_tos[i].val) == 0) {
					dmuci_set_value("asterisk", "sip_options", "tos_audio", list_rtp_tos[i].key);
					break;
				}
			}
		return 0;
	}
	return 0;
}

static int get_voice_service_vp_rtp_rtcp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	pid_t pid = get_pid("asterisk");
	*value = (pid < 0) ? "0" : "1";
	return 0;
}

static int get_voice_service_vp_rtp_rtcp_txrepeatinterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "sip_options", "rtcpinterval", "5000");
	return 0;
}

static int set_voice_service_vp_rtp_rtcp_txrepeatinterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "rtcpinterval", value);
			return 0;
	}
	return 0;
}

static int get_voice_service_vp_rtp_srtp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp;
	struct sip_args *sipargs = (struct sip_args *)data;
	
	dmuci_get_value_by_section_string(sipargs->sip_section, "encryption", &tmp);
	if (strcasecmp(tmp, "yes") == 0)
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_voice_service_vp_rtp_srtp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	struct sip_args *sipargs = (struct sip_args *)data;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(sipargs->sip_section, "encryption", b ? "yes" : "");
			return 0;
	}
	return 0;
}

/*******************LINE **********************************/
/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.Line.{i}.Enable!UCI:asterisk/tel_line,@i-1/enabled*/
static int get_voice_profile_line_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp;
	struct tel_args *telargs = (struct tel_args *)data;

	dmuci_get_value_by_section_string(telargs->sip_section, "enabled", &tmp);
	if (strcmp(tmp, "0") == 0)
		*value = "Disabled";
	else
		*value = "Enabled";
	return 0;
}

static int set_voice_profile_line_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct tel_args *telargs = (struct tel_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProfileEnable, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if(strcmp(value, "Enabled") == 0)
				dmuci_set_value_by_section(telargs->sip_section, "enabled", "1");
			else
				dmuci_set_value_by_section(telargs->sip_section, "enabled", "0");
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.Line.{i}.DirectoryNumber!UCI:asterisk/tel_line,@i-1/extension*/
static int get_line_directory_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct tel_args *telargs = (struct tel_args *)data;
	
	dmuci_get_value_by_section_string(telargs->tel_section, "extension", value);
	return 0;
}

static int set_line_directory_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct tel_args *telargs = (struct tel_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(telargs->tel_section, "extension", value);
			return 0;
	}
	return 0;
}

static int get_voice_profile_line_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status, *q;
	json_object *res;
	char buf[64];
	struct tel_args *telargs = (struct tel_args *)data;
	*value = "Disabled";
	q = buf;
	dmstrappendstr(q, "asterisk");
	dmstrappendchr(q, '.');
	dmstrappendstr(q, "sip");
	dmstrappendchr(q, '.');
	dmstrappendstr(q, section_name(telargs->sip_section) + 3);
	dmstrappendend(q);
	dmubus_call(buf, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "Disabled");
	if(res) {
		status = dmjson_get_value(res, 1, "registered");
		if (strcasecmp(status, "true") == 0) {
			*value = "Up";
		} else {
			status = dmjson_get_value(res, 1, "registry_request_sent");
			if(strcasecmp(status, "true") == 0)
				*value = "Registering";
			else
				*value = "Disabled";
		}
	}
	return 0;
}

static int get_voice_profile_line_callstate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{	
	char *tmp, *line_name;
	struct tel_args *telargs = (struct tel_args *)data;

	line_name = section_name(telargs->tel_section);
	dmuci_get_varstate_string("chan_tel", line_name, "subchannel_0", &tmp);
	if (strcmp(tmp, "ONHOOK") == 0)
		*value = "idle";
	else if (strcmp(tmp, "OFFHOOK") == 0)
		*value = "Disconnecting";
	else if (strcmp(tmp, "DIALING") == 0)
		*value = "Calling";
	else if (strcmp(tmp, "INCALL") == 0)
		*value = "InCall";
	else if (strcmp(tmp, "RINGING") == 0)
		*value = "Ringing";
	else
		*value = "";
	return 0;
}

static int get_line_line_profile(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct tel_args *telargs = (struct tel_args *)data;

	*value = telargs->profile_num;
	return 0;
}

static int set_line_line_profile(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char call_lines[32];
	char *str;
	struct uci_section *sip_s;
	struct tel_args *telargs = (struct tel_args *)data;
			
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			uci_foreach_option_eq("asterisk", "sip_service_provider", "profileinstance", value, sip_s) {
				break;
			}
			if (!sip_s || strcmp(telargs->profile_num, value) == 0)
				return 0;

			delete_line(telargs->tel_section, telargs->sip_section);
			str = update_vp_line_instance(telargs->tel_section, section_name(sip_s));
			add_line(telargs->tel_section, section_name(sip_s));

			dmuci_get_value_by_section_string(sip_s, "call_lines", &value);
			if (value[0] == '\0') {
				value = section_name(telargs->tel_section) + strlen(section_name(telargs->tel_section)) - 1;
				dmuci_set_value_by_section(sip_s, "call_lines", value);
			}
			else {
				str = (section_name(telargs->tel_section) + strlen(section_name(telargs->tel_section)) - 1);
				snprintf(call_lines, sizeof(call_lines), "%s %s", value, str);
				dmuci_set_value_by_section(sip_s, "call_lines", call_lines);
			}
			return 0;
	}
	return 0;
}

static int get_line_tel_line(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *line_name;
	struct tel_args *telargs = (struct tel_args *)data;
	
	line_name = section_name(telargs->tel_section);
	*value = dmstrdup(line_name + strlen(line_name) - 1); //  MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

static int set_line_tel_line(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int error;
	char line_name[8], bname[8], *stype = NULL, *sipaccount = NULL, *lineinstance = NULL, *linealias = NULL, *voice_profile_key = NULL, *v;
	struct tel_args *telargs = (struct tel_args *)data;
	struct uci_section *dmmap_section = NULL, *dmmap_tel_line_section = NULL;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			memset(line_name, '\0', sizeof(line_name));
			strcpy(line_name, section_name(telargs->tel_section));
			snprintf(bname, sizeof(bname), "%s%s", line_name, value);
			error = dmuci_get_section_type("asterisk", bname, &stype);
			if(error)
				return 0;
			dmuci_get_option_value_string("asterisk", bname, "sip_account", &sipaccount);
			if ((sipaccount[0] != '\0' && sipaccount[0] != '-'))
				return 0;
			dmuci_get_value_by_section_string(telargs->tel_section, "sip_account", &sipaccount);
			dmuci_set_value_by_section(telargs->tel_section, "sip_account", "-");
			get_dmmap_section_of_config_section("dmmap_asterisk", "tel_line", section_name(telargs->tel_section), &dmmap_section);
			if(dmmap_section != NULL) {
				dmuci_get_value_by_section_string(dmmap_section, "voice_profile_key", &voice_profile_key);
				dmuci_get_value_by_section_string(dmmap_section, "lineinstance", &lineinstance);
				dmuci_get_value_by_section_string(dmmap_section, "linealias", &linealias);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			}
			dmuci_set_value("asterisk", bname, "sip_account", sipaccount);
			dmuci_add_section_bbfdm("dmmap_asterisk", "tel_line", &dmmap_tel_line_section, &v);
			if(dmmap_section != NULL) {
				dmuci_set_value_by_section(dmmap_tel_line_section, "section_name", bname);
				dmuci_set_value_by_section(dmmap_tel_line_section, "voice_profile_key", voice_profile_key);
				dmuci_set_value_by_section(dmmap_tel_line_section, "lineinstance", lineinstance);
				dmuci_set_value_by_section(dmmap_tel_line_section, "linealias", linealias);
			}
			return 0;
	}
	return 0;
}

static int get_line_comfort_noise_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct tel_args *telargs = (struct tel_args *)data;

	dmuci_get_value_by_section_string(telargs->tel_section, "noise", value);
	return 0;
}

static int set_line_comfort_noise_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	struct tel_args *telargs = (struct tel_args *)data;

	switch (action) {
		case VALUECHECK:
			if(dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(telargs->tel_section, "noise", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_line_voice_processing_cancellation_enable(char *refparam, struct dmctx *ctx,  void *data, char *instance, char **value)
{
	struct tel_args *telargs = (struct tel_args *)data;

	dmuci_get_value_by_section_string(telargs->tel_section, "echo_cancel", value);
	return 0;
}


static int set_line_voice_processing_cancellation_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	struct tel_args *telargs = (struct tel_args *)data;

	switch (action) {
		case VALUECHECK:
			if(dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(telargs->tel_section, "echo_cancel", b ? "1" : "0");
			return 0;
	}
	return 0;
}


static int get_line_calling_features_caller_id_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct tel_args *telargs = (struct tel_args *)data;
	
	dmuci_get_value_by_section_string(telargs->sip_section, "displayname", value);
	return 0;
}

static int set_line_calling_features_caller_id_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct tel_args *telargs = (struct tel_args *)data;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(telargs->sip_section, "displayname", value);
			return 0;
	}
	return 0;
}

static int get_line_calling_features_callwaiting(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct tel_args *)data)->tel_section, "callwaiting", "0");
	return 0;
}

static int set_line_calling_features_callwaiting(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	struct tel_args *telargs = (struct tel_args *)data;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(telargs->tel_section, "callwaiting", b ? "1" : "");
			return 0;
	}
	return 0;
}

static int get_line_sip_auth_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct tel_args *telargs = (struct tel_args *)data;
	
	dmuci_get_value_by_section_string(telargs->sip_section, "authuser", value);
	return 0;
}

static int set_line_sip_auth_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct tel_args *telargs = (struct tel_args *)data;
	
  switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 128, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(telargs->sip_section, "authuser", value);
			return 0;
	}
	return 0;
}

static int set_line_sip_auth_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct tel_args *telargs = (struct tel_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 128, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(telargs->sip_section, "secret", value);
			return 0;
	}
	return 0;
}

static int get_line_sip_uri(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *domain = NULL, *user = NULL;
	struct tel_args *telargs = (struct tel_args *)data;

	dmuci_get_value_by_section_string(telargs->sip_section, "domain", &domain);
	dmuci_get_value_by_section_string(telargs->sip_section, "user", &user);
	if (user && user[0] != '\0' && domain && domain[0] != '\0')
		dmasprintf(value, "%s@%s", user, domain); // MEM WILL BE FREED IN DMMEMCLEAN
	else
		*value = "";
  return 0;
}

static int set_line_sip_uri(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *pch, *spch = NULL, *str1;
	struct tel_args *telargs = (struct tel_args *)data;
	
  switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 389, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			str1 = dmstrdup(value);
			pch = strtok_r(str1, "@", &spch);
			dmuci_set_value_by_section(telargs->sip_section, "user", pch);
			pch = strtok_r(NULL, "@", &spch);
			dmuci_set_value_by_section(telargs->sip_section, "domain", pch);
			dmfree(str1);
			return 0;
	}
	return 0;
}

/******************Line codec ***************************************/
static int codec_compare(const void *s1, const void *s2)
{
	struct codec *sc1 = (struct codec *)s1;
	struct codec *sc2 = (struct codec *)s2;
	if (!sc1->priority) return 1;
	if (!sc2->priority) return -1;
	return (atoi(sc1->priority) - atoi(sc2->priority));
}

static void codec_priority_sort(struct uci_section *sip_section, char *new_codec)
{
	int j, k = 0, size = ARRAY_SIZE(codec_option_array);
	char *ucodec;
	bool found;
	struct codec sipcodec[ARRAY_SIZE(codec_option_array)+1] = {0};
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(sip_section), &dmmap_section);
	for (j = 0; j < ARRAY_SIZE(codec_option_array); j++) {
		dmuci_get_value_by_section_string(sip_section, codec_option_array[j], &ucodec);
		if(ucodec[0] != '\0') {
			found = false;
			for (k = 0; k < available_sip_codecs; k++) {
				if(strcmp(ucodec, allowed_sip_codecs[k].allowed_cdc) == 0) {
					found = true;
					break;
				}
			}
			if (found) {
				sipcodec[j].cdc = allowed_sip_codecs[k].allowed_cdc;
				dmuci_get_value_by_section_string(dmmap_section, allowed_sip_codecs[k].priority_cdc, &(sipcodec[j].priority));
			}
			sipcodec[j].id = codec_option_array[j];
		}
		else {
			sipcodec[j].id = codec_option_array[j];
		}
	}
	if (new_codec) {
		sipcodec[size].id = "codec5";
		found = false;
		for (k = 0; k < available_sip_codecs; k++) {
			if(strcmp(new_codec, allowed_sip_codecs[k].allowed_cdc) == 0) {
				found = true;
				break;
			}
		}
		if (found) {
			sipcodec[size].cdc = allowed_sip_codecs[k].allowed_cdc;
			dmuci_get_value_by_section_string(dmmap_section, allowed_sip_codecs[k].priority_cdc, &(sipcodec[size].priority));
		}
	}
	qsort(sipcodec, ARRAY_SIZE(sipcodec), sizeof(struct codec), codec_compare);

	for (j = 0; j < ARRAY_SIZE(codec_option_array); j++) {
		dmuci_set_value_by_section(sip_section, codec_option_array[j], sipcodec[j].cdc ? sipcodec[j].cdc : "");
	}
}

static void codec_priority_update(struct uci_section *sip_section)
{
	bool found;
	int i, j;
	char *priority = NULL;
	char *codec;
	char pid[4] = "1";
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(sip_section), &dmmap_section);

	for (i = 0; i < available_sip_codecs; i++) {
		dmuci_get_value_by_section_string(dmmap_section, allowed_sip_codecs[i].priority_cdc, &priority);
		if( priority[0] != '\0')
			continue;
		found = false;
		for (j = 0; j < ARRAY_SIZE(codec_option_array); j++) {
			dmuci_get_value_by_section_string(sip_section, codec_option_array[j], &codec);
			if(strcmp(codec, allowed_sip_codecs[i].allowed_cdc) == 0) {
				found = true;
				break;
			}
		}
		if (found)
			snprintf(pid, sizeof(pid), "%d", j+1);
		dmuci_set_value_by_section(dmmap_section, allowed_sip_codecs[i].priority_cdc, pid);
	}
	codec_priority_sort(sip_section, NULL);
}

static int get_codec_entry_id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct line_codec_args *line_codecargs = (struct line_codec_args *)data;
	
	*value = line_codecargs->id;
	return 0;
}

static int capabilities_sip_codecs_get_codec(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	struct line_codec_args *line_codecargs = (struct line_codec_args *)data;
	
	for (i = 0; i < ARRAY_SIZE(capabilities_sip_codecs); i++) {
		if(capabilities_sip_codecs[i].enumid == line_codecargs->enumid) {
			*value = capabilities_sip_codecs[i].c2;
			break;
		}
	}
	return 0;
}

static int capabilities_sip_codecs_get_bitrate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	struct line_codec_args *line_codecargs = (struct line_codec_args *)data;
	
	for (i = 0; i < ARRAY_SIZE(capabilities_sip_codecs); i++) {
		if(capabilities_sip_codecs[i].enumid == line_codecargs->enumid) {
			*value = capabilities_sip_codecs[i].c3;
			break;
		}
	}
	return 0;
}

static int get_capabilities_sip_codecs_pperiod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	struct line_codec_args *line_codecargs = (struct line_codec_args *)data;
	dmuci_get_value_by_section_string(line_codecargs->sip_section, line_codecargs->ptime_cdc, value);
	if ((*value)[0] != '\0')
		return 0;
	for (i = 0; i < ARRAY_SIZE(capabilities_sip_codecs); i++) {
		if(capabilities_sip_codecs[i].enumid == line_codecargs->enumid) {
			*value = capabilities_sip_codecs[i].c5;
			break;
		}
	}
	return 0;
}

static int get_line_codec_list_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	char *val;
	struct line_codec_args *line_codecargs = (struct line_codec_args *)data;
	
	for (i =0; i < ARRAY_SIZE(codec_option_array); i++) {
		dmuci_get_value_by_section_string(line_codecargs->sip_section, codec_option_array[i], &val);
		if (strcmp(val, line_codecargs->cdc) == 0) {
			*value = "1";
			return 0;
		}
	}
	*value = "0";
	return 0;
}

static int get_line_codec_list_priority(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct line_codec_args *line_codecargs = (struct line_codec_args *)data;
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(line_codecargs->sip_section), &dmmap_section);
	if (dmmap_section)
		dmuci_get_value_by_section_string(dmmap_section, line_codecargs->priority_cdc, value);
	return 0;
}

static int set_line_codec_list_packetization(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct line_codec_args *line_codecargs = (struct line_codec_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(line_codecargs->sip_section, line_codecargs->ptime_cdc, value);
			return 0;
	}
	return 0;
}

static int set_line_codec_list_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	int j;
	char *codec;
	struct line_codec_args *line_codecargs = (struct line_codec_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				for (j = 0; j < ARRAY_SIZE(codec_option_array); j++) {
					dmuci_get_value_by_section_string(line_codecargs->sip_section, codec_option_array[j], &codec);
					if(strcmp(codec, line_codecargs->cdc) == 0) {
						return 0;
					}
				}
				codec_priority_sort(line_codecargs->sip_section, line_codecargs->cdc);
			}
			else {
				for (j = 0; j < ARRAY_SIZE(codec_option_array); j++) {
					dmuci_get_value_by_section_string(line_codecargs->sip_section, codec_option_array[j], &codec);
					if(strcmp(codec, line_codecargs->cdc) == 0) {
						dmuci_set_value_by_section(line_codecargs->sip_section, codec_option_array[j], "");
					}
				}
			}
			return 0;
	}
	return 0;
}

static int set_line_codec_list_priority(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int i;
	char *val;
	struct line_codec_args *line_codecargs = (struct line_codec_args *)data;
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(line_codecargs->sip_section), &dmmap_section);
			if (dmmap_section) {
				dmuci_set_value_by_section(dmmap_section, line_codecargs->priority_cdc, value);
				for (i =0; i < ARRAY_SIZE(codec_option_array); i++) {
					dmuci_get_value_by_section_string(line_codecargs->sip_section, codec_option_array[i], &val);
					if (strcmp(val, line_codecargs->cdc) == 0) {
						codec_priority_sort(line_codecargs->sip_section, NULL);
						return 0;
					}
				}
			}
			return 0;
	}
	return 0;
}

static void codec_update_id()
{
	int i = 0;
	int found = 0;
	struct uci_section *s = NULL;
	struct uci_section *ss = NULL;

	for (i = 0; i < available_sip_codecs; i++) {
		update_section_list(DMMAP,"codec_id", "id", 1, allowed_sip_codecs[i].id, NULL, NULL, NULL, NULL);
	}
	if(i == 0) {
		uci_path_foreach_sections(bbfdm, "dmmap", "codec_id", s) {
			if (found != 0) {
				DMUCI_DELETE_BY_SECTION(bbfdm, ss, NULL, NULL);
			}
			ss = s;
			found++;
		}
		if (ss != NULL) {
			DMUCI_DELETE_BY_SECTION(bbfdm, ss, NULL, NULL);
		}
	}
}
////////////////////////SET AND GET ALIAS/////////////////////////////////
int get_service_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "vsalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_service_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "vsalias", value);
			return 0;
	}
	return 0;
}

int get_cap_codec_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct codec_args *)data)->codec_section, "codecalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_cap_codec_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct codec_args *)data)->codec_section, "codecalias", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.Alias!UCI:dmmap_asterisk/sip_service_provider,@i-1/profilealias*/
static int get_voice_profile_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(((struct sip_args *)data)->sip_section), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "profilealias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_voice_profile_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(((struct sip_args *)data)->sip_section), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "profilealias", value);
			return 0;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.Line.{i}.Alias!UCI:dmmap_asterisk/tel_line,@i-1/linealias*/
static int get_line_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_asterisk", "tel_line", section_name(((struct tel_args *)data)->tel_section), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "linealias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_line_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_asterisk", "tel_line", section_name(((struct tel_args *)data)->tel_section), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "linealias", value);
			return 0;
	}
	return 0;
}

static int get_line_codec_list_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct line_codec_args *)data)->codec_sec, "codecalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_line_codec_list_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct line_codec_args *)data)->codec_sec, "codecalias", value);
			return 0;
	}
	return 0;
}
///////////////////////////////////////
static void set_voice_profile_key_of_line(struct uci_section *dmmap_line_section, char* prev_instance)
{
	DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_line_section, "voice_profile_key", prev_instance);
}

static int browseVoiceServiceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *vs = NULL, *vs_last = NULL;

	update_section_list(DMMAP,"voice_service", NULL, 1, NULL, NULL, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap", "voice_service", s) {
		vs = handle_update_instance(1, dmctx, &vs_last, update_instance_alias_bbfdm, 3, s, "vsinstance", "vsalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, vs) == DM_STOP)
			break;
	}
	return 0;
}

static int browseCodecsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	int i = 0;
	char *id, *id_last = NULL;
	struct uci_section *code_sec;
	struct codec_args curr_codec_args = {0};

	init_allowed_sip_codecs();
	codec_update_id();
	uci_path_foreach_sections(bbfdm, "dmmap", "codec_id", code_sec) {
		init_codec_args(&curr_codec_args, allowed_sip_codecs[i].allowed_cdc, allowed_sip_codecs[i].id, allowed_sip_codecs[i].enumid, code_sec);
		id = handle_update_instance(2, dmctx, &id_last, update_instance_alias_bbfdm, 3, code_sec, "codecinstance", "codecalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_codec_args, id) == DM_STOP) {
			fini_codec_args(&curr_codec_args);
			break;
		}
		fini_codec_args(&curr_codec_args);
		i++;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.!UCI:asterisk/sip_service_provider/dmmap_asterisk*/
static int browseProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *profile_num = NULL, *profile_num_last = NULL;
	struct sip_args curr_sip_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	wait_voice_service_up();
	synchronize_specific_config_sections_with_dmmap("asterisk", "sip_service_provider", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		profile_num = handle_update_instance(2, dmctx, &profile_num_last, update_instance_alias_bbfdm, 3, p->dmmap_section, "profileinstance", "profilealias");
		init_sip_args(&curr_sip_args, p->config_section, profile_num_last);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_sip_args, profile_num) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoiceProfile.{i}.Line.{i}.!UCI:asterisk/tel_line/dmmap_asterisk*/
static int browseLineInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	int maxLine, line_id = 0;
	char *line_num = NULL, *last_inst = NULL;
	struct sip_args *sipargs = (struct sip_args *)prev_data;
	struct tel_args curr_tel_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	maxLine = get_voice_service_max_line();

	synchronize_specific_config_sections_with_dmmap_eq("asterisk", "tel_line", "dmmap_asterisk", "sip_account", section_name(sipargs->sip_section), &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		line_id = atoi(section_name(p->config_section) + strlen(section_name(p->config_section)) - 1);
		if ( line_id >= maxLine )
			continue;
		set_voice_profile_key_of_line(p->dmmap_section, prev_instance);
		line_num = handle_update_instance(3, dmctx, &last_inst, update_instance_alias_bbfdm, 3, p->dmmap_section, "lineinstance", "linealias");
		init_tel_args(&curr_tel_args, p->config_section, sipargs->sip_section, sipargs->profile_num); //check difference between sipargs->profile_num and profile_num
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_tel_args, line_num) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseLineCodecListInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	int i = 0;
	char *id = NULL , *id_last = NULL;
	struct tel_args *telargs = (struct tel_args *)prev_data;
	struct uci_section *code_sec = NULL;
	struct line_codec_args curr_line_codec_args = {0};

	init_allowed_sip_codecs();
	codec_update_id();
	codec_priority_update(telargs->sip_section);
	uci_path_foreach_sections(bbfdm, "dmmap", "codec_id", code_sec) {
		init_line_code_args(&curr_line_codec_args, i, telargs->sip_section, code_sec);
		id = handle_update_instance(4, dmctx, &id_last, update_instance_alias_bbfdm, 3, code_sec, "codecinstance", "codecalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_line_codec_args, id) == DM_STOP)
			break;
		i++;
	}
	return 0;
}

/* *** Device.Services. *** */
DMOBJ tServicesObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"VoiceService", &DMREAD, NULL, NULL, NULL, browseVoiceServiceInst, NULL, NULL, NULL, tServicesVoiceServiceObj, tServicesVoiceServiceParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}. *** */
DMOBJ tServicesVoiceServiceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCapabilitiesObj, tServicesVoiceServiceCapabilitiesParams, NULL, BBFDM_BOTH},
{"VoiceProfile", &DMWRITE, add_profile_object, delete_profile_object, NULL, browseProfileInst, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileObj, tServicesVoiceServiceVoiceProfileParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_service_alias, set_service_alias, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.Capabilities. *** */
DMOBJ tServicesVoiceServiceCapabilitiesObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"SIP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCapabilitiesSIPParams, NULL, BBFDM_BOTH},
{"Codecs", &DMREAD, NULL, NULL, NULL, browseCodecsInst, NULL, NULL, NULL, NULL, tServicesVoiceServiceCapabilitiesCodecsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceCapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"MaxProfileCount", &DMREAD, DMT_UNINT, get_max_profile_count, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxLineCount", &DMREAD, DMT_UNINT, get_max_line_count, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxSessionsPerLine", &DMREAD, DMT_UNINT, get_true_value, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxSessionCount", &DMREAD, DMT_UNINT, get_max_session_count, NULL, NULL, NULL, BBFDM_BOTH},
{"SignalingProtocols", &DMREAD, DMT_STRING, get_signal_protocols, NULL, NULL, NULL, BBFDM_BOTH},
{"Regions", &DMREAD, DMT_STRING, get_regions, NULL, NULL, NULL, BBFDM_BOTH},
{"RTCP", &DMREAD, DMT_BOOL, get_true_value, NULL, NULL, NULL, BBFDM_BOTH},
{"SRTP", &DMREAD, DMT_BOOL, get_true_value, NULL, NULL, NULL, BBFDM_BOTH},
{"RTPRedundancy", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"PSTNSoftSwitchOver", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"FaxT38", &DMREAD, DMT_BOOL, get_true_value, NULL, NULL, NULL, BBFDM_BOTH},
{"FaxPassThrough", &DMREAD, DMT_BOOL, get_true_value, NULL, NULL, NULL, BBFDM_BOTH},
{"ModemPassThrough", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"ToneGeneration", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"ToneDescriptionsEditable", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"PatternBasedToneGeneration", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"FileBasedToneGeneration", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"ToneFileFormats", &DMREAD, DMT_STRING, get_empty, NULL, NULL, NULL, BBFDM_BOTH},
{"RingGeneration", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"RingDescriptionsEditable", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"PatternBasedRingGeneration", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"RingPatternEditable", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"FileBasedRingGeneration", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"RingFileFormats", &DMREAD, DMT_STRING, get_empty, NULL, NULL, NULL, BBFDM_BOTH},
{"DigitMap", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"NumberingPlan", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"ButtonMap", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"VoicePortTests", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.Capabilities.SIP. *** */
DMLEAF tServicesVoiceServiceCapabilitiesSIPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Role", &DMREAD, DMT_STRING, get_sip_role, NULL, NULL, NULL, BBFDM_BOTH},
{"Extensions", &DMREAD, DMT_STRING, get_sip_extension, NULL, NULL, NULL, BBFDM_BOTH},
{"Transports", &DMREAD, DMT_STRING, get_sip_transport, NULL, NULL, NULL, BBFDM_BOTH},
{"URISchemes", &DMREAD, DMT_STRING, get_empty, NULL, NULL, NULL, BBFDM_BOTH},
{"EventSubscription", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"ResponseMap", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"TLSAuthenticationProtocols", &DMREAD, DMT_STRING, get_sip_tls_auth_protocols, NULL, NULL, NULL, BBFDM_BOTH},
{"TLSEncryptionProtocols", &DMREAD, DMT_STRING, get_sip_tls_enc_protocols, NULL, NULL, NULL, BBFDM_BOTH},
{"TLSKeyExchangeProtocols", &DMREAD, DMT_STRING, get_sip_tls_key_protocols, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.Capabilities.Codecs.{i}. *** */
DMLEAF tServicesVoiceServiceCapabilitiesCodecsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_cap_codec_alias, set_cap_codec_alias, NULL, NULL, BBFDM_BOTH},
{"EntryID", &DMREAD, DMT_UNINT, get_entry_id, NULL, NULL, NULL, BBFDM_BOTH},
{"Codec", &DMREAD, DMT_STRING, get_capabilities_sip_codec, NULL, NULL, NULL, BBFDM_BOTH},
{"BitRate", &DMREAD, DMT_UNINT, get_capabilities_sip_bitrate, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketizationPeriod", &DMREAD, DMT_STRING, get_capabilities_sip_pperiod, NULL, NULL, NULL, BBFDM_BOTH},
{"SilenceSuppression", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}. *** */
DMOBJ tServicesVoiceServiceVoiceProfileObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"SIP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileSIPParams, NULL, BBFDM_BOTH},
{"ServiceProviderInfo", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileServiceProviderInfoParams, NULL, BBFDM_BOTH},
{"FaxT38", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileFaxT38Params, NULL, BBFDM_BOTH},
{"RTP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileRTPObj, tServicesVoiceServiceVoiceProfileRTPParams, NULL, BBFDM_BOTH},
{"Line", &DMWRITE, add_line_object, delete_line_object, NULL, browseLineInst, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileLineObj, tServicesVoiceServiceVoiceProfileLineParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceVoiceProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_voice_profile_alias, set_voice_profile_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_STRING, get_voice_profile_enable, set_voice_profile_enable, NULL, NULL, BBFDM_BOTH},
{"Reset", &DMWRITE, DMT_BOOL, get_false_value, set_voice_profile_reset, NULL, NULL, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_voice_profile_name, set_voice_profile_name, NULL, NULL, BBFDM_BOTH},
{"SignalingProtocol", &DMWRITE, DMT_STRING, get_voice_profile_signalprotocol, set_voice_profile_signaling_protocol, NULL, NULL, BBFDM_BOTH},
{"MaxSessions", &DMREAD, DMT_UNINT, get_voice_profile_max_sessions, NULL, NULL, NULL, BBFDM_BOTH},
{"NumberOfLines", &DMREAD, DMT_UNINT, get_voice_profile_number_of_lines, NULL, NULL, NULL, BBFDM_BOTH},
{"DTMFMethod", &DMWRITE, DMT_STRING, get_voice_profile_sip_dtmfmethod, set_voice_profile_sip_dtmfmethod, NULL, NULL, BBFDM_BOTH},
{"Region", &DMWRITE, DMT_STRING, get_sip_profile_region, set_sip_profile_region, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.SIP. *** */
DMLEAF tServicesVoiceServiceVoiceProfileSIPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ProxyServer", &DMWRITE, DMT_STRING, get_voice_profile_sip_proxyserver, set_voice_profile_sip_proxyserver, NULL, NULL, BBFDM_BOTH},
//{"ProxyServerPort", &DMWRITE, DMT_UNINT, get_empty, set_sip_proxy_server_port, NULL, NULL, BBFDM_BOTH},
{"ProxyServerTransport", &DMWRITE, DMT_STRING, get_sip_proxy_server_transport, set_sip_proxy_server_transport, NULL, NULL, BBFDM_BOTH},
{"RegistrarServer", &DMWRITE, DMT_STRING, get_voice_profile_sip_registerserver, set_voice_profile_sip_registerserver, NULL, NULL, BBFDM_BOTH},
{"RegistrarServerPort", &DMWRITE, DMT_UNINT, get_voice_profile_sip_registerserverport, set_voice_profile_sip_registerserverport, NULL, NULL, BBFDM_BOTH},
{"RegistrarServerTransport", &DMWRITE, DMT_STRING, get_sip_registrar_server_transport, set_sip_registrar_server_transport, NULL, NULL, BBFDM_BOTH},
{"UserAgentDomain", &DMWRITE, DMT_STRING, get_sip_user_agent_domain, set_sip_user_agent_domain, NULL, NULL, BBFDM_BOTH},
{"UserAgentPort", &DMWRITE, DMT_UNINT, get_sip_user_agent_port, set_sip_user_agent_port, NULL, NULL, BBFDM_BOTH},
{"UserAgentTransport", &DMWRITE, DMT_STRING, get_sip_user_agent_transport, set_sip_user_agent_transport, NULL, NULL, BBFDM_BOTH},
{"OutboundProxy", &DMWRITE, DMT_STRING, get_sip_outbound_proxy, set_sip_outbound_proxy, NULL, NULL, BBFDM_BOTH},
{"OutboundProxyPort", &DMWRITE, DMT_UNINT, get_sip_outbound_proxy_port, set_sip_outbound_proxy_port, NULL, NULL, BBFDM_BOTH},
{"RegistrationPeriod", &DMWRITE, DMT_UNINT, get_sip_registration_period, set_sip_registration_period, NULL, NULL, BBFDM_BOTH},
{"ReInviteExpires", &DMWRITE, DMT_UNINT, get_sip_re_invite_expires, set_sip_re_invite_expires, NULL, NULL, BBFDM_BOTH},
{"RegisterExpires", &DMWRITE, DMT_UNINT, get_sip_re_invite_expires, set_sip_re_invite_expires, NULL, NULL, BBFDM_BOTH},
{"RegisterRetryInterval", &DMWRITE, DMT_UNINT, get_sip_re_invite_expires, set_sip_re_invite_expires, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"CallLines", &DMWRITE, DMT_STRING, get_sip_call_lines, set_sip_call_lines, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.ServiceProviderInfo. *** */
DMLEAF tServicesVoiceServiceVoiceProfileServiceProviderInfoParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Name", &DMWRITE, DMT_STRING, get_voice_service_serviceproviderinfo_name, set_voice_service_serviceproviderinfo_name, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.FaxT38. *** */
DMLEAF tServicesVoiceServiceVoiceProfileFaxT38Params[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_sip_fax_t38_enable, set_sip_fax_t38_enable, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.RTP. *** */
DMOBJ tServicesVoiceServiceVoiceProfileRTPObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"RTCP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileRTPRTCPParams, NULL, BBFDM_BOTH},
{"SRTP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileRTPSRTPParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceVoiceProfileRTPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"LocalPortMin", &DMWRITE, DMT_UNINT, get_voice_service_vp_rtp_portmin, set_voice_service_vp_rtp_portmin, NULL, NULL, BBFDM_BOTH},
{"LocalPortMax", &DMWRITE, DMT_UNINT, get_voice_service_vp_rtp_portmax, set_voice_profile_rtp_localportmax, NULL, NULL, BBFDM_BOTH},
{"DSCPMark", &DMWRITE, DMT_UNINT, get_voice_service_vp_rtp_dscp, set_voice_service_vp_rtp_dscp, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.RTP.RTCP. *** */
DMLEAF tServicesVoiceServiceVoiceProfileRTPRTCPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMREAD, DMT_BOOL, get_voice_service_vp_rtp_rtcp_enable, NULL, NULL, NULL, BBFDM_BOTH},
{"TxRepeatInterval", &DMWRITE, DMT_UNINT, get_voice_service_vp_rtp_rtcp_txrepeatinterval, set_voice_service_vp_rtp_rtcp_txrepeatinterval, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.RTP.SRTP. *** */
DMLEAF tServicesVoiceServiceVoiceProfileRTPSRTPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_voice_service_vp_rtp_srtp_enable, set_voice_service_vp_rtp_srtp_enable, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.Line.{i}. *** */
DMOBJ tServicesVoiceServiceVoiceProfileLineObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"VoiceProcessing", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileLineVoiceProcessingParams, NULL, BBFDM_BOTH},
{"CallingFeatures", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileLineCallingFeaturesParams, NULL, BBFDM_BOTH},
{"SIP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileLineSIPParams, NULL, BBFDM_BOTH},
{"Codec", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileLineCodecObj, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceVoiceProfileLineParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_line_alias, set_line_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_STRING, get_voice_profile_line_enable, set_voice_profile_line_enable, NULL, NULL, BBFDM_BOTH},
{"DirectoryNumber", &DMWRITE, DMT_STRING, get_line_directory_number, set_line_directory_number, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_voice_profile_line_status, set_line_alias, NULL, NULL, BBFDM_BOTH},
{"CallState", &DMREAD, DMT_STRING, get_voice_profile_line_callstate, set_line_alias, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"LineProfile", &DMWRITE, DMT_STRING, get_line_line_profile, set_line_line_profile, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"TELLine", &DMWRITE, DMT_STRING, get_line_tel_line, set_line_tel_line, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"ComfortNoiseEnable", &DMWRITE, DMT_BOOL, get_line_comfort_noise_enable, set_line_comfort_noise_enable, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.Line.{i}.VoiceProcessing. *** */
DMLEAF tServicesVoiceServiceVoiceProfileLineVoiceProcessingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"EchoCancellationEnable", &DMWRITE, DMT_BOOL, get_line_voice_processing_cancellation_enable, set_line_voice_processing_cancellation_enable, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.Line.{i}.CallingFeatures. *** */
DMLEAF tServicesVoiceServiceVoiceProfileLineCallingFeaturesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"CallerIDName", &DMWRITE, DMT_STRING, get_line_calling_features_caller_id_name, set_line_calling_features_caller_id_name, NULL, NULL, BBFDM_BOTH},
{"CallWaitingEnable", &DMWRITE, DMT_BOOL, get_line_calling_features_callwaiting, set_line_calling_features_callwaiting, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.Line.{i}.SIP. *** */
DMLEAF tServicesVoiceServiceVoiceProfileLineSIPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"AuthUserName", &DMWRITE, DMT_STRING, get_line_sip_auth_username, set_line_sip_auth_username, NULL, NULL, BBFDM_BOTH},
{"AuthPassword", &DMWRITE, DMT_STRING, get_empty, set_line_sip_auth_password, NULL, NULL, BBFDM_BOTH},
{"URI", &DMWRITE, DMT_STRING, get_line_sip_uri, set_line_sip_uri, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.Line.{i}.Codec. *** */
DMOBJ tServicesVoiceServiceVoiceProfileLineCodecObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"List", &DMREAD, NULL, NULL, NULL, browseLineCodecListInst, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoiceProfileLineCodecListParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoiceProfile.{i}.Line.{i}.Codec.List.{i}. *** */
DMLEAF tServicesVoiceServiceVoiceProfileLineCodecListParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_line_codec_list_alias, set_line_codec_list_alias, NULL, NULL, BBFDM_BOTH},
{"EntryID", &DMREAD, DMT_UNINT, get_codec_entry_id, NULL, NULL, NULL, BBFDM_BOTH},
{"Codec", &DMREAD, DMT_STRING, capabilities_sip_codecs_get_codec, NULL, NULL, NULL, BBFDM_BOTH},
{"BitRate", &DMREAD, DMT_UNINT, capabilities_sip_codecs_get_bitrate, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketizationPeriod", &DMWRITE, DMT_STRING, get_capabilities_sip_codecs_pperiod, set_line_codec_list_packetization, NULL, NULL, BBFDM_BOTH},
{"SilenceSuppression", &DMREAD, DMT_BOOL, get_false_value, NULL, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_line_codec_list_enable, set_line_codec_list_enable, NULL, NULL, BBFDM_BOTH},
{"Priority", &DMWRITE, DMT_UNINT, get_line_codec_list_priority, set_line_codec_list_priority, NULL, NULL, BBFDM_BOTH},
{0}
};
