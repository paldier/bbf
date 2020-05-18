#include "lanconfigsecurity.h"

static int get_LANConfigSecurity_ConfigPassword(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

static int set_LANConfigSecurity_ConfigPassword(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value("users", "user", "password", value);
		break;
	}
	return 0;
}

DMLEAF tLANConfigSecurityParams[] = {
{"ConfigPassword", &DMWRITE, DMT_STRING, get_LANConfigSecurity_ConfigPassword, set_LANConfigSecurity_ConfigPassword, NULL, NULL, BBFDM_BOTH},
{0}
};
