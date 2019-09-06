#include "datamodelversion.h"

int get_Device_RootDataModelVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= "2.12";
	return 0;
}
