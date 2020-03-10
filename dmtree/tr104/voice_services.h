/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *		Author: Mohamed Kallel <mohamed.kallel@pivasoftware.com>
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 */

#ifndef __VOICE_H
#define __VOICE_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tServicesObj[];
extern DMOBJ tServicesVoiceServiceObj[];
extern DMLEAF tServicesVoiceServiceParams[];
extern DMLEAF tServicesVoiceServiceCapabilitiesParams[];
extern DMOBJ tServicesVoiceServiceCapabilitiesObj[];
extern DMLEAF tServicesVoiceServiceCapabilitiesSIPParams[];
extern DMLEAF tServicesVoiceServiceCapabilitiesCodecsParams[] ;
extern DMOBJ tServicesVoiceServiceVoiceProfileObj[] ;
extern DMLEAF tServicesVoiceServiceVoiceProfileSIPParams[];
extern DMLEAF tServicesVoiceServiceVoiceProfileServiceProviderInfoParams[];
extern DMLEAF tServicesVoiceServiceVoiceProfileParams[];
extern DMOBJ tServicesVoiceServiceVoiceProfileLineObj[];
extern DMOBJ tServicesVoiceServiceVoiceProfileLineCodecObj[];
extern DMLEAF tServicesVoiceServiceVoiceProfileLineCodecListParams[];
extern DMLEAF tServicesVoiceServiceVoiceProfileLineSIPParams[];
extern DMLEAF tServicesVoiceServiceVoiceProfileLineVoiceProcessingParams[];
extern DMLEAF tServicesVoiceServiceVoiceProfileLineCallingFeaturesParams[];
extern DMLEAF tServicesVoiceServiceVoiceProfileLineParams[];
extern DMLEAF tServicesVoiceServiceVoiceProfileRTPParams[];
extern DMOBJ tServicesVoiceServiceVoiceProfileRTPObj[];
extern DMLEAF tServicesVoiceServiceVoiceProfileRTPSRTPParams[];
extern DMLEAF tServicesVoiceServiceVoiceProfileRTPRTCPParams[];
extern DMLEAF tServicesVoiceServiceVoiceProfileFaxT38Params[];

#endif
