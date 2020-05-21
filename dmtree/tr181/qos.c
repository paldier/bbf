/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "qos.h"
#include "os.h"

/* *** Device.QoS. *** */
DMOBJ tQoSObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Classification", &DMWRITE, os_addObjQoSClassification, os_delObjQoSClassification, NULL, os_browseQoSClassificationInst, NULL, NULL, NULL, NULL, tQoSClassificationParams, NULL, BBFDM_BOTH},
{"QueueStats", &DMWRITE, os_addObjQoSQueueStats, os_delObjQoSQueueStats, NULL, os_browseQoSQueueStatsInst, NULL, NULL, NULL, NULL, tQoSQueueStatsParams, NULL, BBFDM_BOTH},
//{"App", &DMWRITE, addObjQoSApp, delObjQoSApp, NULL, browseQoSAppInst, NULL, NULL, NULL, NULL, tQoSAppParams, NULL, BBFDM_BOTH},
//{"Flow", &DMWRITE, addObjQoSFlow, delObjQoSFlow, NULL, browseQoSFlowInst, NULL, NULL, NULL, NULL, tQoSFlowParams, NULL, BBFDM_BOTH},
//{"Policer", &DMWRITE, addObjQoSPolicer, delObjQoSPolicer, NULL, browseQoSPolicerInst, NULL, NULL, NULL, NULL, tQoSPolicerParams, NULL, BBFDM_BOTH},
{"Queue", &DMWRITE, os_addObjQoSQueue, os_delObjQoSQueue, NULL, os_browseQoSQueueInst, NULL, NULL, NULL, NULL, tQoSQueueParams, os_get_linker_qos_queue, BBFDM_BOTH},
{"Shaper", &DMWRITE, os_addObjQoSShaper, os_delObjQoSShaper, NULL, os_browseQoSShaperInst, NULL, NULL, NULL, NULL, tQoSShaperParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tQoSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ClassificationNumberOfEntries", &DMREAD, DMT_UNINT, os_get_QoS_ClassificationNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"QueueStatsNumberOfEntries", &DMREAD, DMT_UNINT, os_get_QoS_QueueStatsNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"ShaperNumberOfEntries", &DMREAD, DMT_UNINT, os_get_QoS_ShaperNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"QueueNumberOfEntries", &DMREAD, DMT_UNINT, os_get_QoS_QueueNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxClassificationEntries", &DMREAD, DMT_UNINT, get_QoS_MaxClassificationEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxAppEntries", &DMREAD, DMT_UNINT, get_QoS_MaxAppEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"AppNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_AppNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxFlowEntries", &DMREAD, DMT_UNINT, get_QoS_MaxFlowEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"FlowNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_FlowNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxPolicerEntries", &DMREAD, DMT_UNINT, get_QoS_MaxPolicerEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"PolicerNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_PolicerNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxQueueEntries", &DMREAD, DMT_UNINT, get_QoS_MaxQueueEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxShaperEntries", &DMREAD, DMT_UNINT, get_QoS_MaxShaperEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"DefaultForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoS_DefaultForwardingPolicy, set_QoS_DefaultForwardingPolicy, NULL, NULL, BBFDM_BOTH},
//{"DefaultTrafficClass", &DMWRITE, DMT_UNINT, get_QoS_DefaultTrafficClass, set_QoS_DefaultTrafficClass, NULL, NULL, BBFDM_BOTH},
//{"DefaultPolicer", &DMWRITE, DMT_STRING, get_QoS_DefaultPolicer, set_QoS_DefaultPolicer, NULL, NULL, BBFDM_BOTH},
//{"DefaultQueue", &DMWRITE, DMT_STRING, get_QoS_DefaultQueue, set_QoS_DefaultQueue, NULL, NULL, BBFDM_BOTH},
//{"DefaultDSCPMark", &DMWRITE, DMT_INT, get_QoS_DefaultDSCPMark, set_QoS_DefaultDSCPMark, NULL, NULL, BBFDM_BOTH},
//{"DefaultEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoS_DefaultEthernetPriorityMark, set_QoS_DefaultEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"DefaultInnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoS_DefaultInnerEthernetPriorityMark, set_QoS_DefaultInnerEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"AvailableAppList", &DMREAD, DMT_STRING, get_QoS_AvailableAppList, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Classification.{i}. *** */
DMLEAF tQoSClassificationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSClassification_Enable, set_QoSClassification_Enable, NULL, NULL, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSClassification_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"Order", &DMWRITE, DMT_UNINT, get_QoSClassification_Order, set_QoSClassification_Order, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, os_get_QoSClassification_Alias, os_set_QoSClassification_Alias, NULL, NULL, BBFDM_BOTH},
//{"DHCPType", &DMWRITE, DMT_STRING, get_QoSClassification_DHCPType, set_QoSClassification_DHCPType, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, os_get_QoSClassification_Interface, os_set_QoSClassification_Interface, NULL, NULL, BBFDM_BOTH},
//{"AllInterfaces", &DMWRITE, DMT_BOOL, get_QoSClassification_AllInterfaces, set_QoSClassification_AllInterfaces, NULL, NULL, BBFDM_BOTH},
{"DestIP", &DMWRITE, DMT_STRING, os_get_QoSClassification_DestIP, os_set_QoSClassification_DestIP, NULL, NULL, BBFDM_BOTH},
//{"DestMask", &DMWRITE, DMT_STRING, get_QoSClassification_DestMask, set_QoSClassification_DestMask, NULL, NULL, BBFDM_BOTH},
//{"DestIPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestIPExclude, set_QoSClassification_DestIPExclude, NULL, NULL, BBFDM_BOTH},
{"SourceIP", &DMWRITE, DMT_STRING, os_get_QoSClassification_SourceIP, os_set_QoSClassification_SourceIP, NULL, NULL, BBFDM_BOTH},
//{"SourceMask", &DMWRITE, DMT_STRING, get_QoSClassification_SourceMask, set_QoSClassification_SourceMask, NULL, NULL, BBFDM_BOTH},
//{"SourceIPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceIPExclude, set_QoSClassification_SourceIPExclude, NULL, NULL, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_INT, os_get_QoSClassification_Protocol, os_set_QoSClassification_Protocol, NULL, NULL, BBFDM_BOTH},
//{"ProtocolExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_ProtocolExclude, set_QoSClassification_ProtocolExclude, NULL, NULL, BBFDM_BOTH},
{"DestPort", &DMWRITE, DMT_INT, os_get_QoSClassification_DestPort, os_set_QoSClassification_DestPort, NULL, NULL, BBFDM_BOTH},
{"DestPortRangeMax", &DMWRITE, DMT_INT, os_get_QoSClassification_DestPortRangeMax, os_set_QoSClassification_DestPortRangeMax, NULL, NULL, BBFDM_BOTH},
//{"DestPortExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestPortExclude, set_QoSClassification_DestPortExclude, NULL, NULL, BBFDM_BOTH},
{"SourcePort", &DMWRITE, DMT_INT, os_get_QoSClassification_SourcePort, os_set_QoSClassification_SourcePort, NULL, NULL, BBFDM_BOTH},
//{"SourcePortRangeMax", &DMWRITE, DMT_INT, get_QoSClassification_SourcePortRangeMax, set_QoSClassification_SourcePortRangeMax, NULL, NULL, BBFDM_BOTH},
//{"SourcePortExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourcePortExclude, set_QoSClassification_SourcePortExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceMACAddress", &DMWRITE, DMT_STRING, get_QoSClassification_SourceMACAddress, set_QoSClassification_SourceMACAddress, NULL, NULL, BBFDM_BOTH},
//{"SourceMACMask", &DMWRITE, DMT_STRING, get_QoSClassification_SourceMACMask, set_QoSClassification_SourceMACMask, NULL, NULL, BBFDM_BOTH},
//{"SourceMACExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceMACExclude, set_QoSClassification_SourceMACExclude, NULL, NULL, BBFDM_BOTH},
//{"DestMACAddress", &DMWRITE, DMT_STRING, get_QoSClassification_DestMACAddress, set_QoSClassification_DestMACAddress, NULL, NULL, BBFDM_BOTH},
//{"DestMACMask", &DMWRITE, DMT_STRING, get_QoSClassification_DestMACMask, set_QoSClassification_DestMACMask, NULL, NULL, BBFDM_BOTH},
//{"DestMACExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestMACExclude, set_QoSClassification_DestMACExclude, NULL, NULL, BBFDM_BOTH},
//{"Ethertype", &DMWRITE, DMT_INT, get_QoSClassification_Ethertype, set_QoSClassification_Ethertype, NULL, NULL, BBFDM_BOTH},
//{"EthertypeExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthertypeExclude, set_QoSClassification_EthertypeExclude, NULL, NULL, BBFDM_BOTH},
//{"SSAP", &DMWRITE, DMT_INT, get_QoSClassification_SSAP, set_QoSClassification_SSAP, NULL, NULL, BBFDM_BOTH},
//{"SSAPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SSAPExclude, set_QoSClassification_SSAPExclude, NULL, NULL, BBFDM_BOTH},
//{"DSAP", &DMWRITE, DMT_INT, get_QoSClassification_DSAP, set_QoSClassification_DSAP, NULL, NULL, BBFDM_BOTH},
//{"DSAPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DSAPExclude, set_QoSClassification_DSAPExclude, NULL, NULL, BBFDM_BOTH},
//{"LLCControl", &DMWRITE, DMT_INT, get_QoSClassification_LLCControl, set_QoSClassification_LLCControl, NULL, NULL, BBFDM_BOTH},
//{"LLCControlExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_LLCControlExclude, set_QoSClassification_LLCControlExclude, NULL, NULL, BBFDM_BOTH},
//{"SNAPOUI", &DMWRITE, DMT_INT, get_QoSClassification_SNAPOUI, set_QoSClassification_SNAPOUI, NULL, NULL, BBFDM_BOTH},
//{"SNAPOUIExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SNAPOUIExclude, set_QoSClassification_SNAPOUIExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorClassID", &DMWRITE, DMT_STRING, get_QoSClassification_SourceVendorClassID, set_QoSClassification_SourceVendorClassID, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorClassIDv6", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceVendorClassIDv6, set_QoSClassification_SourceVendorClassIDv6, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceVendorClassIDExclude, set_QoSClassification_SourceVendorClassIDExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorClassIDMode", &DMWRITE, DMT_STRING, get_QoSClassification_SourceVendorClassIDMode, set_QoSClassification_SourceVendorClassIDMode, NULL, NULL, BBFDM_BOTH},
//{"DestVendorClassID", &DMWRITE, DMT_STRING, get_QoSClassification_DestVendorClassID, set_QoSClassification_DestVendorClassID, NULL, NULL, BBFDM_BOTH},
//{"DestVendorClassIDv6", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestVendorClassIDv6, set_QoSClassification_DestVendorClassIDv6, NULL, NULL, BBFDM_BOTH},
//{"DestVendorClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestVendorClassIDExclude, set_QoSClassification_DestVendorClassIDExclude, NULL, NULL, BBFDM_BOTH},
//{"DestVendorClassIDMode", &DMWRITE, DMT_STRING, get_QoSClassification_DestVendorClassIDMode, set_QoSClassification_DestVendorClassIDMode, NULL, NULL, BBFDM_BOTH},
//{"SourceClientID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceClientID, set_QoSClassification_SourceClientID, NULL, NULL, BBFDM_BOTH},
//{"SourceClientIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceClientIDExclude, set_QoSClassification_SourceClientIDExclude, NULL, NULL, BBFDM_BOTH},
//{"DestClientID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestClientID, set_QoSClassification_DestClientID, NULL, NULL, BBFDM_BOTH},
//{"DestClientIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestClientIDExclude, set_QoSClassification_DestClientIDExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceUserClassID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceUserClassID, set_QoSClassification_SourceUserClassID, NULL, NULL, BBFDM_BOTH},
//{"SourceUserClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceUserClassIDExclude, set_QoSClassification_SourceUserClassIDExclude, NULL, NULL, BBFDM_BOTH},
//{"DestUserClassID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestUserClassID, set_QoSClassification_DestUserClassID, NULL, NULL, BBFDM_BOTH},
//{"DestUserClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestUserClassIDExclude, set_QoSClassification_DestUserClassIDExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorSpecificInfo", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceVendorSpecificInfo, set_QoSClassification_SourceVendorSpecificInfo, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorSpecificInfoExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceVendorSpecificInfoExclude, set_QoSClassification_SourceVendorSpecificInfoExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorSpecificInfoEnterprise", &DMWRITE, DMT_UNINT, get_QoSClassification_SourceVendorSpecificInfoEnterprise, set_QoSClassification_SourceVendorSpecificInfoEnterprise, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorSpecificInfoSubOption", &DMWRITE, DMT_INT, get_QoSClassification_SourceVendorSpecificInfoSubOption, set_QoSClassification_SourceVendorSpecificInfoSubOption, NULL, NULL, BBFDM_BOTH},
//{"DestVendorSpecificInfo", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestVendorSpecificInfo, set_QoSClassification_DestVendorSpecificInfo, NULL, NULL, BBFDM_BOTH},
//{"DestVendorSpecificInfoExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestVendorSpecificInfoExclude, set_QoSClassification_DestVendorSpecificInfoExclude, NULL, NULL, BBFDM_BOTH},
//{"DestVendorSpecificInfoEnterprise", &DMWRITE, DMT_UNINT, get_QoSClassification_DestVendorSpecificInfoEnterprise, set_QoSClassification_DestVendorSpecificInfoEnterprise, NULL, NULL, BBFDM_BOTH},
//{"DestVendorSpecificInfoSubOption", &DMWRITE, DMT_INT, get_QoSClassification_DestVendorSpecificInfoSubOption, set_QoSClassification_DestVendorSpecificInfoSubOption, NULL, NULL, BBFDM_BOTH},
//{"TCPACK", &DMWRITE, DMT_BOOL, get_QoSClassification_TCPACK, set_QoSClassification_TCPACK, NULL, NULL, BBFDM_BOTH},
//{"TCPACKExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_TCPACKExclude, set_QoSClassification_TCPACKExclude, NULL, NULL, BBFDM_BOTH},
//{"IPLengthMin", &DMWRITE, DMT_UNINT, get_QoSClassification_IPLengthMin, set_QoSClassification_IPLengthMin, NULL, NULL, BBFDM_BOTH},
//{"IPLengthMax", &DMWRITE, DMT_UNINT, get_QoSClassification_IPLengthMax, set_QoSClassification_IPLengthMax, NULL, NULL, BBFDM_BOTH},
//{"IPLengthExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_IPLengthExclude, set_QoSClassification_IPLengthExclude, NULL, NULL, BBFDM_BOTH},
//{"DSCPCheck", &DMWRITE, DMT_INT, get_QoSClassification_DSCPCheck, set_QoSClassification_DSCPCheck, NULL, NULL, BBFDM_BOTH},
//{"DSCPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DSCPExclude, set_QoSClassification_DSCPExclude, NULL, NULL, BBFDM_BOTH},
//{"DSCPMark", &DMWRITE, DMT_INT, get_QoSClassification_DSCPMark, set_QoSClassification_DSCPMark, NULL, NULL, BBFDM_BOTH},
//{"EthernetPriorityCheck", &DMWRITE, DMT_INT, get_QoSClassification_EthernetPriorityCheck, set_QoSClassification_EthernetPriorityCheck, NULL, NULL, BBFDM_BOTH},
//{"EthernetPriorityExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthernetPriorityExclude, set_QoSClassification_EthernetPriorityExclude, NULL, NULL, BBFDM_BOTH},
//{"EthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSClassification_EthernetPriorityMark, set_QoSClassification_EthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"InnerEthernetPriorityCheck", &DMWRITE, DMT_INT, get_QoSClassification_InnerEthernetPriorityCheck, set_QoSClassification_InnerEthernetPriorityCheck, NULL, NULL, BBFDM_BOTH},
//{"InnerEthernetPriorityExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_InnerEthernetPriorityExclude, set_QoSClassification_InnerEthernetPriorityExclude, NULL, NULL, BBFDM_BOTH},
//{"InnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSClassification_InnerEthernetPriorityMark, set_QoSClassification_InnerEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"EthernetDEICheck", &DMWRITE, DMT_INT, get_QoSClassification_EthernetDEICheck, set_QoSClassification_EthernetDEICheck, NULL, NULL, BBFDM_BOTH},
//{"EthernetDEIExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthernetDEIExclude, set_QoSClassification_EthernetDEIExclude, NULL, NULL, BBFDM_BOTH},
//{"VLANIDCheck", &DMWRITE, DMT_INT, get_QoSClassification_VLANIDCheck, set_QoSClassification_VLANIDCheck, NULL, NULL, BBFDM_BOTH},
//{"VLANIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_VLANIDExclude, set_QoSClassification_VLANIDExclude, NULL, NULL, BBFDM_BOTH},
//{"OutOfBandInfo", &DMWRITE, DMT_INT, get_QoSClassification_OutOfBandInfo, set_QoSClassification_OutOfBandInfo, NULL, NULL, BBFDM_BOTH},
//{"ForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSClassification_ForwardingPolicy, set_QoSClassification_ForwardingPolicy, NULL, NULL, BBFDM_BOTH},
//{"TrafficClass", &DMWRITE, DMT_INT, get_QoSClassification_TrafficClass, set_QoSClassification_TrafficClass, NULL, NULL, BBFDM_BOTH},
//{"Policer", &DMWRITE, DMT_STRING, get_QoSClassification_Policer, set_QoSClassification_Policer, NULL, NULL, BBFDM_BOTH},
//{"App", &DMWRITE, DMT_STRING, get_QoSClassification_App, set_QoSClassification_App, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.App.{i}. *** */
DMLEAF tQoSAppParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSApp_Enable, set_QoSApp_Enable, NULL, NULL, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSApp_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSApp_Alias, set_QoSApp_Alias, NULL, NULL, BBFDM_BOTH},
//{"ProtocolIdentifier", &DMWRITE, DMT_STRING, get_QoSApp_ProtocolIdentifier, set_QoSApp_ProtocolIdentifier, NULL, NULL, BBFDM_BOTH},
//{"Name", &DMWRITE, DMT_STRING, get_QoSApp_Name, set_QoSApp_Name, NULL, NULL, BBFDM_BOTH},
//{"DefaultForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSApp_DefaultForwardingPolicy, set_QoSApp_DefaultForwardingPolicy, NULL, NULL, BBFDM_BOTH},
//{"DefaultTrafficClass", &DMWRITE, DMT_UNINT, get_QoSApp_DefaultTrafficClass, set_QoSApp_DefaultTrafficClass, NULL, NULL, BBFDM_BOTH},
//{"DefaultPolicer", &DMWRITE, DMT_STRING, get_QoSApp_DefaultPolicer, set_QoSApp_DefaultPolicer, NULL, NULL, BBFDM_BOTH},
//{"DefaultDSCPMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultDSCPMark, set_QoSApp_DefaultDSCPMark, NULL, NULL, BBFDM_BOTH},
//{"DefaultEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultEthernetPriorityMark, set_QoSApp_DefaultEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"DefaultInnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultInnerEthernetPriorityMark, set_QoSApp_DefaultInnerEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Flow.{i}. *** */
DMLEAF tQoSFlowParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSFlow_Enable, set_QoSFlow_Enable, NULL, NULL, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSFlow_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSFlow_Alias, set_QoSFlow_Alias, NULL, NULL, BBFDM_BOTH},
//{"Type", &DMWRITE, DMT_STRING, get_QoSFlow_Type, set_QoSFlow_Type, NULL, NULL, BBFDM_BOTH},
//{"TypeParameters", &DMWRITE, DMT_STRING, get_QoSFlow_TypeParameters, set_QoSFlow_TypeParameters, NULL, NULL, BBFDM_BOTH},
//{"Name", &DMWRITE, DMT_STRING, get_QoSFlow_Name, set_QoSFlow_Name, NULL, NULL, BBFDM_BOTH},
//{"App", &DMWRITE, DMT_STRING, get_QoSFlow_App, set_QoSFlow_App, NULL, NULL, BBFDM_BOTH},
//{"ForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSFlow_ForwardingPolicy, set_QoSFlow_ForwardingPolicy, NULL, NULL, BBFDM_BOTH},
//{"TrafficClass", &DMWRITE, DMT_UNINT, get_QoSFlow_TrafficClass, set_QoSFlow_TrafficClass, NULL, NULL, BBFDM_BOTH},
//{"Policer", &DMWRITE, DMT_STRING, get_QoSFlow_Policer, set_QoSFlow_Policer, NULL, NULL, BBFDM_BOTH},
//{"DSCPMark", &DMWRITE, DMT_INT, get_QoSFlow_DSCPMark, set_QoSFlow_DSCPMark, NULL, NULL, BBFDM_BOTH},
//{"EthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSFlow_EthernetPriorityMark, set_QoSFlow_EthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"InnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSFlow_InnerEthernetPriorityMark, set_QoSFlow_InnerEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Policer.{i}. *** */
DMLEAF tQoSPolicerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSPolicer_Enable, set_QoSPolicer_Enable, NULL, NULL, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSPolicer_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSPolicer_Alias, set_QoSPolicer_Alias, NULL, NULL, BBFDM_BOTH},
//{"CommittedRate", &DMWRITE, DMT_UNINT, get_QoSPolicer_CommittedRate, set_QoSPolicer_CommittedRate, NULL, NULL, BBFDM_BOTH},
//{"CommittedBurstSize", &DMWRITE, DMT_UNINT, get_QoSPolicer_CommittedBurstSize, set_QoSPolicer_CommittedBurstSize, NULL, NULL, BBFDM_BOTH},
//{"ExcessBurstSize", &DMWRITE, DMT_UNINT, get_QoSPolicer_ExcessBurstSize, set_QoSPolicer_ExcessBurstSize, NULL, NULL, BBFDM_BOTH},
//{"PeakRate", &DMWRITE, DMT_UNINT, get_QoSPolicer_PeakRate, set_QoSPolicer_PeakRate, NULL, NULL, BBFDM_BOTH},
//{"PeakBurstSize", &DMWRITE, DMT_UNINT, get_QoSPolicer_PeakBurstSize, set_QoSPolicer_PeakBurstSize, NULL, NULL, BBFDM_BOTH},
//{"MeterType", &DMWRITE, DMT_STRING, get_QoSPolicer_MeterType, set_QoSPolicer_MeterType, NULL, NULL, BBFDM_BOTH},
//{"PossibleMeterTypes", &DMREAD, DMT_STRING, get_QoSPolicer_PossibleMeterTypes, NULL, NULL, NULL, BBFDM_BOTH},
//{"ConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_ConformingAction, set_QoSPolicer_ConformingAction, NULL, NULL, BBFDM_BOTH},
//{"PartialConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_PartialConformingAction, set_QoSPolicer_PartialConformingAction, NULL, NULL, BBFDM_BOTH},
//{"NonConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_NonConformingAction, set_QoSPolicer_NonConformingAction, NULL, NULL, BBFDM_BOTH},
//{"TotalCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_TotalCountedPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"TotalCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_TotalCountedBytes, NULL, NULL, NULL, BBFDM_BOTH},
//{"ConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_ConformingCountedPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"ConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_ConformingCountedBytes, NULL, NULL, NULL, BBFDM_BOTH},
//{"PartiallyConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_PartiallyConformingCountedPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"PartiallyConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_PartiallyConformingCountedBytes, NULL, NULL, NULL, BBFDM_BOTH},
//{"NonConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_NonConformingCountedPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"NonConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_NonConformingCountedBytes, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Queue.{i}. *** */
DMLEAF tQoSQueueParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, os_get_QoSQueue_Enable, os_set_QoSQueue_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, os_get_QoSQueue_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, os_get_QoSQueue_Alias, os_set_QoSQueue_Alias, NULL, NULL, BBFDM_BOTH},
{"TrafficClasses", &DMWRITE, DMT_STRING, os_get_QoSQueue_TrafficClasses, os_set_QoSQueue_TrafficClasses, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, os_get_QoSQueue_Interface, os_set_QoSQueue_Interface, NULL, NULL, BBFDM_BOTH},
//{"AllInterfaces", &DMWRITE, DMT_BOOL, os_get_QoSQueue_AllInterfaces, os_set_QoSQueue_AllInterfaces, NULL, NULL, BBFDM_BOTH},
//{"HardwareAssisted", &DMREAD, DMT_BOOL, os_get_QoSQueue_HardwareAssisted, NULL, NULL, NULL, BBFDM_BOTH},
//{"BufferLength", &DMREAD, DMT_UNINT, os_get_QoSQueue_BufferLength, NULL, NULL, NULL, BBFDM_BOTH},
{"Weight", &DMWRITE, DMT_UNINT, os_get_QoSQueue_Weight, os_set_QoSQueue_Weight, NULL, NULL, BBFDM_BOTH},
{"Precedence", &DMWRITE, DMT_UNINT, os_get_QoSQueue_Precedence, os_set_QoSQueue_Precedence, NULL, NULL, BBFDM_BOTH},
//{"REDThreshold", &DMWRITE, DMT_UNINT, os_get_QoSQueue_REDThreshold, os_set_QoSQueue_REDThreshold, NULL, NULL, BBFDM_BOTH},
//{"REDPercentage", &DMWRITE, DMT_UNINT, os_get_QoSQueue_REDPercentage, os_set_QoSQueue_REDPercentage, NULL, NULL, BBFDM_BOTH},
//{"DropAlgorithm", &DMWRITE, DMT_STRING, os_get_QoSQueue_DropAlgorithm, os_set_QoSQueue_DropAlgorithm, NULL, NULL, BBFDM_BOTH},
{"SchedulerAlgorithm", &DMWRITE, DMT_STRING, os_get_QoSQueue_SchedulerAlgorithm, os_set_QoSQueue_SchedulerAlgorithm, NULL, NULL, BBFDM_BOTH},
{"ShapingRate", &DMWRITE, DMT_INT, os_get_QoSQueue_ShapingRate, os_set_QoSQueue_ShapingRate, NULL, NULL, BBFDM_BOTH},
{"ShapingBurstSize", &DMWRITE, DMT_UNINT, os_get_QoSQueue_ShapingBurstSize, os_set_QoSQueue_ShapingBurstSize, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.QueueStats.{i}. *** */
DMLEAF tQoSQueueStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSQueueStats_Enable, set_QoSQueueStats_Enable, NULL, NULL, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSQueueStats_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, os_get_QoSQueueStats_Alias, os_set_QoSQueueStats_Alias, NULL, NULL, BBFDM_BOTH},
//{"Queue", &DMWRITE, DMT_STRING, get_QoSQueueStats_Queue, set_QoSQueueStats_Queue, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, os_get_QoSQueueStats_Interface, os_set_QoSQueueStats_Interface, NULL, NULL, BBFDM_BOTH},
{"OutputPackets", &DMREAD, DMT_UNINT, os_get_QoSQueueStats_OutputPackets, NULL, NULL, NULL, BBFDM_BOTH},
{"OutputBytes", &DMREAD, DMT_UNINT, os_get_QoSQueueStats_OutputBytes, NULL, NULL, NULL, BBFDM_BOTH},
{"DroppedPackets", &DMREAD, DMT_UNINT, os_get_QoSQueueStats_DroppedPackets, NULL, NULL, NULL, BBFDM_BOTH},
{"DroppedBytes", &DMREAD, DMT_UNINT, os_get_QoSQueueStats_DroppedBytes, NULL, NULL, NULL, BBFDM_BOTH},
{"QueueOccupancyPackets", &DMREAD, DMT_UNINT, os_get_QoSQueueStats_QueueOccupancyPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"QueueOccupancyPercentage", &DMREAD, DMT_UNINT, get_QoSQueueStats_QueueOccupancyPercentage, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Shaper.{i}. *** */
DMLEAF tQoSShaperParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, os_get_QoSShaper_Enable, os_set_QoSShaper_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, os_get_QoSShaper_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, os_get_QoSShaper_Alias, os_set_QoSShaper_Alias, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, os_get_QoSShaper_Interface, os_set_QoSShaper_Interface, NULL, NULL, BBFDM_BOTH},
{"ShapingRate", &DMWRITE, DMT_INT, os_get_QoSShaper_ShapingRate, os_set_QoSShaper_ShapingRate, NULL, NULL, BBFDM_BOTH},
{"ShapingBurstSize", &DMWRITE, DMT_UNINT, os_get_QoSShaper_ShapingBurstSize, os_set_QoSShaper_ShapingBurstSize, NULL, NULL, BBFDM_BOTH},
{0}
};
