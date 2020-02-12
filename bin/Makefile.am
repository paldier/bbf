LIB_BBFDM_VERSION = 3:0:0

lib_LTLIBRARIES = libbbf_api.la

libbbf_api_la_SOURCES =				\
	../libbbf_api/dmbbf.c			\
	../libbbf_api/dmubus.c			\
	../libbbf_api/dmjson.c			\
	../libbbf_api/dmuci.c			\
	../libbbf_api/dmcommon.c 		\
	../libbbf_api/dmmem.c

libbbf_api_la_CFLAGS =		\
	$(AM_CFLAGS)			\
	$(LIBUCI_CFLAGS)		\
	$(LIBUBOX_CFLAGS)		\
	$(LIBUBUS_CFLAGS)

libbbf_api_la_LDFLAGS = 	\
	$(AM_LDFLAGS)			\
	$(LIBUCI_LDFLAGS)		\
	$(LIBUBOX_LDFLAGS)		\
	$(LIBUBUS_LDFLAGS)

libbbf_api_la_LIBADD =		\
	$(AM_LIBS)				\
	$(LIBUCI_LIBS)			\
	$(LIBUBOX_LIBS)			\
	$(LIBUBUS_LIBS)			\
	$(LIBJSON_LIBS)			\
	$(LBLOBMSG_LIBS)


lib_LTLIBRARIES += libbbfdm.la

libbbfdm_la_SOURCES =	\
	../dmentry.c 		\
	../dmentrylibrary.c \
	../dmentryjson.c 	\
	../dmmemjson.c 		\
	../dmoperate.c		\
	../dmdiagnostics.c	\
	../dmbbfcommon.c	\
	../md5.c 			\
	../wepkey.c

if BBF_TR181
libbbfdm_la_SOURCES +=							\
	../dmtree/tr181/device.c					\
	../dmtree/tr181/deviceinfo.c				\
	../dmtree/tr181/managementserver.c			\
	../dmtree/tr181/times.c						\
	../dmtree/tr181/upnp.c						\
	../dmtree/tr181/x_iopsys_eu_ice.c 			\
	../dmtree/tr181/x_iopsys_eu_igmp.c 			\
	../dmtree/tr181/x_iopsys_eu_ipacccfg.c		\
	../dmtree/tr181/x_iopsys_eu_logincfg.c		\
	../dmtree/tr181/x_iopsys_eu_power_mgmt.c	\
	../dmtree/tr181/x_iopsys_eu_syslog.c		\
	../dmtree/tr181/x_iopsys_eu_dropbear.c		\
	../dmtree/tr181/x_iopsys_eu_owsd.c			\
	../dmtree/tr181/x_iopsys_eu_buttons.c		\
	../dmtree/tr181/x_iopsys_eu_wifilife.c		\
	../dmtree/tr181/xmpp.c 						\
	../dmtree/tr181/wifi.c						\
	../dmtree/tr181/ethernet.c					\
	../dmtree/tr181/atm.c						\
	../dmtree/tr181/ptm.c						\
	../dmtree/tr181/bridging.c					\
	../dmtree/tr181/hosts.c						\
	../dmtree/tr181/dhcpv4.c					\
	../dmtree/tr181/ip.c						\
	../dmtree/tr181/ppp.c						\
	../dmtree/tr181/nat.c						\
	../dmtree/tr181/routing.c					\
	../dmtree/tr181/userinterface.c				\
	../dmtree/tr181/firewall.c					\
	../dmtree/tr181/dns.c						\
	../dmtree/tr181/users.c						\
	../dmtree/tr181/dhcpv6.c					\
	../dmtree/tr181/dsl.c						\
	../dmtree/tr181/interfacestack.c			\
	../dmtree/tr181/qos.c						\
	../dmtree/tr181/usb.c 						\
	../dmtree/tr181/datamodelversion.c			\
	../dmtree/tr181/gre.c 						\
	../dmtree/tr181/dynamicdns.c
endif

if BBF_TR104
libbbfdm_la_SOURCES +=							\
	../dmtree/tr104/voice_services.c
endif

if BBF_TR143
libbbfdm_la_SOURCES +=							\
	../dmtree/tr143/diagnostics.c
endif

if BBF_TR157
libbbfdm_la_SOURCES +=							\
	../dmtree/tr157/bulkdata.c 					\
	../dmtree/tr157/softwaremodules.c
endif

if BBF_TR064
libbbfdm_la_SOURCES +=							\
	../dmtree/tr064/upnp_device.c 				\
	../dmtree/tr064/upnp_deviceinfo.c	        \
	../dmtree/tr064/upnp_configuration.c		\
	../dmtree/tr064/upnp_monitoring.c			\
	../dmtree/tr064/upnp_common.c
endif

libbbfdm_la_CFLAGS =		\
	$(AM_CFLAGS)			\
	$(LIBUCI_CFLAGS)		\
	$(LIBUBOX_CFLAGS)		\
	$(LIBUBUS_CFLAGS)

libbbfdm_la_LDFLAGS = 		\
	$(AM_LDFLAGS)			\
	$(LIBUCI_LDFLAGS)		\
	$(LIBUBOX_LDFLAGS)		\
	$(LIBUBUS_LDFLAGS)		\
	-share					\
	-version-info $(LIB_BBFDM_VERSION)

libbbfdm_la_LIBADD =		\
	$(AM_LIBS)				\
	$(LIBUCI_LIBS)			\
	$(LIBUBOX_LIBS)			\
	$(LIBUBUS_LIBS)			\
	$(LIBJSON_LIBS)			\
	$(LIBTRACE_LIBS)		\
	$(LBLOBMSG_LIBS) 		\
	-lbbf_api

libbbfdm_la_CFLAGS+=-I../
libbbfdm_la_CFLAGS+=-I../dmtree/tr181
libbbfdm_la_CFLAGS+=-I../dmtree/tr104
libbbfdm_la_CFLAGS+=-I../dmtree/tr143
libbbfdm_la_CFLAGS+=-I../dmtree/tr157
libbbfdm_la_CFLAGS+=-I../dmtree/tr064
