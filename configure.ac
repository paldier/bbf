AC_INIT([libbbfdm], [0.1], [mohamed.kallel@pivasoftware.com])
AM_INIT_AUTOMAKE

AM_INIT_AUTOMAKE([subdir-objects])

AC_ARG_ENABLE(tr181, [AS_HELP_STRING([--enable-tr181], [enable tr181 device feature])], AC_DEFINE(BBF_TR181),)
AM_CONDITIONAL([BBF_TR181],[test "x$enable_tr181" = "xyes"])

AC_ARG_ENABLE(tr104, [AS_HELP_STRING([--enable-tr104], [enable tr104 voice feature])], AC_DEFINE(BBF_TR104),)
AM_CONDITIONAL([BBF_TR104],[test "x$enable_tr104" = "xyes"])

AC_ARG_ENABLE(tr143, [AS_HELP_STRING([--enable-tr143], [enable tr143 diagnostics feature])], AC_DEFINE(BBF_TR143),)
AM_CONDITIONAL([BBF_TR143],[test "x$enable_tr143" = "xyes"])

AC_ARG_ENABLE(tr157, [AS_HELP_STRING([--enable-tr157], [enable tr157 bulkdata collector feature])], AC_DEFINE(BBF_TR157),)
AM_CONDITIONAL([BBF_TR157],[test "x$enable_tr157" = "xyes"])

AC_ARG_ENABLE(tr064, [AS_HELP_STRING([--enable-tr064], [enable tr064 upnp feature])], AC_DEFINE(BBF_TR064),)
AM_CONDITIONAL([BBF_TR064],[test "x$enable_tr064" = "xyes"])

AC_ARG_ENABLE(libopenssl, [AS_HELP_STRING([--enable-libopenssl], [enable libopenssl feature])], AC_DEFINE(LOPENSSL),)
AM_CONDITIONAL([LOPENSSL],[test "x$enable_libopenssl" = "xyes"])

AC_ARG_ENABLE(libmbedtls, [AS_HELP_STRING([--enable-libmbedtls], [enable libmbedtls upnp feature])], AC_DEFINE(LMBEDTLS),)
AM_CONDITIONAL([LMBEDTLS],[test "x$enable_libmbedtls" = "xyes"])

AC_ARG_ENABLE(generic_openwrt, [AS_HELP_STRING([--enable-generic-openwrt], [enable generic openwrt support])], AC_DEFINE(GENERIC_OPENWRT),)
AM_CONDITIONAL([GENERIC_OPENWRT],[test "x$enable_generic_openwrt" = "xyes"])

# checks for programs
AC_PROG_CC
AM_PROG_CC_C_O
LT_INIT
AC_ENABLE_SHARED

LIBJSON_LIBS='-ljson-c'
AC_SUBST([LIBJSON_LIBS])

AC_ARG_WITH([uci-include-path],
  [AS_HELP_STRING([--with-uci-include-path],
    [location of the uci library headers])],
  [LIBUCI_CFLAGS="-I$withval"])
AC_SUBST([LIBUCI_CFLAGS])

AC_ARG_WITH([uci-lib-path],
  [AS_HELP_STRING([--with-uci-lib-path], [location of the uci library])], [LIBUCI_LDFLAGS="-L$withval"])
AC_SUBST([LIBUCI_LDFLAGS])

LIBUCI_LIBS='-luci'
AC_SUBST([LIBUCI_LIBS])

LIBTRACE_LIBS='-ltrace'
AC_SUBST([LIBTRACE_LIBS])

AC_ARG_WITH([libubox-include-path],
  [AS_HELP_STRING([--with-libubox-include-path],
    [location of the libubox library headers])],
  [LIBUBOX_CFLAGS="-I$withval"])
AC_SUBST([LIBUBOX_CFLAGS])

AC_ARG_WITH([libubox-lib-path],
  [AS_HELP_STRING([--with-libubox-lib-path], [location of the libubox library])], [LIBUBOX_LDFLAGS="-L$withval"])
AC_SUBST([LIBUBOX_LDFLAGS])

LIBUBOX_LIBS='-lubox'
AC_SUBST([LIBUBOX_LIBS])

AC_ARG_WITH([libubus-include-path],
  [AS_HELP_STRING([--with-libubus-include-path],
    [location of the libubus library headers])],
  [LIBUBUS_CFLAGS="-I$withval"])
AC_SUBST([LIBUBUS_CFLAGS])

AC_ARG_WITH([libubus-lib-path],
  [AS_HELP_STRING([--with-libubus-lib-path], [location of the libubus library])], [LIBUBOX_LDFLAGS="-L$withval"])
AC_SUBST([LIBUBUS_LDFLAGS])

LIBUBUS_LIBS='-lubus'
AC_SUBST([LIBUBUS_LIBS])

LBLOBMSG_LIBS='-lblobmsg_json'
AC_SUBST([LBLOBMSG_LIBS])

LIBDLOPEN_LIBS='-ldl'
AC_SUBST([LIBDLOPEN_LIBS])

AM_COND_IF([LOPENSSL], [
	LIBOPENSSL_LIBS='-lssl'
	AC_SUBST([LIBOPENSSL_LIBS])
])

AM_COND_IF([LMBEDTLS], [
	LIBMBETLS_LIBS='-lmbedtls'
	AC_SUBST([LIBMBETLS_LIBS])
])

# checks for header files
AC_CHECK_HEADERS([stdlib.h string.h])

# checks for typedefs, structures, and compiler characteristics
AC_TYPE_UINT8_T

# Makefiles
AC_CONFIG_FILES([
Makefile
bin/Makefile
])

AC_OUTPUT
