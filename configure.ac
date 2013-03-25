#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([LINUX-EOIP],[0.4],[Denys Fedoryshchenko <denys@visp.net.lb>])
AC_CANONICAL_SYSTEM
AC_CONFIG_SRCDIR([minIni.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])


#CFLAGS=-O3
# Checks for programs.
AM_INIT_AUTOMAKE([1.10 no-define])
AC_PROG_CC
AM_PROG_CC_C_O
LT_INIT

# Checks for libraries.
#AC_CHECK_LIB(pthread, pthread_create)
#AC_CHECK_LIB(pthread, pthread_create, [LIBS="$LIBS -lpthread"])
AC_SEARCH_LIBS([pthread_create], [pthread])
AC_CHECK_LIB(lzo2, lzo1x_decompress)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h])
AC_CHECK_HEADERS(pthread.h,, [AC_MSG_ERROR([pthread.h required])])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
#AC_FUNC_MALLOC
AC_CHECK_FUNCS([memmove memset select socket malloc pthread_create])
LDFLAGS="-pthread -ldl $LDFLAGS"
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
