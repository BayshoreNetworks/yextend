#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(yextend, 1.5, support@bayshorenetworks.com)
AC_CONFIG_SRCDIR([main.cpp])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB([archive], [archive_read_new])
AC_CHECK_LIB([crypto], [OPENSSL_init])
AC_CHECK_LIB([yara], [main])
AC_CHECK_LIB([z], [main])
AC_CHECK_LIB([pcrecpp], [main])
AC_CHECK_LIB([uuid], [main])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h syslog.h unistd.h uuid.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([getcwd memset strchr strdup strstr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
