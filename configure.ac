#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(yextend, 1.6, support@bayshorenetworks.com)
AC_CONFIG_SRCDIR([main.cpp])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])

# Checks for programs
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET


# Checks for py libs
AC_MSG_CHECKING([checking for Python libraries used in unit tests])
# Check for Python nose library
python -c 'import nose' 2> /dev/null
if test $? != 0; then
    AC_MSG_ERROR(["Cannot run unit tests: missing Python nose library"])
fi
AC_MSG_RESULT([ok])


# Checks for libraries
AC_CHECK_LIB([archive], [archive_read_new])
AC_CHECK_LIB([crypto], [OPENSSL_init])
AC_CHECK_LIB([yara], [main])
AC_CHECK_LIB([z], [main])
AC_CHECK_LIB([pcrecpp], [main])
AC_CHECK_LIB([uuid], [main])
AC_CHECK_LIB([bz2], [main])

# Checks for header files
AC_CHECK_HEADERS([stdint.h stdlib.h string.h syslog.h unistd.h uuid.h])

# Checks for installed progs
AC_CHECK_PROG(PDFTOTEXT,[pdftotext],[pdftotext],[no])
test "$PDFTOTEXT" == "no" && AC_MSG_ERROR([Required program 'pdftotext' not found.])

# Checks for typedefs, structures, and compiler characteristics
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([getcwd memset strchr strdup strstr])

AC_SUBST([AM_CXXFLAGS], [-std=c++11])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
