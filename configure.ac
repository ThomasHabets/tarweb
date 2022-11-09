# -*- Autoconf -*-
AC_PREREQ([2.69])
AC_INIT([tarweb],[0.0.1],[thomas@habets.se])
AC_CONFIG_SRCDIR([src/tarweb.cc])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE
AC_CONFIG_HEADERS([src/config.h])
AC_LANG(C++)

# Check for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET
PKG_PROG_PKG_CONFIG

# Check for libraries.
PKG_CHECK_MODULES(OPENSSL, openssl >= 3.0.0)
LIBS="$LIBS $OPENSSL_LIBS"
CXXFLAGS="$CXXFLAGS $OPENSSL_CXXFLAGS $OPENSSL_CFLAGS"

# Check for header files.
AC_CHECK_HEADERS([\
sys/random.h \
])

MYSTD="c++20"
if test ! "x$STD" = "x"; then
   MYSTD="$STD"
fi
CXXFLAGS="$CXXFLAGS -std=$MYSTD -g -Wall -Wextra -Wconversion -pedantic"

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

# Status
echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C++ Compiler...: $CXX $CXXFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
