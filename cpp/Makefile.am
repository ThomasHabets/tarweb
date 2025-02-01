AUTOMAKE_OPTIONS=foreign
DISTCLEANFILES=*~
AM_CPPFLAGS=-I$(builddir)

bin_PROGRAMS=\
tarweb

TESTS=\
tarweb_test
check_PROGRAMS=$(TESTS)

tarweb_SOURCES=\
src/main.cc \
src/tls.cc \
src/handshaker.cc \
src/tarweb.cc

tarweb_test_SOURCES=\
src/tarweb_test.cc \
src/tarweb.cc
