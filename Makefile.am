AUTOMAKE_OPTIONS = foreign

CPPFLAGS=-I.
include_HEADERS = /usr/local/include bayshore_yara_wrapper.h filedissect.h wrapper.h bayshore_content_scan.h filedata.h zl.h
lib_YARA = /usr/local/lib

bin_PROGRAMS = ywrapper
ywrapper_SOURCES = filedissect.cpp wrapper.cpp bayshore_content_scan.cpp filedata.cpp main.cpp zl.cpp bayshore_yara_wrapper.c
#ywrapper_LDADD = -lz -larchive -lcrypto -lyara



