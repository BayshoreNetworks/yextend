#****************************************************************************
#
# YEXTEND: Help for YARA users.
# Copyright (C) 2014-2015 by Bayshore Networks, Inc. All Rights Reserved.
#
# This file is part of yextend.
#
# yextend is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# yextend is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with yextend.  If not, see <http://www.gnu.org/licenses/>.
#
#****************************************************************************/



AUTOMAKE_OPTIONS = foreign

CPPFLAGS=-I.
include_HEADERS = /usr/local/include bayshore_yara_wrapper.h filedissect.h wrapper.h bayshore_content_scan.h filedata.h zl.h
lib_YARA = /usr/local/lib

bin_PROGRAMS = yextend
yextend_SOURCES = filedissect.cpp wrapper.cpp bayshore_content_scan.cpp filedata.cpp main.cpp zl.cpp bayshore_yara_wrapper.c
#yextend_LDADD = -lz -larchive -lcrypto -lyara



