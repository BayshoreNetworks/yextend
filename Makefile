#***************************************************************************
#
# YEXTEND: Help for YARA users.
# Copyright (C) 2014 by Bayshore Networks, Inc. All Rights Reserved.
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
#****************************************************************************


CCC=g++
CC=gcc

OBJS=\
	 main.o\
	 bayshore_content_scan.o\
	 wrapper.o\
	 zl.o\
	 filedissect.o\
	 filedata.o\
	 bayshore_yara_wrapper.o\

INCLUDES=-I. -I$(YARAHOME)/include
CPPFLAGS=$(INCLUDES)

EXEFILE=yextend

all:
	make exec

exec: $(OBJS)
	g++ $(OBJS) -L$(YARAHOME)/lib -o $(EXEFILE) -lz -larchive -lcrypto -lyara


clean:
	rm -f $(OBJS)
	rm -f $(EXEFILE)

test:
	LD_LIBRARY_PATH=$(YARAHOME)/lib ./$(EXEFILE) test_rulesets/bayshore.yara.testing.ruleset.bin test_files/




