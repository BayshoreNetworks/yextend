/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * This file is part of yextend.
 *
 * Copyright (c) 2104-2016, Bayshore Networks, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that
 * the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
 * following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *****************************************************************************/


#include <iostream>
#include <algorithm>
using namespace std;

#include <filedissect.h>
#include <wrapper.h>

#include <sys/stat.h>

/* 
 * The following functions implement the high-level API to our content-inspection facilities.
 * High-level applications will want to call these entry points rather than the underlying
 * C++ objects.
 *    
 */

/****************
 * get_content_type
 * ****************/

int get_content_type (const uint8_t *data, size_t sz)
{
	FileDissect fd;
	return fd.GetBufferType (data, std::min(sz,(size_t)100000));
}


/***********************
 * get_content_type_string
 * ***********************/

const char *get_content_type_string (int ft)
{
	FileDissect fd;
	string s = fd.GetFileTypeStr (ft);

	/*
	 * WARNING, this is not thread-safe.
	 * This needs refactoring because the underlying
	 * function in FileDissect returns a std::string
	 * instead of a static const char* as it probably
	 * should
	 */
    static char buf [2048];
    snprintf (buf, sizeof(buf), "%s", s.c_str());

    return buf;
}


/***************
is_type_archive
***************/

bool is_type_archive (int ix)
{
	FileDissect fd;
	return fd.is_archive (ix);
}

/***************
is_type_officex
***************/

bool is_type_officex (int ix)
{
	FileDissect fd;
	return fd.is_officex (ix);
}

/************
is_type_pcap
************/

bool is_type_pcap (int ix)
{
	FileDissect fd;
	return fd.is_pcap (ix);
}

/********************
is_type_unclassified
********************/

bool is_type_unclassified (int ix)
{
	FileDissect fd;
	return fd.is_unclassified (ix);
}

/***********
is_type_tar
***********/

bool is_type_tar (int ix)
{
	FileDissect fd;
	return fd.is_tar (ix);
}

/***********
is_type_xml
***********/

bool is_type_xml (int ix)
{
	FileDissect fd;
	return fd.is_xml (ix);
}

/****************************
is_type_open_document_format
****************************/

bool is_type_open_document_format (int ix)
{
	FileDissect fd;
	return fd.is_open_document_format (ix);
}

/***********
is_type_php
***********/

bool is_type_php (int ix)
{
	FileDissect fd;
	return fd.is_php (ix);
}

/***********
is_type_rar
***********/

bool is_type_rar (int ix)
{
	FileDissect fd;
	return fd.is_rar (ix);
}

/***************
is_type_win_exe
***************/

bool is_type_win_exe (int ix)
{
	FileDissect fd;
	return fd.is_win_exe (ix);
}

/************
is_type_html
************/

bool is_type_html (int ix)
{
	FileDissect fd;
	return fd.is_html (ix);
}

/************
is_type_gzip
************/

bool is_type_gzip (int ix)
{
	FileDissect fd;
	return fd.is_gzip (ix);
}

/***********
is_type_pdf
***********/

bool is_type_pdf (int ix)
{
	FileDissect fd;
	return fd.is_pdf (ix);
}

/**************
is_type_office
**************/

bool is_type_office (int ix)
{
	FileDissect fd;
	return fd.is_office (ix);
}

/*************
is_type_image
*************/

bool is_type_image (int ix)
{
	FileDissect fd;
	return fd.is_image (ix);
}




