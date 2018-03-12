/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * This file is part of yextend.
 *
 * Copyright (c) 2014-2018, Bayshore Networks, Inc.
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

#include "libs/bayshore_file_type_detect.h"
#include <wrapper.h>

#include <sys/stat.h>

/*
 * The following functions implement the high-level API to our content-inspection facilities.
 * High-level applications will want to call these entry points rather than the underlying
 * C++ objects.
 *
 */

/****************
get_content_type
****************/

int get_content_type (const uint8_t *data, size_t sz)
{
	return get_buffer_type (data, std::min(sz,(size_t)100000));
}


/***********************
get_content_type_string
***********************/

char *get_content_type_string (int ft)
{
    char buf[2048];
    get_buffer_type_str(ft, (uint8_t *)buf);

    static char buf2 [2048];
    snprintf (buf2, sizeof(buf2), "%s", buf);

    return buf2;
}


/********************
get_file_object_type
********************/


int get_file_object_type(const uint8_t *file_name)
{
    return get_file_type(file_name);
}


/**************
is_type_matlab
**************/

bool is_type_matlab (int ix)
{
	return is_matlab (ix);
}

/************
is_type_7zip
************/

bool is_type_7zip (int ix)
{
	return is_7zip (ix);
}

/***************
is_type_archive
***************/

bool is_type_archive (int ix)
{
	return is_archive (ix);
}

/***************
is_type_officex
***************/

bool is_type_officex (int ix)
{
	return is_officex (ix);
}

/************
is_type_pcap
************/

bool is_type_pcap (int ix)
{
	return is_pcap (ix);
}

/********************
is_type_unclassified
********************/

bool is_type_unclassified (int ix)
{
	return is_unclassified (ix);
}

/***********
is_type_tar
***********/

bool is_type_tar (int ix)
{
	return is_tar (ix);
}

/***********
is_type_xml
***********/

bool is_type_xml (int ix)
{
	return is_xml (ix);
}

/****************************
is_type_open_document_format
****************************/

bool is_type_open_document_format (int ix)
{
	return is_open_document_format (ix);
}

/***********
is_type_php
***********/

bool is_type_php (int ix)
{
	return is_php (ix);
}

/***********
is_type_rar
***********/

bool is_type_rar (int ix)
{
	return is_rar (ix);
}

/***************
is_type_win_exe
***************/

bool is_type_win_exe (int ix)
{
	return is_win_exe (ix);
}

/*****************
is_type_executable
*****************/

bool is_type_executable (int ix)
{
	return is_executable (ix);
}

/************
is_type_html
************/

bool is_type_html (int ix)
{
	return is_html (ix);
}

/************
is_type_gzip
************/

bool is_type_gzip (int ix)
{
	return is_gzip (ix);
}

/***********
is_type_pdf
***********/

bool is_type_pdf (int ix)
{
	return is_pdf (ix);
}

/**************
is_type_office
**************/

bool is_type_office (int ix)
{
	return is_office (ix);
}

/*************
is_type_image
*************/

bool is_type_image (int ix)
{
	return is_image (ix);
}

/*************
is_type_bzip2
*************/

bool is_type_bzip2 (int ix)
{
	return is_bzip2 (ix);
}
