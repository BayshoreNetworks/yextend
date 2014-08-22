/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * Copyright (C) 2014 by Bayshore Networks, Inc. All Rights Reserved.
 *
 * This file is part of yextend.
 *
 * yextend is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * yextend is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with yextend.  If not, see <http://www.gnu.org/licenses/>.
 *
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
    snprintf (buf, sizeof(buf), s.c_str());

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




