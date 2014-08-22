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


#ifndef __ContentInspection__H_
#define __ContentInspection__H_

#include <stdint.h>
#include <stdio.h>

#include <string>

extern "C" {
	// Pass in a data buffer and size. Returns the content type.
	int get_content_type (const uint8_t*, size_t);

	/* Pass in a content type, and receive a text description of the type.
	 * DO NOT free the memory you get back.
	 */
	const char *get_content_type_string (int);

	bool is_type_officex (int);
    bool is_type_pcap(int);
    bool is_type_unclassified(int);
    bool is_type_tar(int);
    bool is_type_xml(int);
    bool is_type_open_document_format(int);
    bool is_type_php(int);
    bool is_type_rar(int);
    bool is_type_win_exe(int);
    bool is_type_html(int);
    bool is_type_gzip(int);
    bool is_type_pdf(int);
    bool is_type_office(int);
    bool is_type_image(int);
    bool is_type_archive(int);
}

#endif // __ContentInspection__H_
