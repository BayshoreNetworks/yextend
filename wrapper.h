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
