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



#ifndef __bayshorecontentscan__H_
#define __bayshorecontentscan__H_

#include <iostream>
#include <sstream>
#include <fstream>
#include <list>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>

#include <yara.h>

/*
 * Notes:
 * 
 * The calling side (the one using this lib) needs to understand
 * the architecture at hand. A call to the scan_X API's requires:
 * 
 * 		1. buffer
 * 		2. buffer length
 * 		3. rule file (only used by the yara callback - can be NULL or "")
 * 		4. a std::list of struct's of type security_scan_results_t (this will get populated with results if any)
 * 		5. string (const char *) representing a parent file name
 * 		6. callback function name (type of scan to perform), options:
 * 			A. yara_cb
 * 		7. int representing type of scan, types:
 * 			A. "Generic" - index 0 (for internal use only)
 * 			B. "Yara Scan" - index 1
 * 
 */

// structs
struct security_scan_results_t {
	std::string file_scan_type;
	std::string file_scan_result;
	char file_signature_md5[33];
	std::string parent_file_name;
	std::string child_file_name;
	
	security_scan_results_t()
	{
		file_scan_type = "";
		file_scan_result = "";
		memset(file_signature_md5, 0, 33);
		parent_file_name = "";
		child_file_name = "";
	};

	bool is_empty() {
		// Ignore the hash buffer if the other results are empty
		return (!file_scan_type.size() && !file_scan_result.size());
	}
};


// cpp API - these are the main entry points
void scan_content (const uint8_t *, size_t, const char *, std::list<security_scan_results_t> *, const char *, void (*cb)(void*, std::list<security_scan_results_t> *, const char *), int);
void scan_content (const uint8_t *, size_t, YR_RULES *, std::list<security_scan_results_t> *, const char *, void (*cb)(void*, std::list<security_scan_results_t> *, const char *), int);


// by type (used by the API entry points)
void scan_office_open_xml_api(void *, std::list<security_scan_results_t> *, const char *, const char *, bool, void (*cb)(void*, std::list<security_scan_results_t> *, const char *), int);


//callbacks
void yara_cb (void *, std::list<security_scan_results_t> *, const char *child_file_name="");




#endif // __bayshorecontentscan__H_
