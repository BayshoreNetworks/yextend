/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * Copyright (C) 2014-2016 by Bayshore Networks, Inc. All Rights Reserved.
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
