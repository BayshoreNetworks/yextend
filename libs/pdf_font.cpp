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

/* Include order
Own .h.
C.
C++.
Other libraries' .h files.
Your project's .h files.
*/

#include "pdf_font.h"

#include <iostream>
#include <iterator>
#include <regex>
#include <string>


namespace pdfparser {

extern "C" {
Font::Font (){};

Font::Font (std::string id) : id(id) {}


void Font::BuildUnicodeMap(std::string raw_cidfont) {
	const std::regex cid_unicode_re {R"(^<([[:xdigit:]]{2})>\s*<([[:xdigit:]]+)>\s*([\s\S]*))"};
	const std::string cid_ordering = kCmapOrdering+R"(\s*\(([[:w:]]+)\))";
	const std::regex cid_ordering_re {cid_ordering};// TODO regex for ordering
	std::smatch sm;

	// Looks up /Ordering to get endianess
	auto begin = raw_cidfont.find(kCmapBegin) + kCmapBegin.size();
	begin = raw_cidfont.find(kCmapOrdering, begin);
	auto last_part = raw_cidfont.substr(begin, std::string::npos);

	std::regex_search (last_part, sm, cid_ordering_re);
	encoding = sm.str(1);

	// Looks up encoded chars
	begin = last_part.find(kBeginBFChar, begin) + kBeginBFChar.size();
	begin = last_part.find(kBeginHex, begin);

	auto end = last_part.find(kEndBFChar, begin);
	last_part = last_part.substr(begin, end-begin);

	std::regex_search (last_part, sm, cid_unicode_re);
	auto cmap_elem = sm.size();

	while (cmap_elem >= 3) {

		#ifdef DEBUG
		//std::cout << "Elements of sm: "<< cmap_elem << std::endl;
		std::cout << "Element 1(cid): " << sm.str(1) << std::endl;
		std::cout << "Element 2(unicode): " << sm.str(2) << std::endl;
		//std::cout << "Last elem(rest): " << sm.str(cmap_elem-1) << std::endl;
		#endif

		std::string cid = sm.str(1); // It is the cid of cid-value pair
		std::string unicode_str = sm.str(2);
		last_part = sm.str(cmap_elem-1);

		// Orders bytes according little endian or big endian
		/*
		for (auto it = unicode_str.begin(); it != unicode_str.end(); it+=4) {
			Utf16ToByte input;
			std::string utf16(it, it+4); // 4 hexa numbers
			input.utf16 = stoi(utf16, nullptr, 16);
			unicode_map[cid].insert(unicode_map[cid].end(), input.byte, input.byte+2);
		}
		*/

		// Stores encoding as is
		for (auto it = unicode_str.begin(); it != unicode_str.end(); it+=2) {
			std::string utf16(it, it+2); // 2 hexa numbers
			unicode_map[cid].push_back(stoi(utf16, nullptr, 16));
		}

		std::regex_search (last_part, sm, cid_unicode_re);
		cmap_elem = sm.size();
	}
}


UNICODE_MAP Font::GetUnicodeMap() {
	return unicode_map;
}


const char* Font::GetFontEndianess() {
	return kOrdering.at(encoding).c_str();
}

} // !extern "C"

} // !namespace pdfparser
