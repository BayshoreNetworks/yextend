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

#ifndef FONT_H_
#define FONT_H_

//#define DEBUG

/* Include order
Own .h.
C.
C++.
Other libraries' .h files.
Your project's .h files.
*/

#include <cstddef>
#include <string>
#include <map>
#include <vector>

namespace pdfparser {

extern "C" {

using UNICODE_MAP=std::map<std::string, std::vector<uint8_t>>;
//typedef std::map<std::string, std::string> UNICODE_MAP;

const std::string kCmapBegin			{"begincmap"};
const std::string kCmapOrdering			{"/Ordering"};
const std::string kCodeSpaceRangeBegin 	{"begincodespacerange"};
const std::string kBeginBFChar			{"beginbfchar"};
const std::string kEndBFChar			{"endbfchar"};
const std::string kBeginHex				{"<"};


const std::map<std::string, const std::string> kOrdering = {
		{"None", "UTF-8"},
		{"UCS", "UTF-16BE"}
};


class Font {
	union Utf16ToByte {
		uint8_t byte[2];
		char16_t utf16;
	};
	std::string id{};
	std::string base_font{"None"};
	std::string encoding {"None"};
	UNICODE_MAP unicode_map{}; // Key: cid, value: Unicode

public:
	Font();
	Font(std::string id);

	/**
	 * @brief					Parses the unicode map and fills up unicode_map
	 * @param raw_definition	string with raw CIDFont
	 */
	void BuildUnicodeMap(std::string raw_cidfont);
	UNICODE_MAP GetUnicodeMap();
	const char * GetFontEndianess();
};

} // !extern "C"

} // !namespace pdfparser

#endif /* FONTS_H_ */
