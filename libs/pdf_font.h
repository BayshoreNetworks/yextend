/*
 *
 *  Created on: Feb 16, 2018
 *      Author: rodrigo
 */

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
