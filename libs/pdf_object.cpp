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
#include "pdf_object.h"

#include <iconv.h>

#include <cstring>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <istream>
#include <iostream> //debugging
#include <list>
#include <regex>
#include <string>
#include <sstream>
#include <vector>

#include <zlib.h>

#include "pdf_font.h"
#include "pdf_parser_helper.h"
#include "pdf_text_encoding.h"


namespace pdfparser {


extern "C" {


PdfObject::PdfObject() {

}


/**
 * @brief Gets the first pdf object contained in buffer
 * @param buffer pointer to pdf
 * @param size size of buffer
 */
PdfObject::PdfObject(const uint8_t* buffer, size_t size){

	const std::string kObjRegEx = "([0-9]+[[:space:]]+[0-9]+)[[:space:]]+"+kObjBegin+"[[:space:]]+"; // reg_exp.g. '10 0 obj'

	std::string string_buffer(buffer, buffer+size);
	std::regex regexp {kObjRegEx};
	std::smatch sm;
	std::regex_search (string_buffer, sm, regexp); // Searchs for the begining of an object, reg_exp.g. '10 0 obj'

	#ifdef DEBUG
	std::cout << sm.position(0) << std::endl; // Debug
	std::cout << sm.str(0) << std::endl; // Debug
	#endif

	if (sm.size() > 0) {
	//size_t obj_start = FindStringInBuffer (buffer, kObjStart.c_str(), size); //Begin of 'obj' object
	//if (obj_start != std::string::npos){
		auto obj_start = sm.position(0);
		auto obj_end = string_buffer.find(kObjEnd);
		auto obj_header_size = sm[0].length();

		id = sm[1];

		pdf_object = buffer + obj_start;
		object_size = obj_end-obj_start;
		//auto next_item = pdf_object + obj_header_size;

		if (string_buffer.substr(obj_start + obj_header_size, kDictionaryBegin.size()) == "<<") { //It has a dictionary

			DictionaryBoundaries dict_boundaries = GetDictionaryBoundaries(pdf_object + obj_header_size,
					pdf_object + object_size);
			dictionary_start	= dict_boundaries.start;
			dictionary_end 		= dict_boundaries.end;

			UnfoldDictionary(&dictionary, dictionary_start, dictionary_end);
			GetFilters();
			GetStream();
		}
	}
	// There is no more 'obj'
	else {
		object_size = 0;
		pdf_object = buffer + size;
	}
}


PdfObject::~PdfObject(){
	//delete[] decoded_stream;
//	if (dictionary.dictionaries.size() > 0)
//		DeleteDictionary(&dictionary);
}


/*
void PdfObject::DeleteDictionary(Dictionary* dictionary){
	for (auto x: dictionary->dictionaries) {
		DeleteDictionary(x.second);
		delete x.second;
	}
}
*/


std::string PdfObject::GetId() {
	return id;
}


Dictionary* PdfObject::GetDictionary() {
	return &dictionary;
}


void  PdfObject::UnfoldDictionary(Dictionary* dictionary, const uint8_t* begin, const uint8_t* end) { //TODO

	auto dictionary_begin = begin+kDictionaryBegin.size();

	size_t dictionary_index{0};

	//const std::string kObjectBegin = R("^([0-9]+\s+[0-9]+\s+obj)(\s*)([\s\S]*))"; // Obj '15 0 obj'
	//const std::string kNameRegEx 	= R"(^(/[^\x00-\x20\(\)\<\>\[\]\{\}/\%\x7f-\xff]+)(\s*)([\s\S]*))";	// Name objects /Key1+3 Optimal TODO
	const std::string kBoolRegEx	= R"(^(true|false)\s*([\s\S]*))";				// Boolean true or false
	const std::string kNameRegEx 	= R"(^[\s]*(/[[:w:]\+\-]+)\s*([\s\S]*))";			// Name objects /Key1+3
	const std::string kObjRefRegEx 	= R"(^([0-9]+\s+[0-9]+)\s+R\s*([\s\S]*))";		// Indirect object reference '0 5 R'
	// V0 const std::string kArrayRegEx 	= R"(^(\[.*\])([\s\S]*))";				// Arrays '[zzz yyy]'
	const std::string kArrayRegEx 	= R"(^(\[[[:alnum:]\+\-/\R\s]+\])\s*([\s\S]*))";// Arrays '[zzz yyy]'
	const std::string kLiteralRegEx = R"(^(\(.*\))\s*([\s\S]*))";					// Literals '(this is a literal)'
	const std::string kLiteralHexRegEx = R"(^(<[[:xdigit:]]+>)\s*([\s\S]*))";		// Literals in hexa '<FEFF0054>'
	const std::string kNumberRegEx	= R"(^([\+-]?[0-9]*\.?[0-9]*)\s*([\s\S]*))";	// Numbers 33 +33 -33 0.4 .4 +0.4 +.4

	const std::regex bool_regex {kBoolRegEx};
	const std::regex name_regex {kNameRegEx};
	const std::regex obj_ref_regex {kObjRefRegEx};
	const std::regex array_regex {kArrayRegEx};
	const std::regex literal_regex {kLiteralRegEx};
	const std::regex literal_hex_regex {kLiteralHexRegEx};
	const std::regex number_regex {kNumberRegEx};

	std::string last_part(dictionary_begin, end);	//Dictionary splitted in key and rest

	std::smatch sm;
	std::regex_search (last_part, sm, name_regex); // Searches for the beginning of an key /key
	auto directory_elem = sm.size();

	while (directory_elem > 1) {

		std::string key = sm.str(1); // It is the key of key-value pair
		last_part = sm.str(directory_elem-1);
		dictionary_index = dictionary_index + sm.position(directory_elem-1); //to the next char after key

#ifdef DEBUG
		if ((id == "4 0" && true) || (id == "1 0" && false)) {
			std::cout << "DEBUG" << std::endl;
		}
		std::cout << "\nPDF Object: " << id << ". Elements of sm: "<< directory_elem << std::endl;
		//std::cout << "Element 0: " << sm.str(0) << std::endl; // All matches
		std::cout << "Key: " << key << std::endl;
		//std::cout << "Last elem(rest): " << sm.str(directory_elem-1) << std::endl;
#endif

		// It is a key-dictionary pair
		if (last_part.substr(0, kDictionaryBegin.size()) == kDictionaryBegin) { // Contains a dictionary as value
			auto dict_bound = GetDictionaryBoundaries(dictionary_begin + dictionary_index, end);
			Dictionary* new_dict = new Dictionary;
			UnfoldDictionary(new_dict, dict_bound.start, dict_bound.end);
			dictionary->dictionaries[key] = new_dict;

			dictionary_index = dictionary_index + dict_bound.end - dict_bound.start;

			// Advances to the next key
			auto next_key = last_part.find(kNameTagBegin, dict_bound.end - dict_bound.start);
			if (next_key < std::string::npos) {
				// There is still dictionary
				last_part = last_part.substr(next_key, std::string::npos);
			}
			else{
				//No more dictionary to search in
				last_part = "";
			}
		}
		// It is a key-value pair
		else {
			std::smatch sm_bool;
			std::smatch sm_name;
			std::smatch sm_array;
			std::smatch sm_literal;
			std::smatch sm_literal_hex;
			std::smatch sm_obj_ref;
			std::smatch sm_number;

			std::regex_search (last_part, sm_bool, bool_regex);
			std::regex_search (last_part, sm_name, name_regex);
			std::regex_search (last_part, sm_array, array_regex);
			std::regex_search (last_part, sm_literal, literal_regex);
			std::regex_search (last_part, sm_literal_hex, literal_hex_regex);
			std::regex_search (last_part, sm_obj_ref, obj_ref_regex);
			std::regex_search (last_part, sm_number, number_regex);

			if (sm_bool.size() > 0) {
				sm = sm_bool;
			}
			else if (sm_obj_ref.size() > 0) {
				sm = sm_obj_ref;
			}
			else if (sm_array.size() > 0) {
				sm = sm_array;
			}
			else if (sm_literal.size() > 0) {
				sm = sm_literal;
			}
			else if (sm_literal_hex.size() > 0) {
				sm = sm_literal_hex;
			}
			else if (sm_name.size() > 0) {
				sm = sm_name;
			}
			else if (sm_number.size() > 0) {
				sm = sm_number;
			}

			directory_elem = sm.size();

#ifdef DEBUG
			//std::cout << "String: " << last_part << std::endl;
			//std::cout << "Elements of sm: "<< directory_elem << std::endl;
			//std::cout << "Element 0: " << sm.str(0) << std::endl; // All matches
			std::cout << "Element 1: " << sm.str(1) << std::endl;
			//std::cout << "Last elem(rest): " << sm.str(directory_elem-1) << std::endl;
#endif

			auto value = sm.str(1);
			std::replace(value.begin(), value.end(), '\n', ' '); // Replace \n by space
			dictionary->values[key] = value;

			last_part = sm.str(directory_elem-1);
			dictionary_index = dictionary_index + sm.position(directory_elem-1);
		}
		std::regex_search (last_part, sm, name_regex);
		directory_elem = sm.size();
	}
}


void PdfObject::GetFilters() {
	const char kDelimiter {'/'};

	// It has filters
	if (dictionary.values.find(kFilterTagBegin) != dictionary.values.end()) {
		auto filters_buffer = dictionary.values[kFilterTagBegin];

		// If it is an array TODO verify the case of array
		if (filters_buffer.substr(0, kArrayTagBegin.size()) == kArrayTagBegin) {
			auto filters_array = SplitString(filters_buffer, kDelimiter);

			//filters.insert(filters.end(), filters_array.begin(), filters_array.end());
			for (auto x: filters_array) {
				filters.push_back(kDelimiter+x);
			}
		}

		// It is not an array -> single value
		else {
			filters.push_back(filters_buffer);
		}
	}

	// No filter found

	/*
	const char kDelimiter {'/'};

	size_t filter_start = FindStringInBuffer (pdf_object, kFilterTagBegin.c_str(), object_size); //Begin of 'Filter' object

	if (filter_start != std::string::npos){
		filter_start = filter_start + kFilterTagBegin.length();
		size_t filter_size = FindStringInBuffer (pdf_object + filter_start, kFilterTagEnd.c_str(), object_size - filter_start);

		if (filter_size != std::string::npos){
			dictionary_end = pdf_object + filter_start + filter_size;

			std::string line{(char*)pdf_object, filter_start, filter_size};
			auto filters = SplitString(line, kDelimiter);

			for (size_t i = 0; i<filters.size(); i++) {
				if (kFilterDictionary.end() != std::find(kFilterDictionary.begin(), kFilterDictionary.end(), filters[i])) {
					this->filters.push_back(filters[i]);
				}
			}
		}
	}
	else {
		dictionary_end = pdf_object; // No filter found
	}
	*/
}


void PdfObject::GetStream(){

	size_t stream_position = FindStringInBuffer (dictionary_end, kStreamBegin.c_str(), object_size - (dictionary_end - pdf_object)); //Begin of 'stream'

	if (stream_position != std::string::npos){
		stream_position = stream_position + kStreamBegin.length();
		auto stream_buffer = dictionary_end + stream_position;

		// To comply with 7.3.8.1 of ISO 32000:2008 and get exactly the start of stream to decode
		bool correct_syntax = false;
		if (memcmp (stream_buffer, kPdfEol1, 1) == 0) {
			stream_buffer++;
			correct_syntax = true;
		}
		else if (memcmp (stream_buffer, kPdfEol2, 2) == 0){
			stream_buffer = stream_buffer+2;
			correct_syntax = true;
		}

		if (correct_syntax){
			size_t stream_size = FindStringInBuffer (stream_buffer, kStreamEnd.c_str(), object_size - (stream_buffer - pdf_object));

			if (stream_size != std::string::npos){
				// To comply with 7.3.8.1 of ISO 32000:2008 and get exactly the end of stream to decode
				correct_syntax = false;
				if (memcmp (stream_buffer + stream_size - 2, kPdfEol2, 2) == 0) {
					stream_size=stream_size-2;
					correct_syntax = true;
				}
				else if (memcmp (stream_buffer + stream_size - 1, kPdfEol1, 1) == 0){
					stream_size--;
					correct_syntax = true;
				}

				if (correct_syntax){
					stream_start = stream_buffer; // TODO Verify value
					this->stream_size = stream_size;
					stream_end = stream_start + stream_size;
				}
			}
		}
	}
}


bool PdfObject::HasStream(){
	if (stream_size > 0) return true;
	else return false;
}


bool PdfObject::ExtractStream(std::string filter){

#ifdef DEBUG
	std::cout << "\n### DEBUG PdFObject::ExtractStream ###\nApplied filter: " << filter << std::endl; //Debug
#endif

	// It has no filter, so the stream is no encoded
	if (filter == "") {
		std::vector<uint8_t> temp (stream_start, stream_end);
		decoded_stream_vector = temp;
		return true;
	}
	else if ((filter.compare("LZWDecode") != 0) || (filter.compare("FlateDecode") != 0)) {
		FlateLZWDecode();
		return true;
	}
	else {
		#ifdef DEBUG
		std::cout << "No accepted filter" << std::endl;
		#endif

		decoded_stream_vector = {};
		return false;
	}
}


void PdfObject::FlateLZWDecode() {

#ifdef DEBUG
	std::cout << "\n### DEBUG PdfObject::FlateLZWDecode ###\n" << std::endl; // Debug
#endif

	size_t outsize = (stream_size)*DEFLATE_BUFFER_MULTIPLIER;
	auto decoded_stream = new uint8_t [outsize]{'\0'};

	//Now use zlib to inflate. Must be initialized to '\0'
	z_stream zstrm{};

	zstrm.avail_in = stream_size + 1;
	zstrm.avail_out = outsize;
	zstrm.next_in = (Bytef*)(stream_start);
	zstrm.next_out = (Bytef*)decoded_stream;

	int rsti = inflateInit(&zstrm);

	if (rsti == Z_OK)
	{
		int rst2 = inflate (&zstrm, Z_FINISH);

		if (rst2 >= 0)
		{
			//Ok, got something, extract the content:
			auto decoded_stream_size = zstrm.total_out;
			decoded_stream_vector.assign(decoded_stream, decoded_stream+decoded_stream_size);

#ifdef DEBUG
			std::cout << "Obj: " << id <<" Deflating Ok. DECODED content:\n" << decoded_stream << std::endl;
#endif
		}
	}
	else {
#ifdef DEBUG
		std::cout << "Z_NOK" << std::endl;
#endif
	}

	delete[] decoded_stream;
}


std::vector<uint8_t> PdfObject::GetDecodedStream(){
	return decoded_stream_vector;
}


/**
 * Extract text from plain stream.
 *
 * Uses the decoded_stream_vector as input and puts its result in parsed_plain_text.
 */
//TODO Hexadecimal strings
void PdfObject::ParseText(std::map<std::string, Font>& fonts){

	bool in_text_block = false;			// Indicates when the position is inside a BT/ET block
	size_t parenthesis_depth = 0;		// Indicates when the position is inside a block delimited by '(' and ')' (a literal) and its depth. It shall be printed with Tj
	size_t square_brackets_depth = 0;	// Indicates when the position is inside a array. It shall be printed with TJ
	bool escaped_char = false;			// Indicates when the following character is escaped

	uint8_t buffer[EXTRACT_TEXT_BUFFER_SIZE]{'\0'};

	std::string octal_char{};
	std::string text_buffer{};	// Stores temporally the text to be parsed later on
	std::string local_font{};	// Local font in BT/ET

	size_t decoded_stream_idx=0;
	while (decoded_stream_idx < decoded_stream_vector.size()) {
		auto current_char = decoded_stream_vector[decoded_stream_idx++];

		// Rotate the buffer and stores the previous characters to detect BT and ET
		for (unsigned char j=0; j<EXTRACT_TEXT_BUFFER_SIZE-1; ++j) {
			buffer[j] = buffer[j+1];
		}
		buffer[EXTRACT_TEXT_BUFFER_SIZE-1] = current_char;
		std::string buffer_str (buffer, buffer+EXTRACT_TEXT_BUFFER_SIZE);

		// If not in BT/ET check if it is a start of BT/ET (000)->(100) [in_text_block, parentesis_depth, escaped]
		if (!in_text_block && (memcmp(buffer, TEXT_BLOCK_START, 2) == 0)) {
			in_text_block = true;}

		// Inside BT/ET block
		else if (in_text_block) {

			if (parenthesis_depth == 0 && square_brackets_depth == 0) {

				// Font selector
				if (memcmp(buffer, TEXT_FONT, 2) == 0){
					local_font = TEXT_FONT;

					//auto from = reinterpret_cast<const char *>(&decoded_stream_vector[decoded_stream_idx]);
					auto from = decoded_stream_vector.begin() + decoded_stream_idx;
					auto to = from + TEXT_FONT_MAX_SIZE;

					std::string font_buffer(from, to);

					// Searchs for the name of the font
					const std::regex re {R"(^([[:w:]]+)\s)"};
					std::smatch sm;
					std::regex_search (font_buffer, sm, re);
					local_font += sm.str(1);

					// ATTN idx is also incremented here. Buffer becomes corrupted with no impact in parsing
					decoded_stream_idx += sm.str(1).size();
				}

				// TJ received, array buffer has info then parse text array. Nomultilevel arrays allowed
				else if ((memcmp(buffer, TEXT_PRINT_ARRAY, 2) == 0) && (text_buffer.size() > 0)){
					auto font = fonts[local_font];
					ParseTextArray(text_buffer, font);
					text_buffer.clear();
				}

				// Operator resets array and literal buffer
				else if (std::find(kTextResetingOperators.begin(), kTextResetingOperators.end(), buffer_str)
				!= kTextResetingOperators.end()) {
					text_buffer.clear();
				}

				// Start of literal '(' (100)->(110)
				else if (current_char == '(') {
					++parenthesis_depth;
				}

				else if (current_char == '[') {
					++square_brackets_depth;
				}

				// End of BT/ET (100)->(000)
				else if (memcmp(buffer, TEXT_BLOCK_END, 2) == 0){
					in_text_block = false;
					local_font.clear();
					text_buffer.clear();
				}
			}

			// Inside of an array
			else if (square_brackets_depth > 0) {
				if (current_char == ']') {
					--square_brackets_depth;
				}
				else if (current_char == '[') {
					++square_brackets_depth;
				}
				else text_buffer += current_char;
			}

			//  Already inside a literal (110) or (111). TODO reshape with parenthesis parser.
			else if (parenthesis_depth > 0){

				if (escaped_char && octal_char.empty()) {
					if (isdigit(current_char)){
						octal_char.push_back(current_char);
					}

					else {
						escaped_char = false;

						if (current_char == 'n') {
							parsed_plain_text.push_back('\n');}

						else if (current_char == 'r') {
							parsed_plain_text.push_back('\r');}

						else if (current_char == 't') {
							parsed_plain_text.push_back('\t');}

						else if (current_char == 'b'){
							parsed_plain_text.push_back('\b');}

						else if (current_char == 'f'){
							parsed_plain_text.push_back('\f');}

						else if (current_char == '\\'){
							parsed_plain_text.push_back('\\');}

						else if (current_char == '('){
							parsed_plain_text.push_back('(');}

						else if (current_char == ')'){
							parsed_plain_text.push_back(')');}
					}
				}

				else {
					// Escaped and octal
					if (!octal_char.empty()) {

						if (octal_char.size() == 3 || !isdigit(current_char)) {
							escaped_char = false;
							uint8_t actual_char = static_cast<uint8_t>(std::stoi(octal_char));
							parsed_plain_text.push_back(actual_char);
							octal_char.erase();
						}
						else {
							octal_char.push_back(current_char);
						}
					}

					// Not escaped
					if (!escaped_char){

						if (current_char == '\\'){
							escaped_char = true;
						}

						else {
							if (current_char == '(') {
								parenthesis_depth++;
							}
							else if (current_char == ')') {
								parenthesis_depth--;
							}

							if (parenthesis_depth > 0) {
								parsed_plain_text.push_back(current_char);
							}
						}
					}
				}
			}
		}
	}
}


std::vector<uint8_t> PdfObject::GetParsedPlainText(TextEncoding encoding){
	if (encoding == TextEncoding::utf8) {
		std::vector<uint8_t> utf8_text(parsed_plain_text_utf8.begin(), parsed_plain_text_utf8.end());
		return utf8_text;
	}
	else {
		return parsed_plain_text;
	}
}

/**
 * @brief	 start of 'obj' + size of 'obj' + length of flag
 * @return
 */
const uint8_t* PdfObject::GetObjectEnd() {
	if (object_size == 0) {
		return pdf_object;
	}
	else {
		return pdf_object + object_size + kObjEnd.length();
	}
}


/**
 * @brief	Detects the limits of the outer dictionary between the limits provided
 * @param begin
 * @param end
 */
DictionaryBoundaries PdfObject::GetDictionaryBoundaries (const uint8_t* begin, const uint8_t* end) {

	std::string string_buffer(begin, end);

	auto dict_begin = string_buffer.find(kDictionaryBegin);
	DictionaryBoundaries dict_bound{};
	dict_bound.start =  begin + dict_begin;

	size_t last_dictionary_position{dict_begin+kDictionaryBegin.size()}; // Advances chars quantity of '<<' as the first dictionary begin
	size_t dictionaries_counter{1};						// Index of dictionaries. It is already inside the first
	auto dictionary_size = end - begin;					// Not necessarily the dictionary itself, but a limit to search

	// Sweeps dictionary counting inner dictionaries
	while ((last_dictionary_position < dictionary_size) && (dictionaries_counter > 0)) {
		if (string_buffer.substr(dict_begin + last_dictionary_position, kDictionaryBegin.size()) == kDictionaryBegin) {
			last_dictionary_position += 2;
			++dictionaries_counter;
		}
		else if (string_buffer.substr(dict_begin + last_dictionary_position, kDictionaryEnd.size()) == kDictionaryEnd) {
			last_dictionary_position += 2;
			--dictionaries_counter;
		}
		else {
			++last_dictionary_position;
		}
	}
	dict_bound.end = begin + last_dictionary_position;

	return dict_bound;
}


std::string PdfObject::ExtractFontDefinition(Dictionary* dictionary) {
	bool font_found{false};
	std::string font_definition{""};

	auto values = dictionary->values;

	// check if the value is a indirect reference
	if (values.find(kFontTagBegin) != values.end()) {
		font_found = true;
		font_definition = dictionary->values[kFontTagBegin];
		}

	// If not and there are dictionaries check inside them
	else if (dictionary->dictionaries.size() != 0) {
		auto subdictionary = dictionary->dictionaries; //map

		// If the no dictionary key is not Font, analyze insider dictionaries
		if (subdictionary.find(kFontTagBegin) == subdictionary.end()) {

			auto subdictionary_iterator = subdictionary.begin();
			while (!font_found && (subdictionary_iterator != subdictionary.end())) {

				font_definition = ExtractFontDefinition(subdictionary_iterator->second); // pass the dictionary associated

				if (font_definition.size() > 0) {
					font_found = true;
				}
				else {
					std::advance(subdictionary_iterator, 1);
				}
			}
		}
		else { // Font definition is stored in a dictionary
			font_definition =  subdictionary[kFontTagBegin]->IndirectReference();
		}
	}

	return font_definition;
}


void PdfObject::ParseTextArray(std::string& array, Font& font) {
	//TESTME empty font
	std::vector<uint8_t> parsing_buffer{};
	auto unicode_map = font.GetUnicodeMap();

	auto it = array.begin();
	while (it != array.end()){

		// Inside a hexadecimal char
		if (*it == '<') {
			bool is_hexa = true;

			++it;
			while (is_hexa && it != array.end()) {

				if (*(it) == '>') {
					is_hexa = false;
					//++it;
				}
				else {
					std::string cid(it, it+2);
#ifdef DEBUG
					if ((cid == "35") || (cid == "27") || (cid == "28")) {
						//std::cout << "DEBUG\n";
					}
#endif
					//parsed_plain_text.push_back(unicode_map[cid]); //TESTME empty map
					parsing_buffer.insert(parsing_buffer.end(),
							unicode_map[cid].begin(),
							unicode_map[cid].end()); //TESTME empty map

					it+=2;
				}
			}
		}
		//There is literal text inside the array
		else if (*it == '(') {
			// Detect end of literal

			++it;
			auto literal_it_end = it;
			bool is_literal_end {false};
			while (!is_literal_end && (literal_it_end != array.end())) {

				// It's an escaped character, the following one shall be skipped (to be processed in TextParse)
				// For example for the case of \(
				if (*literal_it_end == '\\') {
					literal_it_end +=2;
				}
				else if (*literal_it_end == ')') {
						is_literal_end = true;
				}
				else {
					++literal_it_end;
				}
			}
			std::string literal_to_parse(it, literal_it_end);

			auto literal_parsed = ParseTextLiteral(literal_to_parse);
			parsing_buffer.insert(parsing_buffer.end(), literal_parsed.begin(), literal_parsed.end());

			it = literal_it_end;
		}

		++it;
	}

	// Finished parsing. Convert to utf8 for displaying purpouses
	size_t max_out_buffer = parsing_buffer.size() * 3 + 1;
	std::vector<char> out_buffer(max_out_buffer);

	iconv_t converter = iconv_open("UTF-8", font.GetFontEndianess());
	auto from_ptr = reinterpret_cast<char *>(parsing_buffer.data());
	auto to_ptr = out_buffer.data();
	//char *to_ptr = &(out_buffer[0]);

	size_t in_remaining_buffer = parsing_buffer.size();
	size_t out_remaining_buffer = max_out_buffer;

	iconv(converter, &from_ptr, &in_remaining_buffer, &to_ptr, &out_remaining_buffer);
	auto out_buffer_used = max_out_buffer-out_remaining_buffer;

	// Stores text in original format
	parsed_plain_text.insert(parsed_plain_text.end(), parsing_buffer.begin(), parsing_buffer.end());

	// Stores text in utf8
	parsed_plain_text_utf8.append(&out_buffer[0], out_buffer_used);
	iconv_close(converter);

#ifdef DEBUG
	std::cout << "\nParsed UTF-8 text\n " << parsed_plain_text_utf8.data() << '\n';
	std::cout << "\nParsed raw text\n" << parsed_plain_text.data() << '\n';
#endif

	/*
	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> conversion;
	std::u16string u16(parsed_plain_text.begin(), parsed_plain_text.end());
	auto output1 = conversion.to_bytes(u16);
*/
}


std::string PdfObject::ParseTextLiteral(std::string& text){

	std::string parsed_literal{};
	std::string octal_char{};

	bool escaped_char = false;

	auto it = text.begin();
	while (it != text.end()) {

		// Escaped and octal
		if (escaped_char && octal_char.empty()) {

			// It is an octal. Accumulate digits in octal buffer
			if (isdigit(*it)){
				octal_char.push_back(*it);
			}

			// It is an escaped char but not an octal
			else {
				escaped_char = false;

				if (*it == 'n') {
					parsed_literal.push_back('\n');}

				else if (*it == 'r') {
					parsed_literal.push_back('\r');}

				else if (*it == 't') {
					parsed_literal.push_back('\t');}

				else if (*it == 'b'){
					parsed_literal.push_back('\b');}

				else if (*it == 'f'){
					parsed_literal.push_back('\f');}

				// *it == '\\' || *it == '(' *it == ')'
				else {
					parsed_literal.push_back(*it);
				}
			}
		}

		// Escaped or octal
		else {
			// Octal
			if (!octal_char.empty()) {

				if (octal_char.size() == 3 || !isdigit(*it)) {
					escaped_char = false;
					auto actual_char = static_cast<uint8_t>(std::stoi(octal_char));
					parsed_literal.push_back(actual_char);
					octal_char.erase();
				}
				else {
					octal_char.push_back(*it);
				}
			}

			// Not escaped
			if (!escaped_char){

				if (*it == '\\'){
					escaped_char = true;
				}
				else {
					parsed_literal.push_back(*it);
				}
			}
		}

		++it;
	}
	return parsed_literal;
}


/**
 * @brief	Returns a dictionary in the form "<</key value>>" to be parsed elsewhere
 * @return
 */
std::string Dictionary::IndirectReference() {
	std::string buffer{kDictionaryBegin};

	// TODO Manage many fonts in the same
	for (auto value: values) {
		buffer = buffer + value.first + " " + value.second + " R ";
	}

	// Eliminates the trailing space
	buffer.resize(buffer.size()-1);
	buffer.append(kDictionaryEnd);

	return buffer;
}


} // !extern "C"

} // !namespace pdfparser

