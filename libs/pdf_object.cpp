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
 
#include "pdf_object.h"

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

#include "pdf_parser_helper.h"

namespace pdfparser {
    extern "C" {

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
	            std::cout << sm.position(0) << std::endl;
	            std::cout << sm.str(0) << std::endl;
	        #endif

	        if (sm.size() > 0) {
		        auto obj_start = sm.position(0);
		        auto obj_end = string_buffer.find(kObjEnd);
		        auto obj_header_size = sm[0].length();

		        id = sm[1];

		        pdf_object = buffer + obj_start;
		        object_size = obj_end-obj_start;
		        auto next_item = pdf_object + obj_header_size;

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

        PdfObject::~PdfObject() {
	        delete[] decoded_stream;
        }

        std::string PdfObject::GetId() {
	        return id;
        }

        Dictionary* PdfObject::GetDictionary() {
	        return &dictionary;
        }

        void  PdfObject::UnfoldDictionary(Dictionary* dictionary, const uint8_t* begin, const uint8_t* end) {
	        size_t dictionary_index{0};

	        const std::string kKeyRegEx = "([[:w:]-]+)([[:s:]])*(.*)"; // reg_exp.g. '/Key'
	        const std::string kObjRefRegEx = "^([0-9]+[[:space:]]+[0-9]+)([[:space:]]+R[[:space:]]*)(.*)"; // for indirect object reference '0 5 R'
	        const std::string kArrayRegEx = "^(\\[.*\\])(.*)";													// for arrays '[zzz yyy]'
	        const std::string kLiteralRegEx = "^(\\(.*\\))(.*)";													// for literals '(this is a literal)'


	        const std::regex key_regex {kKeyRegEx};
	        const std::regex obj_ref_regex {kObjRefRegEx};
	        const std::regex array_regex {kArrayRegEx};
	        const std::regex literal_regex{kLiteralRegEx};

	        std::string last_part(begin, end);				//Dictionary splitted in key and rest
	        std::string key{};								// Key of dictionary

	        std::smatch sm;
	        std::regex_search (last_part, sm, key_regex); // Searchs for the begining of an object, reg_exp.g. '10 0 obj'
	        auto directory_elem = sm.size();

	        while (directory_elem > 1) {
		        #ifdef DEBUG
		            std::cout << sm.size() << std::endl;
		            std::cout << sm.str(0) << std::endl;
		            std::cout << sm.str(1) << std::endl;
		            std::cout << sm.str(directory_elem-1) << std::endl;
		        #endif

		        key = sm.str(1);
		        last_part = sm.str(directory_elem-1);
		        dictionary_index = dictionary_index + sm.position(directory_elem-1);

		        // It is a key-dictionary pair
		        if (last_part.substr(0, kDictionaryBegin.size()) == kDictionaryBegin) { // Contains a dictionary as value
			        auto dict_bound = GetDictionaryBoundaries(begin + dictionary_index, end);
			        Dictionary* new_dict = new Dictionary;
			        UnfoldDictionary(new_dict, dict_bound.start, dict_bound.end);
			        dictionary->dictionaries[key] = new_dict;

			        dictionary_index = dictionary_index + dict_bound.end - dict_bound.start;
			        last_part = last_part.substr(dict_bound.end - dict_bound.start, std::string::npos);
		        } else { // It is a key-value pair
			        std::smatch sm_key;
			        std::smatch sm_array;
			        std::smatch sm_literal;
			        std::smatch sm_obj_ref;

			        std::regex_search (last_part, sm_key, key_regex);
			        std::regex_search (last_part, sm_array, array_regex);
			        std::regex_search (last_part, sm_literal, literal_regex);
			        std::regex_search (last_part, sm_obj_ref, obj_ref_regex);

			        if (sm_obj_ref.size() > 0) {
				        sm = sm_obj_ref;
			        } else if (sm_array.size() > 0) {
				        sm = sm_array;
			        } else if (sm_literal.size() > 0) {
				        sm = sm_literal;
			        } else if (sm_key.size() > 0){
				        sm = sm_key;
			        }

			        directory_elem = sm.size();

			        dictionary->values[key] = sm.str(1);

			        last_part = sm.str(directory_elem-1);
			        dictionary_index = dictionary_index + sm.position(directory_elem-1);
		        }

		        std::regex_search (last_part, sm, key_regex);
		        directory_elem = sm.size();
	        }
        }

        void PdfObject::GetFilters() {
	        const char kDelimiter {'/'};

	        size_t filter_start = FindStringInBuffer (pdf_object, kFilterTagBegin.c_str(), object_size); //Begin of 'Filter' object

	        if (filter_start != std::string::npos) {
		        filter_start = filter_start + kFilterTagBegin.length();
		        size_t filter_size = FindStringInBuffer (pdf_object + filter_start, kFilterTagEnd.c_str(), object_size - filter_start);

		        if (filter_size != std::string::npos) {
			        dictionary_end = pdf_object + filter_start + filter_size;

			        std::string line{(char*)pdf_object, filter_start, filter_size};
			        auto filters = SplitString(line, kDelimiter);

			        for (size_t i = 0; i<filters.size(); i++) {
				        if (kFilterDictionary.end() != std::find(kFilterDictionary.begin(), kFilterDictionary.end(), filters[i])) {
					        this->filters.push_back(filters[i]);
				        }
			        }
		        }
	        } else {
		        dictionary_end = pdf_object; // No filter found
	        }
        }

        void PdfObject::GetStream() {

	        size_t stream_position = FindStringInBuffer (dictionary_end, kStreamBegin.c_str(), object_size - (dictionary_end - pdf_object)); //Begin of 'stream'

	        if (stream_position != std::string::npos) {
		        stream_position = stream_position + kStreamBegin.length();
		        auto stream_buffer = dictionary_end + stream_position;

		        // To comply with 7.3.8.1 of ISO 32000:2008 and get exactly the start of stream to decode
		        bool correct_syntax = false;
		        if (memcmp (stream_buffer, kPdfEol1, 1) == 0) {
			        stream_buffer++;
			        correct_syntax = true;
		        } else if (memcmp (stream_buffer, kPdfEol2, 2) == 0) {
			        stream_buffer = stream_buffer+2;
			        correct_syntax = true;
		        }

		        if (correct_syntax) {
			        size_t stream_size = FindStringInBuffer (stream_buffer, kStreamEnd.c_str(), object_size - (stream_buffer - pdf_object));

			        if (stream_size != std::string::npos) {
				        // To comply with 7.3.8.1 of ISO 32000:2008 and get exactly the end of stream to decode
				        correct_syntax = false;
				        if (memcmp (stream_buffer + stream_size - 2, kPdfEol2, 2) == 0) {
					        stream_size=stream_size-2;
					        correct_syntax = true;
				        } else if (memcmp (stream_buffer + stream_size - 1, kPdfEol1, 1) == 0){
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
            return (stream_size > 0);
        }

        bool PdfObject::ExtractStream(std::string filter){
	        #ifdef DEBUG
    	        std::cout << "applied filter:\n" << filter << std::endl; //Debug
	        #endif

	        if (filter == "") {
		        std::vector<uint8_t> temp (stream_start, stream_end);
		        decoded_stream_vector = temp;
		        return true;
	        } else if ((filter.compare("LZWDecode") != 0) || (filter.compare("FlateDecode") != 0)) {
		        FlateLZWDecode();
		        return true;
	        } else {
		        #ifdef DEBUG
		        std::cout << "No accepted filter" << std::endl;
		        #endif

		        decoded_stream_vector = {};
		        return false;
	        }
        }

        void PdfObject::FlateLZWDecode() {
	        #ifdef DEBUG
    	        std::cout << "Deflating..." << std::endl; // Debug
	        #endif

	        size_t outsize = (stream_size)*DEFLATE_BUFFER_MULTIPLIER;
	        decoded_stream = new uint8_t [outsize]{'\0'};

	        //Now use zlib to inflate. Must be initialized to '\0'
	        z_stream zstrm{};

	        zstrm.avail_in = stream_size + 1;
	        zstrm.avail_out = outsize;
	        zstrm.next_in = (Bytef*)(stream_start);
	        zstrm.next_out = (Bytef*)decoded_stream;

	        #ifdef DEBUG
    	        std::cout << "Deflating...2" << std::endl; // DEBUG
	        #endif

	        int rsti = inflateInit(&zstrm);

	        #ifdef DEBUG
    	        std::cout << "Deflating...3" << std::endl; // DEBUG
	        #endif

	        if (rsti == Z_OK) {
		        #ifdef DEBUG
    		        std::cout << "Z_OK" << std::endl;
		        #endif

		        int rst2 = inflate (&zstrm, Z_FINISH);

		        #ifdef DEBUG
		        std::cout << "rst2 = " << rsti << std::endl;
		        #endif

		        if (rst2 >= 0) {
			        //Ok, got something, extract the content:
			        decoded_stream_size = zstrm.total_out;

			        decoded_stream_vector.assign(decoded_stream, decoded_stream+decoded_stream_size);
			        #ifdef DEBUG
			        std::cout << id <<" DECODED content:\n" << decoded_stream << std::endl; // DEBUG
			        #endif
		        }
	        } else {
		        std::cout << "Z_NOK" << std::endl;
	        }
        }

        std::vector<uint8_t> PdfObject::GetDecodedStream(){
	        return decoded_stream_vector;
        }

        /**
         * Extract text from plain stream.
         *
         * Uses the decoded_stream as input and puts its result in parsed_text.
         */
        void PdfObject::TextParser() { //TODO unbalanced parentesis (escaped chars) and Hexadecimal strings
	        bool in_text_block = false;		// Indicates when the position is inside a BT/ET block
	        size_t parenthesis_depth = 0;	// Indicates when the position is inside a block delimited by '(' and ')' (a literal) and its depth
	        bool escaped_char = false;		// Indicates when the following character is escaped

	        uint8_t buffer[EXTRACT_TEXT_BUFFER_SIZE]{'\0'};
	        std::string octal_char{};

	        for (size_t i=0; i < decoded_stream_size; i++) {
		        uint8_t current_char = decoded_stream[i];

		        // Rotate the buffer and stores the previous characters to detect BT and ET
		        buffer[0] = buffer[1];
		        buffer[1] = current_char;

		        // If not in BT/ET check if it is a start of BT/ET (000)->(100) [in_text_block, parentesis_depth, escaped]
		        if (!in_text_block && (memcmp(buffer, TEXT_BLOCK_START, 2) == 0)) {
			        in_text_block = true;
                } else if (in_text_block) {
			        if (parenthesis_depth == 0) {
				        // Start of literal '(' (100)->(110)
				        if (current_char == '(') {
					        parenthesis_depth++;
				        } else if (memcmp(buffer, TEXT_BLOCK_END, 2) == 0) { // End of BT/ET (100)->(000)
					        in_text_block = false;
				        }
			        } else if (parenthesis_depth > 0) { // Already inside a literal (110) or (111)
				        if (escaped_char && octal_char.empty()) {
					        if (isdigit(current_char)) {
						        octal_char.push_back(current_char);
					        } else {
						        escaped_char = false;

						        if (current_char == 'n') {
							        parsed_text.push_back('\n');}

						        else if (current_char == 'r') {
							        parsed_text.push_back('\r');}

						        else if (current_char == 't') {
							        parsed_text.push_back('\t');}

						        else if (current_char == 'b'){
							        parsed_text.push_back('\b');}

						        else if (current_char == 'f'){
							        parsed_text.push_back('\f');}

						        else if (current_char == '\\'){
							        parsed_text.push_back('\\');}

						        else if (current_char == '('){
							        parsed_text.push_back('(');}

						        else if (current_char == ')'){
							        parsed_text.push_back(')');}
					        }
				        } else {
					        // Escaped and octal
					        if (!octal_char.empty()) {
						        if (octal_char.size() == 3 || !isdigit(current_char)) {
							        escaped_char = false;
							        uint8_t actual_char = static_cast<uint8_t>(std::stoi(octal_char));
							        parsed_text.push_back(actual_char);
							        octal_char.erase();
						        } else {
							        octal_char.push_back(current_char);
						        }
					        }

					        // Not escaped
					        if (!escaped_char) {
						        if (current_char == '\\') {
							        escaped_char = true;
						        } else {
							        if (current_char == '(') {
								        parenthesis_depth++;
							        } else if (current_char == ')') {
								        parenthesis_depth--;
							        }

							        if (parenthesis_depth > 0) {
								        parsed_text.push_back(current_char);
							        }
						        }
					        }
				        }
			        }
		        }
	        }

	        #ifdef DEBUG
	            std::string output(parsed_text.begin(), parsed_text.end()); // DEBUG
	            std::cout << "output:\n" << output << std::endl << std::flush; // DEBUG
	        #endif
        }

        //start of 'obj' + size of 'obj' + length of flag
        const uint8_t* PdfObject::GetObjectEnd() {
	        if (object_size == 0) {
		        return pdf_object;
	        } else {
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

	        size_t last_dictionary_position{dict_begin+kDictionaryBegin.size()};	// Two chars '<<' as the first dictionary begin
	        size_t dictionaries_counter{1};								// It has at least 1 dictionary
	        auto dictionaries_quantity = dictionaries_counter;			// Dictionary blocks present
	        auto dictionary_size = end - begin;							// Not necessarily the dictionary itself, but a limit to search

	        while ((last_dictionary_position < dictionary_size) && (dictionaries_counter > 0)) {
		        if (string_buffer.substr(dict_begin + last_dictionary_position, kDictionaryBegin.size()) == kDictionaryBegin) {
			        last_dictionary_position = last_dictionary_position + 2;
			        ++dictionaries_counter;
			        ++dictionaries_quantity;
		        } else if (string_buffer.substr(dict_begin + last_dictionary_position, kDictionaryEnd.size()) == kDictionaryEnd) {
			        last_dictionary_position = last_dictionary_position + 2;
			        --dictionaries_counter;
		        } else {
			        ++last_dictionary_position;
		        }
	        }
	        dict_bound.end = begin + last_dictionary_position;

	        return dict_bound;
        }

    } // !extern "C"

} // !namespace pdfparser
