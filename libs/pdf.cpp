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
#include "pdf.h"

#include <cstring>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <istream>
#include <iostream> //debugging
#include <list>
#include <map>
#include <regex>
#include <string>
#include <sstream>
#include <vector>

#include "pdf_object.h"
#include "pdf_parser_helper.h"

namespace pdfparser {

extern "C" {

Pdf::Pdf(const uint8_t* buffer, size_t size){
	start_pdf = buffer;
	length_pdf = size;

	auto current_obj_pointer = buffer;
	auto current_obj_size = size;

	while (current_obj_size > 0 && current_obj_size != std::string::npos){
		PdfObject pdf_object{current_obj_pointer, current_obj_size};

		auto id = pdf_object.GetId();
		//objects.insert(make_pair(id, pdf_object));

		if (id != "") { // for xref and so it is not recognized as pdf object
			objects.emplace(id, pdf_object);
			BuildObjReference(pdf_object.GetDictionary()); //	Build objects reference library
		}

		current_obj_size = current_obj_size - (pdf_object.GetObjectEnd() - current_obj_pointer);
		current_obj_pointer = pdf_object.GetObjectEnd();
	}
}


Pdf::~Pdf() {
	for (auto obj: objects){
		Dictionary* dictionary = obj.second.GetDictionary();
		if (dictionary->dictionaries.size() > 0)
			DeleteDictionary(dictionary);
	}
}


void Pdf::DeleteDictionary(Dictionary* dictionary){
	for (auto x: dictionary->dictionaries) {
		DeleteDictionary(x.second);
		delete x.second;
	}
}

/*
void Pdf::GetXref(){
	//  It can point to a plain xref object or to a streamed xref object
	xref_offset = FindStringInBufferReverse(start_pdf, "startxref", length_pdf); // TODO Verify

	if(memcmp (start_pdf+xref_offset, "xref", 4)){
		;} //TODO
}
*/

void Pdf::BuildObjReference(Dictionary* dictionary){
	const std::regex obj_ref_regex {Pdf::kObjectReferenceRegEx};
	std::smatch sm;

	// Values
	for (auto x: dictionary->values) {
		std::regex_search (x.second, sm, obj_ref_regex);
		if (sm.size() > 0) {
			obj_ref[x.second] = x.first;
		}
	}
	// Dictionaries
	for (auto x: dictionary->dictionaries) {
		BuildObjReference(x.second);

	}
}

void Pdf::BuildFonts(){

	// Objects are sweep sequentially because a font definition
	// can be a indirect reference or embedded data as a dictionary as a value of /Font
	for (auto object_map: objects) {
		auto object = object_map.second;
		auto dictionary = object.GetDictionary();

#ifdef DEBUG
		if (object.GetId() == "4 0") {
			std::cout << "DEBUG\n";
		}
		std::cout << "Pdf::BuildFonts Obj id: " << object.GetId() << '\n';
#endif

		// Detect /Font key in dictionary
		// The result can be a indirect reference "65 0" or a dictionary in string format "<</F1 5 0>
		auto font_definition = object.ExtractFontDefinition(dictionary);

		// Font found
		if (font_definition.size() > 0) {
			Dictionary* font_dictionary;
			bool new_dictionary{false};

			// font_definition is an indirect reference
			if (font_definition.substr(0, kDictionaryBegin.size()) != kDictionaryBegin) {
				font_dictionary = objects.find(font_definition)->second.GetDictionary();
			}

			// It is an embedded dictionary TESTME
			else {
				new_dictionary = true;
				font_dictionary = new Dictionary{};
				auto font_begin = reinterpret_cast<const uint8_t*>(&font_definition[0]);
				object.UnfoldDictionary(font_dictionary, font_begin, font_begin+font_definition.size());
			}

			// Creates fonts
			for (auto font_it = font_dictionary->values.begin(); font_it != font_dictionary->values.end(); ++font_it){

				auto font_id = font_it->first;
				Font font{font_id};

				auto font_object = objects[font_it->second];

				auto to_unicode_reference = font_object.GetDictionary()->values[kToUnicode];

				// It has /ToUnicode
				if (to_unicode_reference != "") {
					auto unicode = objects[to_unicode_reference];

					// TODO multiple filters in cascade
					auto filter = unicode.GetDictionary()->values[kFilterTagBegin];

					unicode.ExtractStream(filter);
					auto bytes_cmap = unicode.GetDecodedStream();
					std::string cmap(bytes_cmap.begin(), bytes_cmap.end());
					font.BuildUnicodeMap(cmap);
				}

				fonts[font_id] = font;
			}

			// If a new dictionary for font reference '/F1 5 0 R' was needed, destroy it
			if (new_dictionary) {
				delete (font_dictionary);
			}
		}
	}
}


std::vector<uint8_t> Pdf::ExtractText(TextEncoding encoding){
	auto accepted = kFilterDictionary;
	auto rejected_attributes = kNonTextAttributes;
	auto rejected_dictionary = kNonTextDictionaryKeys;

	// BuildFonts is executed once Pdf::ExtractText is called (has no sense to execute it in advance
	// and when all objects are in memory to be sure of having all objects referred indirectly
	Pdf::BuildFonts();

	std::vector<uint8_t> text_buffer{};
	auto whole_text = text_buffer;

	for (auto map_obj: objects) {
		auto id = map_obj.first;
		auto obj = map_obj.second;
	    auto flag = obj_ref[id];

	    bool in_rejected_dict{false};
	    for (auto key: obj.GetDictionary()->values) {
	    	if ((rejected_dictionary.end() != std::find(rejected_dictionary.begin(), rejected_dictionary.end(), key.first)) ||
	    			(rejected_dictionary.end() != std::find(rejected_dictionary.begin(), rejected_dictionary.end(), key.second))){
	    		in_rejected_dict = true;
	    		break;
	    	}
	    }

		if (obj.HasStream() && !in_rejected_dict &&
			((accepted.end() != std::find(accepted.begin(), accepted.end(), flag)) || //It is in accepted or
			(rejected_attributes.end() == std::find(rejected_attributes.begin(), rejected_attributes.end(), flag)))) { //it is not in rejected then process

			if (obj.ExtractStream((obj.GetDictionary())->values[kFilterTagBegin])){

				obj.ParseText(fonts);
				text_buffer = obj.GetParsedPlainText(encoding);
				whole_text.insert(whole_text.end(), text_buffer.begin(), text_buffer.end());
			}

		}
	}
	return whole_text;
}


std::vector<std::vector<uint8_t>> Pdf::ExtractFile(){ //TODO
	auto accepted_keys = kFileAcceptedKeys;
	auto rejected_attributes = kNonFileAttributes;
	auto rejected_dictionary = kNonFileDictionary;

	std::vector<std::vector<uint8_t>> all_files {};

	for (auto map_obj: objects) {

		auto id = map_obj.first;
		auto obj = map_obj.second;
	    auto flag = obj_ref[id];

	    bool is_rejected_dict{false};
	    bool is_accepted_keys{false};
	    for (auto key: obj.GetDictionary()->values) { // Todo verify object 66
	    	if (rejected_dictionary.end() != std::find(rejected_dictionary.begin(),
	    			rejected_dictionary.end(), key.second)) {
	    		is_rejected_dict = true;
	    		break;
	    	}
	    	if (accepted_keys.end() != std::find(accepted_keys.begin(), accepted_keys.end(), key.first)) {
	    		is_accepted_keys = true;
	    		break;
	    	}
	    }

	    bool is_rejected_attributes =
	    		rejected_attributes.end() != std::find(rejected_attributes.begin(), rejected_attributes.end(), flag);

	    //  Has stream AND not in rejected dictionary AND not in rejected attribute AND
	    // (accepted attribures OR flag is not empty)
	    // not in rejected attributes)
	    if (obj.HasStream() && !is_rejected_dict && !is_rejected_attributes &&
	    		(is_accepted_keys || (flag != ""))) {

	    	if (obj.ExtractStream((obj.GetDictionary())->values[kFilterTagBegin])) {
				auto temp = obj.GetDecodedStream();
				all_files.push_back(obj.GetDecodedStream());
			}
		}
	}

	return all_files;
}


size_t Pdf::Size(){
	return objects.size();
	}


} // !extern "C"

} // !namespace pdfparser

