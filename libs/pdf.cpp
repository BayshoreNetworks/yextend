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

        Pdf::Pdf(const uint8_t* buffer, size_t size) {
	        start_pdf = buffer;
	        length_pdf = size;

	        auto current_obj_pointer = buffer;
	        auto current_obj_size = size;

	        while (current_obj_size > 0 && current_obj_size != std::string::npos) {
		        PdfObject pdf_object{current_obj_pointer, current_obj_size};

		        auto id = pdf_object.GetId();
		        objects.emplace(id, pdf_object);

		        BuildObjReference(pdf_object.GetDictionary()); //	Build objects reference library

		        current_obj_size = current_obj_size - (pdf_object.GetObjectEnd() - current_obj_pointer);
		        current_obj_pointer = pdf_object.GetObjectEnd();
	        }
        }

        Pdf::~Pdf() {
	        for (auto obj: objects) {
		        Dictionary* dictionary = obj.second.GetDictionary();
		        if (dictionary->dictionaries.size() > 0)
			        DeleteDictionary(dictionary);
	        }
        }

        void Pdf::DeleteDictionary(Dictionary* dictionary) {
	        for (auto x: dictionary->dictionaries) {
		        DeleteDictionary(x.second);
		        delete x.second;
	        }
        }

        void Pdf::GetXref() {
	        //  It can point to a plain xref object or to a streamed xref object
	        xref_offset = FindStringInBufferReverse(start_pdf, "startxref", length_pdf); // TODO Verify

	        if(memcmp (start_pdf+xref_offset, "xref", 4)){
		        ;} //TODO
        }

        void Pdf::BuildObjReference(Dictionary* dictionary) {
	        const std::string kObjRefRegEx = "^[0-9]+[[:space:]]+[0-9]+"; // for indirect object reference '0 5 R'
	        const std::regex obj_ref_regex {kObjRefRegEx};
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

        std::vector<uint8_t> Pdf::ExtractText() {
	        auto accepted = kFilterDictionary;
	        auto rejected_attributes = kNonTextAttributes;
	        auto rejected_dictionary = kNonTextDictionary;

	        std::vector<uint8_t> text_buffer{};
	        auto whole_text = text_buffer;

	        for (auto map_obj: objects) {
		        auto id = map_obj.first;
		        auto obj = map_obj.second;
	            auto flag = obj_ref[id];

	            bool in_rejected_dict{false};
	            for (auto key: obj.GetDictionary()->values) {
	            	if (rejected_dictionary.end() != std::find(rejected_dictionary.begin(),
	            			rejected_dictionary.end(), key.first)) {
	            		in_rejected_dict = true;
	            		break;
	            	}
	            }

		        if (obj.HasStream() && !in_rejected_dict &&
			        ((accepted.end() != std::find(accepted.begin(), accepted.end(), flag)) || //It is in accepted or
			        (rejected_attributes.end() == std::find(rejected_attributes.begin(), rejected_attributes.end(), flag)))) { //it is not in rejected then process

			        if (obj.ExtractStream((obj.GetDictionary())->values["Filter"])){
				        obj.TextParser();
				        whole_text.insert(whole_text.end(), text_buffer.begin(), text_buffer.end());
			        }
		        }
	        }

	        return whole_text;
        }

        std::vector<std::vector<uint8_t>> Pdf::ExtractFile() { //TODO
	        auto accepted = kFileFlag;
	        auto rejected_attributes = kNonFileAttributes;
	        auto rejected_dictionary = kNonFileDictionary;

	        std::vector<std::vector<uint8_t>> all_files {};

	        for (auto map_obj: objects) {
		        auto id = map_obj.first;
		        auto obj = map_obj.second;
	            auto flag = obj_ref[id];

	            bool in_rejected_dict{false};
	            for (auto key: obj.GetDictionary()->values) { // Todo verify object 66
	            	if (rejected_dictionary.end() != std::find(rejected_dictionary.begin(),
	            			rejected_dictionary.end(), key.second)) {
	            		in_rejected_dict = true;
	            		break;
	            	}
	            }

		        if (obj.HasStream() && !in_rejected_dict &&
			        ((accepted.end() != std::find(accepted.begin(), accepted.end(), flag)) || //It is in accepted or
			        (rejected_attributes.end() == std::find(rejected_attributes.begin(), rejected_attributes.end(), flag)))) { //it is not in rejected then process

			        if (obj.ExtractStream((obj.GetDictionary())->values["Filter"])) {
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
