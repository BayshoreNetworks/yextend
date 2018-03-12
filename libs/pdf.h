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

#ifndef PDF_H_
#define PDF_H_

#include <stdint.h>

#include <cstddef>
#include <string>
#include <map>
#include <vector>

#include "pdf_font.h"
#include "pdf_object.h"
#include "pdf_text_encoding.h"

namespace pdfparser {

extern "C" {



class Pdf {
	const std::string kObjectReferenceRegEx = "^[0-9]+[[:space:]]+[0-9]+"; // for indirect object reference '0 5 R'

	size_t xref_offset{0}; // Offset to start of xref from start_pdf
	std::vector<size_t> xref{}; // Offset of each 'obj' in pdf

	const uint8_t* start_pdf{nullptr};
	size_t length_pdf{0};

	std::unordered_map<std::string, PdfObject> 	objects{};
	std::map<std::string, std::string> 			obj_ref{}; // Map of objects that are the indirect reference for certain dictionary key (
	std::map<std::string, pdfparser::Font>		fonts{}; // Key: Font ID. Value: Font

	//void GetXref();
	void BuildObjReference(Dictionary* dictionary);

	/**
	 * @brief Build the needed Font objects and fill the class attribute fonts.
	 *
	 */
	void BuildFonts(void);
	void DeleteDictionary(Dictionary* dictionary);

public:
	Pdf(const uint8_t* buffer, size_t size);
	~Pdf();

	size_t Size();
	std::vector<uint8_t> ExtractText(TextEncoding encoding);
	std::vector<std::vector<uint8_t>> ExtractFile();
};





} // !extern "C"

} // !namespace pdfparser


#endif /* PDF_H_ */
