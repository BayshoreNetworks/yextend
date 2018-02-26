/*
 *
 *  Created on: Nov 29, 2017
 *      Author: rodrigo
 */

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

	void GetXref();
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
