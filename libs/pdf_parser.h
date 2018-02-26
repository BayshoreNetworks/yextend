/*
 * pdfparser.h
 *
 *  Created on: Nov 29, 2017
 *      Author: rodrigo
 */

#ifndef PDF_PARSER_H_
#define PDF_PARSER_H_

#include <stdint.h>

#include <cstddef>
#include <vector>

#include "pdf.h"
#include "pdf_text_encoding.h"

namespace pdfparser {

extern "C" {


using PDF_DETACH = std::vector<std::vector<uint8_t>>;


std::vector<uint8_t> PdfToText (const uint8_t* pdf_start, size_t pdf_size, pdfparser::TextEncoding encoding = TextEncoding::raw);

PDF_DETACH PdfDetach (const uint8_t* pdf_start, size_t pdf_size);

} // !extern "C"

} // !namespace pdfparser

#endif /* PDF_PARSER_H_ */
