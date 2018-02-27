//============================================================================
// Name        : PDFParser.cpp
// Author      : Rodrigo de Francisco
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

/* Include order
Own .h.
C.
C++.
Other libraries' .h files.
Your project's .h files.
*/

#include "pdf_parser.h"

//#include "pdf.h"


extern "C" {

namespace pdfparser {


/**
 *
 * @param pdf_pointer pointer where the pdf is loaded
 * @param pdf_size size of pdf
 * @return vector with decoded text. Text blocks are separated by \n. User should copy the decoded text.
 */
std::vector<uint8_t> PdfToText (const uint8_t* pdf_pointer, size_t pdf_size, pdfparser::TextEncoding encoding) {

	Pdf pdf{pdf_pointer, pdf_size};
	auto text_buffer = pdf.ExtractText(encoding); // TODO BS-54
	return text_buffer;
}


PDF_DETACH PdfDetach (const uint8_t* pdf_pointer, size_t pdf_size) {

	Pdf pdf{pdf_pointer, pdf_size};
	std::vector<std::vector<uint8_t>> file_buffer = pdf.ExtractFile(); // TODO BS-54
	return file_buffer;
}



	// TODO BS-55
	/*
	std::vector<std::vector<uint8_t>> files_buffer{}; // To store files
	auto current_pdf_pointer = pdf_pointer;
	auto current_pdf_size = pdf_size;
	std::vector<std::string> file_obj_pointers{};	// Pointers to objects containing '/Type Filespec'

	//Pdf pdf{current_pdf_pointer, current_pdf_size};

	while (current_pdf_size > 0 && current_pdf_size != std::string::npos){
		PdfObject pdf_object{current_pdf_pointer, current_pdf_size};

		//pdf_object.ExtractFileObjects();
		//current_text = pdf_object.DecodeText(); // Get the actual text



		current_pdf_size = current_pdf_size - (pdf_object.GetObjectEnd() - current_pdf_pointer);
		current_pdf_pointer = pdf_object.GetObjectEnd();
	}
	return std::vector<std::vector<uint8_t>>{};
*/

} // !namespace pdfparser

} // !extern "C"
