
#ifndef PDFPARSER_H_
#define PDFPARSER_H_

#include <iostream>
#include <cstdio>
#include <string>
#include <stdlib.h>
#include <stdint.h>
#include <cstring>


class PDFParser {
public:
	PDFParser();
	virtual ~PDFParser();
	std::string  ExtractText( const char* filepath  );
	
public:
	std::string extract_text_buffer(const uint8_t *, size_t);
	//char *output_buffer;
	//std::string output_buffer;

private:
	std::string  exc_ExtractText( const char* filepath );
	std::string exc_extract_text_buffer(const uint8_t *, size_t);

};

#endif /* PDFPARSER_H_ */
