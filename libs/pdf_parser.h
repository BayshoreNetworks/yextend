
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
	PDFParser(const uint8_t *, size_t);
	virtual ~PDFParser();
	std::string ExtractText( const char* filepath  );
	
public:
	std::string extract_text_buffer();
	int has_embedded_files(const uint8_t *);

private:
	std::string exc_ExtractText( const char* filepath );
	std::string exc_extract_text_buffer();

	std::string stored_file_name;
	size_t buf_len;
	std::string extracted_file_name;
};

#endif /* PDFPARSER_H_ */
