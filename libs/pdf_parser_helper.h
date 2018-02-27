/*
 * parser.h
 *
 *  Created on: Nov 29, 2017
 *      Author: rodrigo
 */

#ifndef PARSER_HELPER_H_
#define PARSER_HELPER_H_

#include <stdint.h>

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>



namespace pdfparser {

extern "C" {

size_t FindStringInBuffer (const uint8_t* haystack, const char* needle, const size_t haystack_size);
size_t FindStringInBufferReverse (const uint8_t* haystack, const char* needle, const size_t haystack_size);
std::vector<std::string> SplitString(std::string const & string, char delim, size_t quantity = std::string::npos);

} // !extern "C"

} // !namespace pdfparser


#endif /* PARSER_HELPER_H_ */
