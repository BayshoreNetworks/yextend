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


namespace pdfparser {

extern "C" {


/**
 * @brief Returns the position of the first needle in the haystack
 * @param haystack
 * @param needle
 * @param haystack_size
 * @return size_t position in haystack where needle is located
 */
size_t FindStringInBuffer (const uint8_t* haystack, const char* needle, const size_t haystack_size) {
	auto haystack_index = haystack;

	size_t needle_length = std::char_traits<char>::length(needle);

	bool found = false;
	while (!found) {
		found = true;
		for (size_t i=0; i<needle_length; ++i) {
			if (haystack_index[i]!=needle[i]) {
				found = false;
				break;
			}
		}
		if (found) return haystack_index - haystack;
		haystack_index++;
		if (haystack_index - haystack + needle_length >= haystack_size){
			return std::string::npos;
		}
	}
	return std::string::npos;
}


size_t FindStringInBufferReverse (const uint8_t* haystack, const char* needle, const size_t haystack_size) {
	auto haystack_index = haystack+haystack_size;

	size_t needle_length = std::char_traits<char>::length(needle);

	bool found = false;
	while (!found) {
		found = true;
		for (size_t i=1; i<needle_length; ++i) { //Starts in 1 to avoid '/0' at the end of needle. Length is 1 based and needle is 0 based
			if (haystack_index[-i]!=needle[needle_length-i]) { // reversed direction
				found = false;
				break;
			}
		}
		if (found) return haystack_index - haystack;
		--haystack_index;
		if (haystack_index - haystack - needle_length == 0){ // Begin of haystack reached
			return std::string::npos;
		}
	}
	return std::string::npos;
}


/**
 * @brief Splits the string in 'quantity' pieces using delim as delimiter
 * @param string	is the string to be splitted
 * @param delim		string is splitted using this char as delimiter
 * @param quantity	is the quantity of splits. 1 return de first split and the rest. If std::string::npos it splits the whole string
 * @return
 */
std::vector<std::string> SplitString(std::string const & string, char delim, size_t quantity=std::string::npos)
{
    std::vector<std::string> result;
    std::istringstream iss(string);

    std::string token;
    while (std::getline(iss, token, delim) && quantity > 0)
    //for (std::string token; std::getline(iss, token, delim); )
    {
    	result.push_back(std::move(token));
    	quantity--;
    }
    if (quantity == 0){
    	result.push_back(std::move(token));
    }
    return result;
}

/**
 * @brief	Splits the string by any of the characters included in delim
 * @param string
 * @param delim
 * @return
 */
std::vector<std::string> SplitStringAnyChar(std::string const & string, std::string const & delim, size_t quantity) {
	std::vector<std::string> word_vector{};
	std::stringstream stringStream(string);
	std::string line;

	while(std::getline(stringStream, line)) {
		std::size_t prev = 0, pos;

		while (((pos = line.find_first_of(delim, prev)) != std::string::npos) && (quantity >0))
		{
			if (pos > prev) {
				word_vector.push_back(line.substr(prev, pos-prev));
				--quantity;
			}
			prev = pos+1;
		}
		if ((prev < line.length()) || (quantity == 0))
			word_vector.push_back(line.substr(prev, std::string::npos));
	}

	return word_vector;
}


} // !extern "C"

} // !namespace pdfparser
