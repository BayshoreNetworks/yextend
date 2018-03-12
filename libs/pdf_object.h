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

#ifndef OBJECT_H_
#define OBJECT_H_

#include <stdint.h>

#include <cstddef>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "pdf_font.h"
#include "pdf_text_encoding.h"


namespace pdfparser {

extern "C" {

#define DEFLATE_BUFFER_MULTIPLIER		10
#define EXTRACT_TEXT_BUFFER_SIZE		2  //2 needed for BT and ET
//#define EXTRACT_TEXT_OCTAL_BUFFER_SIZE	3
#define TEXT_BLOCK_START				"BT"
#define TEXT_BLOCK_END					"ET"
#define TEXT_FONT						"/F"
#define TEXT_FONT_MAX_SIZE				4	// including "/F"
#define TEXT_PRINT_ARRAY				"TJ" // Command in BT/ET block to print array []
#define TEXT_PRINT_LITERAL				"Tj" // Command in BT/ET block to print literal (). Also ' and " TODO

const std::string kDictionaryBegin	{"<<"};
const std::string kDictionaryEnd	{">>"};

const std::string kToUnicode		{"/ToUnicode"};
const std::string kFilterTagBegin	{"/Filter"}; // Flag of begin of 'Filter' section

struct Dictionary {
	std::unordered_map<std::string, std::string> values; // Stores the key-value pairs of a certain dictionary
	std::unordered_map<std::string, Dictionary*> dictionaries; // Stores the key-dictionary pairs of a certain dictionary

	std::string IndirectReference();
};

struct DictionaryBoundaries {
	const uint8_t* start{nullptr};
	const uint8_t* end{nullptr};
};


const std::vector<std::string> kFilterDictionary{
	"/ASCIIHexDecode",
	"/ASCII85Decode",
	"/LZWDecode",
	"/FlateDecode",
	"/RunLenghtDecode",
	"/CCITTFaxDecode",
	"/JBIG2Decode",
	"/DCTDecode",
	"/JPXDecode",
	"/Crypt"};

const std::vector<std::string> kTextDictionary{ // BS-25. Dismiss no text stream objects (/Length1)
	"/Contents"
	};

const std::vector<std::string> kNonTextDictionaryKeys{ // BS-25. Dismiss no text stream objects (/Length1)
	"/Length1",
	"/Length2",
	"/Length3",
	"/DL",
	"/EmbeddedFile" // This is not a /key, it is a value
	};

const std::vector<std::string> kNonTextAttributes{ // BS-25. Dismiss no text stream objects (/Length1)
	"/ToUnicode",
	"/FontFile2"
	};

const std::vector<std::string> kFileAcceptedKeys{ // BS-26. Detach from PDF attachments specified as files.
	"/DL",
	"/EmbeddedFile"
	};

const std::vector<std::string> kNonFileAttributes{ // BS-26. Detach from PDF attachments specified as files.
	"/Contents",
	"/ToUnicode",
	"/FontFile2"
	};

const std::vector<std::string> kNonFileDictionary{ // BS-26. Detach from PDF attachments specified as files.
	"/ObjStm",
	"/XObject",
	"/XML",
	"/XRef"
	};

// These operators inside a BT/ET block shall reset the array and literal buffers
// i.e., the information in those buffers are related to these operators and have not
// be considered as text
const std::vector<std::string> kTextResetingOperators {
	"Tc", "Tw", "Tz", "TL", "Tf", "Tr", "Ts", 	// Text state operators
	"Td", "TD", "Tm", "T*"						// Text positioning operators
	};


class PdfObject {
	const std::string kObjBegin			{"obj"};	// Flag to start of 'obj' section
	const std::string kObjEnd			{"endobj"}; // Flag of end of 'obj' section

	const std::string kNameTagBegin		{"/"};

	const std::string kFilterTagEnd		{">>"};

	const std::string kArrayTagBegin	{"["};

	const std::string kStreamBegin		{"stream"}; // Flag of begin of 'stream' section
	const std::string kStreamEnd		{"endstream"}; // Flag of end of 'stream' section

	const std::string kFontTagBegin		{"/Font"}; // Indicates the font definition begin

	const char* kPdfEol1 = "\n";
	const char* kPdfEol2 = "\r\n";


	std::string id{};
	Dictionary dictionary{};

	//TODO Use structs instead of isolated members
	const uint8_t*	pdf_object{nullptr};		// Pointer to the start of 'obj' object
	size_t			object_size{0};				// The size of 'obj' object

	const uint8_t* dictionary_start{nullptr};	// Root dictionary
	const uint8_t* dictionary_end{nullptr};		// Root dictionary

	const uint8_t*	stream_start{nullptr};		// Pointer to the start of stream part in uint8_t*
	const uint8_t*	stream_end{nullptr};		// Pointer to the end of stream part in uint8_t*
	size_t			stream_size{0};

	std::vector<uint8_t> 	decoded_stream_vector{}; // Stream after decode (eg. FlateDecode)
	size_t					text_size{0};
	std::vector<uint8_t>	parsed_plain_text{};		// BOM for Little Endian {0xff, 0xfe}. Not needed if endianess is specified en conversion;
	std::string				parsed_plain_text_utf8{};

	std::vector<uint8_t> file{};				// extracted file

	std::vector<std::string> filters{};


	void GetFilters();
	void GetStream();
	void ParseTextArray(std::string& array, Font& font);
	std::string ParseTextLiteral(std::string& text);
	void FlateLZWDecode();
	DictionaryBoundaries GetDictionaryBoundaries (const uint8_t* begin, const uint8_t* end);

public:
	PdfObject(const uint8_t* buffer, size_t size);
	PdfObject();
	~PdfObject();

	std::string GetId();
	Dictionary* GetDictionary();
	bool ExtractStream(std::string filter);

	/**
	 * @brief	Examines the dictionary of the object looking for /Font definition and return it if it exist
	 * @example Returns "65 0" doing reference to 65 0 R where Font is stored or "/F1 5 0 R" in the case font definition embedded
	 * @param pointer to a dictionary struct
	 * @return string containing /Font definition reference information. Empty string otherwise
	 */
	std::string ExtractFontDefinition(Dictionary* dictionary);

	void UnfoldDictionary(Dictionary* dictionary, const uint8_t* begin, const uint8_t* end);

	std::vector<uint8_t> GetDecodedStream();

	/**
	 * @brief Once stream is decoded, it parses the contained text inside BT/ET blocks applying fonts
	 * @param fonts Maps of fonts to translate chars from CID to Unicode when necessary
	 */
	void ParseText(std::map<std::string, Font>& fonts);

	std::vector<uint8_t> GetParsedPlainText(TextEncoding encoding);
	const uint8_t* GetObjectEnd();
	bool HasStream();
};


} // !extern "C"

} // !namespace pdfparser


#endif /* OBJECT_H_ */
