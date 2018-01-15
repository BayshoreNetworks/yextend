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

#ifndef PDF_OBJECT_H_
#define PDF_OBJECT_H_

//#define DEBUG

#include <stdint.h>

#include <cstddef>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace pdfparser {

    extern "C" {

        #define DEFLATE_BUFFER_MULTIPLIER		10
        #define EXTRACT_TEXT_BUFFER_SIZE		2
        #define TEXT_BLOCK_START				"BT"
        #define TEXT_BLOCK_END					"ET"

        struct Dictionary {
	        std::unordered_map<std::string, std::string> values;
	        std::unordered_map<std::string, Dictionary*> dictionaries;
        };

        struct DictionaryBoundaries {
	        const uint8_t* start{nullptr};
	        const uint8_t* end{nullptr};
        };

        const std::vector<std::string> kFilterDictionary {
	        "ASCIIHexDecode",
	        "ASCII85Decode",
	        "LZWDecode",
	        "FlateDecode",
	        "RunLenghtDecode",
	        "CCITTFaxDecode",
	        "JBIG2Decode",
	        "DCTDecode",
	        "JPXDecode",
	        "Crypt"
        };

        const std::vector<std::string> kTextDictionary { // BS-25. Dismiss no text stream objects (/Length1)
	        "Contents"
	    };

        const std::vector<std::string> kNonTextDictionary { // BS-25. Dismiss no text stream objects (/Length1)
	        "Length1",
	        "Length2",
	        "Length3",
	        "DL",
	        "EmbeddedFile"
	    };

        const std::vector<std::string> kNonTextAttributes { // BS-25. Dismiss no text stream objects (/Length1)
	        "ToUnicode",
	        "FontFile2"
	    };

        const std::vector<std::string> kFileFlag { // BS-26. Detach from PDF attachments specified as files.
	        "DL",
	        "EmbeddedFile"
	    };

        const std::vector<std::string> kNonFileAttributes { // BS-26. Detach from PDF attachments specified as files.
	        "Contents"
	    };

        const std::vector<std::string> kNonFileDictionary { // BS-26. Detach from PDF attachments specified as files.
	        "ObjStm",
	        "XObject",
	        "XML",
	        "Xref"
        };

        class PdfObject {
	        const std::string kObjBegin			{"obj"};	// Flag to start of 'obj' section
	        const std::string kObjEnd			{"endobj"}; // Flag of end of 'obj' section

	        const std::string kFilterTagBegin	{"/Filter"}; // Flag of begin of 'Filter' section
	        const std::string kFilterTagEnd		{">>"};
	        const std::string kDictionaryBegin	{"<<"};
	        const std::string kDictionaryEnd	{">>"};

	        const std::string kStreamBegin		{"stream"}; // Flag of begin of 'stream' section
	        const std::string kStreamEnd		{"endstream"}; // Flag of end of 'stream' section

	        const char* kPdfEol1 = "\n";
	        const char* kPdfEol2 = "\r\n";

	        std::string id{};
	        Dictionary dictionary;

	        //TODO Use structs instead of isolated members
	        const uint8_t*	pdf_object{nullptr};		// Pointer to the start of 'obj' object
	        size_t			object_size{0};				// The size of 'obj' object

	        const uint8_t* dictionary_start{nullptr};
	        const uint8_t* dictionary_end{nullptr};

	        const uint8_t*	stream_start{nullptr};			// Pointer to the start of stream part in uint8_t*
	        const uint8_t*	stream_end{nullptr};			// Pointer to the end of stream part in uint8_t*
	        size_t			stream_size{0};

	        std::vector<uint8_t> decoded_stream_vector{};
	        uint8_t*			decoded_stream{nullptr};
	        size_t				decoded_stream_size{0};
	        size_t				text_size{0};
	        std::vector<uint8_t> parsed_text{};

	        std::vector<uint8_t> file{};				// extracted file

	        std::vector<std::string> filters{};

	        void GetFilters();
	        void GetStream();
	        void FlateLZWDecode();
	        void UnfoldDictionary(Dictionary* dictionary, const uint8_t* begin, const uint8_t* end);
	        DictionaryBoundaries GetDictionaryBoundaries (const uint8_t* begin, const uint8_t* end);

        public:
	        PdfObject(const uint8_t* buffer, size_t size);
	        ~PdfObject();

	        std::string GetId();
	        Dictionary* GetDictionary();
	        bool ExtractStream(std::string filter);
	        std::vector<uint8_t> GetDecodedStream();
	        void TextParser();
	        const uint8_t* GetObjectEnd();
	        bool HasStream();
        };

    } // !extern "C"

} // !namespace pdfparser

#endif /* PDF_OBJECT_H_ */
