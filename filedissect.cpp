/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * This file is part of yextend.
 *
 * Copyright (c) 2104-2016, Bayshore Networks, Inc.
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

#include "filedissect.h"

#include <iostream>

#include <math.h>
#include <sys/stat.h>

using namespace std;


static bool ComputeCoincidenceIndex (const char*, size_t, double*);

void *bayshoresubstring(size_t start, size_t stop, const char *src, char *dst, size_t size)
{
	int count = stop - start;
	if ( count >= --size ) {
		count = size;
	}
	sprintf(dst, "%.*s", count, src + start);
}

bool does_file_exist (const char *fn)
{
        struct stat st;
        return ( fn && *fn && (stat (fn, &st) == 0) && (S_ISREG(st.st_mode)) );
}


FileDissect::FileDissect() { 
     
    findRes = 0;
    theLen = 0;
    hexStr = "";
    theSubStr = "";

    myfdata = new FileData();
}

FileDissect::~FileDissect()
{
	if (myfdata)
		delete myfdata;
}

/**********************
FileDissect::GetBufHex
**********************/


void FileDissect::GetBufHex(char *dest, const char *src, int threshold, int *ispe)
{
    int i;
    //int offs = 0;
    /*
    	hex for PE\0\0 - identifier for a 
    	windows portable executable
    */
    const char pestr[] = "50450000";
    char * pt;
    static const char *hexdigits = "0123456789abcdef";

    for(i = 0; i < threshold; i++)
    {
        unsigned char u = (unsigned char)(src[i]);
        dest[i*2] = hexdigits [u >> 4];
        dest[(i*2)+1] = hexdigits [u & 0xf];
    }
    dest[i*2] = '\0';
    // look for the PE header
    pt = strstr(dest, pestr);
    if( pt != NULL )
    {
        *ispe = 1;
    }
}


/**************************
FileDissect::CalcMaxLength
**************************/


int FileDissect::CalcMaxLength() {
	int theLen = 0;
	map<string, int>::iterator hash_it;
	
    std::pair<std::string, int> keyval;
    for(hash_it = FileDataPatterns.begin(); hash_it != FileDataPatterns.end(); ++hash_it){
        keyval = *hash_it;
        if (keyval.first.length() > theLen)
        	theLen = keyval.first.length();
    }
    return theLen;
}


/****************************
FileDissect::findLongestWord
****************************/


int FileDissect::findLongestWord(const char *contents, int bsize)
{
	int counter = 0;
	int max_word = -1;
	int position = 0;

	for(int i = 0; i < bsize; i++)
	{
		/*
		 * Do NOT factor the following entities in to the
		 * count that will make up the longest word/string
		 * discovered:
		 * 
		 * 		line feed - \n - 0x0a
		 * 		carriage return - \r - 0x0d
		 * 		tab - \t - 0x09
		 * 		space - ' '
		 * 
		 */
		if ((contents[i] == 0x0a) || (contents[i] == 0x0d) || (contents[i] == 0x09) || (contents[i] == ' '))
		{
			if (counter > max_word)
			{
				max_word = counter;
				position = i;
			}
			counter = 0;
		}
		else if(contents[i] != ' ')
		{
			counter++;
		}
	}
	return max_word;
}


/***********************************
FileDissect::calculateBufferEntropy
***********************************/


double FileDissect::calculateBufferEntropy(const char * content, int size)
{
	double entropy = 0.0;
	if (size == 0)
		return entropy;
	
	if (size)
	{
		uint8_t byte = 0;
		long byteCounts[256];
		memset(byteCounts, 0, sizeof(long) * 256);
		
		for (int i = 0; i < size; ++i)
		{
			byte = static_cast<uint8_t>(content[i]);
			byteCounts[byte]++;
		}
	
		
		for (int i = 0; i<256; ++i)
		{
			double p = static_cast<double>(byteCounts[i]) / (double)size;
			if (p > 0.0)
			{
				entropy -= p * (log(p) / log(2.0));
			}
		}
	}
	return entropy;
}


/*******************************
FileDissect::indexOfCoincidence
*******************************/


float FileDissect::indexOfCoincidence(const char * contents, int size)
{
	int ctr = size;
	double clen = 0;
	int freq[26];

	for (int i = 0; i < 26; ++i)
		freq[i] = 0;

	for (int i = 0; i < ctr; ++i)
	{
		// if this was using lowercase
		//if(code[i] < 0x61 || code[i] > 0x7a)
		// we are in uppercase
		//if(code[i] < 0x41 || code[i] > 0x5a)
		if(contents[i] < 0x41 || contents[i] > 0x5a)
			continue;
		++clen;
		// we are in uppercase
		++freq[contents[i] - 65];
		// if this was using lowercase
		//++freq[code[i] - 97] ;
	}

	long double ic = 0 ;
	for (int i = 0; i < 26; ++i){
		ic += freq[i] * (freq[i] - 1) ;
	}

	return (ic/(clen * (clen-1)));
}


/***************************
FileDissect::isBufEncrypted
***************************/


bool FileDissect::isBufEncrypted(const char* buf, size_t nL)
{
	int score = 0;
	if (buf && (nL > 0)) {
    	
    	int lword = findLongestWord(buf, nL);
    	if (lword > WORD_THRESHOLD)
    	{
    		score += 1;
    	}
    	
    	double bufferEntropy = calculateBufferEntropy(buf, nL);
    	if (bufferEntropy > ENTROPY_THRESHOLD)
    	{
    		score += 1;
    	}
    	
		double ci;
		if (ComputeCoincidenceIndex (buf, nL, &ci)  && (ci < MIN_IC))
			++score;
    }
	if (score >= 2)
		return true;
	return false;
}


/***************************
FileDissect::GetFileTypeBuf
***************************/


/*
 * GetFileTypeBuf will try to identify a file type
 * based on a small buffer passed in (buf) as
 * opposed to us having to open up the actual
 * file to extract the data to compare against
 * for the purpose of identification
 * pass in at least 600 bytes so that we can
 * look for PE headers in executables
 */
int FileDissect::GetFileTypeBuf(const char* buf, size_t n) {
	
    int zipException = -1;
    int xmlException = -1;
    int theLen;
    size_t threshold = n;
    if (threshold >= THRESHOLD) {
    	threshold = THRESHOLD;
    }
    
    char hexStr[threshold * 2 + 1];
    int isPe = 0;
    GetBufHex(hexStr, buf, threshold, &isPe);

	map<string, int>::iterator hash_it;
    std::pair<std::string, int> keyval;

    for(hash_it = FileDataPatterns.begin(); hash_it != FileDataPatterns.end(); ++hash_it){
        keyval = *hash_it;
        theLen = keyval.first.length();
        char thesubstr[theLen+1];
        int the_offset = 0;

        // put substring into buffer thesubstr
        if ((FileDataPatternOffset[keyval.second] * 2) > 0)
        	the_offset = FileDataPatternOffset[keyval.second] * 2;
        
        if ((the_offset + theLen + 1) <= strlen(hexStr)) {
			bayshoresubstring(the_offset, theLen+1, hexStr, thesubstr, sizeof thesubstr);

			// look for a match with buffer using string.compare
			if (keyval.first.compare(0, theLen, thesubstr, theLen) == 0) {
				/*
				 * exception for zip
				 * so many formats use zip under the hood that
				 * if we return now we may miss details that
				 * provide greater accuracy in the detection
				 * pattern
				 */

				if (keyval.second == 65534) {
					zipException = keyval.second;
					continue;
				}

				if (keyval.second == 15) {
					zipException = 15;
				} else if ((keyval.second == 31) ||
						(keyval.second == 32)) { // php/xml exception
					xmlException = 31;
				} else if ((keyval.second == 26) ||
						(keyval.second == 27)) {
					if (isPe == 1) {
						return 26000;
					} else {
						return keyval.second;
					}
				} else {
					return keyval.second;
				}
			}
        }
    }

    /*
     * if we got here and nothing was detected, plus the zip format
     * WAS detected, then return zip or jar as the return type, otherwise
     * return the default unclassified binary - 65535
     */
	if (zipException != -1)
		return zipException;
	
	// we have php, or is it xml??
	if (xmlException != -1) {
		char thesubstr[11];
		// xml = len 10 in hex 
		bayshoresubstring(0, 11, hexStr, thesubstr, sizeof thesubstr);
		// it is xml
		if (strncmp (thesubstr, "3c3f786d6c", 10) == 0)
			return 45;
        else
        	return xmlException;
	}
	
	if (isBufEncrypted(buf, n))
		return 0;
	
    if (isTextBuffer(buf, threshold))
    	return 29;

	return 65535;

}


/*************************
FileDissect::isTextBuffer
*************************/


bool FileDissect::isTextBuffer(const char *buf, int t) {
	/*
	 * there is no real safe and sure way to
	 * detect that a file is pure ASCII text
	 * in nature. This will have to suffice
	 * for now
	 */
	for(int i = 0; i < t; i++)
	{
		if ((int)buf[i] < 0x20)
		{
            if ((buf[i] != '\n') && (buf[i] != '\r') && (buf[i] != '\t')) {
            	return false;
            }
		}
		if ((int)buf[i] > 0xff)
			return false;
	}
	return true;
}


/***************************
FileDissect::GetFileTypeStr
***************************/


std::string FileDissect::GetFileTypeStr(int fIx) {
	return myfdata->GetType(fIx);
}

/**************************
FileDissect::GetBufferType
**************************/


int FileDissect::GetBufferType (const uint8_t *data, size_t size)
{
	/* 
	 * Alternate entry point for callers that know how much data they have
	 * for us to inspect.
	 */
	if (!data)
		return 65535;
	return GetFileTypeBuf ((const char*)data, size);
}


/***********************
ComputeCoincidenceIndex
***********************/

bool ComputeCoincidenceIndex (const char *buf, size_t sz, double *retval)
{
	/* TODO, there are a number of edge cases in here, including
	 * bad parameters and numerical problems like divisions by zero.
	 * In case of an error, what should we return? Should it be a
	 * low value that signals high entropy to the caller? Or should
	 * it be a high number that signals low entropy?
	 * To avoid this problem, we return a truth value, and place
	 * the computed index (if any) in the caller's parameter.
	 */

	bool ok = false;

	if (buf && sz && retval) {

		// Only look at the first 1meg. This reduces accuracy but
		// renders performance acceptable.
		if (sz > 1000000)
			sz = 1000000;

		uint64_t n_chars = 0;
		uint64_t freq[256]; // use 256 instead of 26 to avoid segfault in case of bugs
		memset (freq, 0, sizeof(freq));

		while (sz--) {
			if (isalpha (*buf)) {
				++freq[ toupper(*buf) ];
				++n_chars;
			}
			++buf;
		}


		double ic = 0.0;
		for (int i = 'A'; i <= 'Z'; ++i)
			ic += double(freq[i]) * double((freq[i] - 1));

		if (n_chars > 1) {
			*retval = ic / ((double)n_chars * (double)(n_chars-1));
			ok = true;
		}
	}

	return ok;

}


/**********
is_officex
**********/

bool FileDissect::is_officex(int fIx) {
	return myfdata->is_officex(fIx);
}

/*******
is_pcap
*******/

bool FileDissect::is_pcap(int fIx) {
	return myfdata->is_pcap(fIx);
}

/***************
is_unclassified
***************/

bool FileDissect::is_unclassified(int fIx) {
	return myfdata->is_unclassified(fIx);
}

/******
is_tar
******/

bool FileDissect::is_tar(int fIx) {
	return myfdata->is_tar(fIx);
}

/******
is_xml
******/

bool FileDissect::is_xml(int fIx) {
	return myfdata->is_xml(fIx);
}

/***********************
is_open_document_format
***********************/

bool FileDissect::is_open_document_format(int fIx) {
	return myfdata->is_open_document_format(fIx);
}

/******
is_php
******/

bool FileDissect::is_php(int fIx) {
	return myfdata->is_php(fIx);
}

/******
is_rar
******/

bool FileDissect::is_rar(int fIx) {
	return myfdata->is_rar(fIx);
}

/**********
is_win_exe
**********/

bool FileDissect::is_win_exe(int fIx) {
	return myfdata->is_win_exe(fIx);
}

/*******
is_html
*******/

bool FileDissect::is_html(int fIx) {
	return myfdata->is_html(fIx);
}

/*******
is_gzip
*******/

bool FileDissect::is_gzip(int fIx) {
	return myfdata->is_gzip(fIx);
}

/******
is_pdf
******/

bool FileDissect::is_pdf(int fIx) {
	return myfdata->is_pdf(fIx);
}

/*********
is_office
*********/

bool FileDissect::is_office(int fIx) {
	return myfdata->is_office(fIx);
}

/********
is_image
********/

bool FileDissect::is_image(int fIx) {
	return myfdata->is_image(fIx);
}

/**********
is_archive
**********/

bool FileDissect::is_archive(int fIx) {
	return myfdata->is_archive(fIx);
}

