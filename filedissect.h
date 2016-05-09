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

#ifndef FILEDISSECT_H
#define FILEDISSECT_H

#include <sstream>
#include <vector>
#include <string>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "filedata.h"

#define THRESHOLD 600
#define WORD_THRESHOLD 45
#define ENTROPY_THRESHOLD 5.0434
#define MIN_IC 0.0403106


class FileDissect {
  public:
    FileDissect();
    virtual ~FileDissect();

    int GetFileTypeBuf(const char* buf, size_t);
    std::string GetFileTypeStr(int fIx);

  public:
	int GetBufferType (const uint8_t*, size_t);
	
	bool is_officex(int);
    bool is_pcap(int);
    bool is_unclassified(int);
    bool is_tar(int);
    bool is_xml(int);
    bool is_open_document_format(int);
    bool is_php(int);
    bool is_rar(int);
    bool is_win_exe(int);
    bool is_html(int);
    bool is_gzip(int);
    bool is_pdf(int);
    bool is_office(int);
    bool is_image(int);
    bool is_archive(int);

  private:
    void GetBufHex(char *dest, const char *src, int threshold, int *ispe);

    int CalcMaxLength();
    bool isTextBuffer(const char *, int);
    bool isBufEncrypted(const char *, size_t);
    int findLongestWord(const char *, int);
    double calculateBufferEntropy(const char *, int);
    float indexOfCoincidence(const char *, int);

    size_t findRes;
    size_t theLen;
    std::string hexStr;
    std::stringstream ss;
    std::string theSubStr; 
    FileData *myfdata;
    
};


#endif
