/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * Copyright (C) 2014 by Bayshore Networks, Inc. All Rights Reserved.
 *
 * This file is part of yextend.
 *
 * yextend is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * yextend is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with yextend.  If not, see <http://www.gnu.org/licenses/>.
 *
 *****************************************************************************/

#ifndef FILEDISSECT_H
#define FILEDISSECT_H

#include <sstream>
#include <vector>
#include <functional>
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
