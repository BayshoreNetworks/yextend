/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * Copyright (C) 2014-2015 by Bayshore Networks, Inc. All Rights Reserved.
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

#ifndef FILEDATA_H
#define FILEDATA_H


#include <map>
#include <string>


extern std::map<std::string, int> FileDataPatterns;
extern std::map<int, int> FileDataPatternOffset;



class FileData {
  public:
    FileData();
	std::map<int, std::string> xpatternmap;
	std::map<std::string, int> xpatterns;
    std::string GetType(int ix);
	std::map<int, int> xpattern_offset;
    
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
    bool is_zip(int);
    bool is_matlab(int);
    bool is_7zip(int);

};



#endif
