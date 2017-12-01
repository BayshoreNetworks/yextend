/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * This file is part of yextend.
 *
 * Copyright (c) 2014-2017, Bayshore Networks, Inc.
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

#include "pdf_parser.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <exception>
#include <uuid/uuid.h>
#include <fstream>
#include <string>

static const char *tmp_path = "/tmp/";
static const char *pdf_to_text = "pdftotext";
static const char *pdf_detach = "pdfdetach";

static std::string get_stdout_cmd(std::string lcmd)
{

	std::string data;
	FILE *stream;
	const int max_buffer = 1024;
	char buffer[max_buffer];
	lcmd.append(" 2>&1");

	stream = popen(lcmd.c_str(), "r");
	if (stream) {
		while (!feof(stream))
			if (fgets(buffer, max_buffer, stream) != NULL)
				data.append(buffer);
		pclose(stream);
	}
	return data;
}

PDFParser::PDFParser(const uint8_t *buffer, size_t buffer_length)
{
    
    size_t uuid_len = 36;
    uuid_t id;
    char uuid_inp[40];
    char uuid_out[40];
    char input_filepath[1024];
    char output_filepath[1024];
    
    //////////////////////////////////////////////////////////
    uuid_generate(id);
    uuid_unparse(id, uuid_inp);
    snprintf(input_filepath, sizeof(input_filepath), "%s%s", tmp_path, uuid_inp);
    // write original buffer to file
    if (buffer && buffer_length) {
        //TODO: Move code out of ctor() into init() method
        std::ofstream fp;
        fp.open(input_filepath, std::ios::out | std::ios::binary );
        fp.write((char*)buffer, buffer_length);
        fp.close();
    }

    //////////////////////////////////////////////////////////
    uuid_generate(id);
    uuid_unparse(id, uuid_out);
    snprintf(output_filepath, sizeof(output_filepath), "%s%s", tmp_path, uuid_out);
    
	// set class variables
	stored_file_name = std::string(input_filepath, strlen(input_filepath));
	buf_len = buffer_length;
	extracted_file_name = std::string(output_filepath, strlen(output_filepath));
}

PDFParser::~PDFParser()
{
	// should we shred here instead?
	if (remove(stored_file_name.c_str()) != 0) {
		std::cout << "Error removing file: " << stored_file_name << std::endl;
	}
	if (remove(extracted_file_name.c_str()) != 0) {
		std::cout << "Error removing file: " << extracted_file_name << std::endl;
	}
	
}

std::string PDFParser::extract_text_buffer()
{
    return exc_extract_text_buffer();
}

std::string PDFParser::exc_extract_text_buffer()
{
    char *cmd = NULL;   
    try {
    	
        char * cmd = new char[12 + stored_file_name.size() + extracted_file_name.size()];
        
        strcpy(cmd, pdf_to_text);
        strcat(cmd, " ");
        strcat(cmd, stored_file_name.c_str());
        strcat(cmd, " ");
        strcat(cmd, extracted_file_name.c_str());
        system(cmd);

        std::ifstream ifs(extracted_file_name.c_str());
        std::string content( (std::istreambuf_iterator<char>(ifs) ),
        		(std::istreambuf_iterator<char>()) );

        delete[] cmd;
        return content;
    } catch (std::exception e) {

        if(cmd) {delete[] cmd;}

        syslog (LOG_INFO|LOG_LOCAL6, "PDFParser encountered fatal error");
        return "";
    }
}


int PDFParser::has_embedded_files()
{
	
	// returns 0 or the number of files detected as emebedded
	char *cmd = new char[8 + strlen(pdf_detach) + stored_file_name.size()];
	
    strcpy(cmd, pdf_detach);
    strcat(cmd, " -list ");
    strcat(cmd, stored_file_name.c_str());
	
    std::string stmp = std::string(get_stdout_cmd(cmd), 0, 3);
    /*
     * we will take 3 bytes above so that should cover some
     * pretty crazy situations cause that represents a lot
     * of attachments.
     * 
     * Might tweak that later to less.
     * 
     * atoi gets rid of chars that don't convert cleanly
     * to int types so no extra work needed there it seems.
     * And if there is no conversion i_auto gets zero
     */
    int i_auto = atoi(stmp.c_str());
    delete[] cmd;
	return i_auto;
}

