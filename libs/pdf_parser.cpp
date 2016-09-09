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

static std::string get_stdout_cmd(std::string lcmd) {

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

PDFParser::PDFParser(const uint8_t *buffer, size_t buffer_length) {
	
    char *input_filename = NULL;
    char *input_filepath = NULL;
    char *output_filename = NULL;
    char *output_filepath = NULL;
    
    size_t tmp_path_len = strlen(tmp_path);
    size_t uuid_len = 32;
    uuid_t id;
    
    //////////////////////////////////////////////////////////
    uuid_generate(id);
    input_filename = new char[uuid_len + tmp_path_len];
    uuid_unparse(id, input_filename);
    input_filepath = new char[tmp_path_len + strlen(input_filename)];
    strcpy(input_filepath, tmp_path);
    strcat(input_filepath, input_filename);
    // write original buffer to file
    std::ofstream fp;
    fp.open(input_filepath, std::ios::out | std::ios::binary );
    fp.write((char*)buffer, buffer_length);
    fp.close();
    //////////////////////////////////////////////////////////
    uuid_generate(id);
    output_filename = new char[uuid_len + tmp_path_len];
    uuid_unparse(id, output_filename);
    output_filepath = new char[tmp_path_len + strlen(output_filename)];
    strcpy(output_filepath, tmp_path);
    strcat(output_filepath, output_filename);
    
	// set class variables
	stored_file_name = std::string(input_filepath, strlen(input_filepath));
	buf_len = buffer_length;
	extracted_file_name = std::string(output_filepath, strlen(output_filepath));
	
	// clean up local vars
    delete input_filename;
    delete input_filepath;
    delete output_filename;
    delete output_filepath;
    
}

PDFParser::~PDFParser() {
	// should we shred here instead?
	remove(stored_file_name.c_str());
	remove(extracted_file_name.c_str());
}

std::string PDFParser::ExtractText( const char* filepath  )
{
    return exc_ExtractText (filepath);
}

std::string PDFParser::exc_ExtractText( const char* filepath  )
{
    char *output_filename = NULL;
    char *output_filepath = NULL;
    char *cmd = NULL;

    try {
    	// 36 + 1
        output_filename = new char[37];
        uuid_t id;
        uuid_generate(id);
        uuid_unparse(id, output_filename);
        // 5+strlen(output_filename)+1
        output_filepath = new char[6 + strlen(output_filename)];
        strcpy(output_filepath, tmp_path);
        strcat(output_filepath, output_filename);

        cmd = new char[12 + strlen(filepath) + strlen(output_filepath)];
        strcpy(cmd, pdf_to_text);
        strcat(cmd, " ");
        strcat(cmd, filepath);        
        strcat(cmd, " ");        
        strcat(cmd, output_filepath);        
        system(cmd);
        std::ifstream ifs(output_filepath);
        std::string content( (std::istreambuf_iterator<char>(ifs) ),
            (std::istreambuf_iterator<char>()) );
        remove(output_filepath);
        
        delete output_filename;
        delete output_filepath;
        delete cmd;

        return content;
    
    } catch (std::exception e) {
        
        if(output_filename){delete output_filename;}
        if(output_filepath){delete output_filepath;}
        if(cmd){delete cmd;}
        remove(output_filepath);
        
        syslog (LOG_INFO|LOG_LOCAL6, "PDFParser encountered fatal error");
        return "";
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

        delete cmd;        
        return content;
    } catch (std::exception e) {

        if(cmd) {delete cmd;}

        syslog (LOG_INFO|LOG_LOCAL6, "PDFParser encountered fatal error");
        return "";
    }
}


int PDFParser::has_embedded_files(const uint8_t *) {
	
	std::cout << get_stdout_cmd("pdfdetach -list test_files/lipsum.txt.pdf") << std::endl;
	return 1;
	
}

