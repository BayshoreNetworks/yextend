#include "pdf_parser.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <exception>
#include <uuid/uuid.h>
#include <fstream>
#include <string>

PDFParser::PDFParser() {
}

PDFParser::~PDFParser() {
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
        output_filename = new char[36+1];
        uuid_t id;
        uuid_generate(id);
        uuid_unparse(id, output_filename);
        output_filepath = new char[5+strlen(output_filename)+1];
        strcpy(output_filepath, "/tmp/");
        strcat(output_filepath, output_filename);

        cmd = new char[9+1+strlen(filepath)+1+strlen(output_filepath)+1];
        strcpy(cmd, "pdftotext ");
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

std::string PDFParser::extract_text_buffer(const uint8_t *buffer, size_t buffer_length)
{
    return exc_extract_text_buffer (buffer, buffer_length);
}

std::string PDFParser::exc_extract_text_buffer(const uint8_t *buffer, size_t buffer_length)
{
    char *input_filename = NULL;
    char *input_filepath = NULL;
    char *output_filename = NULL;
    char *output_filepath = NULL;
    char *cmd = NULL;
    
    try {
        uuid_t id;
        uuid_generate(id);
        input_filename = new char[36+1];
        uuid_unparse(id, input_filename);
        input_filepath = new char[5+strlen(input_filename)+1];
        strcpy(input_filepath, "/tmp/");
        strcat(input_filepath, input_filename);
        
        std::ofstream fp;
        fp.open(input_filepath, std::ios::out | std::ios::binary );
        fp.write((char*)buffer, buffer_length);
        fp.close();

        char *output_filename = new char[36+1];
        uuid_generate(id);
        uuid_unparse(id, output_filename);
        char *output_filepath = new char[5+strlen(output_filename)+1];
        strcpy(output_filepath, "/tmp/");
        strcat(output_filepath, output_filename);

        char * cmd = new char[9+1+strlen(input_filepath)+1+strlen(output_filepath)+1];
        strcpy(cmd, "pdftotext ");
        strcat(cmd, input_filepath);        
        strcat(cmd, " ");        
        strcat(cmd, output_filepath);        
        system(cmd);

        remove(input_filepath);

        std::ifstream ifs(output_filepath);
        std::string content( (std::istreambuf_iterator<char>(ifs) ),
            (std::istreambuf_iterator<char>()) );
        remove(output_filepath);
    
        delete input_filename;
        delete input_filepath;
        delete output_filename;
        delete output_filepath;
        delete cmd;
        
        return content;
    } catch (std::exception e) {
        if(input_filename) {delete input_filename;}
        if(input_filepath) {delete input_filepath;}
        if(output_filename) {delete output_filename;}
        if(output_filepath) {delete output_filepath;}
        if(cmd) {delete cmd;}
        
        remove(input_filepath);
        remove(output_filepath);

        syslog (LOG_INFO|LOG_LOCAL6, "PDFParser encountered fatal error");
        return "";
    }
}

