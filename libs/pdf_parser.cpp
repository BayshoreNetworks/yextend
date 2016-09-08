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
    	// 36 + 1
        output_filename = new char[37];
        uuid_t id;
        uuid_generate(id);
        uuid_unparse(id, output_filename);
        // 5+strlen(output_filename)+1
        output_filepath = new char[6 + strlen(output_filename)];
        strcpy(output_filepath, tmp_path);
        strcat(output_filepath, output_filename);

        /*
         * pdftotext = the first 9
         * 9 + 1 + strlen(filepath) + 1 + strlen(output_filepath) + 1
         */
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
    	// 36 + 1
        input_filename = new char[37];
        uuid_unparse(id, input_filename);
        // 5+strlen(input_filename)+1
        input_filepath = new char[6 + strlen(input_filename)];
        strcpy(input_filepath, tmp_path);
        strcat(input_filepath, input_filename);
        
        std::ofstream fp;
        fp.open(input_filepath, std::ios::out | std::ios::binary );
        fp.write((char*)buffer, buffer_length);
        fp.close();

        // 36 + 1
        char *output_filename = new char[37];
        uuid_generate(id);
        uuid_unparse(id, output_filename);
        char *output_filepath = new char[5+strlen(output_filename)+1];
        strcpy(output_filepath, tmp_path);
        strcat(output_filepath, output_filename);

        /*
         * pdftotext = the first 9
         * 9 + 1 + strlen(input_filepath) + 1 + strlen(output_filepath) + 1
         */
        char * cmd = new char[12 + strlen(input_filepath) + strlen(output_filepath)];
        strcpy(cmd, pdf_to_text);
        strcat(cmd, " ");
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

