/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * Copyright (C) 2014-2016 by Bayshore Networks, Inc. All Rights Reserved.
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


#include <iostream>
#include <list>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <dirent.h>
#include <openssl/md5.h>

#include "bayshore_content_scan.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "bayshore_yara_wrapper.h"

#ifdef __cplusplus
}
#endif


// Get the size of a file
long get_file_size(FILE *file)
{
	long lCurPos, lEndPos;
	lCurPos = ftell(file);
	fseek(file, 0, 2);
	lEndPos = ftell(file);
	fseek(file, lCurPos, 0);
	return lEndPos;
}

char *str_to_md5(const char *str, int length) 
{
	int n;
	MD5_CTX c;
	unsigned char digest[16];
	char *out = (char*)malloc(33);

	MD5_Init(&c);

	while (length > 0) {
		if (length > 512) {
			MD5_Update(&c, str, 512);
		} else {
			MD5_Update(&c, str, length);
		}
		length -= 512;
		str += 512;
	}

	MD5_Final(digest, &c);

	for (n = 0; n < 16; ++n) {
		snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
	}

	return out;
}

bool is_directory(const char* path)
{
	struct stat st;

	if (stat(path,&st) == 0)
		return S_ISDIR(st.st_mode);

	return false;
}

bool does_this_file_exist(const char *fn)
{
	struct stat st;
	return ( fn && *fn && (stat (fn, &st) == 0) && (S_ISREG(st.st_mode)) );
}

double get_yara_version()
{
    FILE *fp;
    int tok_cnt = 0;
    double yara_version = 0.0;
    char yver[10];
    const char t[2] = " ";
    char *token;

    fp = popen("yara -v", "r");
    /*
    if (fp == NULL) {
        printf("Failed to run command\n" );
        exit;
    }
	*/
    if (fp != NULL) {
		fgets(yver, sizeof(yver)-1, fp);
		if (yver != NULL) {
			token = strtok(yver, t);
			while( token != NULL )
			{
				if (tok_cnt == 1) {
					yara_version = strtod(token, NULL);
				}
				token = strtok(NULL, t);
				tok_cnt++;
			}
		}
    }
    pclose(fp);

    return yara_version;
}

static const char *output_labels[] = {
		"File Name: ",
		"File Size: ",
		"Yara Result(s): ",
		"Scan Type: ",
		"File Signature (MD5): ",
		"Non-Archive File Name: ",
		"Parent File Name: ",
		"Child File Name: ",
		"Ruleset File Name: "
};

static const char *alpha = "===============================ALPHA===================================";
static const char *midline = "=======================================================================";
static const char *omega = "===============================OMEGA===================================";

/****
main
****/

int main(int argc, char* argv[])
{

	if (argc != 3) {
		std::cout << std::endl << "usage: ./yextend RULES_FILE [FILE|DIR]" << std::endl << std::endl;
		exit(0);
	}
	
	// get yara runtime version
	double yara_version = get_yara_version();
	// version checks
	if (YEXTEND_VERSION >= 1.2 && yara_version < 3.4) {
		std::cout << std::endl << "Version issue: yextend version " << YEXTEND_VERSION << "+ will not run with yara versions below 3.4" << std::endl << std::endl;
		std::cout << "Your env has yextend version ";
		printf("%.1f\n", YEXTEND_VERSION);
		std::cout << "Your env has yara version ";
		printf("%.1f", yara_version);
		std::cout << std::endl << std::endl;
		exit(0);
	}
	const char *yara_ruleset_file_name = argv[1];
	const char *target_resource = argv[2];
	char fs[300];
	
	/*
	 * pre-process yara rules and then we can use the
	 * pointer to "rules" as an optimized entity.
	 * this is a requirement so that performance
	 * is optimal
	 */
	YR_RULES* rules = NULL;
	rules = bayshore_yara_preprocess_rules(yara_ruleset_file_name);
	if (!rules) {
		if (!does_this_file_exist(yara_ruleset_file_name)) {
			std::cout << std::endl << "Yara Ruleset file: \"" << yara_ruleset_file_name << "\" does not exist, exiting ..." << std::endl << std::endl;
			exit(0);
		}
		std::cout << std::endl << "Problem compiling Yara Ruleset file: \"" << yara_ruleset_file_name << "\", continuing with regular ruleset file ..." << std::endl << std::endl;
	}

	if (is_directory(target_resource)) {

		DIR *dpdf;
		struct dirent *epdf;

		dpdf = opendir(target_resource);
		if (dpdf != NULL) {
			while (epdf = readdir(dpdf)){

				uint8_t *c;
				FILE *file = NULL;

				strncpy (fs, target_resource, strlen(target_resource));
				fs[strlen(target_resource)] = '\0';

				if (epdf->d_name[0] != '.') {

					strncat (fs, epdf->d_name, strlen(epdf->d_name));
					fs[strlen(fs)] = '\0';

					if ((file = fopen(fs, "rb")) != NULL) {
						// Get the size of the file in bytes
						long fileSize = get_file_size(file);

						// Allocate space in the buffer for the whole file
						c = new uint8_t[fileSize];
						// Read the file in to the buffer
						fread(c, fileSize, 1, file);

						std::cout << std::endl << alpha << std::endl;
						std::cout << output_labels[8] << yara_ruleset_file_name << std::endl;
						std::cout << output_labels[0] << fs << std::endl;
						std::cout << output_labels[1] << fileSize << std::endl;

						char *output = str_to_md5((const char *)c, fileSize);
						if (output) {
							std::cout << output_labels[4] << output << std::endl;
							free(output);
						}

						std::list<security_scan_results_t> ssr_list;

						if (rules) {
							
							scan_content (
									c,
									fileSize,
									rules,
									&ssr_list,
									fs,
									yara_cb,
									1);
							
						} else {
							scan_content (
									c,
									fileSize,
									yara_ruleset_file_name,
									&ssr_list,
									fs,
									yara_cb,
									1);
						}

						if (!ssr_list.empty()) {

							std::cout << std::endl << midline << std::endl;
							for (std::list<security_scan_results_t>::const_iterator v = ssr_list.begin();
									v != ssr_list.end();
									v++)
							{
								std::cout << std::endl;
								std::cout << output_labels[2] << v->file_scan_result << std::endl;
								std::cout << output_labels[3] << v->file_scan_type << std::endl;
								if (v->parent_file_name.size()) {
									if (v->child_file_name.size())
										std::cout << output_labels[6] << v->parent_file_name << std::endl << output_labels[7] << v->child_file_name << std::endl;
									else
										std::cout << output_labels[5] << v->parent_file_name << std::endl;
								}
								std::cout << output_labels[4] << v->file_signature_md5 << std::endl;
								std::cout << std::endl;
							}
							std::cout << std::endl << omega << std::endl;
						} else {
							std::cout << std::endl << omega << std::endl;
						}


						delete[] c;
						fclose(file);
					}
				}
			}
			closedir(dpdf);
		}
	} else if(does_this_file_exist(target_resource)) {

		uint8_t *c;
		FILE *file = NULL;
		strncpy (fs, target_resource, strlen(target_resource));
		fs[strlen(target_resource)] = '\0';

		if (fs[0] != '.') {

			if ((file = fopen(fs, "rb")) != NULL) {
				// Get the size of the file in bytes
				long fileSize = get_file_size(file);

				// Allocate space in the buffer for the whole file
				c = new uint8_t[fileSize];

				// Read the file in to the buffer
				fread(c, fileSize, 1, file);

				std::cout << std::endl << alpha << std::endl;
				std::cout << output_labels[0] << fs << std::endl;
				std::cout << output_labels[1] << fileSize << std::endl;
				
				char *output = str_to_md5((const char *)c, fileSize);
				if (output) {
					// XXX fixme
					std::cout << output_labels[4] << output << std::endl;
					free(output);
				}
				
				std::list<security_scan_results_t> ssr_list;

				if (rules) {
					
					scan_content (
							c,
							fileSize,
							rules,
							&ssr_list,
							fs,
							yara_cb,
							1);
				} else {
					scan_content (
							c,
							fileSize,
							yara_ruleset_file_name,
							&ssr_list,
							fs,
							yara_cb,
							1);
				}

				if (!ssr_list.empty()) {
					std::cout << std::endl << midline << std::endl;
					for (std::list<security_scan_results_t>::const_iterator v = ssr_list.begin();
							v != ssr_list.end();
							v++)
					{
						std::cout << std::endl;
						std::cout << output_labels[2] << v->file_scan_result << std::endl;
						std::cout << output_labels[3] << v->file_scan_type << std::endl;
						if (v->parent_file_name.size()) {
							if (v->child_file_name.size())
								std::cout << output_labels[6] << v->parent_file_name << std::endl << output_labels[7] << v->child_file_name << std::endl;
							else
								std::cout << output_labels[5] << v->parent_file_name << std::endl;
						}
						std::cout << output_labels[4] << v->file_signature_md5 << std::endl;
						std::cout << std::endl;
					}
					std::cout << std::endl << omega << std::endl;
				} else {
					std::cout << std::endl << omega << std::endl;
				}

				delete[] c;
				fclose(file);
			}
		}

	} else {
		std::cout << std::endl << "Could not read resource: \"" << target_resource << "\", exiting ..." << std::endl << std::endl;
	}
	
	if (rules != NULL)
		yr_rules_destroy(rules);
	return 0;
}
