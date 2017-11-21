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


#include <iostream>
#include <list>
#include <sstream>
#include <vector>
#include <regex>

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
#include "json.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include "libs/bayshore_yara_wrapper.h"

#ifdef __cplusplus
}
#endif

using json = nlohmann::json;
std::regex yara_meta("(.*):\\[(.*)\\]+");
std::smatch mtch;

///////////////////////////////////////////////////////////////
// Get the size of a file
long get_file_size(FILE *file) {

	long lCurPos, lEndPos;
	lCurPos = ftell(file);
	fseek(file, 0, 2);
	lEndPos = ftell(file);
	fseek(file, lCurPos, 0);
	return lEndPos;
}

char *str_to_md5(const char *str, int length) {
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

bool is_directory(const char* path) {
	struct stat st;

	if (stat(path,&st) == 0)
		return S_ISDIR(st.st_mode);

	return false;
}

bool does_this_file_exist(const char *fn) {
	struct stat st;
	return ( fn && *fn && (stat (fn, &st) == 0) && (S_ISREG(st.st_mode)) );
}

double get_yara_version() {

	FILE *fp;
	double yara_version = 0.0;
	char yver[10];

	fp = popen("yara -v", "r");
	if (fp != NULL) {

		fgets(yver, sizeof(yver)-1, fp);
		if (yver != NULL) {

			yara_version = strtod(yver, NULL);

		}
	}
	pclose(fp);

	return yara_version;
}

void tokenize_string (
		std::string &str,
		std::vector<std::string> &tokens,
		const std::string &delimiters) {


	//std::string token, mystring(str);
	std::string token;
	auto start = 0;
	auto end = str.find(delimiters);
	while(end != std::string::npos){

		//token = mystring.substr(0,mystring.find_first_of(delimiters));
		token = str.substr(start, end - start);
		//std::cout << "WTF: " << token << std::endl;
		//mystring = mystring.substr(mystring.find_first_of(delimiters) + 1);
		tokens.push_back(token);
		start = end + delimiters.length();
		end = str.find(delimiters, start);
		if (end == std::string::npos) {

			//std::cout << "PINGA" << std::endl;
			token = str.substr(start, end);
			tokens.push_back(token);
		}
	}

	/*
    // Skip delimiters at beginning.
    std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
    // Find first "non-delimiter".
    std::string::size_type pos = str.find_first_of(delimiters, lastPos);

    while (std::string::npos != pos || std::string::npos != lastPos) {

        // Found a token, add it to the vector.
        tokens.push_back(str.substr(lastPos, pos - lastPos));
        // Skip delimiters.  Note the "not_of"
        lastPos = str.find_first_not_of(delimiters, pos);
        // Find next "non-delimiter"
        pos = str.find_first_of(delimiters, lastPos);

    }
	 */

	/*
	auto start = 0U;
	auto end = str.find(delimiters);
	while (end != std::string::npos)
	{
	    //std::cout << str.substr(start, end - start) << std::endl;
		std::string s = str.substr(start, end - start);
	    tokens.push_back(s);
	    start = end + delimiters.length();
	    std::cout << "START: " << start << std::endl;
	    end = str.find(delimiters, start);
	    std::cout << "END: " << end << std::endl;
	}
	 */

	/*
    size_t pos = 0;
    std::string token;
    while ((pos = str.find(delimiters)) != std::string::npos) {
        token = str.substr(0, pos);
        //std::cout << token << std::endl;
        tokens.push_back(token);
        str.erase(0, pos + delimiters.length());
    }
	 */




}
///////////////////////////////////////////////////////////////

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

static const char *json_output_labels[] = {
		"file_name",
		"file_size",
		"yara_results",
		"scan_type",
		"file_signature_MD5",
		"non_archive_file_name",
		"parent_file_name",
		"child_file_name",
		"ruleset_file_name",
		"yara_scan_results"
};

static const char *alpha = "===============================ALPHA===================================";
static const char *midline = "=======================================================================";
static const char *omega = "===============================OMEGA===================================";

void usage() {

	std::cout << std::endl << std::endl << "usage:  ./yextend -r RULES_FILE -t TARGET_ENTITY [-j]" << std::endl;
	std::cout << std::endl;
	std::cout << "    -r RULES_FILE = Yara ruleset file [*required]" << std::endl;
	std::cout << "    -t TARGET_ENTITY = file or directory [*required]" << std::endl;
	std::cout << "    -j output in JSON format and nothing more [optional]" << std::endl;

	std::cout << std::endl << std::endl;

}
///////////////////////////////////////////////////////////////


/****
main
 ****/

int main(int argc, char* argv[])
{

	int c;
	bool out_json = false;

	std::string yara_ruleset_file_name = "";
	std::string target_resource = "";

	while ((c = getopt(argc, argv, "r:t:j")) != -1)
		switch (c) {
		case 'r':
			yara_ruleset_file_name = optarg;
			break;
		case 't':
			target_resource = optarg;
			break;
		case 'j':
			out_json = true;
			break;
		case '?':
			std::cout << std::endl << "Problem with args dude ..." << std::endl << std::endl;
			break;
		}

	/*
	std::cout << std::endl;
	std::cout << "R: " << yara_ruleset_file_name << std::endl;
	std::cout << "T: " << target_resource << std::endl;
	std::cout << "JSON: " << out_json << std::endl;
	std::cout << std::endl;
	 */

	if (yara_ruleset_file_name.size() == 0 || target_resource.size() == 0) {

		usage();
		return 1;

	}

	/*
	if (argc != 3) {
		std::cout << std::endl << "usage: ./yextend RULES_FILE [FILE|DIR]" << std::endl << std::endl;
		exit(0);
	}
	 */

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

	/*
	const char *yara_ruleset_file_name = argv[1];
	const char *target_resource = argv[2];
	 */
	char fs[300];

	/*
	 * pre-process yara rules and then we can use the
	 * pointer to "rules" as an optimized entity.
	 * this is a requirement so that performance
	 * is optimal
	 */
	YR_RULES* rules = NULL;
	rules = bayshore_yara_preprocess_rules(yara_ruleset_file_name.c_str());
	if (!rules) {
		if (!does_this_file_exist(yara_ruleset_file_name.c_str())) {
			std::cout << std::endl << "Yara Ruleset file: \"" << yara_ruleset_file_name << "\" does not exist, exiting ..." << std::endl << std::endl;
			exit(0);
		}
		std::cout << std::endl << "Problem compiling Yara Ruleset file: \"" << yara_ruleset_file_name << "\", continuing with regular ruleset file ..." << std::endl << std::endl;
	}

	json j;

	if (is_directory(target_resource.c_str())) {

		DIR *dpdf;
		struct dirent *epdf;

		dpdf = opendir(target_resource.c_str());
		if (dpdf != NULL) {
			while (epdf = readdir(dpdf)){

				uint8_t *c;
				FILE *file = NULL;

				strncpy (fs, target_resource.c_str(), strlen(target_resource.c_str()));
				fs[strlen(target_resource.c_str())] = '\0';

				if (epdf->d_name[0] != '.') {

					strncat (fs, epdf->d_name, strlen(epdf->d_name));
					fs[strlen(fs)] = '\0';

					if (is_directory(fs)) {
						// We do not recurse into directories yet
						continue;
					}

					if ((file = fopen(fs, "rb")) != NULL) {
						// Get the size of the file in bytes
						long file_size = get_file_size(file);

						// Allocate space in the buffer for the whole file
						c = new uint8_t[file_size];
						// Read the file in to the buffer
						fread(c, file_size, 1, file);

						std::cout << std::endl << alpha << std::endl;
						std::cout << output_labels[8] << yara_ruleset_file_name << std::endl;
						std::cout << output_labels[0] << fs << std::endl;
						std::cout << output_labels[1] << file_size << std::endl;

						char *output = str_to_md5((const char *)c, file_size);
						if (output) {
							std::cout << output_labels[4] << output << std::endl;
							free(output);
						}

						std::list<security_scan_results_t> ssr_list;

						if (rules) {

							scan_content (
									c,
									file_size,
									rules,
									&ssr_list,
									fs,
									yara_cb,
									1);

						} else {
							scan_content (
									c,
									file_size,
									yara_ruleset_file_name.c_str(),
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
									if (v->child_file_name.size()) {
										if(v->parent_file_name != v->child_file_name)
											std::cout << output_labels[6] << v->parent_file_name << std::endl << output_labels[7] << v->child_file_name << std::endl;
										else
											std::cout << output_labels[0] << v->parent_file_name << std::endl;
									} else { 
										std::cout << output_labels[5] << v->parent_file_name << std::endl;
									}
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
	} else if (does_this_file_exist(target_resource.c_str())) {

		uint8_t *c;
		FILE *file = NULL;
		strncpy (fs, target_resource.c_str(), strlen(target_resource.c_str()));
		fs[strlen(target_resource.c_str())] = '\0';

		if (fs[0] != '.') {

			if ((file = fopen(fs, "rb")) != NULL) {
				// Get the size of the file in bytes
				long file_size = get_file_size(file);

				// Allocate space in the buffer for the whole file
				c = new uint8_t[file_size];

				// Read the file in to the buffer
				fread(c, file_size, 1, file);

				if (!out_json) {

					std::cout << std::endl << alpha << std::endl;
					std::cout << output_labels[0] << fs << std::endl;
					std::cout << output_labels[1] << file_size << std::endl;

				} else {

					//j.push_back("file_name");
					j[json_output_labels[0]] = fs;
					j[json_output_labels[1]] = file_size;

				}

				char *output = str_to_md5((const char *)c, file_size);
				if (output) {

					if (!out_json) {
						std::cout << output_labels[4] << output << std::endl;
					} else {
						j[json_output_labels[4]] = output;
					}
					free(output);

				}

				std::list<security_scan_results_t> ssr_list;

				if (rules) {

					scan_content (
							c,
							file_size,
							rules,
							&ssr_list,
							fs,
							yara_cb,
							1);
				} else {
					scan_content (
							c,
							file_size,
							yara_ruleset_file_name.c_str(),
							&ssr_list,
							fs,
							yara_cb,
							1);
				}

				if (!ssr_list.empty()) {

					if (!out_json) {
						std::cout << std::endl << midline << std::endl;
					}

					size_t y_cnt = 1;
					for (std::list<security_scan_results_t>::const_iterator v = ssr_list.begin();
							v != ssr_list.end();
							v++)
					{

						if (!out_json) {

							std::cout << std::endl;
							std::cout << output_labels[2] << v->file_scan_result << std::endl;
							std::cout << output_labels[3] << v->file_scan_type << std::endl;
							if (v->parent_file_name.size()) {
								if (v->child_file_name.size()) {
									if ( v->parent_file_name != v->child_file_name)
										std::cout << output_labels[6] << v->parent_file_name << std::endl << output_labels[7] << v->child_file_name << std::endl;
									else
										std::cout << output_labels[0] << v->parent_file_name << std::endl;
								} else {
									std::cout << output_labels[5] << v->parent_file_name << std::endl;
								}
							}
							std::cout << output_labels[4] << v->file_signature_md5 << std::endl;
							std::cout << std::endl;

						} else {

							std::stringstream ss;
							ss << json_output_labels[9] << "_" << y_cnt;

							//j[ss.str()][json_output_labels[2]] = v->file_scan_result;
							/*
							 * tokenize and slice/dice up the results
							 * from Yara hit
							 * 
							 */
							std::vector<std::string> tokens;
							std::string sss = v->file_scan_result;
							tokenize_string (sss, tokens, ", ");
							for (auto& it : tokens) {

								bool b = regex_search(it, mtch, yara_meta);							    
								if (b) {

									std::string yara_rule_hit_name = mtch[1];
									//j[ss.str()][json_output_labels[2]][json_output_labels[10]] = yara_rule_hit_name;
									std::string yara_rule_hit_meta = mtch[2];
									j[ss.str()][json_output_labels[2]][yara_rule_hit_name] = mtch[2];

									std::vector<std::string> tokens_2;
									tokenize_string (yara_rule_hit_meta, tokens_2, ",");

									json j_meta;
									for (auto& it2 : tokens_2) {

										//std::cout << it2 << std::endl;
										std::vector<std::string> tokens_3;
										tokenize_string (it2, tokens_3, "=");

										//std::cout << tokens_3[0] << " --- " << tokens_3[1] << std::endl;

										//std::string k = tokens_3[0];
										//std::string v = tokens_3[1];
										//j[ss.str()][json_output_labels[2]][yara_rule_hit_name][k] = v;
										if (tokens_3[0] == "detected offsets") {
											
											json j_meta_do;
											std::vector<std::string> tokens_4;
											tokenize_string (tokens_3[1], tokens_4, "-");
											
											if (tokens_4.size() == 0) {
												
												j_meta_do.push_back(tokens_3[1]);
												
											} else {
											
												for (auto& it4 : tokens_4) {
													j_meta_do.push_back(it4);
												}
											
											}
											
											j_meta[tokens_3[0]] = j_meta_do;
											
										} else {
											j_meta[tokens_3[0]] = tokens_3[1];
										}

									}

									j[ss.str()][json_output_labels[2]][yara_rule_hit_name] = j_meta;

								}
								/*
								// for each loop
								for (auto x : mtch) {
									std::cout << "HERE: " << x << std::endl;
								}
								 */
							}

							j[ss.str()][json_output_labels[3]] = v->file_scan_type;

							if (v->parent_file_name.size()) {
								if (v->child_file_name.size()) {
									if ( v->parent_file_name != v->child_file_name) {
										j[ss.str()][json_output_labels[6]] = v->parent_file_name;
										j[ss.str()][json_output_labels[7]] = v->child_file_name;
									} else  {
										j[ss.str()][json_output_labels[0]] = v->parent_file_name;
									}
								} else {
									j[ss.str()][json_output_labels[5]] = v->parent_file_name;
								}
							}

							j[ss.str()][json_output_labels[4]] = v->file_signature_md5;

						}

						y_cnt++;

					}

					if (!out_json) {
						std::cout << std::endl << omega << std::endl;
					}

				} else {

					if (!out_json) {
						std::cout << std::endl << omega << std::endl;
					}

				}

				delete[] c;
				fclose(file);
			}

			if (out_json) {
				//std::cout << j.dump();
				// pretty print
				std::cout << j.dump(4);
			}
		}

	} else {
		std::cout << std::endl << "Could not read resource: \"" << target_resource << "\", exiting ..." << std::endl << std::endl;
	}

	if (rules != NULL)
		yr_rules_destroy(rules);

	return 0;
}
