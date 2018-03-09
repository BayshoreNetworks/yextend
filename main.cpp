/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * This file is part of yextend.
 *
 * Copyright (c) 2014-2018, Bayshore Networks, Inc.
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
#include <fstream>
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
		"yara_ruleset_file_name",
		"scan_meta_data",
		"yara_matches_found",
		"children",
		"yara_rule_id",
		"scan_results"
};

static const char *alpha = "===============================ALPHA===================================";
static const char *midline = "=======================================================================";
static const char *omega = "===============================OMEGA===================================";
static const char *json_type_error = "JSON type error";
static const char *json_other_error = "JSON other error";
static const char *json_parse_error = "JSON parse error";
static const char *json_invalid_iterator_error = "JSON invalid iterator error";
static const char *json_out_of_range_error = "JSON out of range error";
static const char *json_exception = "JSON exception";
static const char *meta_delim = ",#+,";

void usage() {

	std::cout << std::endl << std::endl << "usage:  ./yextend -r RULES_FILE -t TARGET_ENTITY [-j]" << std::endl;
	std::cout << std::endl;
	std::cout << "    -r RULES_FILE = Yara ruleset file [*required]" << std::endl;
	std::cout << "    -t TARGET_ENTITY = file or directory [*required]" << std::endl;
	std::cout << "    -j output in JSON format and nothing more [optional]" << std::endl;

	std::cout << std::endl << std::endl;

}
///////////////////////////////////////////////////////////////

bool is_file(const std::string &fpath) {

	struct stat buf;
	if (stat(fpath.c_str(), &buf) != 0) {
		return false;
	}
	return S_ISREG(buf.st_mode);

}

// Get the size of a file
size_t get_file_size(const char *full_file_path) {

	size_t total = 0;

	if (is_file(full_file_path)) {
		std::ifstream file_sz(full_file_path, std::ios::binary | std::ios::ate);
		total = file_sz.tellg();
		file_sz.close();
	}

	return total;
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

	/*
	 * older versions of yara seem to output version like this:
	 *
	 * yara 3.4.0
	 *
	 * while the later ones just do:
	 *
	 * 3.6.0
	 *
	 */
	FILE *fp;
	double yara_version = 0.0;
	char yver[10];
	std::string y = "yara";
	std::string yver_str;

	fp = popen("yara -v", "r");
	if (fp != NULL) {

		if (fgets (yver, sizeof(yver)-1, fp) != NULL) {

			yver_str = yver;
			std::size_t found = yver_str.find(y);
			if (found != std::string::npos) {
				yver_str = yver_str.substr(found + 5);
			}

			//yara_version = strtod(yver, NULL);
			yara_version = strtod(yver_str.c_str(), NULL);

		}

		pclose(fp);

	}

	return yara_version;
}

void tokenize_string (
		std::string &str,
		std::vector<std::string> &tokens,
		const std::string &delimiters) {

	std::string token;
	auto start = 0;
	auto end = str.find(delimiters);
	while(end != std::string::npos){

		token = str.substr(start, end - start);
		tokens.push_back(token);
		start = end + delimiters.length();
		end = str.find(delimiters, start);
		if (end == std::string::npos) {

			token = str.substr(start, end);
			tokens.push_back(token);
		}
	}

}

std::string process_scan_hit_str(const std::string &hit_str,
		const std::string &file_scan_type,
		const std::string &file_signature_md5,
		const std::string &parent_file_name,
		const std::string &child_file_name
		) {

	std::string resp = "";

	bool b = regex_search(hit_str, mtch, yara_meta);
	if (b) {

		std::string yara_rule_hit_name = mtch[1];
		std::string yara_rule_hit_meta = mtch[2];

		std::vector<std::string> tokens_2;
		//tokenize_string (yara_rule_hit_meta, tokens_2, ",");
		tokenize_string (yara_rule_hit_meta, tokens_2, meta_delim);

		json j_meta;
		for (auto& it2 : tokens_2) {

			//std::cout << it2 << std::endl;
			std::vector<std::string> tokens_3;
			tokenize_string (it2, tokens_3, "=");

			//std::cout << tokens_3[0] << " --- " << tokens_3[1] << " --- " << fs << std::endl;

			//std::string k = tokens_3[0];
			//std::string v = tokens_3[1];
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

		j_meta[json_output_labels[3]] = file_scan_type;
		j_meta[json_output_labels[4]] = file_signature_md5;
		j_meta[json_output_labels[12]] = yara_rule_hit_name;

		if (parent_file_name.size()) {
			if (child_file_name.size()) {
				if (parent_file_name != child_file_name) {
					j_meta[json_output_labels[6]] = parent_file_name;
					j_meta[json_output_labels[7]] = child_file_name;
				} else  {
					j_meta[json_output_labels[0]] = parent_file_name;
				}
			} else {
				j_meta[json_output_labels[5]] = parent_file_name;
			}
		}

		if (!j_meta.is_null()) {
			resp = j_meta.dump();
		}

	}

	return resp;

}


std::string process_scan_no_hit(bool hit,
		const std::string &file_scan_result,
		const std::string &file_scan_type,
		const std::string &file_signature_md5,
		const std::string &parent_file_name,
		const std::string &child_file_name,
		size_t file_size
		) {

	std::string resp;

	json j_results;
	j_results[json_output_labels[10]] = hit;

	if (file_scan_result.size() > 0) {
		j_results[json_output_labels[12]] = file_scan_result;
	}

	j_results[json_output_labels[3]] = file_scan_type;
	j_results[json_output_labels[4]] = file_signature_md5;

	if (parent_file_name.size()) {
		if (child_file_name.size()) {
			if (parent_file_name != child_file_name) {
				j_results[json_output_labels[6]] = parent_file_name;
				j_results[json_output_labels[7]] = child_file_name;
			} else  {
				j_results[json_output_labels[0]] = parent_file_name;
			}
		} else {
			j_results[json_output_labels[5]] = parent_file_name;
		}
	}

	if (file_size > 0) {
		j_results[json_output_labels[1]] = file_size;
	}

	if (!j_results.is_null()) {
		resp = j_results.dump();
	}

	return resp;

}


void legacy_output(const std::string &file_scan_result,
		const std::string &file_scan_type,
		const std::string &file_signature_md5,
		const std::string &parent_file_name,
		const std::string &child_file_name,
		size_t file_size
		) {

	std::cout << std::endl;
	std::cout << output_labels[2] << file_scan_result << std::endl;
	std::cout << output_labels[3] << file_scan_type << std::endl;
	if (parent_file_name.size()) {
		if (child_file_name.size()) {
			if (parent_file_name != child_file_name)
				std::cout << output_labels[6] << parent_file_name << std::endl << output_labels[7] << child_file_name << std::endl;
			else
				std::cout << output_labels[0] << parent_file_name << std::endl;
		} else {
			std::cout << output_labels[5] << parent_file_name << std::endl;
		}
	}
	std::cout << output_labels[4] << file_signature_md5 << std::endl;
	std::cout << output_labels[1] << file_size << std::endl;
	std::cout << std::endl;

}


json parse_json_string(std::string j_dat) {

	json j_null;
	try {
		auto j = json::parse(j_dat);
		return j;
	} catch (nlohmann::detail::type_error & e) {
		std::cout << json_type_error << " : " << e.what() << std::endl;
	} catch (nlohmann::detail::parse_error const& e) {
		std::cout << json_parse_error << " : " << e.what() << std::endl;
	} catch (nlohmann::detail::invalid_iterator const& e) {
		std::cout << json_invalid_iterator_error << " : " << e.what() << std::endl;
	} catch (nlohmann::detail::out_of_range const& e) {
		std::cout << json_out_of_range_error << " : " << e.what() << std::endl;
	} catch (nlohmann::detail::other_error const& e) {
		std::cout << json_other_error << " : " << e.what() << std::endl;
	} catch (nlohmann::detail::exception const& e) {
		std::cout << json_exception << " : " << e.what() << std::endl;
	}
	return j_null;

}

///////////////////////////////////////////////////////////////



/****
main
 ****/

int main(int argc, char* argv[]) {

	int c;
	bool out_json = false;
	bool out_json_pretty_print = true;

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

	if (yara_ruleset_file_name.size() == 0 || target_resource.size() == 0) {

		usage();
		return 1;

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


	try {

		json j_main;

		if (is_directory(target_resource.c_str())) {

			DIR *dpdf;
			struct dirent *epdf;

			dpdf = opendir(target_resource.c_str());
			if (dpdf != NULL) {

				while (epdf = readdir(dpdf)) {

					json j_level1;

					uint8_t *c;
					FILE *file = NULL;

					strncpy (fs, target_resource.c_str(), sizeof(fs));
					fs[sizeof(fs)-1]= '\0'; //fs[strlen(target_resource.c_str())] = '\0';

					if (epdf->d_name[0] != '.') {

						json j_children;

						strncat (fs, epdf->d_name, strlen(epdf->d_name));
						fs[strlen(fs)] = '\0';

						if (is_directory(fs)) {
							// We do not recurse into directories yet
							continue;
						}

						if ((file = fopen(fs, "rb")) != NULL) {
							// Get the size of the file in bytes
							size_t file_size = get_file_size(fs);

							// Allocate space in the buffer for the whole file
							c = new uint8_t[file_size];
							// Read the file in to the buffer
							size_t dat_read = fread(c, 1, file_size, file);

							if (dat_read == file_size) {

								if (!out_json) {

									std::cout << std::endl << alpha << std::endl;
									std::cout << output_labels[8] << yara_ruleset_file_name << std::endl;
									std::cout << output_labels[0] << fs << std::endl;
									std::cout << output_labels[1] << file_size << std::endl;

								} else {

									j_level1[json_output_labels[8]] = yara_ruleset_file_name;
									j_level1[json_output_labels[0]] = fs;
									j_level1[json_output_labels[1]] = file_size;

								}

								char *output = str_to_md5((const char *)c, file_size);
								if (output) {

									if (!out_json) {
										std::cout << output_labels[4] << output << std::endl;
									} else {
										j_level1[json_output_labels[4]] = output;
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

									for (std::list<security_scan_results_t>::const_iterator v = ssr_list.begin();
											v != ssr_list.end();
											v++) {

										if (!out_json) {

											legacy_output(v->file_scan_result,
													v->file_scan_type,
													v->file_signature_md5,
													v->parent_file_name,
													v->child_file_name,
													v->file_size
													);

										} else {

											std::string file_scan_result = v->file_scan_result;
											if (file_scan_result.size() > 1) {

												j_level1[json_output_labels[10]] = true;

											}

											std::vector<std::string> tokens;
											std::string delim = meta_delim;
											delim.append(" ");
											tokenize_string (file_scan_result, tokens, delim);

											// we have hits
											if (file_scan_result.size()) {

												// we have multiple hits
												if (tokens.size() > 0) {

													for (auto& it : tokens) {

														std::string pshs_resp = process_scan_hit_str(it,
																v->file_scan_type,
																v->file_signature_md5,
																v->parent_file_name,
																v->child_file_name);

														if (pshs_resp.size()) {

															auto jresp = parse_json_string(pshs_resp);
															if (!jresp.is_null()) {
																jresp[json_output_labels[10]] = true;
																jresp[json_output_labels[1]] = v->file_size;
																j_children.push_back(jresp);
															}

														} else {

															/*
															 * here we have rule hits with not much
															 * in the way of meta-data, an example
															 * of a rule like this:
															 *
															 *     rule is_entropy
															 *     {
															 *         condition:
															 *             math.entropy(0,filesize)>5
															 *     }
															 *
															 *
															 */
															std::string j_no_hit = process_scan_no_hit(true,
																	it,
																	v->file_scan_type,
																	v->file_signature_md5,
																	v->parent_file_name,
																	v->child_file_name,
																	v->file_size
																	);
															if (j_no_hit.size() > 0) {

																auto jnh = parse_json_string(j_no_hit);
																if (!jnh.is_null()) {
																	j_children.push_back(jnh);
																}

															}

														}

													}

												} else { // we have single hit

													std::string pshs_resp = process_scan_hit_str(file_scan_result,
															v->file_scan_type,
															v->file_signature_md5,
															v->parent_file_name,
															v->child_file_name);

													if (pshs_resp.size()) {

														auto jresp = parse_json_string(pshs_resp);
														if (!jresp.is_null()) {
															jresp[json_output_labels[10]] = true;
															jresp[json_output_labels[1]] = v->file_size;
															j_children.push_back(jresp);
														}

													} else {

														std::string j_no_hit = process_scan_no_hit(true,
																file_scan_result,
																v->file_scan_type,
																v->file_signature_md5,
																v->parent_file_name,
																v->child_file_name,
																v->file_size
																);
														if (j_no_hit.size() > 0) {

															auto jnh = parse_json_string(j_no_hit);
															if (!jnh.is_null()) {
																j_children.push_back(jnh);
															}

														}

													}

												}

											} else { // no hits just display meta data

												std::string j_no_hit = process_scan_no_hit(false,
														"",
														v->file_scan_type,
														v->file_signature_md5,
														v->parent_file_name,
														v->child_file_name,
														v->file_size
														);
												if (j_no_hit.size() > 0) {

													auto jnh = parse_json_string(j_no_hit);
													if (!jnh.is_null()) {
														j_children.push_back(jnh);
													}

												}

											}

										}

									}

									if (!out_json) {
										std::cout << std::endl << omega << std::endl;
									}

								} else {

									if (!out_json) {
										std::cout << std::endl << omega << std::endl;
									}

								}

							}

							delete[] c;
							fclose(file);

						}

						if (!j_children.is_null()) {
							j_level1[json_output_labels[13]] = j_children;
						}

					} else {

						continue;

					}

					if (!j_level1.is_null()) {
						j_main.push_back(j_level1);
					}

				}

				closedir(dpdf);

			}

		} else if (does_this_file_exist(target_resource.c_str())) {

			uint8_t *c;
			FILE *file = NULL;
			strncpy (fs, target_resource.c_str(), sizeof(fs));
			fs[sizeof(fs)-1]= '\0'; //fs[strlen(target_resource.c_str())] = '\0';


			if (fs[0] != '.') {

				json j_level1;
				json j_children;

				if ((file = fopen(fs, "rb")) != NULL) {

					// Get the size of the file in bytes
					size_t file_size = get_file_size(fs);

					// Allocate space in the buffer for the whole file
					c = new uint8_t[file_size];

					// Read the file in to the buffer
					//fread(c, file_size, 1, file);
					size_t dat_read = fread(c, 1, file_size, file);

					if (dat_read == file_size) {

						if (!out_json) {

							std::cout << std::endl << alpha << std::endl;
							std::cout << output_labels[0] << fs << std::endl;
							std::cout << output_labels[1] << file_size << std::endl;

						} else {

							j_level1[json_output_labels[8]] = yara_ruleset_file_name;
							j_level1[json_output_labels[0]] = fs;
							j_level1[json_output_labels[1]] = file_size;

						}

						char *output = str_to_md5((const char *)c, file_size);
						if (output) {

							if (!out_json) {
								std::cout << output_labels[4] << output << std::endl;
							} else {
								j_level1[json_output_labels[4]] = output;
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

							for (std::list<security_scan_results_t>::const_iterator v = ssr_list.begin();
									v != ssr_list.end();
									v++) {

								if (!out_json) {

									legacy_output(v->file_scan_result,
											v->file_scan_type,
											v->file_signature_md5,
											v->parent_file_name,
											v->child_file_name,
											v->file_size
											);

								} else {

									std::string file_scan_result = v->file_scan_result;

									if (file_scan_result.size() > 1) {
										j_level1[json_output_labels[10]] = true;
									}

									// we have hits
									if (file_scan_result.size()) {

										std::vector<std::string> tokens;
										std::string delim = meta_delim;
										delim.append(" ");
										//tokenize_string (file_scan_result, tokens, meta_delim);
										tokenize_string (file_scan_result, tokens, delim);

										// we have multiple hits
										if (tokens.size() > 0) {

											for (auto& it : tokens) {

												std::string pshs_resp = process_scan_hit_str(it,
														v->file_scan_type,
														v->file_signature_md5,
														v->parent_file_name,
														v->child_file_name);

												if (pshs_resp.size()) {

													auto jresp = parse_json_string(pshs_resp);
													if (!jresp.is_null()) {
														jresp[json_output_labels[10]] = true;
														jresp[json_output_labels[1]] = v->file_size;
														j_children.push_back(jresp);
													}

												} else {

													std::string j_no_hit = process_scan_no_hit(true,
															it,
															v->file_scan_type,
															v->file_signature_md5,
															v->parent_file_name,
															v->child_file_name,
															v->file_size
															);
													if (j_no_hit.size() > 0) {

														auto jnh = parse_json_string(j_no_hit);
														if (!jnh.is_null()) {
															j_children.push_back(jnh);
														}

													}

												}

											}

										} else { // we have single hit

											std::string pshs_resp = process_scan_hit_str(file_scan_result,
													v->file_scan_type,
													v->file_signature_md5,
													v->parent_file_name,
													v->child_file_name);

											if (pshs_resp.size()) {

												auto jresp = parse_json_string(pshs_resp);
												if (!jresp.is_null()) {
													jresp[json_output_labels[10]] = true;
													jresp[json_output_labels[1]] = v->file_size;
													j_children.push_back(jresp);
												}

											} else {

												std::string j_no_hit = process_scan_no_hit(true,
														file_scan_result,
														v->file_scan_type,
														v->file_signature_md5,
														v->parent_file_name,
														v->child_file_name,
														v->file_size
														);
												if (j_no_hit.size() > 0) {

													auto jnh = parse_json_string(j_no_hit);
													if (!jnh.is_null()) {
														j_children.push_back(jnh);
													}

												}

											}

										}

									} else { // no hits just display meta data

										std::string j_no_hit = process_scan_no_hit(false,
												"",
												v->file_scan_type,
												v->file_signature_md5,
												v->parent_file_name,
												v->child_file_name,
												v->file_size
												);
										if (j_no_hit.size() > 0) {

											//j_children.push_back(json::parse(j_no_hit));
											auto jnh = parse_json_string(j_no_hit);
											if (!jnh.is_null()) {
												j_children.push_back(jnh);
											}

										}

									}

								}

							}

							if (!out_json) {
								std::cout << std::endl << omega << std::endl;
							}

						} else {

							if (!out_json) {
								std::cout << std::endl << omega << std::endl;
							}

						}

					}

					delete[] c;
					fclose(file);
				}

				//j_level1[json_output_labels[13]] = j_children;
				if (!j_children.is_null()) {
					j_level1[json_output_labels[13]] = j_children;
				}

				if (!j_level1.is_null()) {
					j_main.push_back(j_level1);
				}

			}

		} else {

			std::cout << std::endl << "Could not read resource: \"" << target_resource << "\", exiting ..." << std::endl << std::endl;

		}

		if (!j_main.is_null()) {

			if (out_json) {

				if (out_json_pretty_print)
					std::cout << j_main.dump(4);
				else
					std::cout << j_main.dump();

			}

		}

	} catch (nlohmann::detail::type_error & e) {
		std::cout << json_type_error << " : " << e.what() << std::endl;
	} catch (nlohmann::detail::parse_error const& e) {
		std::cout << json_parse_error << " : " << e.what() << std::endl;
	} catch (nlohmann::detail::invalid_iterator const& e) {
		std::cout << json_invalid_iterator_error << " : " << e.what() << std::endl;
	} catch (nlohmann::detail::out_of_range const& e) {
		std::cout << json_out_of_range_error << " : " << e.what() << std::endl;
	} catch (nlohmann::detail::other_error const& e) {
		std::cout << json_other_error << " : " << e.what() << std::endl;
	} catch (nlohmann::detail::exception const& e) {
		std::cout << json_exception << " : " << e.what() << std::endl;
	}

	if (rules != NULL) {
		yr_rules_destroy(rules);
	}

	return 0;
}
