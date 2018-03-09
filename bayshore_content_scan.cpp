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

#ifdef __cplusplus
extern "C" {
#endif

#include "libs/bayshore_yara_wrapper.h"

#ifdef __cplusplus
}
#endif

#include <pcrecpp.h>

#include "bayshore_content_scan.h"
#include "wrapper.h"
#include "libs/zl.h"
#include "libs/bzl.h"
#include "libs/pdf_parser.h"

#include <archive.h>
#include <archive_entry.h>
#include <assert.h>
#include <openssl/md5.h>
#include <algorithm>


///////////////////////////////////////////////////////

struct security_scan_parameters_t {
	const uint8_t *buffer;
	size_t buffer_length;
	char yara_ruleset_filename [300];
	char parent_file_name [300];
	char child_file_name [300];
	char scan_type [300];
	int file_type;
	YR_RULES *rules;

	security_scan_parameters_t() {
		buffer = 0;
		buffer_length = 0;
		*yara_ruleset_filename = 0;
		*parent_file_name = 0;
		*child_file_name = 0;
		*scan_type = 0;
		file_type = -1;
		rules = 0;
	}
};


int iteration_counter = 0;
int archive_failure_counter = 0;

/*
 * type of scan - const data
 *
 * order matters - DO NOT CHANGE,
 * add at the bottom of array
 */
static const char *type_of_scan[] = {
		"Generic", // internal use only
		"Yara Scan"
};


// function declarations

static void scan_content2 (
		const uint8_t *buf,
		size_t sz,
		YR_RULES *rules,
		std::list<security_scan_results_t> *ssr_list,
		const char *parent_file_name,
		void (*cb)(void*, std::list<security_scan_results_t> *, const char *),
		int in_type_of_scan
		);

//////////////////////////////////////////////////////////////
// helper functions

char *str2md5(const char *str, int length)
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

std::string remove_file_extension(const std::string &filename) {
    size_t lastdot = filename.find_last_of(".");
    if (lastdot == std::string::npos)
    	return filename;
    return filename.substr(0, lastdot);
}

bool recurs_threshold_passed(int threshold) {
	int r_threshold = 45;
	if (threshold >= r_threshold)
		return true;
	else
		return false;
}

void increment_recur_counter() {
	iteration_counter++;
	//std::cout << "CNT: " << iteration_counter << std::endl;
}

void increment_archive_failure_counter() {
	archive_failure_counter++;
}

double get_failure_percentage() {

	double total = iteration_counter - 1;

	if (archive_failure_counter > 1 && total > 1)
		return ((double)total/(double)archive_failure_counter) * 100;
	return 0.0;
}

std::string strip_office_open_xml(std::string content, std::string file_type)
{

	std::string regex = "";
	std::string cnt = content;

	if (file_type.compare("docx") == 0) {
		regex = "</w:p>";
		pcrecpp::RE(regex).GlobalReplace(" ", &cnt);
	} else if(file_type.compare("pptx") == 0) {
		regex = "</a:rPr>";
		pcrecpp::RE(regex).GlobalReplace(" ", &cnt);
	}

	pcrecpp::RE("<(.*?)>").GlobalReplace("", &cnt);

	// strip line ending
	std::string::size_type pos = 0;
	while ( ( pos = cnt.find ("\r\n",pos) ) != std::string::npos )
	{
		cnt.erase ( pos, 2 );
	}
	return cnt;
}

void get_buf_hex(char *dest, const char *src, int threshold)
{
    int i;
    static const char *hexdigits = "0123456789abcdef";

    for(i = 0; i < threshold; i++)
    {
        unsigned char u = (unsigned char)(src[i]);
        dest[i*2] = hexdigits [u >> 4];
        dest[(i*2)+1] = hexdigits [u & 0xf];
    }
    dest[i*2] = '\0';
}

void find_open_office_embeddings(void *membuf, size_t size, std::list<std::string> &embeddings)
{
	struct archive *a = archive_read_new();
	if (!a) return;

	struct archive_entry *entry;
	std::string cmp("ObjectReplacements");

	archive_read_support_format_all(a);
	archive_read_support_filter_all(a);

	if (ARCHIVE_OK!=archive_read_open_memory(a, (uint8_t *)membuf, size)) return;
	while (ARCHIVE_OK==archive_read_next_header(a, &entry)) {
		if (archive_entry_size(entry)>0) {
			std::string item(archive_entry_pathname(entry));
			if (item.compare(0, 18, cmp)==0) {
				embeddings.push_back(&item[19]);
			}
		}
	}
	archive_read_close(a);
	archive_read_free(a);
}
//////////////////////////////////////////////////////////////

/************
scan_pdf_api
*************/


void scan_pdf_api(void *cookie,
		std::list<security_scan_results_t> *ssr_list,
		const char *src,
		const char *child_file_name,
		void (*cb)(void*, std::list<security_scan_results_t> *, const char *),
		int in_type_of_scan
		)
{

	security_scan_parameters_t *ssp_local = (security_scan_parameters_t *)cookie;
	assert(ssp_local);

	size_t src_len = 0;
	if (src) src_len = strlen(src);

	/////////////////////////////////////////////////////////
	/*
	 * 1.
	 * scan the entire raw data set (binary format) so that we
	 * can analyze the document in terms of possible malware
	 */
	if (src_len == 0) {
		snprintf (ssp_local->scan_type, sizeof(ssp_local->scan_type), "%s %s", type_of_scan[in_type_of_scan], "(PDF - Raw data)");
	} else {
		snprintf (ssp_local->scan_type, sizeof(ssp_local->scan_type), "%s %s%s", type_of_scan[in_type_of_scan], "(PDF - Raw data)", src);
	}

	if (child_file_name)
		cb((void *)ssp_local, ssr_list, child_file_name);
	else
		cb((void *)ssp_local, ssr_list, "");
	/////////////////////////////////////////////////////////

	/*
	 * declare str_buf here so that it doesnt go
	 * out of scope when "if (in_type_of_scan == 1)"
	 * completes
	 */
	std::string str_buf;
	auto pdf_temp = pdfparser::PdfToText((uint8_t *)ssp_local->buffer, ssp_local->buffer_length);
	str_buf = std::string (pdf_temp.begin(), pdf_temp.end());

	/*
	 * in the case of a byte sequence like this:
	 * 0x00, 0x4F, 0x00, 0x57
	 *
	 * let's re-call PdfToText with a forced encoding of utf8
	 * instead of the default 'raw'
	 */
	if (strlen(str_buf.c_str()) == 0) {
		str_buf.clear();
		auto _pdf_temp = pdfparser::PdfToText((uint8_t *)ssp_local->buffer, ssp_local->buffer_length, pdfparser::TextEncoding::utf8);
		str_buf = std::string (_pdf_temp.begin(), _pdf_temp.end());
	}

	if (str_buf.size()) {

		/*
		 * 2.
		 * scan the extracted text from the PDF so that we
		 * can scan for actual strings
		 */
		if (in_type_of_scan == 1) {

			//str_buf = pdf.extract_text_buffer();
			ssp_local->buffer = (const uint8_t*)str_buf.c_str();
			ssp_local->buffer_length = str_buf.length();

		}

		//std::cout << "EMBED: " << pdf.has_embedded_files() << std::endl;

		if (src_len == 0) {
			snprintf (ssp_local->scan_type, sizeof(ssp_local->scan_type), "%s %s", type_of_scan[in_type_of_scan], "(PDF - Extracted text)");
		} else {
			snprintf (ssp_local->scan_type, sizeof(ssp_local->scan_type), "%s %s%s", type_of_scan[in_type_of_scan], "(PDF - Extracted text)", src);
		}

		if (child_file_name)
			cb((void *)ssp_local, ssr_list, child_file_name);
		else
			cb((void *)ssp_local, ssr_list, "");

	}
	/////////////////////////////////////////////////////////

	// These can no longer be used.
	ssp_local->buffer = NULL;
	ssp_local->buffer_length = 0;

}



/************************
scan_office_open_xml_api
************************/


void scan_office_open_xml_api(
		void *cookie,
		std::list<security_scan_results_t> *oxml_ssr_list,
		const char *src,
		const char *parent_file_name,
		bool context_scan,
		void (*cb)(void*, std::list<security_scan_results_t> *, const char *),
		int in_type_of_scan
		)
{

	cb(cookie, oxml_ssr_list, parent_file_name ? parent_file_name : "");


	security_scan_parameters_t *ssp_local = (security_scan_parameters_t *)cookie;
	assert(ssp_local);

	size_t src_len = 0;
	if (NULL!=src) src_len = strlen(src);

	struct archive *a = archive_read_new();
	assert(a);
	struct archive_entry *entry;
	int r;
	std::list<std::string> embeddings;


	find_open_office_embeddings((uint8_t *)ssp_local->buffer, ssp_local->buffer_length, embeddings);


	archive_read_support_format_all(a);
#if ARCHIVE_VERSION_NUMBER < 3000000
	archive_read_support_compression_all(a);
#elsif ARCHIVE_VERSION_NUMBER >= 3000000
	archive_read_support_filter_all(a);
#endif

	r = archive_read_open_memory(a, (uint8_t *)ssp_local->buffer, ssp_local->buffer_length);

	if (r >= 0) {

		// final sets of data
		uint8_t *final_buff = (uint8_t*) malloc (2048);
		final_buff[0] = 0;
		size_t final_size = 0;
		bool embedded_doc;
		bool macro_file;
		std::string file_type = "";

		for (;;) {

			embedded_doc = false;
			macro_file = false;

			r = archive_read_next_header(a, &entry);

			if (r == ARCHIVE_EOF)
				break;

			if (r != ARCHIVE_OK)
				break;

			if (r < ARCHIVE_WARN)
				break;

			if (archive_entry_size(entry) > 0) {

				char *fname = strdup(archive_entry_pathname(entry));
				//std::cout << fname << std::endl;

				if (fname) {

					std::string oox_type = "";

					if ((strncmp (fname, "word/document.xml", 17) == 0) ||
							(strncmp (fname, "word/header", 11) == 0) ||
							(strncmp (fname, "word/footer", 11) == 0)
						) {
						oox_type = "docx";
					}

					if ((strncmp (fname, "ppt/notesSlides/", 16) == 0) ||
							(strncmp (fname, "ppt/slides/", 11) == 0)
						) {
						oox_type = "pptx";
					}

					if ((strncmp (fname, "xl/worksheets/", 14) == 0) ||
							(strncmp (fname, "xl/sharedStrings", 16) == 0)
							){
						oox_type = "xlsx";
					}

					// deal with embedded docs
					if ((strncmp (fname, "word/embeddings/", 16) == 0) ||
							(strncmp (fname, "ppt/embeddings/", 15) == 0) ||
							(strncmp (fname, "xl/embeddings/", 14) == 0)
							) {
						embedded_doc = true;
					}

					// OpenOffice/LibreOffice -- document content
					if (strncmp(fname, "content.xml", 11) == 0) {
						// The document's content
						oox_type = "odt";
					}

					// macro file present
					if (strncmp(fname, "word/vbaProject.bin", 19) == 0) {
						macro_file = true;
					}

					// Check if this is match for OpenOffice/LibreOffice embeddings
					std::list<std::string>::iterator it;
					std::string item(fname);

					if (embeddings.end()!=std::find(embeddings.begin(), embeddings.end(), item)) {
						oox_type = "odt";
						embedded_doc = true;
					}

					if (oox_type == "docx" ||
							oox_type == "pptx" ||
							oox_type == "xlsx" ||
							oox_type == "odt" ||
							embedded_doc ||
							macro_file
						)
					{

						int x;
						const void *buff;
						size_t lsize;
						off64_t offset;

						for (;;) {
							x = archive_read_data_block(a, &buff, &lsize, &offset);

							if (x == ARCHIVE_EOF) {

								if (recurs_threshold_passed(iteration_counter)) {
									free(fname);
									if (final_buff) free(final_buff);
									goto cleanup_archive;
								}

								final_buff[final_size] = 0;
								int elf_type = get_content_type (final_buff, final_size);
								ssp_local->file_type = elf_type;

								increment_recur_counter();

								////////////////////////////////////////////////////////////////////
								/*
								 * embedded data within the office open xml doc
								 *
								 * if the detected type is officex (open xml) itself
								 * then make a recursive call back into this same
								 * function. otherwise pass the data over to the
								 * callback function for content scanning
								 *
								 */
								if (embedded_doc || macro_file) {

									ssp_local->buffer = final_buff;
									ssp_local->buffer_length = final_size;

									int lf_type = get_content_type (final_buff, final_size);
									ssp_local->file_type = lf_type;

									// ms-office open xml inside open xml
									if (is_type_officex(lf_type)) {

										scan_office_open_xml_api(
												(void *)ssp_local,
												oxml_ssr_list,
												"embedded in an Office Open XML file",
												fname,
												false,
												cb,
												in_type_of_scan);

									} else {

										if (macro_file) {
											snprintf (ssp_local->scan_type, sizeof(ssp_local->scan_type), "%s (%s) %s", type_of_scan[in_type_of_scan], "Macro file: \"vbaProject.bin\"", "embedded in an Office Open XML file");
										} else {
											snprintf (ssp_local->scan_type, sizeof(ssp_local->scan_type), "%s (%s) %s", type_of_scan[in_type_of_scan], get_content_type_string (lf_type), "embedded in an Office Open XML file");
										}

										snprintf (ssp_local->parent_file_name, sizeof(ssp_local->parent_file_name), "%s", parent_file_name);

										cb((void *)ssp_local, oxml_ssr_list, fname);

									}

								} // end if (embedded_doc || macro_file)
								////////////////////////////////////////////////////////////////////

								// non-embedded data ...

								/*
								 * strip out the xml cruft so that scanning is
								 * focused on the actual text
								 *
								 */
								std::string ss = strip_office_open_xml(std::string((const char *)final_buff), oox_type);

								/*
								 * need buffer in hex to make sure we
								 * bypass certain elements of data we
								 * are getting but do not want.
								 *
								 * keep this tight in case we are dealing
								 * with a large data set. get_buf_hex
								 * terminates the destination buffer so
								 * in this case hexStr should be properly
								 * terminated
								 *
								 */
								char hexStr[9];
								get_buf_hex(hexStr, (ss.substr (0,4)).c_str(), 4);

								// do not process zip file header
								if (strncmp (hexStr, "504b0304", 8) != 0) {
									//std::cout << ss << std::endl;
									// this is where we call scans against
									// the data in ss

									int lf_type = get_content_type ((const uint8_t *)ss.c_str(), ss.length());
									ssp_local->file_type = lf_type;
									ssp_local->buffer = (const uint8_t *)ss.c_str();
									ssp_local->buffer_length = ss.length();

									if (src)
										snprintf (ssp_local->scan_type, sizeof(ssp_local->scan_type), "%s %s %s", type_of_scan[in_type_of_scan], "(Office Open XML)", src);
									else
										snprintf (ssp_local->scan_type, sizeof(ssp_local->scan_type), "%s %s", type_of_scan[in_type_of_scan], "(Office Open XML)");
									snprintf (ssp_local->parent_file_name, sizeof(ssp_local->parent_file_name), "%s", parent_file_name);

									cb((void *)ssp_local, oxml_ssr_list, fname);

									ssp_local->buffer = NULL;
									ssp_local->buffer_length = 0;

								}

								// reset
								*final_buff = 0;
								final_size = 0;
								break;

							} else if (x == ARCHIVE_OK) {

								final_size += lsize;
								// extra byte final_size + 1 is for the guard byte
								final_buff = (uint8_t*) realloc (final_buff, final_size + 1);
								assert(final_buff);
								assert(offset + lsize <= final_size);
								memcpy(final_buff + offset, buff, lsize);

							} else {

								break;

							} // end if (x == ARCHIVE_OK)
						} // end for loop
					} // end a bunch of if oox_type
					free(fname);
				} // end if (fname)
			} // end if (archive_entry_size(entry) > 0)
		} // end for loop
		if (final_buff)
			free(final_buff);
	} // end if r >= 0
cleanup_archive:
	// clean up libarchive resources
	archive_read_close(a);
	archive_read_free(a);
}



/*
 * callback
 */

/*******
yara_cb
********/


void yara_cb (void *cookie, std::list<security_scan_results_t> *ssr_list, const char *child_file_name)
{
	/*
	 * yara call back
	 *
	 * this should be the only spot that makes calls out
	 * directly to the bayshore yara wrapper
	 */

	security_scan_parameters_t *ssp_local = (security_scan_parameters_t *)cookie;

	char local_api_yara_results[MAX_YARA_RES_BUF + 1024];
	size_t local_api_yara_results_len = 0;
	/*
	 * to use this API the buffer passed in to param 4 (local_api_yara_results)
	 * must be at least MAX_YARA_RES_BUF + 1024 in size. This is defined in
	 * bayshore_yara_wrapper.h and extended by 1024 in bayshore_yara_wrapper.c
	 *
	 * first check for a native yara compiled rules struct,
	 * if it exists call the wrapper API with it instead of
	 * an actual ruleset file name
	 */

    //used to populate local_api_yara_results if there is a hit
	if (ssp_local->rules) {

		bayshore_yara_wrapper_yrrules_api(
				(uint8_t*)ssp_local->buffer,
				ssp_local->buffer_length,
				ssp_local->rules,
				local_api_yara_results,
				&local_api_yara_results_len);

	    // populate ssr/ssr_list whether there's a hit or not
		security_scan_results_t ssr;
		// populate struct elements
		ssr.file_scan_type = ssp_local->scan_type;
		std::string sres(local_api_yara_results, local_api_yara_results_len);
		ssr.file_scan_result = sres;
		ssr.file_size = ssp_local->buffer_length;

		size_t sspl_sz = strlen(ssp_local->parent_file_name);
		if (sspl_sz > 0) {
			std::string sfname(ssp_local->parent_file_name, sspl_sz);
			ssr.parent_file_name = sfname;
		}

		if (child_file_name) {
			std::string schfname(child_file_name);
			ssr.child_file_name = schfname;
		}

		char *output = str2md5((const char *)ssp_local->buffer, ssp_local->buffer_length);
		if (output) {
			memcpy (ssr.file_signature_md5, output, 33);
			free(output);
		}

		ssr_list->push_back(ssr);

	} else {

		bayshore_yara_wrapper_api(
				(uint8_t*)ssp_local->buffer,
				ssp_local->buffer_length,
				ssp_local->yara_ruleset_filename,
				local_api_yara_results,
				&local_api_yara_results_len);

		security_scan_results_t ssr;
		// populate struct elements
		ssr.file_scan_type = ssp_local->scan_type;
		std::string sres(local_api_yara_results, local_api_yara_results_len);
		ssr.file_scan_result = sres;
		ssr.file_size = ssp_local->buffer_length;

		size_t sspl_sz = strlen(ssp_local->parent_file_name);
		if (sspl_sz > 0) {
			std::string sfname(ssp_local->parent_file_name, sspl_sz);
			ssr.parent_file_name = sfname;
		}

		if (child_file_name) {
			std::string schfname(child_file_name);
			ssr.child_file_name = schfname;
		}

		char *output = str2md5((const char *)ssp_local->buffer, ssp_local->buffer_length);
		if (output) {
			memcpy (ssr.file_signature_md5, output, 33);
			free(output);
		}

		ssr_list->push_back(ssr);
	}

}


/*
 * cpp API
 */

/************
scan_content
************/

void scan_content (
		const uint8_t *buf,
		size_t sz,
		YR_RULES *rules,
		std::list<security_scan_results_t> *ssr_list,
		const char *parent_file_name,
		void (*cb)(void*, std::list<security_scan_results_t> *, const char *),
		int in_type_of_scan
		)
{

	iteration_counter = 0;

	int lin_type_of_scan = -1;
	if (in_type_of_scan < sizeof(type_of_scan) / sizeof(type_of_scan[in_type_of_scan]))
		lin_type_of_scan = in_type_of_scan;
	else
		lin_type_of_scan = 0;

	scan_content2(buf, sz, rules, ssr_list, parent_file_name, cb, lin_type_of_scan);
}


/************
scan_content
************/

void scan_content (
		const uint8_t *buf,
		size_t sz,
		const char *rule_file,
		std::list<security_scan_results_t> *ssr_list,
		const char *parent_file_name,
		void (*cb)(void*, std::list<security_scan_results_t> *, const char *),
		int in_type_of_scan
		)
{

	if (rule_file) {
		YR_RULES* rules = bayshore_yara_preprocess_rules (rule_file);
		if (rules) {
			scan_content (buf, sz, rules, ssr_list, parent_file_name, cb, in_type_of_scan);
			yr_rules_destroy (rules);
		}
	}
}



/*************
scan_content2
*************/

void scan_content2 (
		const uint8_t *buf,
		size_t sz,
		YR_RULES *rules,
		std::list<security_scan_results_t> *ssr_list,
		const char *parent_file_name,
		void (*cb)(void*, std::list<security_scan_results_t> *, const char *),
		int in_type_of_scan
		)
{

	if (buf) {

		/////////////////////////////////////////////////////
		/*
		 * construct the security_scan_parameters_t
		 * struct to pass to the call back funcs
		 *
		 * right here populate the rule_file_name (yara)
		 * and the parent_file_name
		 *
		 * later on, based on detected type, populate
		 * the buffer to be analyzed and its respective
		 * size (length)
		 *
		 */
		security_scan_parameters_t ssp;

		if (in_type_of_scan == 1) {
			if (rules)
				ssp.rules = rules;
		}
		snprintf (ssp.parent_file_name, sizeof(ssp.parent_file_name), "%s", parent_file_name);
		/////////////////////////////////////////////////////

		int buffer_type = get_content_type (buf, sz);
		//std::cout << buffer_type << std::endl;
		bool is_buf_archive = is_type_archive(buffer_type);

		// archive
		if (is_buf_archive) {

			if (recurs_threshold_passed(iteration_counter))
				return;

			increment_recur_counter();
			/*
			 * intercept gzip compression and handle it
			 * outside of libarchive
			 */
			if (is_type_gzip(buffer_type)) {
				// gunzip the data
				ZlibInflator_t myzl;
				myzl.Ingest ((uint8_t *)buf, sz);

				if (myzl.single_result.data && myzl.single_result.used) {

					int lf_type = get_content_type (myzl.single_result.data, myzl.single_result.used);

					std::string tmpfname = std::string(parent_file_name);

					ssp.buffer = myzl.single_result.data;
					ssp.buffer_length = myzl.single_result.used;
					ssp.file_type = lf_type;

					/*
					 * cases like tar.gz, this would be the gunzipped
					 * tarball
					 */
					if (is_type_archive(lf_type)) {

						snprintf (ssp.scan_type, sizeof(ssp.scan_type), "%s (%s) inside GZIP Archive file", type_of_scan[in_type_of_scan], get_content_type_string (lf_type));

						cb((void *)&ssp, ssr_list, (remove_file_extension(tmpfname)).c_str());

						scan_content2 (
								myzl.single_result.data,
								myzl.single_result.used,
								rules,
								ssr_list,
								(remove_file_extension(std::string(parent_file_name))).c_str(),
								cb,
								in_type_of_scan);

					// pdf inside gzip
		            } else if (is_type_pdf(lf_type)) {

						scan_pdf_api(
								(void *)&ssp,
								ssr_list,
								" inside GZIP Archive file",
								(remove_file_extension(tmpfname)).c_str(),
								cb,
								in_type_of_scan);

					// ms-office open xml inside gzip
					} else if (is_type_officex(lf_type)) {

						scan_office_open_xml_api(
								(void *)&ssp,
								ssr_list,
								" inside GZIP Archive file",
								(remove_file_extension(tmpfname)).c_str(),
								false,
								cb,
								in_type_of_scan);

					} else {

						snprintf (ssp.scan_type, sizeof(ssp.scan_type), "%s (%s) inside GZIP Archive file", type_of_scan[in_type_of_scan], get_content_type_string (lf_type));

						cb((void *)&ssp, ssr_list, (remove_file_extension(tmpfname)).c_str());

					}
				} // end if (myzl.single_result.data && myzl.single_result.used)

			} else if (is_type_bzip2(buffer_type)) {

				/*
				 * intercept bzip2 compression and handle it
				 * outside of libarchive
				 */

                BZlibInflator_t mybzl;
                mybzl.bzdecomp((uint8_t*)buf,sz);

                if (mybzl.bzsingle_result.data && mybzl.bzsingle_result.used) {

					int lf_type = get_content_type (mybzl.bzsingle_result.data, mybzl.bzsingle_result.used);

					std::string tmpfname = std::string(parent_file_name);

					ssp.buffer = mybzl.bzsingle_result.data;
					ssp.buffer_length = mybzl.bzsingle_result.used;
					ssp.file_type = lf_type;

					/*
					 * cases like tar.bz, this would be the bunzipped
					 * tarball
					 */
					if (is_type_archive(lf_type)) {

                        snprintf (ssp.scan_type, sizeof(ssp.scan_type), "%s (%s) inside BZIP2 Archive file", type_of_scan[in_type_of_scan], get_content_type_string (lf_type));

						cb((void *)&ssp, ssr_list, (remove_file_extension(tmpfname)).c_str());

						scan_content2 (
								mybzl.bzsingle_result.data,
								mybzl.bzsingle_result.used,
								rules,
								ssr_list,
								(remove_file_extension(std::string(parent_file_name))).c_str(),
								cb,
								in_type_of_scan);

					// pdf inside bzip2
		            } else if (is_type_pdf(lf_type)) {

						scan_pdf_api(
								(void *)&ssp,
								ssr_list,
								" inside BZIP2 Archive file",
								(remove_file_extension(tmpfname)).c_str(),
								cb,
								in_type_of_scan);

					// ms-office open xml inside bzip2
					} else if (is_type_officex(lf_type)) {

						scan_office_open_xml_api(
								(void *)&ssp,
								ssr_list,
								" inside BZIP2 Archive file",
								(remove_file_extension(tmpfname)).c_str(),
								false,
								cb,
								in_type_of_scan);


					} else {

						snprintf (ssp.scan_type, sizeof(ssp.scan_type), "%s (%s) inside BZIP2 Archive file", type_of_scan[in_type_of_scan], get_content_type_string (lf_type));

						cb((void *)&ssp, ssr_list, (remove_file_extension(tmpfname)).c_str());

					}
				} // end if (mybzl.bzsingle_result.data && mybzl.bzsingle_result.used)



			} else {

				// prep stuff for libarchive
				struct archive *a = archive_read_new();
				assert(a);
				struct archive_entry *entry;
				int r;

				archive_read_support_format_all(a);
				archive_read_support_format_raw(a);

#if ARCHIVE_VERSION_NUMBER < 3000000
				archive_read_support_compression_all(a);
#elsif ARCHIVE_VERSION_NUMBER >= 3000000
				archive_read_support_filter_all(a);
#endif

				r = archive_read_open_memory(a, (uint8_t *)buf, sz);

				if (r < 0) {

				} else {
					/*
					 * libarchive understood the archival tech in
					 * place with the data in buffer file_content ...
					 */

					// final sets of data
					uint8_t *final_buff = (uint8_t*) malloc (2048);
					final_buff[0] = 0;
					size_t final_size = 0;

					for (;;) {
						r = archive_read_next_header(a, &entry);

						if (r == ARCHIVE_EOF)
							break;

						if (r != ARCHIVE_OK)
							break;

						if (r < ARCHIVE_WARN)
							break;

						if (archive_entry_size(entry) > 0) {

							char *fname = strdup(archive_entry_pathname(entry));

							int x;
							const void *buff;
							size_t lsize;
							off64_t offset;

							for (;;) {

								x = archive_read_data_block(a, &buff, &lsize, &offset);

								// hit EOF so process constructed buffer
								if (x == ARCHIVE_EOF) {

									if (recurs_threshold_passed(iteration_counter))
										return;

									increment_recur_counter();

									final_buff[final_size] = 0;
									int lf_type = get_content_type (final_buff, final_size);

									ssp.buffer = final_buff;
									ssp.buffer_length = final_size;
									ssp.file_type = lf_type;

									// archive, make recursive call into scan_content
									if (is_type_archive(lf_type)) {

                                        snprintf (ssp.scan_type, sizeof(ssp.scan_type), "%s (%s) inside %s file", type_of_scan[in_type_of_scan], get_content_type_string (lf_type), archive_format_name(a));
										snprintf (ssp.parent_file_name, sizeof(ssp.parent_file_name), "%s", parent_file_name);

										cb((void *)&ssp, ssr_list, fname ? fname : "");

										scan_content2 (final_buff, final_size, rules, ssr_list, fname, cb, in_type_of_scan);

									// pdf
									} else if (is_type_pdf(lf_type)) {

										char scan_src [100];
										snprintf (scan_src, sizeof(scan_src), " inside %s file", archive_format_name(a));
										snprintf (ssp.parent_file_name, sizeof(ssp.parent_file_name), "%s", parent_file_name);

										scan_pdf_api((void *)&ssp, ssr_list, scan_src, fname ? fname : "", cb, in_type_of_scan);

									// ms-office open xml inside archive
									} else if (is_type_officex(lf_type) || is_type_open_document_format(lf_type)) {

										char scan_src [100];
										snprintf (scan_src, sizeof(scan_src), "inside %s file", archive_format_name(a));
										snprintf (ssp.parent_file_name, sizeof(ssp.parent_file_name), "%s", parent_file_name);

										scan_office_open_xml_api((void *)&ssp, ssr_list, scan_src, fname ? fname : "", false, cb, in_type_of_scan);

									} else {

										snprintf (ssp.scan_type, sizeof(ssp.scan_type), "%s (%s) inside %s file", type_of_scan[in_type_of_scan], get_content_type_string (lf_type), archive_format_name(a));
										snprintf (ssp.parent_file_name, sizeof(ssp.parent_file_name), "%s", parent_file_name);

										cb((void *)&ssp, ssr_list, fname ? fname : "");

									}

									// reset to 0
									final_size = 0;
									break;

								} else if (x == ARCHIVE_OK) {

									/*
									 * good to go ...
									 *
									 * extend final_buffer, write data to the
									 * end of it, and terminate back inside of
									 * if (x == ARCHIVE_EOF)
									 */

									final_size += lsize;
									// extra byte final_size + 1 is for the guard byte
									final_buff = (uint8_t*) realloc (final_buff, final_size + 1);
									assert(final_buff);
									assert(offset + lsize <= final_size);
									memcpy(final_buff + offset, buff, lsize);

								} else if (x == ARCHIVE_FAILED) {

									increment_recur_counter();
									increment_archive_failure_counter();
									break;

								} else {

									break;

								} // end if else if
							} // end for
							if (fname)
								free(fname);
						} // end if
					} // end for
					if (final_buff)
						free(final_buff);
				} // end if else

				// free up libarchive resources
				archive_read_close(a);
				archive_read_free(a);
			} // end if gzip else

		} else { // not an archive

			/*
			 * if we are here then we are not dealing
			 * with an archive in the buffer, i.e. not
			 * a zip or gzip or tarball
			 */

			if (recurs_threshold_passed(iteration_counter))
				return;

			increment_recur_counter();

			ssp.buffer = buf;
			ssp.buffer_length = sz;
			ssp.file_type = buffer_type;

			if (is_type_pdf(buffer_type)) {

				scan_pdf_api((void *)&ssp, ssr_list, "", parent_file_name ? parent_file_name : "", cb, in_type_of_scan);

			} else if (is_type_officex(buffer_type) || is_type_open_document_format(buffer_type)) {

				scan_office_open_xml_api((void *)&ssp, ssr_list, "", parent_file_name ? parent_file_name : "", false, cb, in_type_of_scan);

			} else {

				snprintf (ssp.scan_type, sizeof(ssp.scan_type), "%s (%s)", type_of_scan[in_type_of_scan], get_content_type_string (buffer_type));

				cb((void *)&ssp, ssr_list, "");

			}

		} // end if else - archive


		/*
		std::cout << "FAILURES: " << archive_failure_counter << std::endl;
		std::cout << "ITERATIONS: " << iteration_counter << std::endl;
		std::cout << "PERC: " << get_failure_percentage() << std::endl;
		*/
		/////////////////////////////////////////////////////
		if (get_failure_percentage() > 90) {

			security_scan_results_t ssr;
			// populate struct elements
			ssr.file_scan_type = "Archive Anomaly Scan";

			ssr.file_scan_result = "Anomalies present in Archive (possible Decompression Bomb)";

			if (parent_file_name) {
				std::string sfname(parent_file_name);
				ssr.parent_file_name = sfname;
			}

			char *output = str2md5((const char *)buf, sz);
			if (output) {
				memcpy (ssr.file_signature_md5, output, 33);
				free(output);
			}
			ssr_list->push_back(ssr);
		}
		/////////////////////////////////////////////////////
	} // end if (buf)
}
