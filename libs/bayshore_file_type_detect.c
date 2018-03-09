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

#define _GNU_SOURCE

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "bayshore_file_type_detect.h"
#include "bayshore_yara_wrapper.h"


static void compute_coincidence_index (const char*, size_t, double*);
#define AMT 600
#define MAXBUFLEN 2048
#define MAXPATHLEN 8192

int min(int x, int y)
{
	return y ^ ((x ^ y) & -(x < y));
}

void *bayshoresubstring(size_t start, size_t stop, const char *src, char *dst, size_t size)
{
	int count = stop - start;
	if ( count >= --size ) {
		count = size;
	}
	sprintf(dst, "%.*s", count, src + start);
	return dst;
}


/***********************
compute_chi_square_zero
 ***********************/

double compute_chi_square_zero (const uint8_t *data, size_t sz)
{
	double out = -1.0;

	if (data && sz) {
		int64_t observations [256];
		memset (observations, 0, sizeof(observations));

		size_t n_points = sz;
		if (sz != -1) {
			while (sz--)
				observations [*data++] ++;
		}

		int e = 0;
		int i;
		for (i = 0; i < 256; i++)
			if (observations[i])
				e++;
		if (!e)
			return out; // early return; avoid division by zero on empty set
		double expected_value = (double)n_points / (double)e;

		out = 0.0;
		for (i = 0; i < 256; i++) {
			if (observations[i]) {
				double a = ((double)observations[i] - expected_value);
				out += ((a * a) / expected_value);
			}
		}
	}
	return out;
}


/**********************
compute_chi_square_b64
 **********************/

double compute_chi_square_b64 (const uint8_t *data, size_t sz)
{
	double out = -1.0;

	if (data && sz) {
		int64_t observations [256];
		memset (observations, 0, sizeof(observations));

		size_t n_points = sz;
		while (sz--) {
			if (isalnum(*data) || (*data == '+') || (*data == '/'))
				observations [*data] ++;
			data++;
		}

		double expected_value = (double)n_points / 64.0;

		out = 0.0;
		int i;
		for (i = 0; i < 256; i++) {
			if (observations[i]) {
				double a = ((double)observations[i] - expected_value);
				out += ((a * a) / expected_value);
			}
		}

	}

	return out;
}


/******************
is_buffer_encrypted
 *******************/

int is_buffer_encrypted(const uint8_t* buf, size_t nL)
{
	/*
	 * return:
	 *
	 * 1 = true
	 * 0 = false
	 */
	int ret = 0;

	int threshold = 301;
	double dres = 0.0;

	size_t amt = AMT;
	size_t sz;

	if (buf && (nL > 0)) {
		sz = min(nL, amt);

		dres = compute_chi_square_zero (buf, sz);

		/*
		 * encryption test negative, but are we dealing
		 * with base64 encoded data? If so then re-check
		 * for crypto once data has been decoded
		 */
		if (dres >= threshold) {
			dres = compute_chi_square_b64 (buf, sz);
		}
	}

	if (dres > 0.0) {
		if (dres < threshold)
			ret = 1;
	}
	return ret;
}



/*************
get_buffer_hex
 **************/

void get_buffer_hex(char *dest, const char *src, int threshold, int *ispe)
{
	int i;
	//int offs = 0;
	/*
    	hex for PE\0\0 - identifier for a
    	windows portable executable
	 */
	const char pestr[] = "50450000";
	char * pt;
	static const char *hexdigits = "0123456789abcdef";

	for(i = 0; i < threshold; i++)
	{
		unsigned char u = (unsigned char)(src[i]);
		dest[i*2] = hexdigits [u >> 4];
		dest[(i*2)+1] = hexdigits [u & 0xf];
	}
	dest[i*2] = '\0';
	// look for the PE header
	pt = strstr(dest, pestr);
	if( pt != NULL )
	{
		*ispe = 1;
	}
}


/*************************
compute_coincidence_index
 *************************/

void compute_coincidence_index (const char *buf, size_t sz, double *retval)
{
	/* TODO, there are a number of edge cases in here, including
	 * bad parameters and numerical problems like divisions by zero.
	 * In case of an error, what should we return? Should it be a
	 * low value that signals high entropy to the caller? Or should
	 * it be a high number that signals low entropy?
	 * To avoid this problem, we return a truth value, and place
	 * the computed index (if any) in the caller's parameter.
	 */

	//bool ok = false;

	if (buf && *buf && sz && retval) {

		// Only look at the first 1meg. This reduces accuracy but
		// renders performance acceptable.
		if (sz > 1000000)
			sz = 1000000;

		uint64_t n_chars = 0;
		uint64_t freq[256]; // use 256 instead of 26 to avoid segfault in case of bugs
		memset (freq, 0, sizeof(freq));

		while (sz--) {
			if (isalpha (*buf)) {
				++freq[ toupper(*buf) ];
				++n_chars;
			}
			++buf;
		}

		double ic = 0.0;
		int i;
		for (i = 'A'; i <= 'Z'; ++i)
			ic += (double)freq[i] * (double)(freq[i] - 1);

		if (n_chars > 1) {
			*retval = ic / ((double)n_chars * (double)(n_chars-1));
			//ok = true;
		}
	}
	//return ok;
}


/*************
is_text_buffer
 *************/

int is_text_buffer(const uint8_t *buf, size_t sz) {
	/*
	 * there is no real safe and sure way to
	 * detect that a buffer is pure ASCII text
	 * in nature. This will have to suffice
	 * for now
	 *
	 * 1 = ascii text
	 * 0 = not ascii text
	 */

	int i;
	for(i = 0; i < sz; i++)
	{
		if ((int)buf[i] < 0x20)
		{
			if ((buf[i] != '\n') && (buf[i] != '\r') && (buf[i] != '\t')) {
				return 0;
			}
		}
		if ((int)buf[i] > 0xff)
			return 0;
	}
	return 1;
}


/****************
tokenize_yara_str
 *****************/

int tokenize_yara_str(char *buf) {

	int return_type = -1;

	const char s[2] = "-";
	const char ss[3] = ":[";
	char *token;
	char *token_save;
	char *token2;
	char *token2_save;
	int iter_cnt;
	int hex_dec;

	//const char sss[2] = ",";
	const char sss[5] = ",#+,";
	char *token3;
	char *token3_save;

	const char ssss[2] = "=";
	char *token4;
	char *token4_save;

	int known_offset = -1;
	int detected_offset = -1;
	int bayshore_ix = -1;
	int inner_iter_cnt;

	int write_val_ix = 0;
	int write_val_known = 0;
	int write_val_detected = 0;

	/* get the first token */
	token = strtok_r(buf, s, &token_save);

	/* walk through other tokens */
	while( token != NULL )
	{
		iter_cnt = 0;
		/*
		printf("\n\nStarting ...\n");
		printf( "TOKEN: %s\n", token );
		 */
		token2 = strtok_r(token, ss, &token2_save);
		while(token2 != NULL)
		{
			//printf( "TOKEN2: %s\n", token2 );
			if(strstr(token2, "offset=") != NULL) {
				//printf( "Offset exists\n");
				if(strstr(token2, "detected offsets=") != NULL) {
					//printf( "Detected offset exists\n");
					//printf( " %s\n", token2 );
					token3 = strtok_r(token2, sss, &token3_save);
					while( token3 != NULL )
					{
						//printf( "TOKEN3: %s\n", token3 );
						token4 = strtok_r(token3, ssss, &token4_save);
						inner_iter_cnt = 0;
						while( token4 != NULL )
						{
							//printf( "TOKEN4: %s - %d\n", token4, inner_iter_cnt );

							if (write_val_ix == 1) {
								bayshore_ix = atoi(token4);
								write_val_ix = -1;
							}
							if (write_val_known == 1) {
								known_offset = atoi(token4);
								write_val_known = -1;
							}
							if (write_val_detected == 1) {
								sscanf(token4, "%x", &detected_offset);
								write_val_detected = -1;
							}


							if (strncmp(token4, "bayshore_ix", 11) == 0)
								write_val_ix = 1;
							if (strncmp(token4, "offset", 6) == 0)
								write_val_known = 1;
							if (strncmp(token4, "detected offsets", 16) == 0)
								write_val_detected = 1;

							token4 = strtok_r(NULL, ssss, &token4_save);
							inner_iter_cnt++;
							/*
							printf("BAYIX: %d\n", bayshore_ix);
							printf("KNOWNOFF: %d\n", known_offset);
							printf("DETOFF: %d\n", detected_offset);
							 */
							if (bayshore_ix != -1 && known_offset != -1 && detected_offset != -1) {
								if (known_offset == detected_offset)
									return bayshore_ix;
							}
						}
						token3 = strtok_r(NULL, sss, &token3_save);
					}
				}
			}
			/*
			if (iter_cnt == 0) {

				//printf( " %s\n", token2 );
				//printf( "Hex: ");
				sscanf(token2, "%x", &hex_dec);
				//printf( "Dec: %u\n", hex_dec );
			} //else
			//	printf( "String Def: ");
			 */
			token2 = strtok_r(NULL, ss, &token2_save);
			if (iter_cnt == 0)
				iter_cnt++;
		}
		token = strtok_r(NULL, s, &token_save);
	}
	return return_type;
}

int get_buffer_type(const uint8_t *buf, size_t sz) {

	int return_type = -1;

	int zip_exception = -1;
	int xml_exception = -1;
	int is_pe = 0;
	double text_ioc_threshold = 0.1;

	//////////////////////////////////////////////////////////
    char path[MAXPATHLEN];
	if (NULL==getcwd(path, MAXPATHLEN)) {
		// We either have no access or another error occured
		return 65535; //-1;
	}

	strncat (path, "/libs/bayshore_file_type_detect.yara", sizeof(path)-strlen(path)-1);
	//////////////////////////////////////////////////////////

	YR_RULES* rules = bayshore_yara_preprocess_rules (path);

	/*
	 * When calling bayshore_yara_wrapper_yrrules_api, the next-to-last parameter is a
	 * pointer to a caller-supplied char buffer. The caller is required to ensure
	 * that this buffer is at least MAX_YARA_RES_BUF bytes long.
	 */
	char local_api_yara_results[MAX_YARA_RES_BUF + 1024];
	if (rules) {
		size_t local_api_yara_results_len = 0;
		if (bayshore_yara_wrapper_yrrules_api((uint8_t *)buf, sz, rules, local_api_yara_results, &local_api_yara_results_len) > 0) {
			//printf("%s\n", local_api_yara_results);
			return_type = tokenize_yara_str(local_api_yara_results);
		}
		yr_rules_destroy (rules);
	}

	/*
	 * at this stage the yara ruleset data has been processed
	 * depending on what was discovered, or if nothing was
	 * discovered (return_type == -1) we have to probe further
	 */
	if (return_type == 65534) {
		zip_exception = 65534;
	} else if (return_type == 28) {
		zip_exception = 28;
	} else if (return_type == 50) {
		zip_exception = 50;
	} else if (return_type == 31 || return_type == 32) {
		// 31 = php
		xml_exception = 31;
	} else if (return_type != -1) {
		if ((return_type == 26 || return_type == 27)) {
			// is it a Windows PE file?
			if (memmem (buf, sz, "PE\0\0", 4)) {
				return 26000;
			} else {
				return return_type;
			}
		}
		return return_type;
	}

	/*
	 * if we got here and nothing was detected, plus the zip format
	 * WAS detected, then return zip or jar as the return type, otherwise
	 * move on
	 */
	if (zip_exception != -1) {

		/*
		 * differentiate between zip / jar by looking
		 * for - META-INF/MANIFEST.MF
		 *
		 * this isn't perfect but should catch a high
		 * percentage of jar file detection
		 */
		if (memmem (buf, sz, "META-INF/MANIFEST.MF", 20)) {
			return 16;
		} else {
			/*
			 * not a jar file so ....
			 */

			if (zip_exception == 28) {
				return 28;
			}

			if (zip_exception == 50) {
				return 50;
			}

			if (zip_exception == 65534) {
				return 65534;
			}
			return zip_exception;
		}
	}

	/*
	 * if we are here no standard type has been detected so
	 * either we dont know what it is or we have an XML
	 * exception to process
	 */
	// need the buffer in hex for a few checks
	int the_len;
	size_t THRESH = THRESHOLD;
	size_t threshold = min(sz-1, THRESH);
	char hex_str[threshold * 2 + 1];
	get_buffer_hex(hex_str, buf, threshold, &is_pe);

	// we have php, or is it xml??
	if (xml_exception != -1) {
		char thesubstr[11];
		// xml = len 10 in hex
		bayshoresubstring(0, 11, hex_str, thesubstr, sizeof thesubstr);
		// it is xml
		if (strncmp (thesubstr, "3c3f786d6c", 10) == 0) {
			return 45;
		} else {
			// php
			return xml_exception;
		}
	}

	// encrypted?
	if (return_type == -1) {
		double ci = text_ioc_threshold + 1; // ensure the variable is always initialized
		compute_coincidence_index (buf, threshold, &ci);
		/*
		 * we were getting many false positives when
		 * the chi-square tests treat ASCII text as if
		 * its encrypted. A simple index of coincidence
		 * test seems to do the trick here, research shows
		 * that ASCII buffers have values like 0.142857
		 * and 0.351852 while other buffers have values like
		 * 0.0511369 and 0.0382911
		 */
		if (ci <= text_ioc_threshold) {
			if (is_buffer_encrypted(buf, threshold) == 1) {
				return 0;
			}
		}
	}
	// ascii text?
	if (return_type == -1) {
		if (is_text_buffer(buf, sz) == 1)
			return 29;
	}
	// fuck it, we dont know what this is ...
	if (return_type == -1) {
		return_type = 65535;
	}
	return return_type;
}

/*
 * 1 = true
 * 0 = false
 *
 */

// officex - docx, pptx, xslx
int is_officex(int ix) {
	if ((ix == 3) || (ix == 28) || (ix == 50)) {
		/*
		skeyshm_increment_u64 (FILES_RECOGNIZED);
		skeyshm_increment_u64 (FILES_RECOGNIZED_MSOFFICE_OPENXML);
		*/
		return 1;
	}
	return 0;
}

// pcap & pcapng
int is_pcap(int ix) {
	if ((ix == 47) || (ix == 48) || (ix == 49) ||
			(ix == 87) || (ix == 88) || (ix == 89))
		return 1;
	return 0;
}

// unclass
int is_unclassified(int ix) {
	if (ix == 65535)
		return 1;
	return 0;
}

// tar
int is_tar(int ix) {
	if (ix == 46) {
		/*
		skeyshm_increment_u64 (FILES_RECOGNIZED);
		skeyshm_increment_u64 (FILES_RECOGNIZED_ARCHIVE_TAR);
		*/
		return 1;
	}
	return 0;
}

// xml
int is_xml(int ix) {
	if (ix == 45)
		return 1;
	return 0;
}

// odf
int is_open_document_format(int ix) {
	if (ix == 44)
		return 1;
	return 0;
}

// php
int is_php(int ix) {
	if ((ix == 31) || (ix == 32))
		return 1;
	return 0;
}

// rar
int is_rar(int ix) {
	if (ix >= 6 && ix <= 14 || ix == 30) {
		/*
		skeyshm_increment_u64 (FILES_RECOGNIZED);
		skeyshm_increment_u64 (FILES_RECOGNIZED_ARCHIVE_RAR);
		*/
		return 1;
	}
	return 0;
}

// win exe
int is_win_exe(int ix) {
	if ((ix == 26) || (ix == 27) || (ix == 26000) || (ix == 95))
		return 1;
	return 0;
}

// executable
int is_executable(int ix) {

	if ((ix == 0) || (ix == 4) || (ix == 5) ||
			(ix == 26) || (ix == 27) || (ix == 95) ||
			(ix == 96) || (ix == 97) || (ix == 98) ||
			(ix == 99) || (ix == 100) || (ix == 101) ||
			(ix == 26000) || (ix == 65535)
	) {
		return 1;
	}
	return 0;
}

// html
int is_html(int ix) {
	if ((ix == 22) || (ix == 23) || (ix == 24) || (ix == 25)) {
		/*
		skeyshm_increment_u64 (FILES_RECOGNIZED);
		skeyshm_increment_u64 (FILES_RECOGNIZED_HTML);
		*/
		return 1;
	}
	return 0;
}

// gzip
int is_gzip(int ix) {
	if ((ix == 17) || (ix == 18)) {
		/*
		skeyshm_increment_u64 (FILES_RECOGNIZED);
		skeyshm_increment_u64 (FILES_RECOGNIZED_ARCHIVE_GZIP);
		*/
		return 1;
	}
	return 0;
}

// pdf
int is_pdf(int ix) {
	if ((ix == 1) || (ix == 2)) {
		/*
		skeyshm_increment_u64 (FILES_RECOGNIZED);
		skeyshm_increment_u64 (FILES_RECOGNIZED_PDF);
		*/
		return 1;
	}
	return 0;
}

// office - .doc, .ppt, .xsl
int is_office(int ix) {
	if ((ix == 4) || (ix == 5)) {
		/*
		skeyshm_increment_u64 (FILES_RECOGNIZED);
		skeyshm_increment_u64 (FILES_RECOGNIZED_MSOFFICE);
		*/
		return 1;
	}
	return 0;
}

// image
int is_image(int ix) {
	// images are between 33 and 43 inclusive.
	// 119
	if ((ix >= 33 && ix <= 43) || (ix == 119))
		return 1;
	return 0;
}

// zip
int is_zip(int ix) {
	if ((ix == 65534) || (ix == 109) || (ix == 110) || (ix == 111) || (ix == 112)) {
		/*
		skeyshm_increment_u64 (FILES_RECOGNIZED);
		skeyshm_increment_u64 (FILES_RECOGNIZED_ARCHIVE_ZIP);
		*/
		return 1;
	}
	return 0;
}

// matlab
int is_matlab(int ix) {
	if (ix == 51 || ix == 52) {
		/*
		skeyshm_increment_u64 (FILES_RECOGNIZED);
		skeyshm_increment_u64 (FILES_RECOGNIZED_MATLAB);
		*/
		return 1;
	}
	return 0;
}

// 7-zip
int is_7zip(int ix) {
	if (ix == 21) {
		/*
		skeyshm_increment_u64 (FILES_RECOGNIZED);
		skeyshm_increment_u64 (FILES_RECOGNIZED_ARCHIVE_7ZIP);
		*/
		return 1;
	}
	return 0;
}

// archive
int is_archive(int ix) {
	/*
	 * 65534 = zip
	 * 17 = gzip
	 * 18 = gzip
	 * 46 = tar
	 * is_rar() covers all known rar patterns
	 * 21 = 7-zip
	 * 157 = bzip2
	 */
	if ((is_zip(ix)) ||
			(is_gzip(ix)) ||
			(is_tar(ix)) ||
			(is_rar(ix)) ||
			(is_7zip(ix)) ||
			(is_bzip2(ix))
	)
		return 1;
	return 0;
}

// encrypted
int is_encrypted(int ix) {
	if ((ix == 0) || (ix == 11) || (ix == 12) || (ix == 13) ||
			(ix == 14) || (ix == 54) || (ix == 80) || (ix == 81) ||
			(ix == 82) || (ix == 83) || (ix == 84) || (ix == 113) ||
			(ix == 114)) {
		return 1;
	}
	return 0;
}

// bzip2
int is_bzip2(int ix) {
	if (ix == 157) {
		return 1;
	}
	return 0;
}


void get_buffer_type_str(int type, uint8_t *buf) {
	/*
	 * this may not be cleanest way of doing this
	 * (getting the text string of a detected file type)
	 * but it seems fast enough
	 *
	 * I just hate maintaining this data set here
	 * on top of the yara ruleset used for type
	 * detection but this is the path of least
	 * resistance at the moment ...
	 *
	 * The { case ... } code here was generated via
	 * a py script run against the bayshore file
	 * type detection yara ruleset
	 */
	int the_len = 0;

	switch (type) {
	case 0:
		strcpy (buf, "Goodwill guess  Encrypted file detected");
		the_len = 39;
		break;
	case 1:
		strcpy (buf, "Adobe PDF");
		the_len = 9;
		break;
	case 3:
		strcpy (buf, "Microsoft Office Open XML Format Document (DOCX PPTX XLSX)");
		the_len = 58;
		break;
	case 4:
		strcpy (buf, "Microsoft Office document (DOC PPT XLS)");
		the_len = 39;
		break;
	case 6:
		strcpy (buf, "RAR Archive");
		the_len = 11;
		break;
	case 7:
		strcpy (buf, "RAR Archive");
		the_len = 11;
		break;
	case 8:
		strcpy (buf, "RAR Archive");
		the_len = 11;
		break;
	case 9:
		strcpy (buf, "RAR Archive (Part 1 of Multiple Files)");
		the_len = 38;
		break;
	case 10:
		strcpy (buf, "RAR Archive (Subsequent Part of Multiple Files)");
		the_len = 47;
		break;
	case 11:
		strcpy (buf, "Encrypted RAR Archive");
		the_len = 21;
		break;
	case 12:
		strcpy (buf, "Encrypted RAR Archive");
		the_len = 21;
		break;
	case 13:
		strcpy (buf, "Encrypted RAR Archive (Part 1 of Multiple Files)");
		the_len = 48;
		break;
	case 14:
		strcpy (buf, "Encrypted RAR Archive (Subsequent Part of Multiple Files)");
		the_len = 57;
		break;
	case 16:
		strcpy (buf, "Jar Archive");
		the_len = 11;
		break;
	case 17:
		strcpy (buf, "GZIP Archive");
		the_len = 12;
		break;
	case 18:
		strcpy (buf, "GZIP Archive");
		the_len = 12;
		break;
	case 19:
		strcpy (buf, "Compressed Tape Archive (TARZ)");
		the_len = 30;
		break;
	case 20:
		strcpy (buf, "Compressed Tape Archive (TARZ)");
		the_len = 30;
		break;
	case 21:
		strcpy (buf, "7-Zip compressed file");
		the_len = 21;
		break;
	case 22:
		strcpy (buf, "HTML File");
		the_len = 9;
		break;
	case 23:
		strcpy (buf, "HTML File");
		the_len = 9;
		break;
	case 24:
		strcpy (buf, "HTML File");
		the_len = 9;
		break;
	case 25:
		strcpy (buf, "HTML File");
		the_len = 9;
		break;
	case 26:
		strcpy (buf, "Windows Executable");
		the_len = 18;
		break;
	case 27:
		strcpy (buf, "Windows Executable");
		the_len = 18;
		break;
	case 28:
		strcpy (buf, "Microsoft Office Open XML Format Document (DOCX PPTX XLSX)");
		the_len = 58;
		break;
	case 29:
		strcpy (buf, "ASCII Text File");
		the_len = 15;
		break;
	case 30:
		strcpy (buf, "Encrypted RAR Archive");
		the_len = 21;
		break;
	case 31:
		strcpy (buf, "PHP Source Code");
		the_len = 15;
		break;
	case 32:
		strcpy (buf, "PHP Source Code");
		the_len = 15;
		break;
	case 33:
		strcpy (buf, "JPEG image file");
		the_len = 15;
		break;
	case 34:
		strcpy (buf, "JPEG (EXIF) image file");
		the_len = 22;
		break;
	case 35:
		strcpy (buf, "JPEG (SPIFF) image file");
		the_len = 23;
		break;
	case 36:
		strcpy (buf, "JPEG2000 image file");
		the_len = 19;
		break;
	case 37:
		strcpy (buf, "Bitmap image file");
		the_len = 17;
		break;
	case 38:
		strcpy (buf, "GIF image file");
		the_len = 14;
		break;
	case 39:
		strcpy (buf, "TIFF image file");
		the_len = 15;
		break;
	case 40:
		strcpy (buf, "TIFF image file");
		the_len = 15;
		break;
	case 41:
		strcpy (buf, "TIFF image file");
		the_len = 15;
		break;
	case 42:
		strcpy (buf, "TIFF image file");
		the_len = 15;
		break;
	case 43:
		strcpy (buf, "PNG image file");
		the_len = 14;
		break;
	case 44:
		strcpy (buf, "Open Document Format (ODF) document");
		the_len = 35;
		break;
	case 45:
		strcpy (buf, "XML Document");
		the_len = 12;
		break;
	case 46:
		strcpy (buf, "TAR Archive");
		the_len = 11;
		break;
	case 47:
		strcpy (buf, "PCAP file");
		the_len = 9;
		break;
	case 48:
		strcpy (buf, "PCAP file");
		the_len = 9;
		break;
	case 50:
		strcpy (buf, "Microsoft Office Open XML Format Document (DOCX PPTX XLSX)");
		the_len = 58;
		break;
	case 51:
		strcpy (buf, "MATLAB 5X");
		the_len = 9;
		break;
	case 52:
		strcpy (buf, "MATLAB 7X");
		the_len = 9;
		break;
	case 53:
		strcpy (buf, "CATIA Model");
		the_len = 11;
		break;
	case 54:
		strcpy (buf, "Mujahideen Secrets 2 encrypted file");
		the_len = 35;
		break;
	case 55:
		strcpy (buf, "AutoCAD Drawing");
		the_len = 15;
		break;
	case 56:
		strcpy (buf, "Lotus Notes Database");
		the_len = 20;
		break;
	case 57:
		strcpy (buf, "Lotus Notes Database Template");
		the_len = 29;
		break;
	case 58:
		strcpy (buf, "Microsoft Outlook Personal Folder File");
		the_len = 38;
		break;
	case 59:
		strcpy (buf, "Generic E-Mail (EML) File");
		the_len = 25;
		break;
	case 60:
		strcpy (buf, "Generic E-Mail (EML) File");
		the_len = 25;
		break;
	case 61:
		strcpy (buf, "Generic E-Mail (EML) File");
		the_len = 25;
		break;
	case 62:
		strcpy (buf, "Generic E-Mail (EML) File");
		the_len = 25;
		break;
	case 63:
		strcpy (buf, "Generic E-Mail (EML) File");
		the_len = 25;
		break;
	case 64:
		strcpy (buf, "Outlook Express address book (Win95)");
		the_len = 36;
		break;
	case 65:
		strcpy (buf, "Outlook Express E-Mail Folder");
		the_len = 29;
		break;
	case 66:
		strcpy (buf, "Outlook Address File");
		the_len = 20;
		break;
	case 67:
		strcpy (buf, "Outlook Address File");
		the_len = 20;
		break;
	case 68:
		strcpy (buf, "PGP/GPG Public Key File - RSA Key Length 1024");
		the_len = 45;
		break;
	case 69:
		strcpy (buf, "PGP/GPG Public Key File - RSA Key Length 2048");
		the_len = 45;
		break;
	case 70:
		strcpy (buf, "PGP/GPG Public Key File - RSA Key Length 3072");
		the_len = 45;
		break;
	case 71:
		strcpy (buf, "PGP/GPG Public Key File - RSA Key Length 4096");
		the_len = 45;
		break;
	case 72:
		strcpy (buf, "PGP/GPG Private Key File - RSA Key Length 1024");
		the_len = 46;
		break;
	case 73:
		strcpy (buf, "PGP/GPG Private Key File - RSA Key Length 2048");
		the_len = 46;
		break;
	case 74:
		strcpy (buf, "PGP/GPG Private Key File - RSA Key Length 3072");
		the_len = 46;
		break;
	case 75:
		strcpy (buf, "PGP/GPG Private Key File - RSA Key Length 4096");
		the_len = 46;
		break;
	case 76:
		strcpy (buf, "PGP/GPG Private Key File (password protected) - RSA Key Length 1024");
		the_len = 67;
		break;
	case 77:
		strcpy (buf, "PGP/GPG Private Key File (password protected) - RSA Key Length 2048");
		the_len = 67;
		break;
	case 78:
		strcpy (buf, "PGP/GPG Private Key File (password protected) - RSA Key Length 3072");
		the_len = 67;
		break;
	case 79:
		strcpy (buf, "PGP/GPG Private Key File (password protected) - RSA Key Length 4096");
		the_len = 67;
		break;
	case 80:
		strcpy (buf, "PGP/GPG Encrypted File - RSA Key Length 1024");
		the_len = 44;
		break;
	case 81:
		strcpy (buf, "PGP/GPG Encrypted File - RSA Key Length 2048");
		the_len = 44;
		break;
	case 82:
		strcpy (buf, "PGP/GPG Encrypted File - RSA Key Length 3072");
		the_len = 44;
		break;
	case 83:
		strcpy (buf, "PGP/GPG Encrypted File - RSA Key Length 4096");
		the_len = 44;
		break;
	case 84:
		strcpy (buf, "PGP Encrypted Message (ciphertext)");
		the_len = 34;
		break;
	case 85:
		strcpy (buf, "PGP Public Key Block");
		the_len = 20;
		break;
	case 86:
		strcpy (buf, "PGP Private Key Block");
		the_len = 21;
		break;
	case 87:
		strcpy (buf, "PCAP file");
		the_len = 9;
		break;
	case 88:
		strcpy (buf, "PCAP file");
		the_len = 9;
		break;
	case 89:
		strcpy (buf, "PCAPNG file");
		the_len = 11;
		break;
	case 90:
		strcpy (buf, "Windows Policy Administrative Template");
		the_len = 38;
		break;
	case 91:
		strcpy (buf, "Windows Policy Administrative Template");
		the_len = 38;
		break;
	case 92:
		strcpy (buf, "Windows Policy Administrative Template");
		the_len = 38;
		break;
	case 93:
		strcpy (buf, "Windows Group Policy Administrative Template");
		the_len = 44;
		break;
	case 94:
		strcpy (buf, "China Mobile Application");
		the_len = 24;
		break;
	case 95:
		strcpy (buf, "Windows Executable");
		the_len = 18;
		break;
	case 96:
		strcpy (buf, "ELF Executable");
		the_len = 14;
		break;
	case 97:
		strcpy (buf, "Mach-O 32-Bit Big Endian");
		the_len = 24;
		break;
	case 98:
		strcpy (buf, "Mach-O 32-Bit Little Endian");
		the_len = 27;
		break;
	case 99:
		strcpy (buf, "Mach-O 64-Bit Big Endian");
		the_len = 24;
		break;
	case 100:
		strcpy (buf, "Mach-O 64-Bit Little Endian");
		the_len = 27;
		break;
	case 101:
		strcpy (buf, "Java Bytecode or Mach-O FAT Binary");
		the_len = 34;
		break;
	case 102:
		strcpy (buf, "Java Bytecode (Pack200 compression)");
		the_len = 35;
		break;
	case 103:
		strcpy (buf, "Java Serialization Data");
		the_len = 23;
		break;
	case 104:
		strcpy (buf, "Microsoft Net Resource File");
		the_len = 27;
		break;
	case 105:
		strcpy (buf, "Shockwave Flash File (SWF)");
		the_len = 26;
		break;
	case 106:
		strcpy (buf, "Shockwave Flash File (SWF)");
		the_len = 26;
		break;
	case 107:
		strcpy (buf, "Flash Video File (FLV)");
		the_len = 22;
		break;
	case 108:
		strcpy (buf, "Torrent File");
		the_len = 12;
		break;
	case 109:
		strcpy (buf, "Zip Archive");
		the_len = 11;
		break;
	case 110:
		strcpy (buf, "Zip Archive");
		the_len = 11;
		break;
	case 111:
		strcpy (buf, "PKSFX Self-Extracting Archive");
		the_len = 29;
		break;
	case 112:
		strcpy (buf, "PKLITE Compressed ZIP Archive");
		the_len = 29;
		break;
	case 113:
		strcpy (buf, "Puffer Encrypted Archive");
		the_len = 24;
		break;
	case 114:
		strcpy (buf, "Puffer ASCII-Armored Encrypted Archive");
		the_len = 38;
		break;
	case 115:
		strcpy (buf, "VirtualBox Disk Image (VDI)");
		the_len = 27;
		break;
	case 116:
		strcpy (buf, "VMware 3 Virtual Disk");
		the_len = 21;
		break;
	case 117:
		strcpy (buf, "VMware 4 Virtual Disk");
		the_len = 21;
		break;
	case 118:
		strcpy (buf, "VMware 4 Virtual Disk");
		the_len = 21;
		break;
	case 119:
		strcpy (buf, "TIFF image file");
		the_len = 15;
		break;
	case 120:
		strcpy (buf, "Compiled HTML");
		the_len = 13;
		break;
	case 121:
		strcpy (buf, "Windows Help File");
		the_len = 17;
		break;
	case 122:
		strcpy (buf, "Windows Help File");
		the_len = 17;
		break;
	case 123:
		strcpy (buf, "Shell Script (shebang)");
		the_len = 22;
		break;
	case 124:
		strcpy (buf, "MPEG Video file");
		the_len = 15;
		break;
	case 125:
		strcpy (buf, "MPEG Video file");
		the_len = 15;
		break;
	case 126:
		strcpy (buf, "Microsoft Windows Media Audio/Video File (ASF WMA WMV)");
		the_len = 54;
		break;
	case 127:
		strcpy (buf, "Wave File (WAV)");
		the_len = 15;
		break;
	case 128:
		strcpy (buf, "Audio Video Interleaved File (AVI)");
		the_len = 34;
		break;
	case 129:
		strcpy (buf, "Real Audio Metadata File (RAM)");
		the_len = 30;
		break;
	case 130:
		strcpy (buf, "RealMedia File (RM)");
		the_len = 19;
		break;
	case 131:
		strcpy (buf, "QuickTime Movie");
		the_len = 15;
		break;
	case 132:
		strcpy (buf, "QuickTime Movie (MP4)");
		the_len = 21;
		break;
	case 133:
		strcpy (buf, "QuickTime Movie (3GP)");
		the_len = 21;
		break;
	case 134:
		strcpy (buf, "QuickTime Movie (3GP)");
		the_len = 21;
		break;
	case 135:
		strcpy (buf, "QuickTime - Apple Lossless Audio Codec file (M4A)");
		the_len = 49;
		break;
	case 136:
		strcpy (buf, "QuickTime Movie (M4V)");
		the_len = 21;
		break;
	case 137:
		strcpy (buf, "QuickTime Movie (MP4)");
		the_len = 21;
		break;
	case 138:
		strcpy (buf, "QuickTime Movie (MP4)");
		the_len = 21;
		break;
	case 139:
		strcpy (buf, "QuickTime Movie (MP4)");
		the_len = 21;
		break;
	case 140:
		strcpy (buf, "QuickTime Movie (MP4)");
		the_len = 21;
		break;
	case 141:
		strcpy (buf, "QuickTime Movie (MOV)");
		the_len = 21;
		break;
	case 142:
		strcpy (buf, "MPEG-4 Video File (3GP5)");
		the_len = 24;
		break;
	case 143:
		strcpy (buf, "PGP/GPG Signed Content");
		the_len = 22;
		break;
	case 144:
		strcpy (buf, "Javascript open tag");
		the_len = 19;
		break;
	case 145:
		strcpy (buf, "Javascript close tag");
		the_len = 20;
		break;
	case 146:
		strcpy (buf, "Iframe open tag");
		the_len = 15;
		break;
	case 147:
		strcpy (buf, "Iframe close tag");
		the_len = 16;
		break;
	case 148:
		strcpy (buf, "MS-Office macro");
		the_len = 15;
		break;
	case 149:
		strcpy (buf, "MPEG-1 Audio Layer 3 File (MP3)");
		the_len = 31;
		break;
	case 150:
		strcpy (buf, "Expert Witness Compression Formatted file (EWF)");
		the_len = 47;
		break;
	case 151:
		strcpy (buf, "EnCase Evidence File Format (Version 2)");
		the_len = 39;
		break;
	case 152:
		strcpy (buf, "Adobe PostScript File (PS)");
		the_len = 26;
		break;
	case 153:
		strcpy (buf, "Adobe PostScript File (PS)");
		the_len = 26;
		break;
	case 154:
		strcpy (buf, "Adobe Encapsulated PostScript File (EPS)");
		the_len = 40;
		break;
	case 155:
		strcpy (buf, "Windows shell link (shortcut) file");
		the_len = 34;
		break;
	case 156:
		strcpy (buf, "Microsoft Common Object File Format (COFF) relocatable object code file");
		the_len = 71;
		break;
	case 157:
		strcpy (buf, "bzip2 Compressed Archive");
		the_len = 24;
		break;
	case 26000:
		strcpy (buf, "Windows Portable Executable");
		the_len = 27;
		break;
	case 65534:
		strcpy (buf, "Zip Archive");
		the_len = 11;
		break;
	case 65535:
		strcpy (buf, "Unclassified Binary");
		the_len = 19;
		break;
	default:
		the_len = 0;
		break;
	}
	buf[the_len] = '\0';
}


int get_file_type(const uint8_t *file_name) {

	if (!file_name) return -1;

	// open and read file
	// pass buffer and length to get_buffer_type
	// return val returned from get_buffer_type
	int ret = -1;
	char source[MAXBUFLEN + 1];

	FILE *fp = fopen((const char*)file_name, "r");
	if (fp != NULL) {
		size_t newLen = fread(source, sizeof(char), MAXBUFLEN, fp);
		if ( ferror( fp ) != 0 ) {
			fputs("Error reading file", stderr);
			ret = -1; // signal the error
		} else {
			source[newLen++] = '\0'; /* Just to be safe. */
			ret = get_buffer_type((uint8_t *)source, strlen(source));
		}
		fclose(fp);
	}
	//printf("RET: %d\n\n", ret);
	return ret;
}
