/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * This file is part of yextend.
 *
 * Copyright (c) 2104-2016, Bayshore Networks, Inc.
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

#include "bayshore_file_type_detect.h"
#include "bayshore_yara_wrapper.h"


static void compute_coincidence_index (const char*, size_t, double*);
#define AMT 600

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
		while (sz--)
			observations [*data++] ++;

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

	if (buf && sz && retval) {

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
	
	const char sss[2] = ",";
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

int get_file_type(const uint8_t *buf, size_t sz) {
	int return_type = -1;
	
    int zip_exception = -1;
    int xml_exception = -1;
    int is_pe = 0;
    double text_ioc_threshold = 0.1;
    
	//////////////////////////////////////////////////////////
	/*
	 * this has to get replaced for production, using it
	 * like this for testing now
	 */
	//char *path = NULL;
	char path[8192];
	*path = 0;
	strncat (path, getcwd(NULL, 0), sizeof(path)-strlen(path)-1);
	//path = getcwd(NULL, 0);
	//std::string ltfn = path;
	//ltfn.append("/yara_ruleset/bayshore_file_type_detect.yara");
	//strncat (path, "/yara_ruleset/bayshore_file_type_detect.yara", sizeof(path)-strlen(path)-1);
	strncat (path, "/libs/bayshore_file_type_detect.yara", sizeof(path)-strlen(path)-1);
	//printf("%s\n", path);
	//////////////////////////////////////////////////////////

	//char local_tmp_file_name[] 
	//YR_RULES* rules = bayshore_yara_preprocess_rules (ltfn.c_str());
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
	} else if (return_type == 31 || return_type == 32) {
		xml_exception = 31;
	} else if (return_type != -1) {
		if ((return_type == 26 || return_type == 27)) {
			// is it a Windows PE file?
			if (memmem (buf, sz, "PE\0\0", 4)) {
				//skeyshm_increment_u64 (FILES_RECOGNIZED);
				//skeyshm_increment_u64 (FILES_RECOGNIZED_WIN_EXE_PORTABLE);
				return 26000;
			} else {
				//skeyshm_increment_u64 (FILES_RECOGNIZED);
				//skeyshm_increment_u64 (FILES_RECOGNIZED_WIN_EXE);
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
		//skeyshm_increment_u64 (FILES_RECOGNIZED);
		//skeyshm_increment_u64 (FILES_RECOGNIZED_ARCHIVE_ZIP);
		return zip_exception;
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
			//skeyshm_increment_u64 (FILES_RECOGNIZED);
			//skeyshm_increment_u64 (FILES_RECOGNIZED_XML);
			return 45;
		} else {
        	return xml_exception;
		}
	}

	// encrypted?
	if (return_type == -1) {
		double ci;
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
				//skeyshm_increment_u64 (FILES_RECOGNIZED);
				//skeyshm_increment_u64 (FILES_RECOGNIZED_ENCRYPTED);
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
		//skeyshm_increment_u64 (FILES_RECOGNIZED);
		//skeyshm_increment_u64 (FILES_RECOGNIZED_MSOFFICE_OPENXML);
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
		//skeyshm_increment_u64 (FILES_RECOGNIZED);
		//skeyshm_increment_u64 (FILES_RECOGNIZED_ARCHIVE_TAR);
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
		//skeyshm_increment_u64 (FILES_RECOGNIZED);
		//skeyshm_increment_u64 (FILES_RECOGNIZED_ARCHIVE_RAR);
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

// html
int is_html(int ix) {
	if ((ix == 22) || (ix == 23) || (ix == 24) || (ix == 25)) {
		//skeyshm_increment_u64 (FILES_RECOGNIZED);
		//skeyshm_increment_u64 (FILES_RECOGNIZED_HTML);
		return 1;
	}
	return 0;
}

// gzip
int is_gzip(int ix) {
	if ((ix == 17) || (ix == 18)) {
		//skeyshm_increment_u64 (FILES_RECOGNIZED);
		//skeyshm_increment_u64 (FILES_RECOGNIZED_ARCHIVE_GZIP);
		return 1;
	}
	return 0;
}

// pdf
int is_pdf(int ix) {
	if ((ix == 1) || (ix == 2)) {
		//skeyshm_increment_u64 (FILES_RECOGNIZED);
		//skeyshm_increment_u64 (FILES_RECOGNIZED_PDF);
		return 1;
	}
	return 0;
}

// office - .doc, .ppt, .xsl
int is_office(int ix) {
	if ((ix == 4) || (ix == 5)) {
		//skeyshm_increment_u64 (FILES_RECOGNIZED);
		//skeyshm_increment_u64 (FILES_RECOGNIZED_MSOFFICE);
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
		//skeyshm_increment_u64 (FILES_RECOGNIZED);
		//skeyshm_increment_u64 (FILES_RECOGNIZED_ARCHIVE_ZIP);
		return 1;
	}
	return 0;
}

// matlab
int is_matlab(int ix) {
	if (ix == 51 || ix == 52) {
		//skeyshm_increment_u64 (FILES_RECOGNIZED);
		//skeyshm_increment_u64 (FILES_RECOGNIZED_MATLAB);
		return 1;
	}
	return 0;
}

// 7-zip
int is_7zip(int ix) {
	if (ix == 21) {
		//skeyshm_increment_u64 (FILES_RECOGNIZED);
		//skeyshm_increment_u64 (FILES_RECOGNIZED_ARCHIVE_7ZIP);
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
	 */
    if ((is_zip(ix)) ||
        (is_gzip(ix)) ||
        (is_tar(ix)) ||
        (is_rar(ix)) ||
        (is_7zip(ix))
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



void get_file_type_str(int type, uint8_t *buf) {
    char str1[]= "SOMETHING";
    // TODO .... need str values in here
    strncpy ( buf, str1, sizeof(buf) );
}

