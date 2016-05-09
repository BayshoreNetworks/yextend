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

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>

#include "bayshore_yara_wrapper.h"

//defines
#define MAX_ARGS_TAG            32
#define MAX_ARGS_IDENTIFIER     32
#define MAX_ARGS_EXT_VAR        32
#define MAX_ARGS_MODULE_DATA    32
/*
#define PRIx64 "llx"
#define PRId64 "lld"
*/

// structs
/*
typedef struct _MODULE_DATA
{
	const char* module_name;
	void* module_data;
	size_t module_data_size;
	struct _MODULE_DATA* next;

} MODULE_DATA;
*/
typedef struct _MODULE_DATA
{
  const char* module_name;
  YR_MAPPED_FILE mapped_file;
  struct _MODULE_DATA* next;

} MODULE_DATA;

// vars and initializations
char* tags[MAX_ARGS_TAG + 1];
char* identifiers[MAX_ARGS_IDENTIFIER + 1];
char* ext_vars[MAX_ARGS_EXT_VAR + 1];
char* modules_data[MAX_ARGS_EXT_VAR + 1];

int show_strings = TRUE;
int show_meta = TRUE;

MODULE_DATA* modules_data_list = NULL;

static char yara_results[MAX_YARA_RES_BUF + 1024];

// functions
void print_scanner_error(int error)
{
	switch (error)
	{
	case ERROR_SUCCESS:
		break;
	case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
		fprintf(stderr, "can not attach to process (try running as root)\n");
		break;
	case ERROR_INSUFICIENT_MEMORY:
		fprintf(stderr, "not enough memory\n");
		break;
	case ERROR_SCAN_TIMEOUT:
		fprintf(stderr, "scanning timed out\n");
		break;
	case ERROR_COULD_NOT_OPEN_FILE:
		fprintf(stderr, "could not open file\n");
		break;
	case ERROR_UNSUPPORTED_FILE_VERSION:
		fprintf(stderr, "rules were compiled with a newer version of YARA.\n");
		break;
	case ERROR_CORRUPT_FILE:
		fprintf(stderr, "corrupt compiled rules file.\n");
		break;
	default:
		fprintf(stderr, "internal error: %d\n", error);
		break;
	}
}

void print_compiler_error(
		int error_level,
		const char* file_name,
		int line_number,
		const char* message,
		void* user_data
		)
{
	if (error_level == YARA_ERROR_LEVEL_ERROR)
	{
		fprintf(stderr, "%s(%d): error: %s\n", file_name, line_number, message);
	} else {
		fprintf(stderr, "%s(%d): warning: %s\n", file_name, line_number, message);
	}
}

int bayshore_yara_handle_message(int message, YR_RULE* rule, void* data)
{
	int is_matching;
	int count = 0;
	int limit = 0;

	is_matching = (message == CALLBACK_MSG_RULE_MATCHING);

	/*
	 * if there is a match with a yara rule then concat the 
	 * relevant meta-data to the variable yara_results
	 */
	if (is_matching)
	{
		char yara_meta_results[MAX_YARA_RES_BUF];
		yara_meta_results[0] = 0;
		
		// assuming yara_results is a buffer and not a pointer
		strncat (yara_results, rule->identifier, sizeof(yara_results)-strlen(yara_results)-1);
		
		if (show_meta) {
			YR_META* meta;
			//printf("[ ");
			yr_rule_metas_foreach(rule, meta)
			{
				if (meta != rule->metas)
					strncat (yara_meta_results, ",", sizeof(yara_results)-strlen(yara_results)-1);
				
				if (meta->type == META_TYPE_INTEGER) {
					strncat (yara_meta_results, meta->identifier, sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
					strncat (yara_meta_results, "=", sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
					
					char intstr[15];
					//sprintf(intstr, "%d", meta->integer);
					//sprintf(intstr, "%" PRId64, meta->integer);
					snprintf(intstr, sizeof(intstr), "%ld", meta->integer);
					strncat (yara_meta_results, intstr, sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
				} else if (meta->type == META_TYPE_BOOLEAN) {
					strncat (yara_meta_results, meta->identifier, sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
					strncat (yara_meta_results, "=", sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
					
					char intstr[15];
					sprintf(intstr, "%s", meta->integer ? "true" : "false");
					strncat (yara_meta_results, intstr, sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
				} else {
					strncat (yara_meta_results, meta->identifier, sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
					strncat (yara_meta_results, "=", sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
					strncat (yara_meta_results, meta->string, sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
				}
			}
			//printf("] ");
		}
		//printf("] ");
		
		int hit_cnt = 0;
		char tmp_str_results[4096];
		tmp_str_results[0] = 0;
		
		if (show_strings) {
			YR_STRING* string;
			yr_rule_strings_foreach(rule, string)
			{
				YR_MATCH* match;
				yr_string_matches_foreach(string, match)
				{
					/*
					 * the following lines display the actual offset (in hex), and
					 * the string definition identifier from the yara rule,
					 * where the target yara rule matched the data being
					 * scanned/searched
					 * 
					 */					
					char tmp_results[1024];
			    	//sprintf(tmp_results, "0x%" PRIx64 ":%s-", match->base + match->offset, string->identifier);
			    	//sprintf(tmp_results, "0x%lx:%s-", match->base + match->offset, string->identifier);
					snprintf(tmp_results, sizeof(tmp_results), "0x%lx:%s-", match->base + match->offset, string->identifier);
			    	strncat(tmp_str_results, tmp_results, sizeof(tmp_str_results)-strlen(tmp_str_results)-1);
					
					hit_cnt += 1;
				}
			}
			//printf("%d\n\n", hit_cnt);
		}
		
		if (strlen(tmp_str_results) > 0) {
			// get rid of last dash
			tmp_str_results[strlen(tmp_str_results)-1] = 0;
			/*
			 * adjust starting comma output based on length of yara_meta_results ...
			 * so if there is no meta data to output we dont start with
			 * a comma here
			 */
			if (strlen(yara_meta_results) > 0)
				strncat (yara_meta_results, ",detected offsets=", sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
			else
				strncat (yara_meta_results, "detected offsets=", sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
			strncat (yara_meta_results, tmp_str_results, sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
		}
	    
	    /*
	     * for now let's only display the hit count if there
	     * is also metadata to display
	     */
		if (strlen(yara_meta_results) > 0) {
		    if (hit_cnt > 0) {
		    	strncat (yara_meta_results, ",hit_count=", sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
		    	// convert into to str (char array)
		    	char intstr[15];
		    	sprintf(intstr, "%d", hit_cnt);
		    	strncat (yara_meta_results, intstr, sizeof(yara_meta_results)-strlen(yara_meta_results)-1);
		    }
			strncat (yara_results, ":[", sizeof(yara_results)-strlen(yara_results)-1);
			strncat (yara_results, yara_meta_results, sizeof(yara_results)-strlen(yara_results)-1);
			strncat (yara_results, "]", sizeof(yara_results)-strlen(yara_results)-1);
		}
		
		strncat (yara_results, ", ", sizeof(yara_results)-strlen(yara_results)-1);
		count++;
	}

	if (limit != 0 && count >= limit)
		return CALLBACK_ABORT;

	return CALLBACK_CONTINUE;
}

int bayshore_yara_callback(
		int message,
		void* message_data,
		void* user_data
	)
{
	YR_MODULE_IMPORT* mi;
	YR_OBJECT* object;
	MODULE_DATA* module_data;

	switch(message)
	{
	case CALLBACK_MSG_RULE_MATCHING:
	case CALLBACK_MSG_RULE_NOT_MATCHING:
		/*
		 * dont need 'data' because we are not processing a file
		 * but Yara's structure is set so I am not changing
		 * the number of parameters passed in, just ignoring
		 * 'data'
		 */
		return bayshore_yara_handle_message(message, (YR_RULE *)message_data, user_data);

	case CALLBACK_MSG_IMPORT_MODULE:

		mi = (YR_MODULE_IMPORT*) message_data;
		module_data = modules_data_list;

		while (module_data != NULL)
		{
			if (strcmp(module_data->module_name, mi->module_name) == 0)
			{
				mi->module_data = module_data->mapped_file.data;
				mi->module_data_size = module_data->mapped_file.size;
				break;
			}

			module_data = module_data->next;
		}

		return CALLBACK_CONTINUE;
	}
	return CALLBACK_ERROR;
}


int is_integer(const char *str)
{
	if (*str == '-')
		str++;
	
	while(*str)
	{
		if (!isdigit(*str))
			return FALSE;
		str++;
	}
	return TRUE;
}


int is_float(const char *str)
{
	int has_dot = FALSE;
	
	if (*str == '-')      // skip the minus sign if present
		str++;
	
	if (*str == '.')      // float can't start with a dot
		return FALSE;
	
	while(*str)
	{
		if (*str == '.')
		{
			if (has_dot)      // two dots, not a float
				return FALSE;
			
			has_dot = TRUE;
		}
		else if (!isdigit(*str))
		{
			return FALSE;
		}
		str++;
	}
	return has_dot; // to be float must contain a dot
}


int define_external_variables(
		YR_RULES* rules,
		YR_COMPILER* compiler)
{
	int i;
	for (i = 0; ext_vars[i] != NULL; i++)
	{
		char* equal_sign = strchr(ext_vars[i], '=');

		if (!equal_sign)
		{
			fprintf(stderr, "error: wrong syntax for `-d` option.\n");
			return FALSE;
		}

		// Replace the equal sign with null character to split the external
		// variable definition (i.e: myvar=somevalue) in two strings: identifier
		// and value.

		*equal_sign = '\0';

		char* identifier = ext_vars[i];
		char* value = equal_sign + 1;


		if (is_float(value))
		{
			if (rules != NULL)
				yr_rules_define_float_variable(
						rules,
						identifier,
						atof(value));

			if (compiler != NULL)
				yr_compiler_define_float_variable(
						compiler,
						identifier,
						atof(value));
		}
		else if (is_integer(value))
		{
			if (rules != NULL)
				yr_rules_define_integer_variable(
						rules,
						identifier,
						atoi(value));

			if (compiler != NULL)
				yr_compiler_define_integer_variable(
						compiler,
						identifier,
						atoi(value));
		}
		else if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0)
		{
			if (rules != NULL)
				yr_rules_define_boolean_variable(
						rules,
						identifier,
						strcmp(value, "true") == 0);

			if (compiler != NULL)
				yr_compiler_define_boolean_variable(
						compiler,
						identifier,
						strcmp(value, "true") == 0);
		}
		else
		{
			if (rules != NULL)
				yr_rules_define_string_variable(
						rules,
						identifier,
						value);

			if (compiler != NULL)
				yr_compiler_define_string_variable(
						compiler,
						identifier,
						value);
		}
	}

	return TRUE;
}


int load_modules_data()
{
	int i;
	for (i = 0; modules_data[i] != NULL; i++)
	{
		char* equal_sign = strchr(modules_data[i], '=');

		if (!equal_sign)
		{
			fprintf(stderr, "error: wrong syntax for `-x` option.\n");
			return FALSE;
		}

		*equal_sign = '\0';

		MODULE_DATA* module_data = (MODULE_DATA*) malloc(sizeof(MODULE_DATA));

		if (module_data != NULL)
		{
			module_data->module_name = modules_data[i];

			int result = yr_filemap_map(equal_sign + 1, &module_data->mapped_file);

			if (result != ERROR_SUCCESS)
			{
				free(module_data);
				fprintf(stderr, "error: could not open file \"%s\".\n", equal_sign + 1);
				return FALSE;
			}

			module_data->next = modules_data_list;
			modules_data_list = module_data;
		}
	}

	return TRUE;
}


void unload_modules_data()
{
	MODULE_DATA* module_data = modules_data_list;

	while(module_data != NULL)
	{
		MODULE_DATA* next_module_data = module_data->next;

		yr_filemap_unmap(&module_data->mapped_file);
		free(module_data);

		module_data = next_module_data;
	}

	modules_data_list = NULL;
}

void cleanup()
{
	unload_modules_data();
}

/*
 * had to define a function to use instead of yara's built in
 * macro:
 * 
 * 		#define exit_with_code(code) { rresult = code; goto _exit; }
 * 		
 * that macro uses a goto call that assumes it's in the main function.
 * So it kills the rules object. Since we are in an API model we have
 * no main function and I need to return that rules object from the
 * bayshore_yara_preprocess_rules function.
 */
void exit_with_code_cleanup(int code, YR_COMPILER *compiler, YR_RULES *rules)
{
	unload_modules_data();
	
	if (compiler != NULL)
		yr_compiler_destroy(compiler);
	
	if (rules != NULL)
		yr_rules_destroy(rules);
	
	yr_finalize();
}

/*
 * should return a pointer to populated YR_RULES struct,
 * otherwise it should return a pointer to NULL (0) 
 */
YR_RULES *bayshore_yara_preprocess_rules (const char *rule_filename)
{
	int rresult;
	int errors;
	struct stat st;
	YR_COMPILER* compiler = NULL;
	YR_RULES* rules = NULL;

	// Return NULL if we didn't get a real filename or a real file.
	if (!rule_filename || stat (rule_filename, &st) || !S_ISREG (st.st_mode))
		return NULL;

	if (!load_modules_data()) {
		//exit_with_code(EXIT_FAILURE);
		exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
	}

	// Try to read the file. This will fail on anything but a precompiled
	// yara ruleset file. In particular, a text file containing valid rules
	// will give ERROR_INVALID_FILE.
	// On success, cleanup and return the rules structure.
	// On invalid-file, try to compile the file.
	// Otherwise, bail.
	rresult = yr_initialize();

	if (rresult != ERROR_SUCCESS)
	{
		fprintf(stderr, "error: initialization error (%d)\n", rresult);
		//exit_with_code(EXIT_FAILURE);
		exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
	}

	rresult = yr_rules_load (rule_filename, &rules);

	// Accepted result are ERROR_SUCCESS or ERROR_INVALID_FILE
	// if we are passing the rules in source form, if result is
	// different from those exit with error.
	if (rresult != ERROR_SUCCESS &&
		rresult != ERROR_INVALID_FILE)
	{
		print_scanner_error(rresult);
		//exit_with_code(EXIT_FAILURE);
		exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
	}
	if (rresult == ERROR_SUCCESS)
	{
		if (!define_external_variables(rules, NULL)) {
			//exit_with_code(EXIT_FAILURE);
			exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		}
	}
	else
	{
		// Rules file didn't contain compiled rules, let's handle it
		// as a text file containing rules in source form.
		if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
			//exit_with_code(EXIT_FAILURE);
			exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		}

		if (!define_external_variables(NULL, compiler)) {
			//exit_with_code(EXIT_FAILURE);
			exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		}

		yr_compiler_set_callback(compiler, print_compiler_error, NULL);

		FILE* rule_file = fopen(rule_filename, "r");

		if (rule_file == NULL)
		{
			fprintf(stderr, "error: could not open file: %s\n", rule_filename);
			//exit_with_code(EXIT_FAILURE);
			exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		}

		int errors = yr_compiler_add_file(compiler, rule_file, NULL, rule_filename);

		fclose(rule_file);

		if (errors > 0) {
			//exit_with_code(EXIT_FAILURE);
			exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		}

		rresult = yr_compiler_get_rules(compiler, &rules);

		yr_compiler_destroy(compiler);

		compiler = NULL;

		if (rresult != ERROR_SUCCESS) {
			//exit_with_code(EXIT_FAILURE);
			exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		}
	}	
	return rules;
}


/*
 * this entry API assumes that the yara ruleset(s) have
 * been pre-compiled and processed into a YR_RULES struct,
 * a pointer to that struct in mem gets passed in here instead
 * of a pointer to a ruleset file
 */
int bayshore_yara_wrapper_yrrules_api(
		uint8_t* file_content,
		size_t file_size,
		YR_RULES* rules,
		char *api_yara_results,
		size_t *api_yara_results_len
		)
{
	int yresult;
	int errors;
	
	// clear this for new data
	*yara_results = 0;
	*api_yara_results = 0;

	// if there is no content or YR_RULES struct this wont work
	if (file_content && rules) {
		
		yresult = yr_initialize();
		
		yresult = yr_rules_scan_mem(
				rules,
				file_content,
				file_size,
				0,
				(YR_CALLBACK_FUNC)bayshore_yara_callback,
				(void*)"file-name",
				0);

		if (yresult != ERROR_SUCCESS)
		{
			print_scanner_error(yresult);
		}

		yr_finalize();
		cleanup();
		
		// we have rule hits from yara
		if (*yara_results) {
			snprintf(api_yara_results, MAX_YARA_RES_BUF + 1024, "%s", yara_results);
			size_t sl = strlen(api_yara_results);
			if (sl >= 2) {
                sl -= 2;
				api_yara_results[sl] = 0;
            }
			if (api_yara_results_len)
				*api_yara_results_len = sl;
			return 1;
		}
	}
	return 0;
}

/*
 * this is the original entry point API, it
 * expects a yara ruleset file pointer to be
 * passed in and it will compile those rules
 * into a local YR_RULES struct. This is 
 * sub-optimal because we have to perform
 * that compilation process eveytime this
 * entry point is used, look at 
 * bayshore_yara_wrapper_yrrules_api usage
 * for a faster option
 */
int bayshore_yara_wrapper_api(
		uint8_t* file_content,
		size_t file_size,
		const char *yara_ruleset_filename,
		char *api_yara_results,
		size_t *api_yara_results_len
		)
{
	int yresult;
	int errors;
	FILE* rule_file;	
	YR_COMPILER* compiler = NULL;
	YR_RULES* rules = NULL;

	// clear this for new data
	*yara_results = 0;
	*api_yara_results = 0;

	// if there is no value in yara_ruleset_filename then yara will not work
	if (file_content && *yara_ruleset_filename) {
		
		if (!load_modules_data()) {
			//exit_with_code(EXIT_FAILURE);
			exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		}

		yresult = yr_initialize();
		
		if (yresult != ERROR_SUCCESS)
		{
			fprintf(stderr, "error: initialization error (%d)\n", yresult);
			//exit_with_code(EXIT_FAILURE);
			exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		}

		// Try to load the rules file as a binary file containing
		// compiled rules first		
		yresult = yr_rules_load(yara_ruleset_filename, &rules);
		
		
		// Accepted result are ERROR_SUCCESS or ERROR_INVALID_FILE
		// if we are passing the rules in source form, if result is
		if (yresult != ERROR_SUCCESS &&
		    yresult != ERROR_INVALID_FILE)
		{
		    print_scanner_error(yresult);
		    //exit_with_code(EXIT_FAILURE);
		    exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		}

		if (yresult == ERROR_SUCCESS)
		{
			if (!define_external_variables(rules, NULL)) {
				//exit_with_code(EXIT_FAILURE);
				exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
			}
		}
		else
		{
			// Rules file didn't contain compiled rules, let's handle it
		    // as a text file containing rules in source form.

		    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
		    	//exit_with_code(EXIT_FAILURE);
		    	exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		    }

		    if (!define_external_variables(NULL, compiler)) {
		    	//exit_with_code(EXIT_FAILURE);
		    	exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		    }

		    yr_compiler_set_callback(compiler, print_compiler_error, NULL);

		    FILE* rule_file = fopen(yara_ruleset_filename, "r");

		    if (rule_file == NULL)
		    {
		    	fprintf(stderr, "error: could not open file: %s\n", yara_ruleset_filename);
		    	//exit_with_code(EXIT_FAILURE);
		    	exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		    }

		    int errors = yr_compiler_add_file(compiler, rule_file, NULL, yara_ruleset_filename);

		    fclose(rule_file);

		    if (errors > 0) {
		    	//exit_with_code(EXIT_FAILURE);
		    	exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		    }

		    yresult = yr_compiler_get_rules(compiler, &rules);

		    yr_compiler_destroy(compiler);

		    compiler = NULL;

		    if (yresult != ERROR_SUCCESS) {
		    	//exit_with_code(EXIT_FAILURE);
		    	exit_with_code_cleanup(EXIT_FAILURE, compiler, rules);
		    }
		}

		yresult = yr_rules_scan_mem(
				rules,
				file_content,
				file_size,
				0,
				(YR_CALLBACK_FUNC)bayshore_yara_callback,
				(void*)"file-name",
				0);

		if (yresult != ERROR_SUCCESS)
		{
			print_scanner_error(yresult);
		}

		yr_rules_destroy(rules);
		yr_finalize();
		cleanup();

		// we have rule hits from yara
		if (*yara_results) {
			snprintf(api_yara_results, MAX_YARA_RES_BUF, "%s", yara_results);
			size_t sl = strlen(api_yara_results);
			if (sl >= 2) {
				sl -= 2;
				api_yara_results[sl] = 0;
			}
			if (api_yara_results_len)
				*api_yara_results_len = sl;
			return 1;
		}
	}
	return 0;
}
