/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * Copyright (C) 2014-2015 by Bayshore Networks, Inc. All Rights Reserved.
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

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>

#include "bayshore_yara_wrapper.h"

//defines
#define EXTERNAL_TYPE_INTEGER   1
#define EXTERNAL_TYPE_BOOLEAN   2
#define EXTERNAL_TYPE_STRING    3

// structs
typedef struct _EXTERNAL
{
	char type;
	char*  name;
	union {
		char* string;
		int integer;
		int boolean;
	};
	struct _EXTERNAL* next;
} EXTERNAL;

typedef struct _TAG
{
	char* identifier;
	struct _TAG* next;
} TAG;

typedef struct _IDENTIFIER
{
	char* name;
	struct _IDENTIFIER* next;
} IDENTIFIER;

typedef struct _MODULE_DATA
{
	const char* module_name;
	void* module_data;
	size_t module_data_size;
	struct _MODULE_DATA* next;

} MODULE_DATA;

// vars and initializations
EXTERNAL* externals_list = NULL;
TAG* specified_tags_list = NULL;
IDENTIFIER* specified_rules_list = NULL;
MODULE_DATA* modules_data_list = NULL;

static char yara_results[2048];

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

void cleanup()
{

	IDENTIFIER* identifier;
	IDENTIFIER* next_identifier;
	TAG* tag;
	TAG* next_tag;
	EXTERNAL* external;
	EXTERNAL* next_external;
	MODULE_DATA* module_data;
	MODULE_DATA* next_module_data;

	tag = specified_tags_list;

	while(tag != NULL)
	{
		next_tag = tag->next;
		free(tag);
		tag = next_tag;
	}

	external = externals_list;

	if (external) {
		while(external != NULL)
		{
			next_external = external->next;
			free(external);
			external = next_external;
		}
	}

	identifier = specified_rules_list;

	while(identifier != NULL)
	{
		next_identifier = identifier->next;
		free(identifier);
		identifier = next_identifier;
	}
	
	module_data = modules_data_list;

	while(module_data != NULL)
	{
		next_module_data = module_data->next;
		free(module_data);
		module_data = next_module_data;
	}
}

int bayshore_yara_handle_message(int message, YR_RULE* rule, void* data)
{
	int is_matching;
	int count = 0;
	int limit = 0;

	is_matching = (message == CALLBACK_MSG_RULE_MATCHING);

	/*
	 * if there is a match with a yara rule then concat those 
	 * results to the variable yara_results
	 */
	if (is_matching)
	{
		// assuming yara_results is a buffer and not a pointer
		strncat (yara_results, rule->identifier, sizeof(yara_results)-strlen(yara_results)-1);
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
				mi->module_data = module_data->module_data;
				mi->module_data_size = module_data->module_data_size;
				break;
			}

			module_data = module_data->next;
		}

		return CALLBACK_CONTINUE;
	}
	return CALLBACK_ERROR;
}


/*
 * should return a pointer to populated YR_RULES struct,
 * otherwise it should return a pointer to NULL (0) 
 */
YR_RULES *bayshore_yara_preprocess_rules (const char *rule_filename)
{
	int rresult;
	int errors;
	YR_COMPILER* compiler;
	EXTERNAL *external = NULL;
	FILE* rule_file;
	YR_RULES* rules;
	struct stat st;
	
	// Return NULL if we didn't get a real filename or a real file.
	if (!rule_filename || stat (rule_filename, &st) || !S_ISREG (st.st_mode))
		return NULL;


	// Try to read the file. This will fail on anything but a precompiled
	// yara ruleset file. In particular, a text file containing valid rules
	// will give ERROR_INVALID_FILE.
	// On success, cleanup and return the rules structure.
	// On invalid-file, try to compile the file.
	// Otherwise, bail.

	rresult = yr_rules_load (rule_filename, &rules);

	if (rresult == ERROR_SUCCESS) {
		cleanup();
		return rules;
	}
	else if (rresult != ERROR_INVALID_FILE) {
		print_scanner_error(rresult);
		yr_finalize();
		cleanup();
		return NULL;
	}
	else { // try to compile the file
		rules = NULL;

		if (yr_compiler_create(&compiler) == ERROR_SUCCESS) {
			
			yr_compiler_set_callback (compiler, print_compiler_error, NULL);

			// add the externals if any
			while (external) {
				switch (external->type) {
					case EXTERNAL_TYPE_INTEGER:
						yr_compiler_define_integer_variable(
								compiler,
								external->name,
								external->integer);
						break;

					case EXTERNAL_TYPE_BOOLEAN:
						yr_compiler_define_boolean_variable(
								compiler,
								external->name,
								external->boolean);
						break;

					case EXTERNAL_TYPE_STRING:
						yr_compiler_define_string_variable(
								compiler,
								external->name,
								external->string);
						break;
				}
				external = external->next;
			}

			// now try to read and compile the file
			if (rule_file = fopen (rule_filename, "r")) { // = is correct
				errors = yr_compiler_add_file (compiler, rule_file, NULL, rule_filename);
				fclose (rule_file);
				if (!errors)
					yr_compiler_get_rules (compiler, &rules);
			}
			else
				fprintf (stderr, "could not open file: %s\n", rule_filename);

			// required cleanup
			yr_compiler_destroy (compiler);
		}

		yr_finalize();
		cleanup();
		return rules;
	}
}

/*
 * this entry API assumes that the yara ruleset(s) have
 * been pre-compiled and processed into a YR_RULES struct,
 * a pointer to that struct in mem gets passed in here instead
 * of a pointer to a ruleset file
 * 
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
		
		yr_initialize();
		
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
	YR_RULES* rules;
	YR_COMPILER* compiler;
	EXTERNAL* external;
	FILE* rule_file;

	// clear this for new data
	*yara_results = 0;
	*api_yara_results = 0;

	// if there is no value in yara_ruleset_filename then yara will not work
	if (file_content && *yara_ruleset_filename) {

		yr_initialize();
		yresult = yr_rules_load(yara_ruleset_filename, &rules);
		
		if (yresult != ERROR_SUCCESS && yresult != ERROR_INVALID_FILE)
		{
			print_scanner_error(yresult);
			yr_finalize();
			cleanup();
			return EXIT_FAILURE;
		}

		if (yresult != ERROR_SUCCESS)
		{
			if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
			{
				yr_finalize();
				cleanup();
				return EXIT_FAILURE;
			}

			external = externals_list;

			if (external) {
				while (external != NULL)
				{
					switch (external->type)
					{
					case EXTERNAL_TYPE_INTEGER:
						yr_compiler_define_integer_variable(
								compiler,
								external->name,
								external->integer);
						break;
	
					case EXTERNAL_TYPE_BOOLEAN:
						yr_compiler_define_boolean_variable(
								compiler,
								external->name,
								external->boolean);
						break;
	
					case EXTERNAL_TYPE_STRING:
						yr_compiler_define_string_variable(
								compiler,
								external->name,
								external->string);
						break;
					}
					external = external->next;
				}
			}

			yr_compiler_set_callback(compiler, print_compiler_error, NULL);
			rule_file = fopen(yara_ruleset_filename, "r");
			
			if (rule_file == NULL)
			{
				fprintf(stderr, "could not open file: %s\n", yara_ruleset_filename);
				yr_compiler_destroy(compiler);
				yr_finalize();
				cleanup();
				return EXIT_FAILURE;
			}

			errors = yr_compiler_add_file(compiler, rule_file, NULL, yara_ruleset_filename);

			fclose(rule_file);

			if (errors > 0)
			{
				yr_compiler_destroy(compiler);
				yr_finalize();
				cleanup();
				return EXIT_FAILURE;
			}

			yresult = yr_compiler_get_rules(compiler, &rules);
			yr_compiler_destroy(compiler);

			if (yresult != ERROR_SUCCESS)
			{
				yr_finalize();
				cleanup();
				return EXIT_FAILURE;
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
