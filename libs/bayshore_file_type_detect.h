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

#ifndef __bayshorefiletypedetect__H_
#define __bayshorefiletypedetect__H_

#include <stdint.h>

#define THRESHOLD 600


#ifdef __cplusplus
extern "C" {
#endif

int get_buffer_type(const uint8_t *, size_t);
void get_buffer_type_str(int, uint8_t *);

int get_file_type(const uint8_t *);

int is_officex(int);
int is_pcap(int);
int is_unclassified(int);
int is_tar(int);
int is_xml(int);
int is_open_document_format(int);
int is_php(int);
int is_rar(int);
int is_win_exe(int);
int is_html(int);
int is_gzip(int);
int is_pdf(int);
int is_office(int);
int is_image(int);
int is_zip(int);
int is_matlab(int);
int is_7zip(int);
int is_archive(int);
int is_encrypted(int);
int is_executable(int);
int is_bzip2(int);

#ifdef __cplusplus
}
#endif

#endif // __bayshorefiletypedetect__H_
