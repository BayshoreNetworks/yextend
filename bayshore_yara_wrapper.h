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

#ifndef __bayshoreyarawrapper__H_
#define __bayshoreyarawrapper__H_


#include <yara.h>
#include <stdio.h>
#include <stdint.h>


#define MAX_YARA_RES_BUF 8192
#define YEXTEND_VERSION 1.4

/* 
 * When calling bayshore_yara_wrapper_api, the next-to-last parameter is a
 * pointer to a caller-supplied char buffer. The caller is required to ensure
 * that this buffer is at least MAX_YARA_RES_BUF bytes long.
 */
#ifdef __cplusplus
extern "C" {
#endif

int bayshore_yara_wrapper_api(uint8_t*, size_t, const char *, char *, size_t *);
YR_RULES *bayshore_yara_preprocess_rules(const char *);
int bayshore_yara_wrapper_yrrules_api(uint8_t*, size_t, YR_RULES *, char *, size_t *);

#ifdef __cplusplus
}
#endif


#endif // __bayshoreyarawrapper__H_

