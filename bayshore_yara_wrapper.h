/*****************************************************************************
 *
 * YWRAPPER: Help for YARA users.
 * Copyright (C) 2014 by Bayshore Networks, Inc. All Rights Reserved.
 *
 * This file is part of ywrapper.
 *
 * ywrapper is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * ywrapper is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with ywrapper.  If not, see <http://www.gnu.org/licenses/>.
 *
 *****************************************************************************/

#ifndef __bayshoreyarawrapper__H_
#define __bayshoreyarawrapper__H_


#include <stdio.h>
#include <stdint.h>

#define MAX_YARA_RES_BUF 2048

/* 
 * When calling bayshore_yara_wrapper_api, the next-to-last parameter is a
 * pointer to a caller-supplied char buffer. The caller is required to ensure
 * that this buffer is at least MAX_YARA_RES_BUF bytes long.
 */
#ifdef __cplusplus
extern "C"
#endif
int bayshore_yara_wrapper_api(uint8_t*, size_t, const char *, char *, size_t *);


#endif // __bayshoreyarawrapper__H_

