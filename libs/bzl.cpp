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




#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "bzl.h"

#include <iostream>
using namespace std;

BZlibInflator_t::BZlibInflator_t(){

    
    bzStreamEnd = false;
    total = 0;
    
    bz.bzalloc =NULL;
    bz.bzfree = NULL;
    bz.opaque = NULL;
    
    int u = BZ2_bzDecompressInit(&bz, 0, 0);
    
    bzError = (u != BZ_OK);
    
    bzsingle_result.size = 2048;
    bzsingle_result.used = 0;
    bzsingle_result.data = (uint8_t*) malloc (bzsingle_result.size);
    bzsingle_result.data[0] = 0;
    
}


BZlibInflator_t::~BZlibInflator_t(){

    BZ2_bzDecompressEnd(&bz);
   
    if(bzsingle_result.data)
        free(bzsingle_result.data);
    
}

void BZlibInflator_t::bzdecomp(uint8_t* buf, size_t sz){

    if(bzError || bzStreamEnd || !buf || !sz){
        return;
    }
    
    if((bzsingle_result.size - bzsingle_result.used) < (sz*2)){

        bzsingle_result.size += (sz * 2); 
		bzsingle_result.data = (uint8_t*) realloc (bzsingle_result.data, bzsingle_result.size);
		
		if (!bzsingle_result.data) {
			bzError = true;
			return;
		}
	}

    bz.next_in = (char*)buf;
	bz.avail_in = sz;
	bz.next_out = (char*)(bzsingle_result.data + bzsingle_result.used);
	bz.avail_out = bzsingle_result.size - bzsingle_result.used - 1;

	if (!bz.avail_out) {
		bzError = true;
		return;
	}

	size_t outsize = bz.avail_out;

    int r = BZ2_bzDecompress(&bz);
    
    if (r == BZ_OK) {
		bzsingle_result.used += (outsize - bz.avail_out);
		assert (bzsingle_result.used < bzsingle_result.size);
		bzsingle_result.data [bzsingle_result.used] = 0;
		total = bzsingle_result.used;

		if (bz.avail_in || !bz.avail_out) {
			
            bzdecomp(buf + sz - bz.avail_in, bz.avail_in);
		}
	}
    else if(r == BZ_STREAM_END){
        
        bzsingle_result.used += (outsize - bz.avail_out);
		assert (bzsingle_result.used < bzsingle_result.size);
		bzsingle_result.data [bzsingle_result.used] = 0;
		total = bzsingle_result.used;
		bzStreamEnd = true;	
    }
    else {        
		bzError = true;		
	}

}


