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




#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include <zlib.h>
#include "zl.h"

#include <iostream>
#include <algorithm>
using namespace std;


/* This implementation supports two different ways of storing the uncompressed data:
 * As a single large contiguous buffer; and as a vector of allocated "grains."
 * I'm really not sure whether there is an advantage to either model in a high-speed,
 * process-dense firewall. For the moment, the single-buffer model is enabled.
 * Change the ifdefs on the Ingest method to switch to the other.
 *
 * The single-buffer model relies on realloc, which means it's probably doing some
 * memory copying.
 */

/******************************
ZlibInflator_t::ZlibInflator_t
******************************/

ZlibInflator_t::ZlibInflator_t()
{
	z.zalloc = Z_NULL;
	z.zfree = Z_NULL;
	z.opaque = Z_NULL;
	z.next_in = Z_NULL;
	z.avail_in = 0;
	int u = inflateInit2 (&z, 16 + MAX_WBITS);
	bError = (u != Z_OK);
	bStreamEnd = false;
	total = 0;

	single_result.size = 2048;
	single_result.used = 0;
	single_result.data = (uint8_t*) malloc (single_result.size);
	single_result.data [0] = 0;
}

/*******************************
ZlibInflator_t::~ZlibInflator_t
*******************************/

ZlibInflator_t::~ZlibInflator_t()
{
	//cerr << Grains.size() << endl;
	inflateEnd (&z);
	for (int y=0; y < Grains.size(); y++) {
		if (Grains[y].data)
			free (Grains[y].data);
	}
	if (single_result.data)
		free (single_result.data);
}


/**********************
ZlibInflator_t::Ingest
**********************/

#if USE_GRAIN_VECTOR
void ZlibInflator_t::Ingest (uint8_t *buf, size_t sz)
{
	if (bError || bStreamEnd || !buf || !sz)
		return;

	grain_t G;
	G.size = std::min (sz * 2, (size_t)100);
	G.used = 0;
	G.data = (uint8_t*) malloc (G.size + 1);

	z.next_in = buf;
	z.avail_in = sz;
	z.next_out = G.data;
	z.avail_out = G.size;

	int r = inflate (&z, Z_SYNC_FLUSH);
	if (r == Z_OK) {
		//cerr << "OK: " << z.avail_in << ", " << z.avail_out << endl;
		G.used = G.size - z.avail_out;
		G.data [G.used] = 0;
		total += G.used;
		Grains.push_back (G);
		if (z.avail_in || !z.avail_out) {
			//cerr << "R:";
			Ingest (buf + sz - z.avail_in, z.avail_in);
		}
	}
	else if (r == Z_STREAM_END) {
		free (G.data);
		bStreamEnd = true;
	}
	else {
		free (G.data);
		bError = true;
		// use z.msg to access the last error msg.
	}
}
#endif

void ZlibInflator_t::Ingest (uint8_t *buf, size_t sz)
{
	if (bError || bStreamEnd || !buf || !sz)
		return;

	if ((single_result.size - single_result.used) < (sz * 2)) {
		single_result.size += (sz * 2); 
		//uint8_t *rrr = single_result.data;
		single_result.data = (uint8_t*) realloc (single_result.data, single_result.size);
		/*
		if (rrr != single_result.data)
			cerr << "D[" << single_result.size << "]\n"; // how many reallocs do we do?
		*/
		if (!single_result.data) {
			bError = true;
			return;
		}
	}

	z.next_in = buf;
	z.avail_in = sz;
	z.next_out = single_result.data + single_result.used;
	z.avail_out = single_result.size - single_result.used - 1;
	if (!z.avail_out) {
		// this is really an assert, not a realistic error condition
		bError = true;
		return;
	}

	size_t outsize = z.avail_out;
	int r = inflate (&z, Z_SYNC_FLUSH);
	if (r == Z_OK) {
		//cerr << "OK: " << z.avail_in << ", " << z.avail_out << endl;
		single_result.used += (outsize - z.avail_out);
		assert (single_result.used < single_result.size);
		single_result.data [single_result.used] = 0;
		total = single_result.used;

		if (z.avail_in || !z.avail_out) {
			//cerr << "R:";
			Ingest (buf + sz - z.avail_in, z.avail_in);
		}
	}
	else if (r == Z_STREAM_END) {
		single_result.used += (outsize - z.avail_out);
		assert (single_result.used < single_result.size);
		single_result.data [single_result.used] = 0;
		total = single_result.used;
		bStreamEnd = true;
	}
	else {
		bError = true;
		// use z.msg to access the last error msg.
	}
}

/*********************
ZlibInflator_t::_Dump
*********************/

void ZlibInflator_t::_Dump()
{
	cerr << "Total " << total << endl;
	cerr << ">>>>>>>" << single_result.data << "<<<<<<<\n";
}

