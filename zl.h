/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * Copyright (C) 2014 by Bayshore Networks, Inc. All Rights Reserved.
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




#ifndef __ZLIB_SUPPORT__H__
#define __ZLIB_SUPPORT__H__


#include <vector>

/********************
class ZlibInflator_t
********************/

class ZlibInflator_t
{
	public:
		ZlibInflator_t();
		virtual ~ZlibInflator_t();

		void Ingest (uint8_t*, size_t);
		void _Dump();

		struct grain_t {
			size_t size;
			size_t used;
			uint8_t *data;
		};

	private:
		z_stream z;
		bool bError;
		bool bStreamEnd;
		size_t total;
		std::vector<grain_t> Grains;

	public:
		grain_t single_result;
};


#endif // __ZLIB_SUPPORT__H__
