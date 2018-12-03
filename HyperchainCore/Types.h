//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2011 aMule Team ( admin@amule.org / http://www.amule.org )
// Copyright (c) 2002-2011 Merkur ( devs@emule-project.net / http://www.emule-project.net )
//
// Any parts of this program derived from the xMule, lMule or eMule project,
// or contributed by third-party developers are copyrighted by their
// respective authors.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
//

#ifndef TYPES_H
#define TYPES_H


#include <list>			
#include <vector>		
#include <string>

#ifndef _MSC_VER
	#ifndef __STDC_FORMAT_MACROS
		#define __STDC_FORMAT_MACROS
	#endif
	#include <inttypes.h>
	#define LONGLONG(x) x##ll
	#define ULONGLONG(x) x##llu
#else
	typedef unsigned __int8 byte;
	typedef unsigned __int8 uint8_t;
	typedef unsigned __int16 uint16_t;
	typedef unsigned __int32 uint32_t;
	typedef unsigned __int64 uint64_t;
	typedef signed __int8 int8_t;
	typedef signed __int16 int16_t;
	typedef signed __int32 int32_t;
	typedef signed __int64 int64_t;
	#define LONGLONG(x) x##i64
	#define ULONGLONG(x) x##ui64
#endif

typedef uint8_t		uint8;
typedef uint16_t	uint16;
typedef uint32_t	uint32;
typedef uint64_t	uint64;
typedef int8_t		sint8;
typedef int16_t		sint16;
typedef int32_t		sint32;
typedef int64_t		sint64;
typedef uint8_t		byte;


class CKnownFile;


typedef std::list<CKnownFile*> CKnownFilePtrList;


typedef std::vector<uint8>  ArrayOfUInts8;
typedef std::vector<uint16> ArrayOfUInts16;
typedef std::vector<uint32> ArrayOfUInts32;
typedef std::vector<uint64> ArrayOfUInts64;
typedef std::list<uint32>	ListOfUInts32;


#ifndef __cplusplus
	typedef int bool;
#endif


#ifdef _WIN32			
	#ifndef NOMINMAX
		#define NOMINMAX
	#endif
	#include <windows.h> 
	
	#ifndef W_OK
		enum
		{
			F_OK = 0,  
			X_OK = 1,  
			W_OK = 2,   
			R_OK = 4   
		};
	#endif 
	#ifdef __WINDOWS__
		#include <wx/msw/winundef.h>	
	#endif
	#undef GetUserName
#else 
	typedef struct sRECT {
	  uint32 left;
	  uint32 top;
	  uint32 right;
	  uint32 bottom;
	} RECT;
#endif


#endif