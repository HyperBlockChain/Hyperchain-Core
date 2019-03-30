/*Copyright 2016-2019 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this?
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,?
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

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

