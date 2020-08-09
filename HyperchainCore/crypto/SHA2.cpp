/*Copyright 2016-2020 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#include "sha2.h"

#ifndef _MSC_VER
#include <inttypes.h>
#else 
typedef unsigned __int32 uint32_t;
#endif

extern void GetSHA256(unsigned char* hash_sha256, const char* str, size_t length)
{
	Digest<DT::sha256> digest;
	digest.AddData(str, length);
	std::string d = digest.getDigest();
	memcpy(hash_sha256, d.data(),d.size());
}

void displayHash(unsigned char hash[32])
{
	printf("0x");

	for (int i = 0; i < 32; ++i)
	{
		printf("%x", hash[i]);
	}

	printf("\n");
}

const char * const ALPHABET =
"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const char ALPHABET_MAP[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
	-1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
	-1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
};

// result must be declared: char result[len * 137 / 100];
int EncodeBase58(const unsigned char *bytes, int len, unsigned char result[]) 
{
	unsigned char *digits = new unsigned char[len * 2];
	memset(digits,0,len*2);

	int digitslen = 1;
	for (int i = 0; i < len; i++) {
		unsigned int carry = (unsigned int)bytes[i];
		for (int j = 0; j < digitslen; j++) {
			carry += (unsigned int)(digits[j]) << 8;
			digits[j] = (unsigned char)(carry % 58);
			carry /= 58;
		}
		while (carry > 0) {
			digits[digitslen++] = (unsigned char)(carry % 58);
			carry /= 58;
		}
	}
	int resultlen = 0;
	// leading zero bytes
	for (; resultlen < len && bytes[resultlen] == 0;)
		result[resultlen++] = '1';
	// reverse
	for (int i = 0; i < digitslen; i++)
		result[resultlen + i] = ALPHABET[digits[digitslen - 1 - i]];
	result[digitslen + resultlen] = 0;
	delete [] digits;

	return digitslen + resultlen;
}

// result must be declared (for the worst case): char result[len * 2];
int DecodeBase58(const unsigned char *str, int len, unsigned char *result) 
{
	result[0] = 0;
	int resultlen = 1;
	for (int i = 0; i < len; i++) {
		unsigned int carry = (unsigned int)ALPHABET_MAP[str[i]];
		for (int j = 0; j < resultlen; j++) {
			carry += (unsigned int)(result[j]) * 58;
			result[j] = (unsigned char)(carry & 0xff);
			carry >>= 8;
		}
		while (carry > 0) {
			result[resultlen++] = (unsigned int)(carry & 0xff);
			carry >>= 8;
		}
	}

	for (int i = 0; i < len && str[i] == '1'; i++)
		result[resultlen++] = 0;

	// Poorly coded, but guaranteed to work.
	for (int i = resultlen - 1, z = (resultlen >> 1) + (resultlen & 1);
		i >= z; i--) {
		int k = result[i];
		result[i] = result[resultlen - i - 1];
		result[resultlen - i - 1] = k;
	}
	return resultlen;
}