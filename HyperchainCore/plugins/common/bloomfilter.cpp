/*Copyright 2016-2020 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this? software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED,? INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include"bloomfilter.h"

#include <iostream>
#include <string>
#include <math.h>
#include <stdio.h>
#include <fstream>
#include <memory>

using namespace std;

static unsigned int SDBMHash(const char* str, int len)
{
    unsigned int hash = 0;

    while (len--) {
        hash = (*str++) + (hash << 6) + (hash << 16) - hash;
    }
    return (hash & 0x7FFFFFFF);
}

static unsigned int RSHash(const char* str, int len)
{
    unsigned int b = 378551;
    unsigned int a = 63689;
    unsigned int hash = 0;

    while (len--) {
        hash = hash * a + (*str++);
        a *= b;
    }
    return (hash & 0x7FFFFFFF);
}

static unsigned int JSHash(const char* str, int len)
{
    unsigned int hash = 1315423911;

    while (len--) {
        hash ^= ((hash << 5) + (*str++) + (hash >> 2));
    }
    return (hash & 0x7FFFFFFF);
}

static unsigned int PJWHash(const char* str, int len)
{
    unsigned int BitsInUnignedInt = (unsigned int)(sizeof(unsigned int) * 8);
    unsigned int ThreeQuarters = (unsigned int)((BitsInUnignedInt * 3) / 4);
    unsigned int OneEighth = (unsigned int)(BitsInUnignedInt / 8);
    unsigned int HighBits = (unsigned int)(0xFFFFFFFF) << (BitsInUnignedInt - OneEighth);
    unsigned int hash = 0;
    unsigned int test = 0;

    while (len--) {
        hash = (hash << OneEighth) + (*str++);
        if ((test = hash & HighBits) != 0) {
            hash = ((hash ^ (test >> ThreeQuarters))& (~HighBits));
        }
    }
    return (hash & 0x7FFFFFFF);
}

static unsigned int APHash(const char* str, int len)
{
    unsigned int hash = 0;
    int i;

    for (i = 0; *str; i++) {
        if ((i & 1) == 0) {
            hash ^= ((hash << 7) ^ (*str++) ^ (hash >> 3));
        }
        else {
            hash ^= (~((hash << 11) ^ (*str++) ^ (hash >> 5)));
        }
    }
    return (hash & 0x7FFFFFFF);
}

static unsigned int DJBHash(const char* str, int len)
{
    unsigned int hash = 5381;

    while (len--) {
        hash += (hash << 5) + (*str++);
    }
    return (hash & 0x7FFFFFFF);
}

static unsigned int ELFHash(const char* str, int len)
{
    unsigned int hash = 0;
    unsigned int x = 0;

    while (len--) {
        hash = (hash << 4) + (*str++);
        if ((x = hash & 0xF0000000L) != 0) {
            hash ^= (x >> 24);
            hash &= ~x;
        }
    }
    return (hash & 0x7FFFFFFF);
}

static unsigned int BKDRHash(const char* str, int len)
{
    unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
    unsigned int hash = 0;

    while (len--) {
        hash = hash * seed + (*str++);
    }
    return (hash & 0x7FFFFFFF);
}

BloomFilter::BloomFilter(size_t hash_func_count)
    : _hash_func_count(hash_func_count),
    _object_count(0)
    //_md5_hash_result(std::unique_ptr<unsigned char[]>(new unsigned char[_md5_result_size_bytes]))
{
    hashtable_init();
    _vec_bit_pool.resize(_hashfunctable.size());

    if (0 == hash_func_count) {
        throw std::invalid_argument("Bloomfilter could not be initialized: hash_func_count must be larger than 0");
    }
    if (_md5_result_size_bytes < _hash_func_count * _bytes_per_hash_func) {
        throw std::invalid_argument("Bloomfilter could not be initialized: hash_func_count too large, hash_func_count *  bytes_per_hash_function must be smaller or equal to MD5_result_size_bytes");
    }
}

void BloomFilter::insert(const char* object, int len)
{
    insert(string(object, object + len));
}

void BloomFilter::insert(const std::string& object)
{
    int  hashval;
    for (int i = 0; i != _hashfunctable.size(); i++) {
        hashval = _hashfunctable[i](object.c_str(), object.size());
        _vec_bit_pool[i][hashval & 0xFF] = true;
        _vec_bit_pool[i][hashval >> 16] = true;
    }

    md5hash(object);
    const uint16_t* const object_hashes = reinterpret_cast<const uint16_t* const>(_md5_hash_result);

    for (size_t i = 0; i < _hash_func_count; i++) {
        const uint16_t index_to_set = object_hashes[i];
        _md5_store[index_to_set] = true;
    }
    ++_object_count;
}

void BloomFilter::clear()
{
    _md5_store.reset();
    for (auto& elm : _vec_bit_pool) {
        elm.reset();
    }
    _object_count = 0;
}

bool BloomFilter::contain(const char* object, int len) const
{
    return contain(string(object, object + len));
}

bool BloomFilter::contain(const std::string& object) const
{
    int  hashval;
    for (int i = 0; i != _hashfunctable.size(); i++) {
        hashval = _hashfunctable[i](object.c_str(), object.size());

        if (!_vec_bit_pool[i][hashval & 0xFF] || !_vec_bit_pool[i][hashval >> 16]) {
            return false;
        }
    }

    

    md5hash(object);
    const uint16_t* const object_hashes = reinterpret_cast<const uint16_t* const>(_md5_hash_result);

    for (size_t i = 0; i < _hash_func_count; i++) {
        const uint16_t index_to_get = object_hashes[i];
        if (!_md5_store[index_to_get]) {
            return false;
        }
    }

    return true;
}

size_t BloomFilter::object_count() const
{
    return _object_count;
}

bool BloomFilter::empty() const
{
    return 0 == object_count();
}


int BloomFilter::hashtable_init()
{
    _hashfunctable.push_back(*PJWHash);
    _hashfunctable.push_back(*JSHash);
    _hashfunctable.push_back(*RSHash);
    _hashfunctable.push_back(*SDBMHash);
    _hashfunctable.push_back(*APHash);
    _hashfunctable.push_back(*DJBHash);
    _hashfunctable.push_back(*BKDRHash);
    _hashfunctable.push_back(*ELFHash);
    return _hashfunctable.size();

}
