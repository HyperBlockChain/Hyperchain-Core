/*Copyright 2016-2019 hyperchain.net (Hyperchain)

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

#ifndef __UINT128_H__
#define __UINT128_H__

#include "../Types.h"
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/version.hpp>
#include <boost/serialization/array.hpp>
#include <sstream>
#include <typeinfo>
////////////////////////////////////////
////////////////////////////////////////
#define VERSION_CHECK(__VAR__, __VERSION__) \
if (version > __VERSION__) { \
	std::stringstream ss;\
	ss << typeid(__VAR__).name() << " cannot analyze : Datas version is "<<version<<", Local version is " << __VERSION__;\
	throw std::runtime_error(ss.str());\
}
/**
 * Class representing an unsigned 128-bit integer.
 *
 * Not all operations are valid, especially multiplicative operations
 * (multiply, divide) and shift right are not implemented.
 *
 * @if maint
 * Internal representation: The number is stored as a whole little-endian
 * 128-bit number.
 * @endif
 */
 //32 is length of hex string.
 //sizeof(m_data)
class CUInt128 : public std::integral_constant<size_t, 16>
{
public:
    CUInt128(const CUInt128& value) throw()
    {
        setValue(value);
    }

    CUInt128(CUInt128&& value) throw() :m_data(std::move(value.m_data))
    {
    }

    explicit CUInt128(bool fill = false) throw()
    {
        m_data.u64_data[0] = m_data.u64_data[1] = (fill ? (uint64_t)-1 : 0);
    }

    explicit CUInt128(uint32_t value) throw()
    {
        setValue(value);
    }

    explicit CUInt128(const uint8_t valueBE[CUInt128::value]) throw()
    {
        SetValueBE(valueBE);
    }

    explicit CUInt128(const std::string &hexString)
    {
        SetHexString(hexString);
    }

    /**
     * Generates a new number, copying the most significant 'numBits' bits from 'value'.
     * The remaining bits are randomly generated.
     */
    CUInt128(const CUInt128& value, unsigned numBits);

    /* Bit at level 0 being most significant. */
    unsigned getBitNumber(unsigned bit) const throw()
    {
        return bit <= 127 ? (m_data.u32_data[(127 - bit) / 32] >> ((127 - bit) % 32)) & 1 : 0;
    }

    /* Bit at level 0 being most significant. */
    CUInt128& setBitNumber(unsigned bit, unsigned value)
    {
        //wxCHECK(bit <= 127, *this);

        if (value)
            m_data.u32_data[(127 - bit) / 32] |= 1 << ((127 - bit) % 32);
        else
            m_data.u32_data[(127 - bit) / 32] &= ~(1 << ((127 - bit) % 32));

        return *this;
    }

    uint64_t Lower64() const
    {
        return m_data.u64_data[0];
    }

    uint64_t High64() const
    {
        return m_data.u64_data[1];
    }

    uint64_t& Lower64()
    {
        return m_data.u64_data[0];
    }

    uint64_t& High64()
    {
        return m_data.u64_data[1];
    }

    /* Chunk 0 being the most significant */
    uint32_t get32BitChunk(unsigned val) const throw()
    {
        return val < 4 ? m_data.u32_data[3 - val] : 0;
    }

    /* Chunk 0 being the most significant */
    void set32BitChunk(unsigned chunk, uint32_t value)
    {
        //wxCHECK2(chunk < 4, return);

        m_data.u32_data[3 - chunk] = value;
    }

    CUInt128& SetValueBE(const uint8_t *valueBE) throw();
    CUInt128& SetHexString(const std::string & s) throw();

    std::string ToHexString() const;
    std::string ToBinaryString(bool trim = false) const;
    void ToByteArray(uint8_t *b) const;

    /**
     * Stores value used by the crypt functions.
     *
     * Since eMule started to use the value as-is (four little-endian 32-bit integers in big-endian order),
     * we have to reproduce that same representation on every platform.
     *
     * @param buf Buffer to hold the value. Must be large enough to hold the data (16 bytes at least),
     *	and must not be NULL.
     */
    void StoreCryptValue(uint8_t *buf) const;
    bool IsZero() const throw() { return (m_data.u64_data[0] | m_data.u64_data[1]) == 0; }
    int GetNonZeroTopBit();
private:
    int CompareTo(const CUInt128& other) const throw();
    int CompareTo(uint32_t value) const throw();
    CUInt128& Add(const CUInt128& value) throw();
    CUInt128& Add(uint32_t value) throw() { return value ? Add(CUInt128(value)) : *this; }
    CUInt128& Subtract(const CUInt128& value) throw();
    CUInt128& Subtract(uint32_t value) throw() { return value ? Subtract(CUInt128(value)) : *this; }
    CUInt128& ShiftLeft(unsigned bits) throw();

    CUInt128& XOR(const CUInt128& value) throw()
    {
        m_data.u64_data[0] ^= value.m_data.u64_data[0];
        m_data.u64_data[1] ^= value.m_data.u64_data[1];

        return *this;
    }


public:
    bool operator< (const CUInt128& value) const throw() { return (CompareTo(value) < 0); }
    bool operator> (const CUInt128& value) const throw() { return (CompareTo(value) > 0); }
    bool operator<=(const CUInt128& value) const throw() { return (CompareTo(value) <= 0); }
    bool operator>=(const CUInt128& value) const throw() { return (CompareTo(value) >= 0); }
    bool operator==(const CUInt128& value) const throw() { return (CompareTo(value) == 0); }
    bool operator!=(const CUInt128& value) const throw() { return (CompareTo(value) != 0); }

    bool operator< (uint32_t value) const throw() { return (CompareTo(value) < 0); }
    bool operator> (uint32_t value) const throw() { return (CompareTo(value) > 0); }
    bool operator<=(uint32_t value) const throw() { return (CompareTo(value) <= 0); }
    bool operator>=(uint32_t value) const throw() { return (CompareTo(value) >= 0); }
    bool operator==(uint32_t value) const throw() { return (CompareTo(value) == 0); }
    bool operator!=(uint32_t value) const throw() { return (CompareTo(value) != 0); }

    CUInt128& operator= (const CUInt128& value) throw() { setValue(value); return *this; }
    CUInt128& operator+=(const CUInt128& value) throw() { return Add(value); }
    CUInt128& operator-=(const CUInt128& value) throw() { return Subtract(value); }
    CUInt128& operator^=(const CUInt128& value) throw() { return XOR(value); }

    CUInt128& operator= (uint32_t value) throw() { setValue(value); return *this; }
    CUInt128& operator+=(uint32_t value) throw() { return Add(value); }
    CUInt128& operator-=(uint32_t value) throw() { return Subtract(value); }
    CUInt128& operator^=(uint32_t value) throw() { return value ? XOR(CUInt128(value)) : *this; }

    CUInt128& operator<<=(unsigned bits) throw() { return ShiftLeft(bits); }

    CUInt128& operator=(CUInt128&& value) throw() { m_data = std::move(value.m_data); return *this; }
    CUInt128  operator+(const CUInt128& value) const throw() { return CUInt128(*this).operator+=(value); }
    CUInt128  operator-(const CUInt128& value) const throw() { return CUInt128(*this).operator-=(value); }
    CUInt128  operator^(const CUInt128& value) const throw() { return CUInt128(*this).operator^=(value); }

    CUInt128  operator+(uint32_t value) const throw() { return CUInt128(*this).operator+=(value); }
    CUInt128  operator-(uint32_t value) const throw() { return CUInt128(*this).operator-=(value); }
    CUInt128  operator^(uint32_t value) const throw() { return CUInt128(*this).operator^=(value); }

    CUInt128  operator<<(unsigned bits) const throw() { return CUInt128(*this).operator<<=(bits); }

    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version) {
        VERSION_CHECK(*this, 0)

        ar & boost::serialization::make_array(reinterpret_cast<uint8_t*>(&m_data), sizeof(m_data));
    }

private:
    void setValue(const CUInt128& other) throw()
    {
        m_data.u64_data[0] = other.m_data.u64_data[0];
        m_data.u64_data[1] = other.m_data.u64_data[1];
    }

    void setValue(uint32_t value) throw()
    {
        m_data.u32_data[0] = value;
        m_data.u32_data[1] = 0;
        m_data.u64_data[1] = 0;
    }

    union {
        uint32_t u32_data[4];
        uint64_t u64_data[2];
    } m_data;
};
BOOST_CLASS_VERSION(CUInt128, 0)

inline bool operator==(uint32_t x, const CUInt128& y) throw() { return y.operator==(x); }
inline bool operator!=(uint32_t x, const CUInt128& y) throw() { return y.operator!=(x); }
inline bool operator<(uint32_t x, const CUInt128& y) throw() { return y.operator>(x); }
inline bool operator>(uint32_t x, const CUInt128& y) throw() { return y.operator<(x); }
inline bool operator<=(uint32_t x, const CUInt128& y) throw() { return y.operator>=(x); }
inline bool operator>=(uint32_t x, const CUInt128& y) throw() { return y.operator<=(x); }
inline CUInt128 operator+(uint32_t x, const CUInt128& y) throw() { return y.operator+(x); }
inline CUInt128 operator-(uint32_t x, const CUInt128& y) throw() { return CUInt128(x).operator-(y); }
inline CUInt128 operator^(uint32_t x, const CUInt128& y) throw() { return y.operator^(x); }


#endif
// File_checked_for_headers
