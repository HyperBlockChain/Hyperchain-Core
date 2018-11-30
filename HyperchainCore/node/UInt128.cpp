//
// This file is part of the aMule Project.
//
// Copyright (c) 2008-2011 Dévai Tamás ( gonosztopi@amule.org )
// Copyright (c) 2004-2011 Angel Vidal ( kry@amule.org )
// Copyright (c) 2004-2011 aMule Team ( admin@amule.org / http://www.amule.org )
// Copyright (c) 2003-2011 Barry Dunne (http://www.emule-project.net)
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


// Note To Mods //
/*
Please do not change anything here and release it..
There is going to be a new forum created just for the Kademlia side of the client..
If you feel there is an error or a way to improve something, please
post it in the forum first and let us look at it.. If it is a real improvement,
it will be added to the offical client.. Changing something without knowing
what all it does can cause great harm to the network if released in mass form..
Any mod that changes anything within the Kademlia side will not be allowed to advertise
there client on the eMule forum..
*/
#include <assert.h>

#include <iomanip>
#include <sstream>
using namespace std;

#include "UInt128.h"





CUInt128::CUInt128(const CUInt128 &value, unsigned numBits)
{

	unsigned numULONGs = numBits / 32;
	for (unsigned i = 0; i < numULONGs; i++) {
		Set32BitChunk(i, value.Get32BitChunk(i));
	}


	for (unsigned i = numULONGs * 32; i < numBits; i++) {
		SetBitNumber(i, value.GetBitNumber(i));
	}

	numULONGs = (numBits + 31) / 32;
	for (unsigned i = numBits; i < numULONGs * 32; i++) {
		SetBitNumber(i, rand() % 2);
	}


	for (unsigned i = numULONGs; i < 3; i++) {
		Set32BitChunk(i, rand());
	}
}

std::string CUInt128::ToHexString() const
{


	std::ostringstream oss;
	oss.flags(ios::hex);

	for (int i = 3; i >= 0; i--) {
		oss << setfill('0') << setw(8) << m_data.u32_data[i];
	}

	return oss.str();
}

std::string CUInt128::ToBinaryString(bool trim) const
{

	return "";
}

CUInt128& CUInt128::SetValueBE(const uint8_t *valueBE) throw()
{


	m_data.u32_data[3] = *(uint32_t*)valueBE;
	m_data.u32_data[2] = *(uint32_t*)(valueBE + 4);
	m_data.u32_data[1] = *(uint32_t*)(valueBE + 8);
	m_data.u32_data[0] = *(uint32_t*)(valueBE + 12);
	return *this;
}

CUInt128& CUInt128::SetHexString(const std::string & s) throw()
{
	assert(s.size() == 2 * sizeof(m_data.u32_data[0]) * sizeof(m_data.u32_data) / sizeof(m_data.u32_data[0]));
	istringstream iss;
	istringstream stream;

	stream.flags(ios::hex);
	iss.str(s);
	
	int i = sizeof(m_data.u32_data)/ sizeof(m_data.u32_data[0]);
	char piece[2 * sizeof(m_data.u32_data[0]) + 1] = {0};
	while (iss.get(piece,sizeof(piece))) {
		int length = iss.tellg();
		stream.str(piece);
		stream >> m_data.u32_data[--i];
		iss.seekg(length, ios::beg);
		stream.seekg(0,ios::beg);
	}
	
	return *this;
}

void CUInt128::ToByteArray(uint8_t *b) const
{

}

void CUInt128::StoreCryptValue(uint8_t *buf) const
{

}

int CUInt128::CompareTo(const CUInt128 &other) const throw()
{
	for (int i = 3; i >= 0; i--) {
	    if (m_data.u32_data[i] < other.m_data.u32_data[i])
			return -1;
	    if (m_data.u32_data[i] > other.m_data.u32_data[i])
			return 1;
	}
	return 0;
}

int CUInt128::CompareTo(uint32_t value) const throw()
{
	if ((m_data.u64_data[1] > 0) || (m_data.u32_data[1] > 0) || (m_data.u32_data[0] > value))
		return 1;
	if (m_data.u32_data[0] < value)
		return -1;
	return 0;
}

CUInt128& CUInt128::Add(const CUInt128 &value) throw()
{
	if (value.IsZero()) return *this;

	int64_t sum = 0;
	for (int i = 0; i < 4; i++) {
		sum += m_data.u32_data[i];
		sum += value.m_data.u32_data[i];
		m_data.u32_data[i] = (uint32_t)sum;
		sum >>= 32;
	}
	return *this;
}

CUInt128& CUInt128::Subtract(const CUInt128 &value) throw()
{
	if (value.IsZero()) return *this;

	int64_t sum = 0;
	for (int i = 0; i < 4; i++) {
		sum += m_data.u32_data[i];
		sum -= value.m_data.u32_data[i];
		m_data.u32_data[i] = (uint32_t)sum;
		sum >>= 32;
	}
	return *this;
}

CUInt128& CUInt128::ShiftLeft(unsigned bits) throw()
{
	if ((bits == 0) || IsZero())
		return *this;

	if (bits > 127) {
		SetValue((uint32_t)0);
		return *this;
	}

	union {
		uint32_t u32_data[4];
		uint64_t u64_data[2];
	} result = {{ 0, 0, 0, 0 }};
	int indexShift = (int)bits / 32;
	int64_t shifted = 0;
	for (int i = 3; i >= indexShift; i--)
	{
		shifted += ((int64_t)m_data.u32_data[3 - i]) << (bits % 32);
		result.u32_data[3 - i + indexShift] = (uint32_t)shifted;
		shifted = shifted >> 32;
	}
	m_data.u64_data[0] = result.u64_data[0];
	m_data.u64_data[1] = result.u64_data[1];

	return *this;
}

