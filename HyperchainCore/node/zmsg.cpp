/*Copyright 2016-2020 hyperchain.net (Hyperchain)

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

#include "zmsg.h"
#include "mdp.h"

#include <vector>
#include <string>
#include <stdarg.h>
using namespace std;


void zmsg::clear()
{
    m_part_data.clear();
}

void zmsg::set_part(size_t part_nbr, char *data)
{
    if (part_nbr < m_part_data.size()) {
        m_part_data[part_nbr] = data;
    }
}

bool zmsg::recv(zmq::socket_t & socket)
{
    clear();
    while (1) {
        zmq::message_t message(0);
        try {
            if (!socket.recv(message)) {
                return false;
            }
        }
        catch (zmq::error_t error) {
            std::cout << "E: " << error.what() << std::endl;
            return false;
        }

        m_part_data.push_back(std::string((char*)message.data(), message.size()));
        if (!message.more()) {
            break;
        }
    }
    return true;
}

int zmsg::send(zmq::socket_t & socket)
{
    for (size_t part_nbr = 0; part_nbr < m_part_data.size(); part_nbr++) {
        zmq::message_t message;
        std::string data = m_part_data[part_nbr];

        message.rebuild(data.size());
        memcpy(message.data(), data.c_str(), data.size());
        try {
            zmq::send_flags flags = zmq::send_flags::sndmore | zmq::send_flags::dontwait;
            if (part_nbr >= m_part_data.size() - 1) {
                flags = zmq::send_flags::none | zmq::send_flags::dontwait;
            }

            while (!g_sys_interrupted) {
                auto rc = socket.send(message, flags);
                if (!rc.has_value()) {
                    

                    continue;
                }
                if (rc.value() != data.size()) {
                    throw std::runtime_error("data send failure");
                }
                break;
            }
        }
        catch (zmq::error_t error) {
            cout << "zmq error catch: " << zmq_strerror(error.num());
            assert(error.num() != 0);
        }
        catch (std::exception error) {
            cout << "zmq send error catch: " << error.what();
        }

    }
    clear();
}

size_t zmsg::parts()
{
    return m_part_data.size();
}

void zmsg::body_set(const char *body, size_t len)
{
    if (m_part_data.size() > 0) {
        m_part_data.erase(m_part_data.end() - 1);
    }
    push_back((char*)body, len);
}

void zmsg::body_fmt(const char* fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    int sz = std::vsnprintf(nullptr, 0, fmt, args);
    va_end(args);

    std::string buf(sz, 0);

    va_start(args, fmt);
    std::vsnprintf(&buf[0], sz + 1, fmt, args);
    va_end(args);

    body_set((char*)buf.c_str(), buf.size());
}

// zmsg_push
void zmsg::push_front(string&& part)
{
    m_part_data.insert(m_part_data.begin(), part);
}


void zmsg::push_front(const char *part)
{
    m_part_data.insert(m_part_data.begin(), part);
}

void zmsg::push_front(const void *part, size_t len)
{
    string u((const char*)part, len);
    m_part_data.insert(m_part_data.begin(), u);
}

void zmsg::push_back(const void *part, size_t len)
{
    m_part_data.push_back(string((const char*)part, len));
}

char * zmsg::encode_uuid(unsigned char *data)
{
    static char
        hex_char[] = "0123456789ABCDEF";

    assert(data[0] == 0);
    char *uuidstr = new char[34];
    uuidstr[0] = '@';
    int byte_nbr;
    for (byte_nbr = 0; byte_nbr < 16; byte_nbr++) {
        uuidstr[byte_nbr * 2 + 1] = hex_char[data[byte_nbr + 1] >> 4];
        uuidstr[byte_nbr * 2 + 2] = hex_char[data[byte_nbr + 1] & 15];
    }
    uuidstr[33] = 0;
    return (uuidstr);
}


unsigned char * zmsg::decode_uuid(char *uuidstr)
{
    static char
        hex_to_bin[128] = {
           -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, /* */
           -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, /* */
           -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, /* */
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1, /* 0..9 */
           -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1, /* A..F */
           -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, /* */
           -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1, /* a..f */
           -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1 }; /* */

    assert(strlen(uuidstr) == 33);
    assert(uuidstr[0] == '@');
    unsigned char *data = new unsigned char[17];
    int byte_nbr;
    data[0] = 0;
    for (byte_nbr = 0; byte_nbr < 16; byte_nbr++)
        data[byte_nbr + 1]
        = (hex_to_bin[uuidstr[byte_nbr * 2 + 1] & 127] << 4)
        + (hex_to_bin[uuidstr[byte_nbr * 2 + 2] & 127]);

    return (data);
}

string zmsg::pop_front()
{
    if (m_part_data.size() == 0) {
        return 0;
    }
    string part = m_part_data.front();
    m_part_data.erase(m_part_data.begin());
    return part;
}

void zmsg::append(const char *part, int len)
{
    assert(part);
    push_back((char*)part, len);
}

char *zmsg::address()
{
    if (m_part_data.size() > 0) {
        return (char*)m_part_data[0].c_str();
    }
    else {
        return 0;
    }
}

void zmsg::wrap(const char *address, const char *delim)
{
    if (delim) {
        push_front((char*)delim);
    }
    push_front((char*)address);
}

std::string zmsg::unwrap()
{
    if (m_part_data.size() == 0) {
        return NULL;
    }
    std::string addr = (char*)pop_front().c_str();
    if (address() && *address() == 0) {
        pop_front();
    }
    return addr;
}

void zmsg::dump()
{
    std::cerr << "--------------------------------------" << std::endl;
    for (unsigned int part_nbr = 0; part_nbr < m_part_data.size(); part_nbr++) {
        string data = m_part_data[part_nbr];

        // Dump the message as text or binary
        int is_text = 1;
        for (unsigned int char_nbr = 0; char_nbr < data.size(); char_nbr++)
            if (data[char_nbr] < 32 || data[char_nbr] > 127)
                is_text = 0;

        std::cerr << "[" << std::setw(3) << std::setfill('0') << (int)data.size() << "] ";
        for (unsigned int char_nbr = 0; char_nbr < data.size(); char_nbr++) {
            if (is_text) {
                std::cerr << (char)data[char_nbr];
            }
            else {
                std::cerr << std::hex << std::setw(2) << std::setfill('0') << (short int)data[char_nbr];
            }
        }
        std::cerr << std::endl;
    }
}

