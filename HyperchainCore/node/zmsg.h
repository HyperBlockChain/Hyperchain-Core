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

#ifndef __ZMSG_H_INCLUDED__
#define __ZMSG_H_INCLUDED__

#include "zhelpers.hpp"

#include <vector>
#include <string>
#include <stdarg.h>
using namespace std;

class zmsg {
public:

   zmsg() {}

   zmsg(char const *body, size_t len)
   {
       body_set(body, len);
   }

   zmsg(zmq::socket_t &socket)
   {
       recv(socket);
   }

   zmsg(zmsg &&msg)
   {
       m_part_data = std::move(msg.m_part_data);
   }

   zmsg(const zmsg &msg)
   {
       m_part_data.resize(msg.m_part_data.size());
       std::copy(msg.m_part_data.begin(), msg.m_part_data.end(), m_part_data.begin());
   }

   virtual ~zmsg()
   {
      clear();
   }

   void clear();

   void set_part(size_t part_nbr, char *data);

   bool recv(zmq::socket_t & socket);
   int send(zmq::socket_t & socket);

   size_t parts();

   void body_set(const char *body, size_t len);
   void body_fmt(const char* fmt, ...);

   void push_front(string&& part);
   void push_front(const char *part);
   void push_front(const void *part, size_t len);
   void push_back(const void *part, size_t len);

   static char * encode_uuid(unsigned char *data);

   static unsigned char * decode_uuid(char *uuidstr);

   string pop_front();
   void append(const char *part, int len);

   char *address();

   void wrap(const char *address, const char *delim);

   std::string unwrap();

   void dump();

  private:
   std::vector<string> m_part_data;
};

#endif /* ZMSG_H_ */
