#Copyright 2016-2020 hyperchain.net (Hyperchain)
#Distributed under the MIT software license, see the accompanying
#file COPYING or https://opensource.org/licenses/MIT.

#Permission is hereby granted, free of charge, to any person obtaining a copy of this
#software and associated documentation files (the "Software"), to deal in the Software
#without restriction, including without limitation the rights to use, copy, modify, merge,
#publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
#to whom the Software is furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all copies or
#substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
#INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
#PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE

#FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
#OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#DEALINGS IN THE SOFTWARE.
#

CMAKE_MINIMUM_REQUIRED(VERSION 3.7)

set(CMAKE_CXX_STANDARD 11)

if(UNIX)

SET(HC_FLAG "$ENV{CXXFLAGS} -Wall -ggdb -fstack-protector -fstack-protector-all")
SET(CMAKE_CXX_FLAGS_DEBUG "${HC_FLAG} -O0 -g -Wl,--retain-symbols-file=${CMAKE_CURRENT_SOURCE_DIR}/../retain.lds -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../export.lds")
SET(CMAKE_CXX_FLAGS_RELEASE "${HC_FLAG} -O3 -Wl,--retain-symbols-file=${CMAKE_CURRENT_SOURCE_DIR}/../retain.lds -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../export.lds")

elseif(WIN32)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /MD")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zi /Od /MDd")

ADD_DEFINITIONS(/D__WXMSW__ /DNOMINMAX /DUDT_EXPORTS)

endif()

#set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

PROJECT(ledger)


IF( NOT CMAKE_BUILD_TYPE )
   SET( CMAKE_BUILD_TYPE Release)
ENDIF()
message(STATUS "Build Type: " "${CMAKE_BUILD_TYPE}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../..)

#include current directory
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "Found openssl")
endif()

if (NOT TARGET Oracle::BerkeleyDB)
	find_package(BerkeleyDB REQUIRED)
endif()


#set(Boost_USE_STATIC_LIBS ON)
find_package (Boost REQUIRED COMPONENTS system program_options date_time filesystem thread serialization)

set(HYPERCHAIN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)
FILE(GLOB ledger_SRC "*.cpp" "cryptopp/*.cpp")
FILE(GLOB ledger_HEAD "*.h" "cryptopp/*.h")


#All source files
set(final_HEAD
    ${ledger_HEAD}
	${HyperChain_HEAD}
	${node_HEAD}
	${udt_HEAD}
	${db_HEAD}
	)

set(final_SRC
    ${ledger_SRC}
	${node_SRC}
	${udt_SRC}
	${db_SRC}
	)

add_library(${PROJECT_NAME} SHARED ${final_SRC} ${final_HEAD})

target_link_libraries(${PROJECT_NAME} Oracle::BerkeleyDB OpenSSL::Crypto hyperchainspace)
target_link_libraries(${PROJECT_NAME} Boost::system Boost::program_options Boost::serialization Boost::filesystem Boost::thread Boost::fiber)
target_link_libraries(${PROJECT_NAME} cppzmq libzmq cppzmq-static libzmq-static)

configure_file (
"${PROJECT_SOURCE_DIR}/../../config.h.in"
"${PROJECT_BINARY_DIR}/config.h")

install( TARGETS ${PROJECT_NAME} DESTINATION bin COMPONENT ${CORECOMPONET})


