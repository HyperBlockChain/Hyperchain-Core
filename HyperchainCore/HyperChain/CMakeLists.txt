#Copyright 2016-2019 hyperchain.net (Hyperchain)
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

add_definitions("$ENV{CXXFLAGS} -O0 -Wall -g -rdynamic -ggdb -fstack-protector -fstack-protector-all")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -rdynamic -ggdb -fstack-protector -fstack-protector-all")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

elseif(WIN32)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /MD")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zi /Od /MDd")

ADD_DEFINITIONS(/D__WXMSW__ /DNOMINMAX)

endif()

#set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

PROJECT(hyperchainspace)

set(BIN_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

IF( NOT CMAKE_BUILD_TYPE )
   SET( CMAKE_BUILD_TYPE Release)
ENDIF()
message(STATUS "Build Type: " "${CMAKE_BUILD_TYPE}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)

#include current directory
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "Found openssl")
endif()

find_package(cpprestsdk REQUIRED)
if(cpprestsdk_FOUND)
    message(STATUS "Found cpprestsdk")
endif()

find_package(SQLite3 REQUIRED)
if(SQLite3_FOUND)
    message(STATUS "Found SQLite3")
endif()

#set(Boost_USE_STATIC_LIBS ON)
find_package (Boost REQUIRED COMPONENTS system program_options date_time filesystem thread serialization)

set(HC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

FILE(GLOB chainspace_SRC "*.cpp")
FILE(GLOB chainspace_HEAD "*.h")

FILE(GLOB main_SRC "${HC_DIR}/*.cpp")
FILE(GLOB main_HEAD "${HC_DIR}/*.h")

list(FILTER main_SRC EXCLUDE REGEX ".*main.cpp$")

#
#
if(NOT WIN32)
list(FILTER main_SRC EXCLUDE REGEX "newLog.cpp")
endif()

FILE(GLOB node_SRC "${HC_DIR}/node/UInt128.cpp")
FILE(GLOB node_HEAD "${HC_DIR}/node/UInt128.h")

FILE(GLOB db_SRC "${HC_DIR}/db/dbmgr.cpp" "${HC_DIR}/db/HyperchainDB.cpp")
FILE(GLOB db_HEAD "${HC_DIR}/db/dbmgr.h" "${HC_DIR}/db/HyperchainDB.h")

FILE(GLOB crypto_SRC "${HC_DIR}/crypto/*.cpp")
FILE(GLOB crypto_HEAD "${HC_DIR}/crypto/*.h")

FILE(GLOB data_SRC "${HC_DIR}/data/*.cpp")

FILE(GLOB headers_SRC "${HC_DIR}/headers/*.cpp")
FILE(GLOB headers_HEAD "${HC_DIR}/headers/*.h")

FILE(GLOB spdlog_HEAD "${HC_DIR}/spdlog/*")

FILE(GLOB sqlite3_HEAD "${HC_DIR}/thirdparty/sqlite3/*.h")

FILE(GLOB util_SRC "${HC_DIR}/util/*.cpp")
FILE(GLOB util_HEAD "${HC_DIR}/util/*.h")

FILE(GLOB utility_SRC "${HC_DIR}/utility/*.cpp")
FILE(GLOB utility_HEAD "${HC_DIR}/utility/*.h")

FILE(GLOB wnd_SRC "${HC_DIR}/wnd/*.cpp")
FILE(GLOB wnd_HEAD "${HC_DIR}/wnd/*.h")

FILE(GLOB consensus_SRC "${HC_DIR}/consensus/*.cpp")
FILE(GLOB consensus_HEAD "${HC_DIR}/consensus/*.h")

#All source files
set(final_HEAD
    ${chainspace_HEAD}
    ${main_HEAD}
	${node_HEAD}
	${db_HEAD}
	${headers_HEAD}
	${crypto_HEAD}
	${utility_HEAD}
	${util_HEAD}
	${sqlite3_HEAD}
	${spdlog_HEAD}
	${wnd_HEAD}
	${consensus_HEAD}
	)

set(final_SRC
    ${chainspace_SRC}
    ${main_SRC}
	${node_SRC}
	${db_SRC}
	${data_SRC}
	${headers_SRC}
	${crypto_SRC}
	${utility_SRC}
	${util_SRC}
	${sqlite3_SRC}
	${spdlog_SRC}
	${wnd_SRC}
	${consensus_SRC}
	)


add_library(${PROJECT_NAME} ${final_SRC} ${final_HEAD})

if(NOT WIN32)
target_compile_options(hyperchainspace PRIVATE -fPIC)
endif()


target_link_libraries(${PROJECT_NAME} cpprestsdk::cpprest OpenSSL::Crypto ${BerkeleyDB_LIBRARIES} ${SQLITE3_LIBRARIES})
target_link_libraries(${PROJECT_NAME} Boost::system Boost::program_options Boost::serialization Boost::filesystem Boost::thread)


configure_file (
"${PROJECT_SOURCE_DIR}/../config.h.in"
"${PROJECT_BINARY_DIR}/config.h")
