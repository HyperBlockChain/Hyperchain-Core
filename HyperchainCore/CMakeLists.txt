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

add_definitions(-D_DEBUG)
add_definitions(-DDEBUG)

SET(HC_FLAG "$ENV{CXXFLAGS} -Wall -rdynamic -ggdb -fstack-protector -fstack-protector-all")
SET(CMAKE_CXX_FLAGS_DEBUG "${HC_FLAG} -O0 -g")
SET(CMAKE_CXX_FLAGS_RELEASE "${HC_FLAG} -O3")

elseif(WIN32)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /MD /EHsc")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zi /Od /MDd /EHsc")

ADD_DEFINITIONS(/D__WXMSW__ /DNOMINMAX /DUDT_EXPORTS)

endif()

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

PROJECT(hc)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
if(NOT WIN32)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

IF( NOT CMAKE_BUILD_TYPE )
   SET( CMAKE_BUILD_TYPE Release)
ENDIF()
message(STATUS "Build Type: " "${CMAKE_BUILD_TYPE}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

#include current directory
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(SQLite3 REQUIRED)
if(SQLite3_FOUND)
    message(STATUS "Found SQLite3")
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "Found openssl")
endif()

find_package(cpprestsdk REQUIRED)
if(cpprestsdk_FOUND)
    message(STATUS "Found cpprestsdk")
endif()

find_package(cppzmq CONFIG REQUIRED)
if(cppzmq_FOUND)
    message(STATUS "Found ZeroMQ")
endif()

#set(Boost_USE_STATIC_LIBS ON)
find_package (Boost REQUIRED COMPONENTS system program_options date_time filesystem thread serialization fiber)


if(UNIX)
    find_package(breakpad REQUIRED)
elseif(WIN32)
    find_package(unofficial-breakpad CONFIG REQUIRED)
endif()

include_directories(${breakpad_INCLUDE_DIRS})

cmake_policy(SET CMP0071 NEW)

#set(CMAKE_AUTOMOC TRUE)
#set(CMAKE_AUTORCC TRUE)

set(main_SRC Log.cpp newLog.cpp NodeInfo.cpp main.cpp consolecommandhandler.cpp AppPlugins.cpp)
set(main_HEAD Log.h newLog.h NodeInfo.h Types.h consolecommandhandler.h AppPlugins.h plugins/PluginContext.h)

FILE(GLOB crypto_SRC "crypto/*.cpp")
FILE(GLOB crypto_HEAD "crypto/*.h")

FILE(GLOB data_SRC "data/*.cpp")

FILE(GLOB db_SRC "db/*.cpp")
FILE(GLOB db_HEAD "db/*.h")

FILE(GLOB headers_SRC "headers/*.cpp")
FILE(GLOB headers_HEAD "headers/*.h")

FILE(GLOB HttpUnit_SRC "HttpUnit/*.cpp")
FILE(GLOB HttpUnit_HEAD "HttpUnit/*.h")

FILE(GLOB HyperChain_SRC "HyperChain/*.cpp")
FILE(GLOB HyperChain_HEAD "HyperChain/*.h")
FILE(GLOB HyperChain_HPP "HyperChain/*.hpp")

FILE(GLOB node_SRC "node/*.cpp")
FILE(GLOB node_HEAD "node/*.h")
FILE(GLOB node_HPP "node/*.hpp")

FILE(GLOB spdlog_HEAD "spdlog/*")

FILE(GLOB sqlite3_HEAD "thirdparty/sqlite3/*.h")

FILE(GLOB udt_SRC "udt/*.cpp")
FILE(GLOB udt_HEAD "udt/*.h")

FILE(GLOB util_SRC "util/*.cpp")
FILE(GLOB util_HEAD "util/*.h")

FILE(GLOB utility_SRC "utility/*.cpp")
FILE(GLOB utility_HEAD "utility/*.h")

FILE(GLOB wnd_SRC "wnd/*.cpp")
FILE(GLOB wnd_HEAD "wnd/*.h")

FILE(GLOB consensus_SRC "consensus/*.cpp" "consensus/*.hpp")
FILE(GLOB consensus_HEAD "consensus/*.h")

#All source files
set(final_HEAD
    ${main_HEAD}
	${crypto_HEAD}
	${headers_HEAD}
	${HttpUnit_HEAD}
	${HyperChain_HEAD}
	${HyperChain_HPP}
	${node_HEAD}
	${node_HPP}
	${utility_HEAD}
	${wnd_HEAD}
	${db_HEAD}
	${udt_HEAD}
	${util_HEAD}
	${sqlite3_HEAD}
	${spdlog_HEAD}
	${consensus_HEAD}
	)

set(final_SRC
    ${main_SRC}
	${crypto_SRC}
	${data_SRC}
	${headers_SRC}
	${HttpUnit_SRC}
	${HyperChain_SRC}
	${node_SRC}
	${utility_SRC}
	${wnd_SRC}
	${db_SRC}
	${udt_SRC}
	${util_SRC}
	${consensus_SRC}
	)

set(resource_SRC ${CMAKE_BINARY_DIR}/logo.rc)

if(WIN32)
set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /level='requireAdministrator' /uiAccess='false' /SUBSYSTEM:CONSOLE" )
endif()

#install componet definition
set(CORECOMPONET "HyperChain")

add_subdirectory(HyperChain)
add_subdirectory(plugins/paracoin)
add_subdirectory(plugins/ledger)

add_executable(${PROJECT_NAME} ${final_SRC} ${final_HEAD} ${WRAP_FILES})

if(WIN32)
target_link_libraries(${PROJECT_NAME} bcrypt.lib)
else()
target_link_libraries(${PROJECT_NAME} dl)
endif()


target_link_libraries(${PROJECT_NAME} cpprestsdk::cpprest OpenSSL::Crypto ${SQLITE3_LIBRARIES})
target_link_libraries(${PROJECT_NAME} Boost::system Boost::program_options Boost::serialization Boost::filesystem Boost::thread Boost::fiber)
target_link_libraries(${PROJECT_NAME} unofficial::breakpad::libbreakpad_client)
target_link_libraries(${PROJECT_NAME} cppzmq libzmq cppzmq-static libzmq-static)

include(HyperChainCPack.cmake)

configure_file (
"${PROJECT_SOURCE_DIR}/logo.rc.in"
"${PROJECT_BINARY_DIR}/logo.rc")

configure_file (
"${PROJECT_SOURCE_DIR}/config.h.in"
"${PROJECT_BINARY_DIR}/config.h")



