# ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0. See the LICENSE file.


include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(include_dir ${PROJECT_SOURCE_DIR}/include)



add_library(
    ethash
    bit_manipulation.h
    builtins.h
    endianness.hpp
    ${include_dir}/ethash/ethash.h
    ${include_dir}/ethash/ethash.hpp
    ethash-internal.hpp
    ethash.cpp
    ${include_dir}/ethash/hash_types.h
    managed.cpp
    ${include_dir}/ethash/keccak.h
    ${include_dir}/ethash/keccak.hpp
    keccak.c
    keccakf800.c
    keccakf1600.c
    kiss99.hpp
    primes.h
    primes.c
    ${include_dir}/ethash/progpow.hpp
    progpow.cpp
)

if(NOT WIN32)
target_compile_options(ethash PRIVATE -fPIC)
endif()

target_include_directories(ethash PUBLIC $<BUILD_INTERFACE:${include_dir}>$<INSTALL_INTERFACE:include>)

write_basic_package_version_file(ethashConfigVersion.cmake COMPATIBILITY SameMajorVersion)

configure_package_config_file(
    ../../cmake/Config.cmake.in
    ethashConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ethash
)


get_filename_component(ETHASH_PRIVATE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/.. ABSOLUTE)
set(ETHASH_PRIVATE_INCLUDE_DIR ${ETHASH_PRIVATE_INCLUDE_DIR} PARENT_SCOPE)