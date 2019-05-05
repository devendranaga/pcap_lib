project(pcap_lib)
cmake_minimum_required(VERSION 2.5)


set(LIBRARY_SOURCES
        pcap_parser.cc)

include_directories(./)

set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_C_FLAGS "-Os -Wall -Wno-unused-parameter -Wno-visibility -Werror -D_FORTIFY_SOURCE=2 -fstack-protector")
set(CMAKE_CXX_FLAGS "-Os -Wall -Wno-unused-parameter -std=c++11 -Wno-visibility -Werror -D_FORTIFY_SOURCE=2 -fstack-protector")


add_library(ncpcap SHARED ${LIBRARY_SOURCES})


