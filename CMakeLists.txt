cmake_minimum_required(VERSION 3.16)
project(projekt)

set(CMAKE_CXX_STANDARD 17)

include(FindPCAP.cmake)

include_directories(.)

add_executable(projekt main.cpp
        args.cpp
        args.hpp)

target_link_libraries(projekt ${PCAP_LIBRARY})