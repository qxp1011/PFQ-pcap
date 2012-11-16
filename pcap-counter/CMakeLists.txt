cmake_minimum_required(VERSION 2.4)

set(CMAKE_VERBOSE_MAKEFILE 1)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -L ../libpcap-1.3.0/ -Ofast -march=native -Wall -std=c++0x")

#set (CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} ./libpcap-1.3.0/) 

include_directories(.)

add_executable(pcap-counters pcap-counters.cpp)

target_link_libraries(pcap-counters -lpcap -lpfq -lpthread)
