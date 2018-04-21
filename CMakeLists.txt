cmake_minimum_required(VERSION 3.7)
project(TAP)

set(CMAKE_CXX_STANDARD 14)

set(SOURCE_FILES
        src/tap.cpp
        src/lpack.c
        src/lua_ctx.cpp
        src/lua_pcap.cpp
        include/nmp.h
        include/types.h
        include/lua_ctx.h
        include/lua_pcap.h
        include/lua_lpack.h)
include_directories(./include)
add_executable(TAP ${SOURCE_FILES})

#set( CMAKE_C_FLAGS  ${CMAKE_C_FLAGS})
#set( CMAKE_CXX_FLAGS   ${CMAKE_CXX_FLAGS})


find_library(
        LUALIB
        NAMES lua
        PATHS /usr/lib /usr/local/lib
)

target_link_libraries(TAP ${LUALIB} -lpthread -ldl -lpcap)