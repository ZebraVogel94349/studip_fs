cmake_minimum_required(VERSION 3.10)
project(studip_fs)

find_package(CURL REQUIRED)

add_executable(studip_fs src/main.cpp)
target_link_libraries(studip_fs PRIVATE CURL::libcurl)

