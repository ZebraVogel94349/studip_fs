cmake_minimum_required(VERSION 3.10)

project(studip_fs
    LANGUAGES CXX
    VERSION 0.1.0
)

find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

set(CMAKE_CXX_STANDARD 20)

add_executable(studip_fs src/main.cpp)

target_link_libraries(studip_fs PRIVATE CURL::libcurl)

target_include_directories(studip_fs PRIVATE ${FUSE3_INCLUDE_DIRS} include)
target_link_libraries(studip_fs PRIVATE ${FUSE3_LIBRARIES})
