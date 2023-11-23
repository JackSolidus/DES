cmake_minimum_required(VERSION 3.0)


include_directories("headers" "sources")

project(DES_lab)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

FILE(GLOB_RECURSE headers FOLLOW_SYMLINKS "headers/*.h")
FILE(GLOB_RECURSE sources FOLLOW_SYMLINKS "src/*.cpp")

add_subdirectory(main)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES source_list)