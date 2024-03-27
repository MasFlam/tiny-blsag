cmake_minimum_required(VERSION 3.5)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

project(TinyBLSAG VERSION 0.1.0 LANGUAGES C)

find_package(Sodium REQUIRED)

add_library(tinyblsag blsag.c sha3.c)
target_link_libraries(tinyblsag PRIVATE sodium)

add_executable(example main.c sha3.c)
target_link_libraries(example PRIVATE tinyblsag)
