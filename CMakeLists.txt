cmake_minimum_required(VERSION 3.5)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

project(TinyRistretto255BLSAG VERSION 0.1.0 LANGUAGES C)

add_executable(tiny-ristretto255-blsag main.c sha3.c)

find_package(Sodium REQUIRED)

target_link_libraries(tiny-ristretto255-blsag PRIVATE sodium)
