# CMakeLists.txt (Root)

cmake_minimum_required(VERSION 3.20)

if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

project(RE-Tools LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(Capstone REQUIRED)
include_directories(${CAPSTONE_INCLUDE_DIR})
add_subdirectory(src)
enable_testing()
add_subdirectory(tests)