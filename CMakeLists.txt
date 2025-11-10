cmake_minimum_required(VERSION 3.10)
project(re-tools VERSION 0.1.0 LANGUAGES C CXX)

# Pengaturan C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Opsi Build
option(BUILD_SHARED_LIBS "Build menggunakan shared libraries" ON)
option(BUILD_TESTS "Build unit tests" ON)

# Setup Output Direktori
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Include Direktori Global
include_directories(include)
include_directories(core/parser/include)
include_directories(core/disassembler/include)

# Core Modules
file(GLOB_RECURSE CORE_SOURCES
    "core/parser/src/*.cpp"
    "core/disassembler/src/*.cpp"
)

if(NOT CORE_SOURCES)
    message(FATAL_ERROR "TIDAK ADA SOURCE FILE DITEMUKAN!")
endif()

# Buat library utama
add_library(retools_core SHARED ${CORE_SOURCES})

# Unit Tests
if(BUILD_TESTS)
    enable_testing()
    
    # Test Parser
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/parser/testParseHeaderElf.cpp")
        add_executable(test_parser tests/parser/testParseHeaderElf.cpp)
        target_link_libraries(test_parser PRIVATE retools_core)
        add_test(NAME TestParser COMMAND test_parser)
    endif()

    # Test Disassembler
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/disassembler/testDecodeInstruksi.cpp")
        add_executable(test_disasm tests/disassembler/testDecodeInstruksi.cpp)
        target_link_libraries(test_disasm PRIVATE retools_core)
        add_test(NAME TestDisasm COMMAND test_disasm)
    endif()
endif()

message(STATUS "Konfigurasi re-tools selesai. Siap untuk build.")