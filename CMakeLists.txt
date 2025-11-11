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
include_directories(core/hexeditor/include)
include_directories(core/analyzer/include)
include_directories(core/tracer/include)
include_directories(os_specific/linux)
include_directories(os_specific/windows)
include_directories(tools/binaryDiff/include)
include_directories(tools/cfgVisualizer/include)

# Core Modules
file(GLOB_RECURSE CORE_SOURCES
    "core/parser/src/*.cpp"
    "core/disassembler/src/*.cpp"
    "core/hexeditor/src/*.cpp"
    "core/analyzer/src/*.cpp"
    "core/tracer/src/*.cpp"
    "tools/binaryDiff/src/*.cpp"
    "tools/cfgVisualizer/src/*.cpp"
)

# OS Specific Modules
file(GLOB_RECURSE OS_SPECIFIC_SOURCES
    "os_specific/linux/*.cpp"
    "os_specific/windows/*.cpp"
)

if(NOT CORE_SOURCES)
    message(FATAL_ERROR "TIDAK ADA SOURCE FILE DITEMUKAN!")
endif()

# Library utama
add_library(retools_core SHARED 
    ${CORE_SOURCES}
    ${OS_SPECIFIC_SOURCES}
)

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

    # Test HexEditor
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/hexeditor/testLihatBytes.cpp")
        add_executable(test_hexeditor tests/hexeditor/testLihatBytes.cpp)
        target_link_libraries(test_hexeditor PRIVATE retools_core)
        add_test(NAME TestHexEditor COMMAND test_hexeditor)
    endif()

    # Test Analyzer
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/analyzer/testHitungEntropy.cpp")
        add_executable(test_analyzer tests/analyzer/testHitungEntropy.cpp)
        target_link_libraries(test_analyzer PRIVATE retools_core)
        add_test(NAME TestAnalyzer COMMAND test_analyzer)
    endif()
    
    # Test Tracer
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/tracer/testAttachProses.cpp")
        add_executable(test_tracer tests/tracer/testAttachProses.cpp)
        target_link_libraries(test_tracer PRIVATE retools_core)
        
        # Link library spesifik OS
        if(UNIX AND NOT APPLE)
             target_link_libraries(test_tracer PRIVATE pthread)
        endif()
        if(WIN32)
             target_link_libraries(test_tracer PRIVATE Advapi32.lib)
        endif()

        add_test(NAME TestTracer COMMAND test_tracer)
    endif()

    # Test BinaryDiff
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/tools/binaryDiff/testDiffBinary.cpp")
        add_executable(test_binary_diff tests/tools/binaryDiff/testDiffBinary.cpp)
        target_link_libraries(test_binary_diff PRIVATE retools_core)
        add_test(NAME TestBinaryDiff COMMAND test_binary_diff)
    endif()

    # Test CFGVisualizer
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/tools/cfgVisualizer/testGenerateCFG.cpp")
        add_executable(test_cfg_visualizer tests/tools/cfgVisualizer/testGenerateCFG.cpp)
        target_link_libraries(test_cfg_visualizer PRIVATE retools_core)
        add_test(NAME TestCFGVisualizer COMMAND test_cfg_visualizer)
    endif()
endif()

message(STATUS "Konfigurasi re-tools selesai. Siap untuk build.")