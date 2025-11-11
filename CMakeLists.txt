cmake_minimum_required(VERSION 3.10)
project(re-tools VERSION 0.1.0 LANGUAGES C CXX)

include(ExternalProject)
find_program(CARGO_EXECUTABLE cargo REQUIRED)

set(RUST_PROJECT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/core_rs)
set(RUST_EP_DIR ${CMAKE_CURRENT_BINARY_DIR}/rust_ep_build)
set(RUST_TARGET_DIR ${RUST_EP_DIR}/target)
set(RUST_LIB_NAME core_rs)

if(WIN32)
  if(MINGW)
    set(RUST_LIB_PREFIX "lib")
    set(RUST_LIB_SUFFIX ".a")
  else()
    set(RUST_LIB_PREFIX "")
    set(RUST_LIB_SUFFIX ".lib")
  endif()
else()
  set(RUST_LIB_PREFIX "lib")
  set(RUST_LIB_SUFFIX ".a")
endif()

set(RUST_LIB_FILE ${RUST_TARGET_DIR}/release/${RUST_LIB_PREFIX}${RUST_LIB_NAME}${RUST_LIB_SUFFIX})

ExternalProject_Add(
    core_rs_project
    SOURCE_DIR ${RUST_PROJECT_DIR}
    BINARY_DIR ${RUST_EP_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CARGO_EXECUTABLE} build --release
                  --manifest-path ${RUST_PROJECT_DIR}/Cargo.toml
                  --target-dir ${RUST_TARGET_DIR}
    INSTALL_COMMAND ""
    BYPRODUCTS ${RUST_LIB_FILE}
)

add_library(core_rs_lib STATIC IMPORTED)
set_target_properties(core_rs_lib PROPERTIES IMPORTED_LOCATION ${RUST_LIB_FILE})
add_dependencies(core_rs_lib core_rs_project)

if(WIN32 AND MINGW)
  set_target_properties(core_rs_lib PROPERTIES
    INTERFACE_LINK_LIBRARIES "ws2_32;ntdll;userenv;bcrypt"
  )
endif()

# Pengaturan C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Opsi Build
option(BUILD_SHARED_LIBS "Build menggunakan shared libraries" ON)
option(BUILD_TESTS "Build unit tests" ON)

# Setup Output Direktori
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

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
    # "core/disassembler/src/*.cpp"
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

target_link_libraries(retools_core PRIVATE core_rs_lib)
add_dependencies(retools_core core_rs_lib)

set_target_properties(retools_core PROPERTIES OUTPUT_NAME "retools_core")

# Windows
if(WIN32 AND MINGW)
    get_filename_component(MINGW_BIN_DIR ${CMAKE_C_COMPILER} DIRECTORY)

    file(GLOB RUNTIME_DLLS
        "${MINGW_BIN_DIR}/libgcc_s_*.dll"
        "${MINGW_BIN_DIR}/libstdc++-*.dll"
        "${MINGW_BIN_DIR}/libwinpthread-*.dll"
    )
    if(RUNTIME_DLLS)
        message(STATUS "Menyalin MinGW runtime DLLs ke ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
        file(COPY ${RUNTIME_DLLS} DESTINATION ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
endif()

# CLI Tool
if(EXISTS "${CMAKE_SOURCE_DIR}/interfaces/cli/retools_cli.cpp")
    add_executable(retools_cli
        interfaces/cli/retools_cli.cpp
    )
    target_link_libraries(retools_cli PRIVATE retools_core)
endif()

# Unit Tests
if(BUILD_TESTS)
    enable_testing()
    find_package(Python3 COMPONENTS Interpreter)
    if(NOT Python3_FOUND)
        message(WARNING "Python 3 interpreter not found, skipping Python tests.")
    endif()

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

    # Test CLI Tool
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/interfaces/cli/test_cli_tool.cpp")
        add_executable(test_cli_tool tests/interfaces/cli/test_cli_tool.cpp)
        add_test(NAME TestCLITool COMMAND test_cli_tool)
        set_property(TEST TestCLITool PROPERTY WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()

    # Test Python Pipeline
    if(Python3_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/tests/interfaces/python/test_python_pipeline.py")
        
        set(PYTHON_PACKAGE_ROOT ${CMAKE_SOURCE_DIR}/interfaces/python)
        set(DLL_PATH ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}) 

        add_test(
            NAME TestPythonPipeline
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/interfaces/python/test_python_pipeline.py
            WORKING_DIRECTORY ${DLL_PATH}
        )

        # Separator PATH
        if(WIN32)
            set(PATH_SEP ";")
            set(ENV_VAR_PATH "Path")
        else()
            set(PATH_SEP ":")
            set(ENV_VAR_PATH "LD_LIBRARY_PATH")
        endif()

        set(TEST_PYTHONPATH "${PYTHON_PACKAGE_ROOT}")
        set_property(TEST TestPythonPipeline PROPERTY
            ENVIRONMENT 
                "PYTHONPATH=${TEST_PYTHONPATH}"
                "${ENV_VAR_PATH}=${DLL_PATH}${PATH_SEP}$ENV{${ENV_VAR_PATH}}"
        )
    endif()

    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/integration/test_full_cpp_integration.cpp")
        add_executable(test_full_cpp_integration tests/integration/test_full_cpp_integration.cpp)
        
        target_link_libraries(test_full_cpp_integration PRIVATE retools_core core_rs_lib)
        
        add_test(NAME TestFullCppIntegration COMMAND test_full_cpp_integration)
    endif()

endif()

message(STATUS "Konfigurasi re-tools selesai. Siap untuk build.")