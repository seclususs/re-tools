cmake_minimum_required(VERSION 3.15)
project(re-tools LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing()

set(LIB_DIR ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})
set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include/retools)

include_directories(${INCLUDE_DIR})

set(RUST_LIB_DIR "${PROJECT_SOURCE_DIR}/core/target/release")
set(RUST_STATIC_LIB_PATH "${RUST_LIB_DIR}/libre_tools.a")

add_library(retools_core_static STATIC IMPORTED GLOBAL)
set_target_properties(retools_core_static PROPERTIES
    IMPORTED_LOCATION "${RUST_STATIC_LIB_PATH}"
)
target_include_directories(retools_core_static INTERFACE ${INCLUDE_DIR})

if(WIN32 AND CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set_target_properties(retools_core_static PROPERTIES
        INTERFACE_LINK_LIBRARIES "ws2_32;userenv;bcrypt;ntdll"
    )
endif()

set(CPP_TARGETS
    retools_cli
    test_parser
    test_disasm
    test_hexeditor
    test_analyzer
    test_tracer
    test_binary_diff
    test_cfg_visualizer
    test_cli_tool
    test_full_cpp_integration
)

add_executable(retools_cli "interfaces/cli/retools_cli.cpp")
add_executable(test_parser "tests/parser/testParseBinaryHeader.cpp")
add_executable(test_disasm "tests/disassembler/testDecodeInstruksi.cpp")
add_executable(test_hexeditor "tests/hexeditor/testLihatBytes.cpp")
add_executable(test_analyzer "tests/analyzer/testHitungEntropy.cpp")
add_executable(test_tracer "tests/tracer/testAttachProses.cpp")
add_executable(test_binary_diff "tests/tools/binaryDiff/testDiffBinary.cpp")
add_executable(test_cfg_visualizer "tests/tools/cfgVisualizer/testGenerateCFG.cpp")
add_executable(test_cli_tool "tests/interfaces/cli/test_cli_tool.cpp")
add_executable(test_full_cpp_integration "tests/integration/test_full_cpp_integration.cpp")

foreach(TARGET ${CPP_TARGETS})
    target_link_libraries(${TARGET} PRIVATE retools_core_static)
endforeach()

if(DEFINED ENV{VIRTUAL_ENV})
    file(TO_CMAKE_PATH "$ENV{VIRTUAL_ENV}/Scripts/python.exe" VENV_PYTHON_EXE)
    if(EXISTS "${VENV_PYTHON_EXE}")
        set(Python3_EXECUTABLE "${VENV_PYTHON_EXE}" CACHE FILEPATH "Python executable from VIRTUAL_ENV" FORCE)
    endif()
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)
message(STATUS "CTest akan menggunakan Python: ${Python3_EXECUTABLE}")

set(PYTHON_TEST_SCRIPT "${PROJECT_SOURCE_DIR}/tests/interfaces/python/test_python_pipeline.py")
add_test(NAME TestPythonPipeline COMMAND "${Python3_EXECUTABLE}" "${PYTHON_TEST_SCRIPT}")
set_tests_properties(TestPythonPipeline PROPERTIES WORKING_DIRECTORY "${LIB_DIR}")

add_test(NAME TestParser COMMAND test_parser)
add_test(NAME TestDisasm COMMAND test_disasm)
add_test(NAME TestHexEditor COMMAND test_hexeditor)
add_test(NAME TestAnalyzer COMMAND test_analyzer)
add_test(NAME TestTracer COMMAND test_tracer)
add_test(NAME TestBinaryDiff COMMAND test_binary_diff)
add_test(NAME TestCFGVisualizer COMMAND test_cfg_visualizer)
add_test(NAME TestCLITool COMMAND test_cli_tool)
add_test(NAME TestFullCppIntegration COMMAND test_full_cpp_integration)

set(CPP_TEST_NAMES
    TestParser TestDisasm TestHexEditor TestAnalyzer TestTracer
    TestBinaryDiff TestCFGVisualizer TestCLITool TestFullCppIntegration
)
set_tests_properties(${CPP_TEST_NAMES} PROPERTIES WORKING_DIRECTORY "${LIB_DIR}")

if(WIN32 AND CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    get_filename_component(MINGW_BIN_DIR ${CMAKE_CXX_COMPILER} DIRECTORY)
    file(TO_CMAKE_PATH "${MINGW_BIN_DIR}" MINGW_BIN_DIR_CMAKE)

    set(MINGW_REQUIRED_DLLS
        "${MINGW_BIN_DIR_CMAKE}/libstdc++-6.dll"
        "${MINGW_BIN_DIR_CMAKE}/libgcc_s_seh-1.dll"
        "${MINGW_BIN_DIR_CMAKE}/libwinpthread-1.dll"
    )

    foreach(DLL_FILE ${MINGW_REQUIRED_DLLS})
        if(EXISTS "${DLL_FILE}")
            foreach(TARGET ${CPP_TARGETS})
                add_custom_command(
                    TARGET ${TARGET}
                    POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${DLL_FILE}"
                    "${LIB_DIR}"
                )
            endforeach()
        else()
            message(WARNING "DLL yang diperlukan tidak ditemukan: ${DLL_FILE}")
        endif()
    endforeach()

    set(MINGW_PATH_PART "${MINGW_BIN_DIR_CMAKE};")
else()
    message(WARNING "Compiler CXX bukan GNU. Tes C++ mungkin gagal menemukan runtime.")
    set(MINGW_PATH_PART "")
endif()


file(TO_CMAKE_PATH "${LIB_DIR}" LIB_DIR_CMAKE)
file(TO_CMAKE_PATH "$ENV{PATH}" ENV_PATH_CMAKE)

set(CTEST_DLL_PATH "${LIB_DIR_CMAKE};${MINGW_PATH_PART}${ENV_PATH_CMAKE}")

set_tests_properties(
    TestPythonPipeline
    ${CPP_TEST_NAMES}
    PROPERTIES
    ENVIRONMENT "PATH=${CTEST_DLL_PATH}"
)

message(STATUS "Konfigurasi re-tools selesai. Siap untuk build.")