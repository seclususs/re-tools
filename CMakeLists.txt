cmake_minimum_required(VERSION 3.15)
project(re-tools LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include(FetchContent)

message(STATUS "[Dependency] Fetching FTXUI...")
FetchContent_Declare(ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG v5.0.0
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(ftxui)

message(STATUS "[Dependency] Fetching nlohmann/json...")
FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json
  GIT_TAG v3.11.3
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(json)

set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include/retools)
set(CLI_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/interfaces/cli/include)
include_directories(${INCLUDE_DIR} ${CLI_INCLUDE_DIR})

set(RUST_LIB_DIR "${PROJECT_SOURCE_DIR}/core/target/release")

if(MSVC)
    set(RUST_LIB_NAME "re_tools.lib")
    message(STATUS "[Toolchain] MSVC detected. Expecting: ${RUST_LIB_NAME}")
    add_compile_definitions(RETOOLS_MSVC)
elseif(MINGW OR CYGWIN)
    set(RUST_LIB_NAME "libre_tools.a")
    message(STATUS "[Toolchain] MinGW/GNU detected. Expecting: ${RUST_LIB_NAME}")
    add_compile_definitions(RETOOLS_MINGW)
else()
    set(RUST_LIB_NAME "libre_tools.a")
    message(STATUS "[Toolchain] Unix-like (GCC/Clang) detected. Expecting: ${RUST_LIB_NAME}")
endif()

set(RUST_STATIC_LIB_PATH "${RUST_LIB_DIR}/${RUST_LIB_NAME}")

if(NOT EXISTS "${RUST_STATIC_LIB_PATH}")
    message(WARNING 
        "\n[WARN] Rust static library not found at: ${RUST_STATIC_LIB_PATH}\n"
        "Hint: Run 'build.bat' or 'build.sh' to compile the Core first.\n"
        "Linking will fail if the library is missing at build time."
    )
endif()

add_library(retools_core_static STATIC IMPORTED GLOBAL)
set_target_properties(retools_core_static PROPERTIES
    IMPORTED_LOCATION "${RUST_STATIC_LIB_PATH}"
)
target_include_directories(retools_core_static INTERFACE ${INCLUDE_DIR})

if(WIN32)
    set_target_properties(retools_core_static PROPERTIES
        INTERFACE_LINK_LIBRARIES "ws2_32;userenv;bcrypt;ntdll;psapi;advapi32;kernel32;user32;shell32"
    )
elseif(UNIX AND NOT APPLE)
    set_target_properties(retools_core_static PROPERTIES
        INTERFACE_LINK_LIBRARIES "dl;pthread;util;rt;m"
    )
elseif(APPLE)
    set_target_properties(retools_core_static PROPERTIES
        INTERFACE_LINK_LIBRARIES "System;resolv;pthread;m"
    )
endif()

add_executable(retools_cli
    "interfaces/cli/src/main.cpp"
    "interfaces/cli/src/cli_engine.cpp"
    "interfaces/cli/src/cli_utils.cpp"
    "interfaces/cli/src/cli_repl.cpp"
)

target_link_libraries(retools_cli PRIVATE 
    retools_core_static
    ftxui::screen
    ftxui::dom
    ftxui::component
    nlohmann_json::nlohmann_json
)

enable_testing()

add_executable(test_static_cpp "tests/cpp/test_static.cpp")
target_link_libraries(test_static_cpp PRIVATE retools_core_static)

add_executable(test_dynamic_cpp "tests/cpp/test_dynamic.cpp")
target_link_libraries(test_dynamic_cpp PRIVATE retools_core_static)

add_executable(target_dummy "tests/cpp/target_dummy.cpp")

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    set(PYTHON_TEST_SCRIPT "${PROJECT_SOURCE_DIR}/tests/python/test_integration.py")
    add_test(NAME TestPythonIntegration COMMAND "${Python3_EXECUTABLE}" "${PYTHON_TEST_SCRIPT}")
    set_tests_properties(TestPythonIntegration PROPERTIES WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
endif()

add_test(NAME TestStaticCpp COMMAND test_static_cpp)
add_test(NAME TestDynamicCpp COMMAND test_dynamic_cpp)
set_tests_properties(TestStaticCpp TestDynamicCpp PROPERTIES WORKING_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

message(STATUS "Build configuration ready. Output: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")