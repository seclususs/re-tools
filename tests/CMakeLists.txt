# tests/CMakeLists.txt

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)

set(gtest_build_samples OFF CACHE BOOL "Build GTest samples" FORCE)
set(gtest_build_tests OFF CACHE BOOL "Build GTest's own tests" FORCE)

FetchContent_MakeAvailable(googletest)

include_directories(${googletest_SOURCE_DIR}/googletest/include)
include_directories(${googletest_SOURCE_DIR}/googlemock/include)
include_directories(
    ../src/modules/utils/include
    ../src/modules/binary_parser/include
    ../src/modules/disassembler/include
    ../src/modules/prompt_builder/include
    ../src/modules/llm_client/include
    ../src/modules/reporting/include
)

# Test: binary_parser
add_executable(test_binary_parser test_binary_parser.cpp)
target_link_libraries(test_binary_parser
    PRIVATE
    GTest::gtest_main
    binary_parser_lib
)
add_test(NAME TestBinaryParser COMMAND test_binary_parser)

# Test: disassembler
add_executable(test_disassembler test_disassembler.cpp)
target_link_libraries(test_disassembler
    PRIVATE
    GTest::gtest_main
    disassembler_lib
)
add_test(NAME TestDisassembler COMMAND test_disassembler)

# Test: prompt_builder
add_executable(test_prompt_builder test_prompt_builder.cpp)
target_link_libraries(test_prompt_builder
    PRIVATE
    GTest::gtest_main
    prompt_builder_lib
)
add_test(NAME TestPromptBuilder COMMAND test_prompt_builder)

# Test: llm_client
add_executable(test_llm_client test_llm_client.cpp)
target_link_libraries(test_llm_client
    PRIVATE
    GTest::gtest_main
    llm_client_lib
)
add_test(NAME TestLLMClient COMMAND test_llm_client)