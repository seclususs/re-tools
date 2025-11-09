# src/CMakeLists.txt

add_subdirectory(modules)
add_executable(re_tools main.cpp)

target_link_libraries(re_tools
    PUBLIC
    utils_lib
    binary_parser_lib
    disassembler_lib
    prompt_builder_lib
    llm_client_lib
    reporting_lib
)