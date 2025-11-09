# src/modules/prompt_builder/CMakeLists.txt
add_library(prompt_builder_lib
    src/prompt_builder.cpp
)

target_include_directories(prompt_builder_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(prompt_builder_lib
    PUBLIC
    utils_lib
    disassembler_lib
)