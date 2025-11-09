# src/modules/binary_parser/CMakeLists.txt
add_library(binary_parser_lib
    src/binary_parser.cpp
)

target_include_directories(binary_parser_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(binary_parser_lib
    PUBLIC
    utils_lib
)