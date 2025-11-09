# src/modules/utils/CMakeLists.txt
add_library(utils_lib
    src/utils.cpp
)

target_include_directories(utils_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)