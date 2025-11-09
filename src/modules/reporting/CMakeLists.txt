# src/modules/reporting/CMakeLists.txt
add_library(reporting_lib
    src/reporting.cpp
)

target_include_directories(reporting_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(reporting_lib
    PUBLIC
    utils_lib
)