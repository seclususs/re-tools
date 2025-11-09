# src/modules/disassembler/CMakeLists.txt
add_library(disassembler_lib
    src/disassembler.cpp
)

target_include_directories(disassembler_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CAPSTONE_INCLUDE_DIRS}
)

target_link_libraries(disassembler_lib
    PUBLIC
    utils_lib
    ${CAPSTONE_LIBRARIES}
)