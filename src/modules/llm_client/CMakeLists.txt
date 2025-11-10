# src/modules/llm_client/CMakeLists.txt

find_package(cpr REQUIRED)
find_package(nlohmann_json REQUIRED)

add_library(llm_client_lib
    src/llm_client.cpp
)

target_include_directories(llm_client_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(llm_client_lib
    PUBLIC
    utils_lib
    cpr::cpr
    nlohmann_json::nlohmann_json
)