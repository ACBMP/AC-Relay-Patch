cmake_minimum_required(VERSION 3.20)
project(ac_relay LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(SOURCES
    src/dllmain.cpp
    src/config.cpp
    src/logger.cpp
    src/relay.cpp
    src/ipv6.cpp
    src/game_hooks.cpp
    src/crash_log.cpp
    external/safetyhook/safetyhook.cpp
    external/safetyhook/Zydis.c
)

add_library(ac_relay SHARED ${SOURCES})

set_target_properties(ac_relay PROPERTIES
    PREFIX ""
    SUFFIX ".asi"
    OUTPUT_NAME "ac_relay"
)

target_include_directories(ac_relay PRIVATE
    src
    external/inipp
    external/spdlog/include
    external/safetyhook
)

target_compile_definitions(ac_relay PRIVATE
    WIN32
    _WINDOWS
    _USRDLL
    NOMINMAX
    ZYDIS_STATIC_BUILD
    ZYCORE_STATIC_BUILD
)

target_link_libraries(ac_relay PRIVATE
    ws2_32
)

if(MSVC)
    target_compile_options(ac_relay PRIVATE /utf-8 /EHsc)
    set_property(TARGET ac_relay PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
    target_link_options(ac_relay PRIVATE
        $<$<CONFIG:Release>:/OPT:REF>
        $<$<CONFIG:Release>:/OPT:ICF>
    )
endif()

add_custom_command(TARGET ac_relay POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/ac_relay.ini
        $<TARGET_FILE_DIR:ac_relay>/ac_relay.ini
)
