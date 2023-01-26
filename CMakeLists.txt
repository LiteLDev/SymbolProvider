cmake_minimum_required(VERSION 3.21)
project(SymDBHelper)

set(CMAKE_CXX_STANDARD 17)

add_definitions(-D"NDEBUG" -D"_LIB" -D"_UNICODE" -D"UNICODE")

add_compile_options(
        /permissive- /GS /GL /W3 /Gy /Zc:wchar_t /Gm- /sdl /Zc:inline /fp:precise
        /errorReport:prompt /WX- /Zc:forScope /Gd /Oi /FC /diagnostics:column /utf-8
        "$<$<CONFIG:Debug>:/Od;/MDd>"
        "$<$<CONFIG:Release>:/O2;/MD>"
)

add_library(SymDBHelper STATIC SymDBHelper.cpp)
target_link_libraries(SymDBHelper)
