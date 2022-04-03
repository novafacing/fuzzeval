file(GLOB srcs *.c)
if(BUILD_STATIC_LIBS)
    add_library(pov STATIC ${srcs})
else(BUILD_STATIC_LIBS)
    add_library(pov ${srcs})
endif(BUILD_STATIC_LIBS)

target_compile_definitions(pov PUBLIC -DNPATCHED)
if(NOT WIN32)
    target_compile_options(pov PUBLIC
        -pedantic
        -fno-builtin
        -O0
    )
endif()

target_include_directories(pov PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pov LINK_PUBLIC cgc)