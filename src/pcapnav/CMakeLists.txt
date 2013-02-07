include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(pcapnav_SRCS
    pcapnav_macros.h
    pcapnav_globals.c
    pcapnav_debug.c 
    pcapnav_debug.h
    pcapnav_private.h
    pcapnav.h 
    pcapnav.c
    pcapnav_append.h 
    pcapnav_append.c
    pcapnav_header.h 
    pcapnav_header.c
    pcapnav_trace.h 
    pcapnav_trace.c
    pcapnav_util.h 
    pcapnav_util.c
    pcapnav_buf.h 
    pcapnav_buf.c
    pcapnav_timestamp.h
)

add_library(pcapnavStatic STATIC ${pcapnav_SRCS})
if (UNIX)
    # the output name of the static library shouldn't conflict with the
    # shared library because they use different extensions (.a versus .so)
    set_target_properties(pcapnavStatic PROPERTIES OUTPUT_NAME pcapnav)
endif ()
target_link_libraries(pcapnavStatic)
