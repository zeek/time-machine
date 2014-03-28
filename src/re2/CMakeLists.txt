# GCC is giving warnings about this.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-sign-compare")

include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_SOURCE_DIR}/..
                    ${CMAKE_CURRENT_SOURCE_DIR}/../re2)

set(re2_SRCS
    bitstate.cc
    compile.cc
    dfa.cc
    filtered_re2.cc
    mimics_pcre.cc
    nfa.cc
    onepass.cc
    parse.cc
    perl_groups.cc
    prefilter.cc
    prefilter_tree.cc
    prog.cc
    re2.cc
    regexp.cc
    set.cc
    simplify.cc
    tostring.cc
    unicode_casefold.cc
    unicode_groups.cc
    util/arena.cc
    util/benchmark.cc
    util/hash.cc
    util/pcre.cc
    util/random.cc
    util/rune.cc
    util/stringpiece.cc
    util/stringprintf.cc
    util/strutil.cc
    util/test.cc
    util/thread.cc
    util/valgrind.cc
)

add_library(re2Static STATIC ${re2_SRCS})
if (UNIX)
    # the output name of the static library shouldn't conflict with the
    # shared library because they use different extensions (.a versus .so)
    set_target_properties(re2Static PROPERTIES OUTPUT_NAME re2)
endif ()
target_link_libraries(re2Static)
