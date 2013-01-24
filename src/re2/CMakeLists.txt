include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_SOURCE_DIR}/..
                    ${CMAKE_CURRENT_SOURCE_DIR}/../re2)

set(re2_SRCS
    bitstate.cc
    compile.cc
    dfa.cc
    filtered_re2.cc
    filtered_re2.h
    mimics_pcre.cc
    nfa.cc
    onepass.cc
    parse.cc
    perl_groups.cc
    prefilter.cc
    prefilter.h
    prefilter_tree.cc
    prefilter_tree.h
    prog.cc
    prog.h
    re2.cc
    re2.h
    regexp.cc
    regexp.h
    set.cc
    set.h
    simplify.cc
    stringpiece.h
    tostring.cc
    unicode_casefold.cc
    unicode_casefold.h
    unicode_groups.cc
    unicode_groups.h
    variadic_function.h
    walker-inl.h
    util/arena.cc
    util/arena.h
    util/atomicops.h
    util/benchmark.cc
    util/benchmark.h
    util/flags.h
    util/hash.cc
    util/logging.h
    util/mutex.h
    util/pcre.cc
    util/pcre.h
    util/random.cc
    util/random.h
    util/rune.cc
    util/sparse_array.h
    util/sparse_set.h
    util/stringpiece.cc
    util/stringprintf.cc
    util/strutil.cc
    util/test.cc
    util/test.h
    util/thread.cc
    util/thread.h
    util/utf.h
    util/util.h
    util/valgrind.cc
    util/valgrind.h
)

add_library(re2Static STATIC ${re2_SRCS})
if (UNIX)
    # the output name of the static library shouldn't conflict with the
    # shared library because they use different extensions (.a versus .so)
    set_target_properties(re2Static PROPERTIES OUTPUT_NAME re2)
endif ()
target_link_libraries(re2Static)
#install(TARGETS re2Static DESTINATION lib)

#install(FILES ${CMAKE_CURRENT_BINARY_DIR}/broccoli.h DESTINATION include)
