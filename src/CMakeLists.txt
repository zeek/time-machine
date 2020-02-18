enable_language(C ASM)
bison_target(CMDParser cmd_parser.yy ${CMAKE_CURRENT_BINARY_DIR}/cmd_parser.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/cmd_parser.h
             VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/cmd_parser.output
             COMPILE_FLAGS "--debug")
flex_target(CMDScanner cmd_scanner.ll ${CMAKE_CURRENT_BINARY_DIR}/cmd_scanner.cc)
add_flex_bison_dependency(CMDScanner CMDParser)

bison_target(CONFParser conf_parser.yy ${CMAKE_CURRENT_BINARY_DIR}/conf_parser.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/conf_parser.h
             VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/conf_parser.output
             COMPILE_FLAGS "--debug")
flex_target(CONFScanner conf_scanner.ll ${CMAKE_CURRENT_BINARY_DIR}/conf_scanner.cc)
add_flex_bison_dependency(CONFScanner CONFParser)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_SOURCE_DIR}/..)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/main.cc.in
               ${CMAKE_CURRENT_BINARY_DIR}/main.cc)

#configure_file(util-config.h.in ${CMAKE_CURRENT_BINARY_DIR}/util-config.h)

set(timemachine_SRCS
    ${BISON_CMDParser_INPUT}
    ${FLEX_CMDScanner_INPUT}
    ${BISON_CMDParser_OUTPUTS}
    ${FLEX_CMDScanner_OUTPUTS}
    ${BISON_CONFParser_INPUT}
    ${FLEX_CONFScanner_INPUT}
    ${BISON_CONFParser_OUTPUTS}
    ${FLEX_CONFScanner_OUTPUTS}
    util.cc
    BroccoliComm.cc
    BroccoliComm.hh
    bro_inet_ntop.c
    bro_inet_ntop.h 
    Connection.cc
    Connection.hh
    Connections.cc
    Connections.hh
    #DiskIndex.cc
    #DiskIndex.hh
    DynClass.cc
    DynClass.hh
    Fifo.cc
    Fifo.hh
    FifoDisk.cc
    FifoDisk.hh
    FifoMem.cc
    FifoMem.hh
    Hash.cc
    Hash.h
    #HashIterator.hh
    H3.h
    #Index.cc
    Index.hh
    IndexEntry.hh
    IndexField.cc
    IndexField.hh
    IndexHash.cc
    IndexHash.hh
    #IPAddr.cc
    #IPAddr.h
    LogFile.cc
    LogFile.hh
    #modp_numtoa.h
    #net_util.h
    Query.cc
    Query.hh
    #Queue.cc
    #Queue.hh
    Storage.cc
    Storage.hh
    conf.h
    ${CMAKE_CURRENT_BINARY_DIR}/main.cc
    packet_headers.h
    rmtconsole.cc
    tm.h
    types.h
    #util.h
)

set (CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-g -Wall")

set(CMAKE_C_FLAGS "-DPCAPNAV_DEBUG")

set (EXTRA_LIBS ${EXTRA_LIBS} ${OpenSSL_SSL_LIBRARY} ${OpenSSL_CRYPTO_LIBRARY} -DPCAPNAV_DEBUG)

set(tm_query_benchmark_SRCS
    tm_query_benchmark.cc
)

add_subdirectory(re2)
add_subdirectory(pcapnav)
add_subdirectory(fmt)

if (USE_BROCCOLI)
    include_directories(${Broccoli_INCLUDE_DIR})
    list(APPEND OPTLIBS ${Broccoli_LIBRARY})

    add_executable(tm_query_benchmark ${tm_query_benchmark_SRCS})
    target_link_libraries(tm_query_benchmark ${CMAKE_THREAD_LIBS_INIT} ${OPTLIBS} ${PCAP_LIBRARY} re2Static)
endif()

add_executable(timemachine ${timemachine_SRCS})
#set_target_properties(timemachine PROPERTIES COMPILE_DEFINITIONS "-save-temps")
target_link_libraries(timemachine PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${PCAP_LIBRARY} ${Readline_LIBRARY} ${OPTLIBS} ${EXTRA_LIBS} re2Static pcapnavStatic) # "-save-temps")

target_link_libraries(timemachine PRIVATE fmt-header-only)

if (NOT TimeMachine_SKIP_INSTALL)
    install(TARGETS timemachine DESTINATION bin)
endif ()

# This is set to assist superprojects that want to build Time Machine
# from source and rely on it as a target
set(TimeMachine_EXE timemachine
    CACHE STRING "TimeMachine executable" FORCE)
