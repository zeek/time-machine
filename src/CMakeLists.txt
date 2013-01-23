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
flex_target(CMDScanner conf_scanner.ll ${CMAKE_CURRENT_BINARY_DIR}/conf_scanner.cc)
add_flex_bison_dependency(CONFScanner CONFParser)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR})

set(timemachine_SRCS
    ${BISON_CMDParser_INPUT}
    ${FLEX_CMDScanner_INPUT}
    ${BISON_CMDParser_OUTPUTS}
    ${FLEX_CMDScanner_OUTPUTS}
    ${BISON_CONFParser_INPUT}
    ${FLEX_CONFScanner_INPUT}
    ${BISON_CONFParser_OUTPUTS}
    ${FLEX_CONFScanner_OUTPUTS}
    BroccoliComm.cc
    BroccoliComm.hh
    Connection.cc
    Connection.hh
    Connections.cc
    Connections.hh
    DiskIndex.cc
    DiskIndex.hh
    DynClass.cc
    DynClass.hh
    Fifo.cc
    Fifo.hh
    FifoDisk.cc
    FifoDisk.hh
    FifoMem.cc
    FifoMem.hh
    Hash.cc
    Hash.hh
    Index.cc
    Index.hh
    IndexEntry.hh
    IndexField.cc
    IndexField.hh
    IndexHash.cc
    IndexHash.hh
    LogFile.cc
    LogFile.hh
    Query.cc
    Query.hh
    Queue.cc
    Queue.hh
    Storage.cc
    Storage.hh
    broSendPkts.cc
    bropipe.cc
    client.cc
    conf.h
    jhash3.h
    main.cc
    packet_headers.h
    querybm.cc
    rmtconsole.cc
    tm.h
    tm_q.cc
    types.h
    util.cc
    util.h
)

add_executable(timemachine ${timemachine_SRCS})

if (NOT TimeMachine_SKIP_INSTALL)
    install(TARGETS timemachine DESTINATION bin)
endif ()

# This is set to assist superprojects that want to build BinPac
# from source and rely on it as a target
set(TimeMachine_EXE timemachine
    CACHE STRING "TimeMachine executable" FORCE)
