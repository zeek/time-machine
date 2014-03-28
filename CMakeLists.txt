project(TimeMachine C CXX)
cmake_minimum_required(VERSION 2.6.3 FATAL_ERROR)
include(cmake/CommonCMakeConfig.cmake)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

set(PREFIX "${CMAKE_INSTALL_PREFIX}")
set(ETC "${BRO_ETC_INSTALL_DIR}")

########################################################################
## Dependency Configuration

include(FindRequiredPackage)

FindRequiredPackage(FLEX)
FindRequiredPackage(BISON)
FindRequiredPackage(PCAP)
FindRequiredPackage(Readline)
FindRequiredPackage(Threads)

# Optional Dependencies

set(USE_BROCCOLI false)
find_package(Broccoli)
if (BROCCOLI_FOUND)
    set(USE_BROCCOLI true)
    include_directories(BEFORE ${Broccoli_INCLUDE_DIR})
    list(APPEND OPTLIBS ${Broccoli_LIBRARY})
endif ()

if (MISSING_PREREQS)
    foreach (prereq ${MISSING_PREREQ_DESCS})
        message(SEND_ERROR ${prereq})
    endforeach ()
    message(FATAL_ERROR "Configuration aborted due to missing prerequisites")
endif ()

########################################################################
## System Introspection

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})

########################################################################
## Recurse on sub-directories

add_subdirectory(src)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/etc/timemachine.cfg.in
               ${CMAKE_CURRENT_BINARY_DIR}/etc/timemachine.cfg)

include(InstallPackageConfigFile)
InstallPackageConfigFile(
    ${CMAKE_CURRENT_BINARY_DIR}/etc/timemachine.cfg
    ${ETC}
    timemachine.cfg)

########################################################################
## Build Summary

if (TimeMachine_SKIP_INSTALL)
    set(timemachine_install_summary "Install skipped")
else ()
    set(timemachine_install_summary "${CMAKE_INSTALL_PREFIX}")
endif ()

if (CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)
endif ()

message(
    "\n==================|  TimeMachine Build Summary  |===================="
    "\n"
    "\nInstall prefix:    ${timemachine_install_summary}"
    "\nConfig File Dir:   ${BRO_ETC_INSTALL_DIR}"

    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\nBroccoli:          ${USE_BROCCOLI}"
    "\n================================================================\n"
)

include(UserChangedWarning)
