project(TimeMachine C CXX)
cmake_minimum_required(VERSION 2.6.3 FATAL_ERROR)
include(cmake/CommonCMakeConfig.cmake)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

set(PREFIX "${CMAKE_INSTALL_PREFIX}")
set(ETC "${BRO_ETC_INSTALL_DIR}")

########################################################################
## Dependency Configuration

include(FindRequiredPackage)
include(CheckSymbolExists)


FindRequiredPackage(FLEX)
FindRequiredPackage(BISON)
FindRequiredPackage(PCAP)
FindRequiredPackage(Readline)
FindRequiredPackage(Threads)

include_directories(BEFORE ${Readline_INCLUDE_DIR})
# target_link_libraries(-lreadline) 

find_package(OpenSSL REQUIRED)
include_directories(BEFORE ${OpenSSL_INCLUDE_DIR})

# Optional Dependencies

set(USE_BROCCOLI false)
find_package(Broccoli)
if (BROCCOLI_FOUND)
    set(USE_BROCCOLI true)
    include_directories(BEFORE ${Broccoli_INCLUDE_DIR})
    list(APPEND OPTLIBS ${Broccoli_LIBRARY})
endif ()

set(HAVE_PERFTOOLS false)
set(USE_PERFTOOLS_DEBUG false)
set(USE_PERFTOOLS_TCMALLOC false)
set(USE_PERFTOOLS_CPU false)

if (NOT DISABLE_PERFTOOLS)
   find_package(GooglePerftools)
endif ()

if (GOOGLEPERFTOOLS_FOUND)
    set(HAVE_PERFTOOLS true)
    # Non-Linux systems may not be well-supported by gperftools, so
    # require explicit request from user to enable it in that case.
    if (${CMAKE_SYSTEM_NAME} MATCHES "Linux" OR ENABLE_PERFTOOLS)
        set(USE_PERFTOOLS_TCMALLOC true)

        if (ENABLE_PERFTOOLS_DEBUG)
            # Enable heap debugging with perftools.
            set(USE_PERFTOOLS_DEBUG true)
            include_directories(BEFORE ${GooglePerftools_INCLUDE_DIR})
            list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES_DEBUG})
        else ()
            # Link in tcmalloc for better performance.
            list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES})
        endif ()
        
        if (ENABLE_PERFTOOLS_CPU)
            # Enable CPU usage debugging with perftools.
            set(USE_PERFTOOLS_CPU true)
            include_directories(BEFORE ${GooglePerftools_INCLUDE_CPU})
            list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES_CPU})
        else ()
            list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES})
        endif ()
    endif ()
endif ()

if (MISSING_PREREQS)
    foreach (prereq ${MISSING_PREREQ_DESCS})
        message(SEND_ERROR ${prereq})
    endforeach ()
    message(FATAL_ERROR "Configuration aborted due to missing prerequisites")
endif ()

if (ENABLE_PERFTOOLS_CPU OR ENABLE_PERFTOOLS_DEBUG OR ENABLE_PERFTOOLS)
    # Just a no op to prevent CMake from complaining about manually-specified
    # ENABLE_PERFTOOLS_DEBUG or ENABLE_PERFTOOLS not being used if google
    # perftools weren't found
endif ()

set(CMAKE_CXX_FLAGS "-g -Wall -O3")
set(CMAKE_C_FLAGS "-g -Wall -O3")
add_definitions("-O3")

#detect 32 or 64 bit compiler
# Also in config.h.in
IF(CMAKE_SYSTEM_PROCESSOR MATCHES "^(i.86|x86|x86_64)$")
    include(CheckTypeSize)
    check_type_size("void*" SIZEOF_VOID_P BUILTIN_TYPES_ONLY)
    if (${SIZEOF_VOID_P} EQUAL 8)
        set(CMAKE_SYSTEM_PROCESSOR_x86 64)
    else()
        set(CMAKE_SYSTEM_PROCESSOR_x86 32)
    endif()
ENDIF()

check_symbol_exists(PATH_MAX limits.h HAVE_PATH_MAX)

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
    "\ngperftools found:  ${HAVE_PERFTOOLS}"
    "\n        tcmalloc:  ${USE_PERFTOOLS_TCMALLOC}"
    "\n       debugging:  ${USE_PERFTOOLS_DEBUG}"
    "\n     cpu_profile:  ${USE_PERFTOOLS_CPU}"
    "\n================================================================\n"
)

include(UserChangedWarning)
