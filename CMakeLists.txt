# CMakeLists.txt --- CMake project settings
#    ex) cmake -G "Visual Studio 9 2008"
#    ex) cmake -DCMAKE_BUILD_TYPE=Release -G "MSYS Makefiles"
##############################################################################

# CMake minimum version
cmake_minimum_required(VERSION 3.12.4)

# project name and language
project(Entours CXX)

# check build type
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, default to Debug")
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# make uppercase string of build type
string(TOUPPER "${CMAKE_BUILD_TYPE}" uppercase_CMAKE_BUILD_TYPE)

# check build type again
if (NOT uppercase_CMAKE_BUILD_TYPE MATCHES "^(DEBUG|RELEASE|RELWITHDEBINFO|MINSIZEREL)$")
    message(FATAL_ERROR "Invalid value for CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif()

# enable C compilers
enable_language(C)

# enable Win32 resource
enable_language(RC)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # using Clang
    set(CMAKE_C_FLAGS "-static")
    set(CMAKE_CXX_FLAGS "-static")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # using GCC
    set(CMAKE_C_FLAGS "-static -static-libgcc -static-libstdc++")
    set(CMAKE_CXX_FLAGS "-static -static-libgcc -static-libstdc++")
elseif (MSVC)
    # replace "/MD" with "/MT" (building without runtime DLLs)
    set(CompilerFlags
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    foreach(CompilerFlags ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlags} "${${CompilerFlags}}")
    endforeach()

    add_link_options(/NODEFAULTLIB:libcmtd)
endif()

##############################################################################
# options

option(ENTOURS_USE_SAMPLES "Use samples" OFF)
option(ENTOURS_WIN_7 "Windows 7 is target" OFF)
option(ENTOURS_CL_17_OR_NEWER "CL 17 or newer" OFF)
option(ENTOURS_ANALYZE "Enable analyzing" OFF)
option(ENTOURS_NO_SEH "No Structured Exception Handling (SEH) support" OFF)

if (ENTOURS_NO_SEH)
    add_definitions(-DENTOURS_NO_SEH)
endif()

##############################################################################

set(ENTOURS_CONFIG "")

# TODO: Choose one of the followings:
set(ENTOURS_TARGET_PROCESSOR "X86")
#set(ENTOURS_TARGET_PROCESSOR "X64")
#set(ENTOURS_TARGET_PROCESSOR "IA64")
#set(ENTOURS_TARGET_PROCESSOR "ARM")
#set(ENTOURS_TARGET_PROCESSOR "ARM64")

##############################################################################

# uppercase ENTOURS_TARGET_PROCESSOR
string(TOUPPER "${ENTOURS_TARGET_PROCESSOR}" ENTOURS_TARGET_PROCESSOR_UPPER)
set(ENTOURS_TARGET_PROCESSOR ${ENTOURS_TARGET_PROCESSOR_UPPER})

if (ENTOURS_TARGET_PROCESSOR STREQUAL "AMD64")
    set(ENTOURS_TARGET_PROCESSOR "X64")
endif()

if (ENTOURS_TARGET_PROCESSOR MATCHES "64")
    set(ENTOURS_64BIT 1)
    set(ENTOURS_BITS 64)
else()
    set(ENTOURS_32BIT 1)
    set(ENTOURS_BITS 32)
endif()

##############################################################################

if (ENTOURS_TARGET_PROCESSOR STREQUAL "X64")
    message(STATUS "Building for 64-bit X64.")
    set(ENTOURS_SOURCE_BROWSING 0)
    set(ENTOURS_OPTION_PROCESSOR X86)
    set(ENTOURS_OPTION_BITS 32)
elseif (ENTOURS_TARGET_PROCESSOR STREQUAL "IA64")
    message(STATUS "Building for 64-bit IA64.")
    set(ENTOURS_OPTION_PROCESSOR X86)
    set(ENTOURS_OPTION_BITS 32)
elseif (ENTOURS_TARGET_PROCESSOR STREQUAL "X86")
    message(STATUS "Building for 32-bit X86.")
    set(ENTOURS_OPTION_BITS 64)
    # Don't set ENTOURS_OPTION_PROCESSOR for x64 because we don't *know* that
    # we'll run on a 64-bit machine.
elseif (ENTOURS_TARGET_PROCESSOR STREQUAL "ARM")
    message(STATUS "Building for 32-bit ARM.")
elseif (ENTOURS_TARGET_PROCESSOR STREQUAL "ARM64")
    message(STATUS "Building for 64-bit ARM.")
else()
    message(STATUS "Note: To select the target processor architecture set")
    message(STATUS "      ENTOURS_TARGET_PROCESSOR.")
    message(STATUS "ENTOURS_TARGET_PROCESSOR: '${ENTOURS_TARGET_PROCESSOR}'")
    message(FATAL_ERROR "Unknown target processor: ${ENTOURS_TARGET_ARCHITECTURE}")
endif()

##############################################################################

set(ROOT ${CMAKE_SOURCE_DIR})

set(INCD "${CMAKE_BINARY_DIR}/include")
set(LIBD "${CMAKE_BINARY_DIR}/lib.${ENTOURS_TARGET_PROCESSOR}${ENTOURS_CONFIG}")
set(BIND "${CMAKE_BINARY_DIR}/bin.${ENTOURS_TARGET_PROCESSOR}${ENTOURS_CONFIG}")

if (NOT (ENTOURS_OPTION_PROCESSOR STREQUAL ""))
    set(OPTD "${CMAKE_BINARY_DIR}/bin.${ENTOURS_OPTION_PROCESSOR}${ENTOURS_CONFIG}")
endif()

set(INCDS "${CMAKE_BINARY_DIR}/include")

set(LIBDS "${CMAKE_BINARY_DIR}/lib.x86${ENTOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/lib.x64${ENTOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/lib.ia64${ENTOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/lib.arm${ENTOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/lib.arm64${ENTOURS_CONFIG}")

set(BINDS "${CMAKE_BINARY_DIR}/bin.x86${ENTOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/bin.x64${ENTOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/bin.ia64${ENTOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/bin.arm${ENTOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/bin.arm64${ENTOURS_CONFIG}")

if (NOT (EXISTS "${INCD}"))
    file(MAKE_DIRECTORY "${INCD}")
    message(STATUS "Created ${INCD}")
endif()
if (NOT (EXISTS "${LIBD}"))
    file(MAKE_DIRECTORY "${LIBD}")
    message(STATUS "Created ${LIBD}")
endif()
if (NOT (EXISTS "${BIND}"))
    file(MAKE_DIRECTORY "${BIND}")
    message(STATUS "Created ${BIND}")
endif()

# set output directory
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIBD})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIBD})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIND})

##############################################################################

include_directories(${INCDS} samples/syelog)

# subdirectories
subdirs(src)

if (ENTOURS_USE_SAMPLES)
    subdirs(samples)
endif()

##############################################################################
