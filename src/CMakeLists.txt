## CMakeLists.txt for Entours.
## Copyright (C) 2018 Katayama Hirofumi MZ. All Rights Reserved.
##############################################################################

##############################################################################
# ENTOURS_CFLAGS

set(ENTOURS_CFLAGS)

# /W4: Sets which warning level to output.
if (MSVC)
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} /W4)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} -pedantic -Wall -Wno-tautological-compare)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} -pedantic -Wall -Wno-tautological-compare)
endif()

# /WX: Treats all warnings as errors.
if (MSVC)
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} /WX)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} -Werror)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} -Werror)
endif()

# /Zi: Generates complete debugging information.
if (MSVC)
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} /Zi)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} -g3 -ggdb)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} -g3 -ggdb)
endif()

# /MT: Creates a multithreaded executable file using LIBCMT.lib.
if (MSVC)
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} /MT)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} -pthread)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} -pthread)
endif()

# /Gy: Enables function-level linking.
if (MSVC)
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} /Gy)
endif()

# /Zl: Removes default library name from .obj file (x86 only).
if (MSVC)
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} /Zl)
endif()

# /Gm-: Disable minimal rebuild.
if (MSVC)
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} /Gm-)
endif()

# /Od: Disables optimization.
if (MSVC)
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} /Od)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} -O0)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} -O0)
endif()

if (ENTOURS_TARGET_PROCESSOR STREQUAL "IA64")
    if (MSVC)
        # intrinsic rdtebex not available; using newer Windows headers with older compiler
        set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} /wd4163) 
    endif()
endif()

if (ENTOURS_WIN_7 AND ENTOURS_CL_17_OR_NEWER)
    set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} -D_USING_V110_SDK71_)
elseif (ENTOURS_ANALYZE)
    if (MSVC)
        set(ENTOURS_CFLAGS ${ENTOURS_CFLAGS} /analyze)
    endif()
endif()

##############################################################################

add_library(entours
    entours.cpp
    modules.cpp
    disasm.cpp
    image.cpp
    creatwth.cpp
    disolx86.cpp
    disolx64.cpp
    disolia64.cpp
    disolarm.cpp
    disolarm64.cpp)
target_compile_options(entours PRIVATE ${ENTOURS_CFLAGS})

configure_file(entours.h ${INCD}/entours.h COPYONLY)
configure_file(entver.h ${INCD}/entver.h COPYONLY)
configure_file(unsal2.h ${INCD}/unsal2.h COPYONLY)

##############################################################################
