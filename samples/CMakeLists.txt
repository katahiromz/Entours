##  Common CMakeLists.txt for Entours test programs.
##  Copyright (C) Katayama Hirofumi MZ.  All rights reserved.
##############################################################################

set(ENTOURS_SAMPLE_CFLAGS)

if (MSVC)
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} ${CLIB})
endif()

# /Zi: Generates complete debugging information.
if (MSVC)
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} /Zi)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -g3 -ggdb)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -g3 -ggdb)
endif()

# /Gm-: Disable minimal rebuild.
if (MSVC)
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} /Gm-)
endif()

# /W4: Sets which warning level to output.
if (MSVC)
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} /W4)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -pedantic -Wall)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -pedantic -Wall)
endif()

# /WX: Treats all warnings as errors.
if (MSVC)
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} /WX)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -Werror)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -Werror)
endif()

# /Od: Disables optimization.
if (MSVC)
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} /Od)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -O0)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -O0)
endif()

# /FR: Generates browser files.
if (MSVC)
    if (NOT (DEFINED ENTOURS_SOURCE_BROWSING) OR ENTOURS_SOURCE_BROWSING EQUAL 1)
        set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} /FR)
    else()
        set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} /I${INCD})
    endif()
endif()

if (DEFINED ENTOURS_WIN_7 AND DEFINED ENTOURS_CL_17_OR_NEWER)
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -D_USING_V110_SDK71_)
endif()

if (ENTOURS_TARGET_PROCESSOR STREQUAL "X86")
    set(ASM ml)
elseif (ENTOURS_TARGET_PROCESSOR STREQUAL "X64")
    set(ASM ml64)
elseif (ENTOURS_TARGET_PROCESSOR STREQUAL "IA64")
    set(ASM ias)
    set(ENTOURS_SAMPLE_AFLAGS -F COFF32_PLUS)
    if (MSVC)
        set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} /wd4163) # intrinsic rdtebex not available; using newer Windows headers with older compiler
        #set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} /wd4996 /wd4068)
    endif()
elseif (ENTOURS_TARGET_PROCESSOR STREQUAL "ARM")
    set(ASM armasm)
    set(ENTOURS_SAMPLE_AFLAGS -coff_thumb2_only)
    set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -D_ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE)

    # redundant with windows.h except for midl proxies
    if (ENTOURS_TARGET_PROCESSOR STREQUAL "X64")
        set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -D_AMD64_)
    else()
        set(ENTOURS_SAMPLE_CFLAGS ${ENTOURS_SAMPLE_CFLAGS} -D_${ENTOURS_TARGET_PROCESSOR}_)
    endif()
endif()

set(DEPS syelog entours)
set(LIBS ${DEPS})

##############################################################################

add_compile_options(${ENTOURS_SAMPLE_CFLAGS})

subdirs(
    syelog
    setdll
    withdll
    simple
)

##############################################################################
# tests

add_test(
    NAME setdll-sleep5
    COMMAND $<TARGET_FILE:setdll> -r $<TARGET_FILE:sleep5>)

add_test(
    NAME sleep5
    COMMAND $<TARGET_FILE:sleep5>)

if (ENTOURS_BITS EQUAL 32)
    add_test(
        NAME setdll-simple32
        COMMAND $<TARGET_FILE:setdll> -d:$<TARGET_FILE:simple32> $<TARGET_FILE:sleep5>)
else()
    add_test(
        NAME setdll-simple64
        COMMAND $<TARGET_FILE:setdll> -d:$<TARGET_FILE:simple64> $<TARGET_FILE:sleep5>)
endif()

add_test(
    NAME sleep5-2
    COMMAND $<TARGET_FILE:sleep5>)

add_test(
    NAME remove-simple
    COMMAND $<TARGET_FILE:setdll> -r $<TARGET_FILE:sleep5>)

add_test(
    NAME sleep5-3
    COMMAND $<TARGET_FILE:sleep5>)

if (ENTOURS_BITS EQUAL 32)
    add_test(
        NAME withdll-simple32
        COMMAND $<TARGET_FILE:withdll> -d:$<TARGET_FILE:simple32> $<TARGET_FILE:sleep5>)
else()
    add_test(
        NAME withdll-simple64
        COMMAND $<TARGET_FILE:withdll> -d:$<TARGET_FILE:simple64> $<TARGET_FILE:sleep5>)
endif()

##############################################################################
