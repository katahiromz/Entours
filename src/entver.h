// Common version parameters.
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Copyright (c) 2018 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>.

#define _USING_V110_SDK71_ 1
#include <winver.h>
#if 0
    #include <windows.h>
    #include <entours.h>
#else
    #ifndef ENTOURS_STRINGIFY
        #define ENTOURS_STRINGIFY(x)    ENTOURS_STRINGIFY_(x)
        #define ENTOURS_STRINGIFY_(x)    #x
    #endif

    #define VER_FILEFLAGSMASK   0x3fL
    #define VER_FILEFLAGS       0x0L
    #define VER_FILEOS          0x00040004L
    #define VER_FILETYPE        0x00000002L
    #define VER_FILESUBTYPE     0x00000000L
#endif
#define VER_ENTOURS_BITS    ENTOUR_STRINGIFY(ENTOURS_BITS)
