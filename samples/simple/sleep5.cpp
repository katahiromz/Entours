// Entours Test Program (sleep5.cpp of sleep5.exe)
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Copyright (c) 2018 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char ** argv)
{
    if (argc == 2) {
        Sleep(atoi(argv[1]) * 1000);
    }
    else {
        printf("sleep5.exe: Starting.\n");

        Sleep(5000);

        printf("sleep5.exe: Done sleeping.\n");
    }
    return 0;
}
