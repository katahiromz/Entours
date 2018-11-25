// Entours Test Program (msgbox.cpp of msgbox.exe)
// Copyright (c) 2018 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "entours.h"

int main(void)
{
    MessageBox(NULL, TEXT("Unhooked"), TEXT("Unhooked"), MB_ICONINFORMATION);

#ifdef _WIN64
    HMODULE hDLL = LoadLibraryA("msgbox-payload64.dll");
#else
    HMODULE hDLL = LoadLibraryA("msgbox-payload32.dll");
#endif

    MessageBox(NULL, TEXT("Unhooked"), TEXT("Unhooked"), MB_ICONINFORMATION);

    FreeLibrary(hDLL);

    MessageBox(NULL, TEXT("Unhooked"), TEXT("Unhooked"), MB_ICONINFORMATION);

    return 0;
}
