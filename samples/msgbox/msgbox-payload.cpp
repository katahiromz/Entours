// Entours Test Program (msgbox.cpp of msgbox.exe)
// Copyright (c) 2018 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "entours.h"

static auto TrueMessageBoxA = &MessageBoxA;
static auto TrueMessageBoxW = &MessageBoxW;

extern "C"
int WINAPI NewMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    return TrueMessageBoxA(hWnd, "Hooked", "Hooked", uType);
}

extern "C"
int WINAPI NewMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    return TrueMessageBoxW(hWnd, L"Hooked", L"Hooked", uType);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    if (EntourIsHelperProcess())
    {
        return TRUE;
    }

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        EntourRestoreAfterWith();
        EntourTransactionBegin();
        EntourUpdateThread(GetCurrentThread());
        EntourAttach(&TrueMessageBoxA, NewMessageBoxA);
        EntourAttach(&TrueMessageBoxW, NewMessageBoxW);
        error = EntourTransactionCommit();
        break;

    case DLL_PROCESS_DETACH:
        EntourTransactionBegin();
        EntourUpdateThread(GetCurrentThread());
        EntourDetach(&TrueMessageBoxA, NewMessageBoxA);
        EntourDetach(&TrueMessageBoxW, NewMessageBoxW);
        error = EntourTransactionCommit();
        break;
    }

    error = error;
    return TRUE;
}
