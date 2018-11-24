// Entours Test Program (simple.cpp of simple.dll)
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Copyright (c) 2018 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>.
//
// This DLL will entour the Windows SleepEx API so that TimedSleep function
// gets called instead.  TimedSleepEx records the before and after times, and
// calls the real SleepEx API through the TrueSleepEx function pointer.

#include <stdio.h>
#include <windows.h>
#include "entours.h"

static LONG dwSlept = 0;
static DWORD (WINAPI * TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

extern "C"
DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    DWORD dwBeg = GetTickCount();
    DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
    DWORD dwEnd = GetTickCount();

    InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);

    return ret;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    if (EntourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        EntourRestoreAfterWith();

        printf("simple" ENTOURS_STRINGIFY(ENTOURS_BITS) ".dll:"
               " Starting.\n");
        fflush(stdout);

        EntourTransactionBegin();
        EntourUpdateThread(GetCurrentThread());
        EntourAttach(&(PVOID&)TrueSleepEx, (void *)TimedSleepEx);
        error = EntourTransactionCommit();

        if (error == NO_ERROR) {
            printf("simple" ENTOURS_STRINGIFY(ENTOURS_BITS) ".dll:"
                   " Entoured SleepEx().\n");
        }
        else {
            printf("simple" ENTOURS_STRINGIFY(ENTOURS_BITS) ".dll:"
                   " Error entouring SleepEx(): %d\n", (int)error);
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        EntourTransactionBegin();
        EntourUpdateThread(GetCurrentThread());
        EntourDetach(&(PVOID&)TrueSleepEx, (void *)TimedSleepEx);
        error = EntourTransactionCommit();

        printf("simple" ENTOURS_STRINGIFY(ENTOURS_BITS) ".dll:"
               " Removed SleepEx() (result=%d), slept %d ticks.\n", (int)error, (int)dwSlept);
        fflush(stdout);
    }
    return TRUE;
}
