// Entours Test Program (setdll.cpp of setdll.exe)
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Copyright (c) 2018 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>.
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <shellapi.h>
#include "entours.h"
#include <strsafe.h>

////////////////////////////////////////////////////////////// Error Messages.

VOID AssertMessage(PCSTR szMsg, PCSTR szFile, INT nLine)
{
    printf("ASSERT(%s) failed in %s, line %d.", szMsg, szFile, (int)nLine);
}

#define ASSERT(x)   \
do { if (!(x)) { AssertMessage(#x, __FILE__, __LINE__); DebugBreak(); }} while (0)

//////////////////////////////////////////////////////////////////////////////

static BOOLEAN  s_fRemove = FALSE;
static CHAR     s_szDllPath[MAX_PATH] = "";

//////////////////////////////////////////////////////////////////////////////
//  This code verifies that the named DLL has been configured correctly
//  to be imported into the target process.  DLLs must export a function with
//  ordinal #1 so that the import table touch-up magic works.

static BOOL CALLBACK ExportCallback(_In_opt_ PVOID pContext,
                                    _In_ ULONG nOrdinal,
                                    _In_opt_ LPCSTR pszName,
                                    _In_opt_ PVOID pCode)
{
    (void)pContext;
    (void)pCode;
    (void)pszName;

    if (nOrdinal == 1) {
        *((BOOL *)pContext) = TRUE;
    }
    return TRUE;
}

BOOL DoesDllExportOrdinal1(PCHAR pszDllPath)
{
    HMODULE hDll = LoadLibraryExA(pszDllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hDll == NULL) {
        printf("setdll.exe: LoadLibraryEx(%s) failed with error %d.\n",
               pszDllPath,
               (int)GetLastError());
        return FALSE;
    }

    BOOL validFlag = FALSE;
    EntourEnumerateExports(hDll, &validFlag, ExportCallback);
    FreeLibrary(hDll);
    return validFlag;
}

//////////////////////////////////////////////////////////////////////////////

static BOOL CALLBACK ListBywayCallback(_In_opt_ PVOID pContext,
                                       _In_opt_ LPCSTR pszFile,
                                       _Outptr_result_maybenull_ LPCSTR *ppszOutFile)
{
    (void)pContext;

    *ppszOutFile = pszFile;
    if (pszFile) {
        printf("    %s\n", pszFile);
    }
    return TRUE;
}

static BOOL CALLBACK ListFileCallback(_In_opt_ PVOID pContext,
                                      _In_ LPCSTR pszOrigFile,
                                      _In_ LPCSTR pszFile,
                                      _Outptr_result_maybenull_ LPCSTR *ppszOutFile)
{
    (void)pContext;

    *ppszOutFile = pszFile;
    printf("    %s -> %s\n", pszOrigFile, pszFile);
    return TRUE;
}

static BOOL CALLBACK AddBywayCallback(_In_opt_ PVOID pContext,
                                      _In_opt_ LPCSTR pszFile,
                                      _Outptr_result_maybenull_ LPCSTR *ppszOutFile)
{
    PBOOL pbAddedDll = (PBOOL)pContext;
    if (!pszFile && !*pbAddedDll) {                     // Add new byway.
        *pbAddedDll = TRUE;
        *ppszOutFile = s_szDllPath;
    }
    return TRUE;
}

BOOL SetFile(PCHAR pszPath)
{
    BOOL bGood = TRUE;
    HANDLE hOld = INVALID_HANDLE_VALUE;
    HANDLE hNew = INVALID_HANDLE_VALUE;
    PENTOUR_BINARY pBinary = NULL;

    CHAR szOrg[MAX_PATH];
    CHAR szNew[MAX_PATH];
    CHAR szOld[MAX_PATH];

    szOld[0] = '\0';
    szNew[0] = '\0';

    StringCchCopyA(szOrg, sizeof(szOrg), pszPath);
    StringCchCopyA(szNew, sizeof(szNew), szOrg);
    StringCchCatA(szNew, sizeof(szNew), "#");
    StringCchCopyA(szOld, sizeof(szOld), szOrg);
    StringCchCatA(szOld, sizeof(szOld), "~");
    printf("  %s:\n", pszPath);

    hOld = CreateFileA(szOrg,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

    if (hOld == INVALID_HANDLE_VALUE) {
        printf("Couldn't open input file: %s, error: %d\n",
               szOrg, (int)GetLastError());
        bGood = FALSE;
        goto end;
    }

    hNew = CreateFileA(szNew,
                       GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hNew == INVALID_HANDLE_VALUE) {
        printf("Couldn't open output file: %s, error: %d\n",
               szNew, (int)GetLastError());
        bGood = FALSE;
        goto end;
    }

    if ((pBinary = EntourBinaryOpen(hOld)) == NULL) {
        printf("EntourBinaryOpen failed: %d\n", (int)GetLastError());
        goto end;
    }

    if (hOld != INVALID_HANDLE_VALUE) {
        CloseHandle(hOld);
        hOld = INVALID_HANDLE_VALUE;
    }

    {
        BOOL bAddedDll = FALSE;

        EntourBinaryResetImports(pBinary);

        if (!s_fRemove) {
            if (!EntourBinaryEditImports(pBinary,
                                         &bAddedDll,
                                         AddBywayCallback, NULL, NULL, NULL)) {
                printf("EntourBinaryEditImports failed: %d\n", (int)GetLastError());
            }
        }

        if (!EntourBinaryEditImports(pBinary, NULL,
                                     ListBywayCallback, ListFileCallback,
                                     NULL, NULL)) {

            printf("EntourBinaryEditImports failed: %d\n", (int)GetLastError());
        }

        if (!EntourBinaryWrite(pBinary, hNew)) {
            printf("EntourBinaryWrite failed: %d\n", (int)GetLastError());
            bGood = FALSE;
        }

        EntourBinaryClose(pBinary);
        pBinary = NULL;

        if (hNew != INVALID_HANDLE_VALUE) {
            CloseHandle(hNew);
            hNew = INVALID_HANDLE_VALUE;
        }

        if (bGood) {
            if (!DeleteFileA(szOld)) {
                DWORD dwError = GetLastError();
                if (dwError != ERROR_FILE_NOT_FOUND) {
                    printf("Warning: Couldn't delete %s: %d\n", szOld, (int)dwError);
                    bGood = FALSE;
                }
            }
            if (!MoveFileA(szOrg, szOld)) {
                printf("Error: Couldn't back up %s to %s: %d\n",
                       szOrg, szOld, (int)GetLastError());
                bGood = FALSE;
            }
            if (!MoveFileA(szNew, szOrg)) {
                printf("Error: Couldn't install %s as %s: %d\n",
                       szNew, szOrg, (int)GetLastError());
                bGood = FALSE;
            }
        }

        DeleteFileA(szNew);
    }


  end:
    if (pBinary) {
        EntourBinaryClose(pBinary);
        pBinary = NULL;
    }
    if (hNew != INVALID_HANDLE_VALUE) {
        CloseHandle(hNew);
        hNew = INVALID_HANDLE_VALUE;
    }
    if (hOld != INVALID_HANDLE_VALUE) {
        CloseHandle(hOld);
        hOld = INVALID_HANDLE_VALUE;
    }
    return bGood;
}

//////////////////////////////////////////////////////////////////////////////

void PrintUsage(void)
{
    printf("Usage:\n"
           "    setdll [options] binary_files\n"
           "Options:\n"
           "    /d:file.dll  : Add file.dll binary files\n"
           "    /r           : Remove extra DLLs from binary files\n"
           "    /?           : This help screen.\n");
}

//////////////////////////////////////////////////////////////////////// main.

int main(int argc, char **argv)
{
    BOOL fNeedHelp = FALSE;
    PCHAR pszFilePart = NULL;

    int arg = 1;
    for (; arg < argc; arg++) {
        if (argv[arg][0] == '-' || argv[arg][0] == '/') {
            CHAR *argn = argv[arg] + 1;
            CHAR *argp = argn;
            while (*argp && *argp != ':' && *argp != '=')
                argp++;
            if (*argp == ':' || *argp == '=')
                *argp++ = '\0';

            switch (argn[0]) {

              case 'd':                                 // Set DLL
              case 'D':
                if ((strchr(argp, ':') != NULL || strchr(argp, '\\') != NULL) &&
                    GetFullPathNameA(argp, sizeof(s_szDllPath), s_szDllPath, &pszFilePart)) {
                }
                else {
                    StringCchPrintfA(s_szDllPath, sizeof(s_szDllPath), "%s", argp);
                }
                break;

              case 'r':                                 // Remove extra set DLLs.
              case 'R':
                s_fRemove = TRUE;
                break;

              case '?':                                 // Help
                fNeedHelp = TRUE;
                break;

              default:
                fNeedHelp = TRUE;
                printf("Bad argument: %s:%s\n", argn, argp);
                break;
            }
        }
    }
    if (argc == 1) {
        fNeedHelp = TRUE;
    }
    if (!s_fRemove && s_szDllPath[0] == 0) {
        fNeedHelp = TRUE;
    }
    if (fNeedHelp) {
        PrintUsage();
        return 1;
    }


    if (s_fRemove) {
        printf("Removing extra DLLs from binary files.\n");
    }
    else {
        if (!DoesDllExportOrdinal1(s_szDllPath)) {
            printf("Error: %s does not export function with ordinal #1.\n",
                   s_szDllPath);
            return 2;
        }
        printf("Adding %s to binary files.\n", s_szDllPath);
    }

    for (arg = 1; arg < argc; arg++) {
        if (argv[arg][0] != '-' && argv[arg][0] != '/') {
            SetFile(argv[arg]);
        }
    }
    return 0;
}
