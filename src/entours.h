// Core Entours Functionality (entours.h of entours.lib)
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Copyright (c) 2018 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>.

#pragma once
#ifndef _ENTOURS_H_
#define _ENTOURS_H_

#define ENTOURS_VERSION     0x4c0c1   // 0xMAJORcMINORcPATCH

//////////////////////////////////////////////////////////////////////////////

#undef ENTOURS_X64
#undef ENTOURS_X86
#undef ENTOURS_IA64
#undef ENTOURS_ARM
#undef ENTOURS_ARM64
#undef ENTOURS_BITS
#undef ENTOURS_32BIT
#undef ENTOURS_64BIT

#if defined(_X86_)
    #define ENTOURS_X86
    #define ENTOURS_OPTION_BITS 64
#elif defined(_AMD64_)
    #define ENTOURS_X64
    #define ENTOURS_OPTION_BITS 32
#elif defined(_IA64_)
    #define ENTOURS_IA64
    #define ENTOURS_OPTION_BITS 32
#elif defined(_ARM_)
    #define ENTOURS_ARM
#elif defined(_ARM64_)
    #define ENTOURS_ARM64
#else
    #error Unknown architecture (x86, amd64, ia64, arm, arm64)
#endif

#ifdef _WIN64
    #undef ENTOURS_32BIT
    #define ENTOURS_64BIT 1
    #define ENTOURS_BITS 64
    //#define ENTOURS_OPTION_BITS 32
#else
    #define ENTOURS_32BIT 1
    #undef ENTOURS_64BIT
    #define ENTOURS_BITS 32
    //#define ENTOURS_OPTION_BITS 32
#endif

#define VER_ENTOURS_BITS    ENTOUR_STRINGIFY(ENTOURS_BITS)

//////////////////////////////////////////////////////////////////////////////

#include <guiddef.h>

#include "unsal2.h"

#if __cplusplus >= 201103L
    #define ENTOURS_ALIGNAS(x) alignas(x)
#else
    #define ENTOURS_ALIGNAS(x) __declspec(align(x))
#endif

#if defined(__GNUC__) || defined(__clang__) || defined(ENTOURS_NO_SEH)
    #define __try if (1)
    #define __except else if
    #define __finally
#endif

#if defined(__GNUC__) || defined(__clang__)
    #ifndef ENTOURS_NO_SEG
        #define ENTOURS_NO_SEG
    #endif
#endif

#ifdef ENTOURS_NO_SEG
    #define ENTOURS_SHARED(name) __attribute__((section(name), shared))
#else
    #define ENTOURS_SHARED(name)
#endif

#ifndef _MSC_VER
    #undef C_ASSERT
    #if __cplusplus >= 201103L
        #define C_ASSERT(expr) static_assert((expr), #expr)
    #else
        #define C_ASSERT(expr) typedef char __C_ASSERT__[(expr) ? 1 : -1]
    #endif
#endif

//////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/////////////////////////////////////////////////// Instruction Target Macros.
//
#define ENTOUR_INSTRUCTION_TARGET_NONE          NULL
#define ENTOUR_INSTRUCTION_TARGET_DYNAMIC       ((PVOID)(LONG_PTR)-1)
#define ENTOUR_SECTION_HEADER_SIGNATURE         0x00727444   // "Dtr\0"

extern const GUID ENTOUR_EXE_RESTORE_GUID;
extern const GUID ENTOUR_EXE_HELPER_GUID;

#define ENTOUR_TRAMPOLINE_SIGNATURE             0x21727444  // Dtr!
typedef struct _ENTOUR_TRAMPOLINE ENTOUR_TRAMPOLINE, *PENTOUR_TRAMPOLINE;

/////////////////////////////////////////////////////////// Binary Structures.
//
#include <pshpack8.h>
typedef struct _ENTOUR_SECTION_HEADER
{
    DWORD       cbHeaderSize;
    DWORD       nSignature;
    DWORD       nDataOffset;
    DWORD       cbDataSize;

    DWORD       nOriginalImportVirtualAddress;
    DWORD       nOriginalImportSize;
    DWORD       nOriginalBoundImportVirtualAddress;
    DWORD       nOriginalBoundImportSize;

    DWORD       nOriginalIatVirtualAddress;
    DWORD       nOriginalIatSize;
    DWORD       nOriginalSizeOfImage;
    DWORD       cbPrePE;

    DWORD       nOriginalClrFlags;
    DWORD       reserved1;
    DWORD       reserved2;
    DWORD       reserved3;

    // Followed by cbPrePE bytes of data.
} ENTOUR_SECTION_HEADER, *PENTOUR_SECTION_HEADER;

typedef struct _ENTOUR_SECTION_RECORD
{
    DWORD       cbBytes;
    DWORD       nReserved;
    GUID        guid;
} ENTOUR_SECTION_RECORD, *PENTOUR_SECTION_RECORD;

typedef struct _ENTOUR_CLR_HEADER
{
    // Header versioning
    ULONG                   cb;
    USHORT                  MajorRuntimeVersion;
    USHORT                  MinorRuntimeVersion;

    // Symbol table and startup information
    IMAGE_DATA_DIRECTORY    MetaData;
    ULONG                   Flags;

    // Followed by the rest of the IMAGE_COR20_HEADER
} ENTOUR_CLR_HEADER, *PENTOUR_CLR_HEADER;

typedef struct _ENTOUR_EXE_RESTORE
{
    DWORD               cb;
    DWORD               cbidh;
    DWORD               cbinh;
    DWORD               cbclr;

    PBYTE               pidh;
    PBYTE               pinh;
    PBYTE               pclr;

    IMAGE_DOS_HEADER    idh;
    union {
        IMAGE_NT_HEADERS    inh;        // all environments have this
#ifdef IMAGE_NT_OPTIONAL_HDR32_MAGIC    // some environments do not have this
        IMAGE_NT_HEADERS32  inh32;
#endif
#ifdef IMAGE_NT_OPTIONAL_HDR64_MAGIC    // some environments do not have this
        IMAGE_NT_HEADERS64  inh64;
#endif
#ifdef IMAGE_NT_OPTIONAL_HDR64_MAGIC    // some environments do not have this
        BYTE                raw[sizeof(IMAGE_NT_HEADERS64) +
                                sizeof(IMAGE_SECTION_HEADER) * 32];
        C_ASSERT(sizeof(IMAGE_NT_HEADERS64) == 0x108);
#else
        BYTE                raw[0x108 + sizeof(IMAGE_SECTION_HEADER) * 32];
#endif
    };
    ENTOUR_CLR_HEADER   clr;
} ENTOUR_EXE_RESTORE, *PENTOUR_EXE_RESTORE;

// The size can change, but assert for clarity due to the muddying #ifdefs.
#ifdef _WIN64
    C_ASSERT(sizeof(ENTOUR_EXE_RESTORE) == 0x688);
#else
    C_ASSERT(sizeof(ENTOUR_EXE_RESTORE) == 0x678);
#endif

typedef struct _ENTOUR_EXE_HELPER
{
    DWORD               cb;
    DWORD               pid;
    DWORD               nDlls;
    CHAR                rDlls[4];
} ENTOUR_EXE_HELPER, *PENTOUR_EXE_HELPER;

#include <poppack.h>

#define ENTOUR_SECTION_HEADER_DECLARE(cbSectionSize) \
{ \
    sizeof(ENTOUR_SECTION_HEADER), \
    ENTOUR_SECTION_HEADER_SIGNATURE, \
    sizeof(ENTOUR_SECTION_HEADER), \
    (cbSectionSize), \
    0, 0, 0, 0,\ 0, 0, 0, 0, \
}

/////////////////////////////////////////////////////////////// Helper Macros.

#define ENTOURS_STRINGIFY(x)    ENTOURS_STRINGIFY_(x)
#define ENTOURS_STRINGIFY_(x)   #x

///////////////////////////////////////////////////////////// Binary Typedefs.

typedef BOOL (CALLBACK *PF_ENTOUR_BINARY_BYWAY_CALLBACK)(
    _In_opt_ LPCVOID pContext,
    _In_opt_ LPCSTR pszFile,
    _Outptr_result_maybenull_ LPCSTR *ppszOutFile);

typedef BOOL (CALLBACK *PF_ENTOUR_BINARY_FILE_CALLBACK)(
    _In_opt_ LPCVOID pContext,
    _In_ LPCSTR pszOrigFile,
    _In_ LPCSTR pszFile,
    _Outptr_result_maybenull_ LPCSTR *ppszOutFile);

typedef BOOL (CALLBACK *PF_ENTOUR_BINARY_SYMBOL_CALLBACK)(
    _In_opt_ LPCVOID pContext,
    _In_ ULONG nOrigOrdinal,
    _In_ ULONG nOrdinal,
    _Out_ ULONG *pnOutOrdinal,
    _In_opt_ LPCSTR pszOrigSymbol,
    _In_opt_ LPCSTR pszSymbol,
    _Outptr_result_maybenull_ LPCSTR *ppszOutSymbol);

typedef BOOL (CALLBACK *PF_ENTOUR_BINARY_COMMIT_CALLBACK)(
    _In_opt_ LPCVOID pContext);

typedef BOOL (CALLBACK *PF_ENTOUR_ENUMERATE_EXPORT_CALLBACK)(_In_opt_ LPCVOID pContext,
                                                             _In_ ULONG nOrdinal,
                                                             _In_opt_ LPCSTR pszName,
                                                             _In_opt_ LPCVOID pCode);

typedef BOOL (CALLBACK *PF_ENTOUR_IMPORT_FILE_CALLBACK)(_In_opt_ LPCVOID pContext,
                                                        _In_opt_ HMODULE hModule,
                                                        _In_opt_ LPCSTR pszFile);

typedef BOOL (CALLBACK *PF_ENTOUR_IMPORT_FUNC_CALLBACK)(_In_opt_ LPCVOID pContext,
                                                        _In_ DWORD nOrdinal,
                                                        _In_opt_ LPCSTR pszFunc,
                                                        _In_opt_ LPCVOID pvFunc);

// Same as PF_ENTOUR_IMPORT_FUNC_CALLBACK but extra indirection on last parameter.
typedef BOOL (CALLBACK *PF_ENTOUR_IMPORT_FUNC_CALLBACK_EX)(_In_opt_ LPCVOID pContext,
                                                           _In_ DWORD nOrdinal,
                                                           _In_opt_ LPCSTR pszFunc,
                                                           _In_opt_ PVOID* ppvFunc);

typedef VOID * PENTOUR_BINARY;
typedef VOID * PENTOUR_LOADED_BINARY;

//////////////////////////////////////////////////////////// Transaction APIs.

LONG WINAPI EntourTransactionBegin(VOID);
LONG WINAPI EntourTransactionAbort(VOID);
LONG WINAPI EntourTransactionCommit(VOID);
LONG WINAPI EntourTransactionCommitEx(_Out_opt_ PVOID **pppFailedPointer);

LONG WINAPI EntourUpdateThread(_In_ HANDLE hThread);

LONG WINAPI EntourAttach_(_Inout_ PVOID *ppPointer,
                          _In_ LPCVOID pEntour);

LONG WINAPI EntourAttachEx_(_Inout_ PVOID *ppPointer,
                            _In_ LPCVOID pEntour,
                            _Out_opt_ PENTOUR_TRAMPOLINE *ppRealTrampoline,
                            _Out_opt_ PVOID *ppRealTarget,
                            _Out_opt_ PVOID *ppRealEntour);

LONG WINAPI EntourDetach_(_Inout_ PVOID *ppPointer,
                          _In_ LPCVOID pEntour);

#define EntourAttach(ppPointer, pEntour) \
    EntourAttach_((PVOID *)(ppPointer), (PVOID)(pEntour))
#define EntourAttachEx(ppPointer, pEntour, ppRealTrampoline, ppRealTarget, ppRealEntour) \
    EntourAttachEx_((PVOID *)(ppPointer), (PVOID)(pEntour), (ppRealTrampoline), (ppRealTarget), (ppRealEntour))
#define EntourDetach(ppPointer, pEntour) \
    EntourDetach_((PVOID *)(ppPointer), (PVOID)(pEntour))

BOOL WINAPI EntourSetIgnoreTooSmall(_In_ BOOL fIgnore);
BOOL WINAPI EntourSetRetainRegions(_In_ BOOL fRetain);
PVOID WINAPI EntourSetSystemRegionLowerBound(_In_ LPCVOID pSystemRegionLowerBound);
PVOID WINAPI EntourSetSystemRegionUpperBound(_In_ LPCVOID pSystemRegionUpperBound);

////////////////////////////////////////////////////////////// Code Functions.

PVOID WINAPI EntourFindFunction(_In_ LPCSTR pszModule,
                                _In_ LPCSTR pszFunction);
PVOID WINAPI EntourCodeFromPointer(_In_ LPCVOID pPointer,
                                   _Out_opt_ PVOID *ppGlobals);
PVOID WINAPI EntourCopyInstruction(_In_opt_ LPCVOID pDst,
                                   _Inout_opt_ PVOID *ppDstPool,
                                   _In_ LPCVOID pSrc,
                                   _Out_opt_ PVOID *ppTarget,
                                   _Out_opt_ LONG *plExtra);
BOOL WINAPI EntourSetCodeModule(_In_ HMODULE hModule,
                                _In_ BOOL fLimitReferencesToModule);

///////////////////////////////////////////////////// Loaded Binary Functions.

HMODULE WINAPI EntourGetContainingModule(_In_ LPCVOID pvAddr);
HMODULE WINAPI EntourEnumerateModules(_In_opt_ HMODULE hModuleLast);
PVOID WINAPI EntourGetEntryPoint(_In_opt_ HMODULE hModule);
ULONG WINAPI EntourGetModuleSize(_In_opt_ HMODULE hModule);
BOOL WINAPI EntourEnumerateExports(_In_ HMODULE hModule,
                                   _In_opt_ LPCVOID pContext,
                                   _In_ PF_ENTOUR_ENUMERATE_EXPORT_CALLBACK pfExport);
BOOL WINAPI EntourEnumerateImports(_In_opt_ HMODULE hModule,
                                   _In_opt_ LPCVOID pContext,
                                   _In_opt_ PF_ENTOUR_IMPORT_FILE_CALLBACK pfImportFile,
                                   _In_opt_ PF_ENTOUR_IMPORT_FUNC_CALLBACK pfImportFunc);

BOOL WINAPI EntourEnumerateImportsEx(_In_opt_ HMODULE hModule,
                                     _In_opt_ LPCVOID pContext,
                                     _In_opt_ PF_ENTOUR_IMPORT_FILE_CALLBACK pfImportFile,
                                     _In_opt_ PF_ENTOUR_IMPORT_FUNC_CALLBACK_EX pfImportFuncEx);

_Writable_bytes_(*pcbData)
_Readable_bytes_(*pcbData)
_Success_(return != NULL)
PVOID WINAPI EntourFindPayload(_In_opt_ HMODULE hModule,
                               _In_ REFGUID rguid,
                               _Out_ DWORD *pcbData);

_Writable_bytes_(*pcbData)
_Readable_bytes_(*pcbData)
_Success_(return != NULL)
PVOID WINAPI EntourFindPayloadEx(_In_ REFGUID rguid,
                                 _Out_ DWORD * pcbData);

DWORD WINAPI EntourGetSizeOfPayloads(_In_opt_ HMODULE hModule);

///////////////////////////////////////////////// Persistent Binary Functions.

PENTOUR_BINARY WINAPI EntourBinaryOpen(_In_ HANDLE hFile);

_Writable_bytes_(*pcbData)
_Readable_bytes_(*pcbData)
_Success_(return != NULL)
PVOID WINAPI EntourBinaryEnumeratePayloads(_In_ PENTOUR_BINARY pBinary,
                                           _Out_opt_ GUID *pGuid,
                                           _Out_ DWORD *pcbData,
                                           _Inout_ DWORD *pnIterator);

_Writable_bytes_(*pcbData)
_Readable_bytes_(*pcbData)
_Success_(return != NULL)
PVOID WINAPI EntourBinaryFindPayload(_In_ PENTOUR_BINARY pBinary,
                                     _In_ REFGUID rguid,
                                     _Out_ DWORD *pcbData);

PVOID WINAPI EntourBinarySetPayload(_In_ PENTOUR_BINARY pBinary,
                                    _In_ REFGUID rguid,
                                    _In_reads_opt_(cbData) PVOID pData,
                                    _In_ DWORD cbData);
BOOL WINAPI EntourBinaryDeletePayload(_In_ PENTOUR_BINARY pBinary, _In_ REFGUID rguid);
BOOL WINAPI EntourBinaryPurgePayloads(_In_ PENTOUR_BINARY pBinary);
BOOL WINAPI EntourBinaryResetImports(_In_ PENTOUR_BINARY pBinary);
BOOL WINAPI EntourBinaryEditImports(_In_ PENTOUR_BINARY pBinary,
                                    _In_opt_ LPCVOID pContext,
                                    _In_opt_ PF_ENTOUR_BINARY_BYWAY_CALLBACK pfByway,
                                    _In_opt_ PF_ENTOUR_BINARY_FILE_CALLBACK pfFile,
                                    _In_opt_ PF_ENTOUR_BINARY_SYMBOL_CALLBACK pfSymbol,
                                    _In_opt_ PF_ENTOUR_BINARY_COMMIT_CALLBACK pfCommit);
BOOL WINAPI EntourBinaryWrite(_In_ PENTOUR_BINARY pBinary, _In_ HANDLE hFile);
BOOL WINAPI EntourBinaryClose(_In_ PENTOUR_BINARY pBinary);

/////////////////////////////////////////////////// Create Process & Load Dll.

typedef BOOL (WINAPI *PENTOUR_CREATE_PROCESS_ROUTINEA)(
    _In_opt_ LPCSTR lpApplicationName,
    _Inout_opt_ LPSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOA lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (WINAPI *PENTOUR_CREATE_PROCESS_ROUTINEW)(
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation);

BOOL WINAPI EntourCreateProcessWithDllA(_In_opt_ LPCSTR lpApplicationName,
                                        _Inout_opt_ LPSTR lpCommandLine,
                                        _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                        _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                        _In_ BOOL bInheritHandles,
                                        _In_ DWORD dwCreationFlags,
                                        _In_opt_ LPVOID lpEnvironment,
                                        _In_opt_ LPCSTR lpCurrentDirectory,
                                        _In_ LPSTARTUPINFOA lpStartupInfo,
                                        _Out_ LPPROCESS_INFORMATION lpProcessInformation,
                                        _In_ LPCSTR lpDllName,
                                        _In_opt_ PENTOUR_CREATE_PROCESS_ROUTINEA pfCreateProcessA);

BOOL WINAPI EntourCreateProcessWithDllW(_In_opt_ LPCWSTR lpApplicationName,
                                        _Inout_opt_ LPWSTR lpCommandLine,
                                        _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                        _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                        _In_ BOOL bInheritHandles,
                                        _In_ DWORD dwCreationFlags,
                                        _In_opt_ LPVOID lpEnvironment,
                                        _In_opt_ LPCWSTR lpCurrentDirectory,
                                        _In_ LPSTARTUPINFOW lpStartupInfo,
                                        _Out_ LPPROCESS_INFORMATION lpProcessInformation,
                                        _In_ LPCSTR lpDllName,
                                        _In_opt_ PENTOUR_CREATE_PROCESS_ROUTINEW pfCreateProcessW);

BOOL WINAPI EntourCreateProcessWithDllExA(_In_opt_ LPCSTR lpApplicationName,
                                          _Inout_opt_ LPSTR lpCommandLine,
                                          _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                          _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                          _In_ BOOL bInheritHandles,
                                          _In_ DWORD dwCreationFlags,
                                          _In_opt_ LPVOID lpEnvironment,
                                          _In_opt_ LPCSTR lpCurrentDirectory,
                                          _In_ LPSTARTUPINFOA lpStartupInfo,
                                          _Out_ LPPROCESS_INFORMATION lpProcessInformation,
                                          _In_ LPCSTR lpDllName,
                                          _In_opt_ PENTOUR_CREATE_PROCESS_ROUTINEA pfCreateProcessA);

BOOL WINAPI EntourCreateProcessWithDllExW(_In_opt_ LPCWSTR lpApplicationName,
                                          _Inout_opt_  LPWSTR lpCommandLine,
                                          _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                          _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                          _In_ BOOL bInheritHandles,
                                          _In_ DWORD dwCreationFlags,
                                          _In_opt_ LPVOID lpEnvironment,
                                          _In_opt_ LPCWSTR lpCurrentDirectory,
                                          _In_ LPSTARTUPINFOW lpStartupInfo,
                                          _Out_ LPPROCESS_INFORMATION lpProcessInformation,
                                          _In_ LPCSTR lpDllName,
                                          _In_opt_ PENTOUR_CREATE_PROCESS_ROUTINEW pfCreateProcessW);

BOOL WINAPI EntourCreateProcessWithDllsA(_In_opt_ LPCSTR lpApplicationName,
                                         _Inout_opt_ LPSTR lpCommandLine,
                                         _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                         _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                         _In_ BOOL bInheritHandles,
                                         _In_ DWORD dwCreationFlags,
                                         _In_opt_ LPVOID lpEnvironment,
                                         _In_opt_ LPCSTR lpCurrentDirectory,
                                         _In_ LPSTARTUPINFOA lpStartupInfo,
                                         _Out_ LPPROCESS_INFORMATION lpProcessInformation,
                                         _In_ DWORD nDlls,
                                         _In_reads_(nDlls) LPCSTR *rlpDlls,
                                         _In_opt_ PENTOUR_CREATE_PROCESS_ROUTINEA pfCreateProcessA);

BOOL WINAPI EntourCreateProcessWithDllsW(_In_opt_ LPCWSTR lpApplicationName,
                                         _Inout_opt_ LPWSTR lpCommandLine,
                                         _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                         _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                         _In_ BOOL bInheritHandles,
                                         _In_ DWORD dwCreationFlags,
                                         _In_opt_ LPVOID lpEnvironment,
                                         _In_opt_ LPCWSTR lpCurrentDirectory,
                                         _In_ LPSTARTUPINFOW lpStartupInfo,
                                         _Out_ LPPROCESS_INFORMATION lpProcessInformation,
                                         _In_ DWORD nDlls,
                                         _In_reads_(nDlls) LPCSTR *rlpDlls,
                                         _In_opt_ PENTOUR_CREATE_PROCESS_ROUTINEW pfCreateProcessW);

BOOL WINAPI EntourProcessViaHelperA(_In_ DWORD dwTargetPid,
                                    _In_ LPCSTR lpDllName,
                                    _In_ PENTOUR_CREATE_PROCESS_ROUTINEA pfCreateProcessA);

BOOL WINAPI EntourProcessViaHelperW(_In_ DWORD dwTargetPid,
                                    _In_ LPCSTR lpDllName,
                                    _In_ PENTOUR_CREATE_PROCESS_ROUTINEW pfCreateProcessW);

BOOL WINAPI EntourProcessViaHelperDllsA(_In_ DWORD dwTargetPid,
                                        _In_ DWORD nDlls,
                                        _In_reads_(nDlls) LPCSTR *rlpDlls,
                                        _In_ PENTOUR_CREATE_PROCESS_ROUTINEA pfCreateProcessA);

BOOL WINAPI EntourProcessViaHelperDllsW(_In_ DWORD dwTargetPid,
                                        _In_ DWORD nDlls,
                                        _In_reads_(nDlls) LPCSTR *rlpDlls,
                                        _In_ PENTOUR_CREATE_PROCESS_ROUTINEW pfCreateProcessW);

BOOL WINAPI EntourUpdateProcessWithDll(_In_ HANDLE hProcess,
                                       _In_reads_(nDlls) LPCSTR *rlpDlls,
                                       _In_ DWORD nDlls);

BOOL WINAPI EntourUpdateProcessWithDllEx(_In_ HANDLE hProcess,
                                         _In_ HMODULE hImage,
                                         _In_ BOOL bIs32Bit,
                                         _In_reads_(nDlls) LPCSTR *rlpDlls,
                                         _In_ DWORD nDlls);

BOOL WINAPI EntourCopyPayloadToProcess(_In_ HANDLE hProcess,
                                       _In_ REFGUID rguid,
                                       _In_reads_bytes_(cbData) PVOID pvData,
                                       _In_ DWORD cbData);
BOOL WINAPI EntourRestoreAfterWith(VOID);
BOOL WINAPI EntourRestoreAfterWithEx(_In_reads_bytes_(cbData) PVOID pvData,
                                     _In_ DWORD cbData);
BOOL WINAPI EntourIsHelperProcess(VOID);
VOID CALLBACK EntourFinishHelperProcess(_In_ HWND,
                                        _In_ HINSTANCE,
                                        _In_ LPSTR,
                                        _In_ INT);

#ifdef UNICODE
    #define EntourCreateProcessWithDll      EntourCreateProcessWithDllW
    #define PENTOUR_CREATE_PROCESS_ROUTINE  PENTOUR_CREATE_PROCESS_ROUTINEW
    #define EntourCreateProcessWithDllEx    EntourCreateProcessWithDllExW
    #define EntourCreateProcessWithDlls     EntourCreateProcessWithDllsW
    #define EntourProcessViaHelper          EntourProcessViaHelperW
    #define EntourProcessViaHelperDlls      EntourProcessViaHelperDllsW
#else   // ndef UNICODE
    #define EntourCreateProcessWithDll      EntourCreateProcessWithDllA
    #define PENTOUR_CREATE_PROCESS_ROUTINE  PENTOUR_CREATE_PROCESS_ROUTINEA
    #define EntourCreateProcessWithDllEx    EntourCreateProcessWithDllExA
    #define EntourCreateProcessWithDlls     EntourCreateProcessWithDllsA
    #define EntourProcessViaHelper          EntourProcessViaHelperA
    #define EntourProcessViaHelperDlls      EntourProcessViaHelperDllsA
#endif  // ndef UNICODE

//////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif // __cplusplus

//////////////////////////////////////////////// Entours Internal Definitions.

#ifdef __cplusplus
#ifdef ENTOURS_INTERNAL

#define NOTHROW
// #define NOTHROW (nothrow)

//////////////////////////////////////////////////////////////////////////////

#include <dbghelp.h>

#ifdef IMAGEAPI // defined by DBGHELP.H
typedef LPAPI_VERSION (NTAPI *PF_ImagehlpApiVersionEx)(_In_ LPAPI_VERSION AppVersion);

typedef BOOL (NTAPI *PF_SymInitialize)(_In_ HANDLE hProcess,
                                       _In_opt_ LPCSTR UserSearchPath,
                                       _In_ BOOL fInvadeProcess);
typedef DWORD (NTAPI *PF_SymSetOptions)(_In_ DWORD SymOptions);
typedef DWORD (NTAPI *PF_SymGetOptions)(VOID);
typedef DWORD64 (NTAPI *PF_SymLoadModule64)(_In_ HANDLE hProcess,
                                            _In_opt_ HANDLE hFile,
                                            _In_ LPSTR ImageName,
                                            _In_opt_ LPSTR ModuleName,
                                            _In_ DWORD64 BaseOfDll,
                                            _In_opt_ DWORD SizeOfDll);
typedef BOOL (NTAPI *PF_SymGetModuleInfo64)(_In_ HANDLE hProcess,
                                            _In_ DWORD64 qwAddr,
                                            _Out_ PIMAGEHLP_MODULE64 ModuleInfo);
typedef BOOL (NTAPI *PF_SymFromName)(_In_ HANDLE hProcess,
                                     _In_ LPSTR Name,
                                     _Out_ PSYMBOL_INFO Symbol);

typedef struct _ENTOUR_SYM_INFO
{
    HANDLE                  hProcess;
    HMODULE                 hDbgHelp;
    PF_ImagehlpApiVersionEx pfImagehlpApiVersionEx;
    PF_SymInitialize        pfSymInitialize;
    PF_SymSetOptions        pfSymSetOptions;
    PF_SymGetOptions        pfSymGetOptions;
    PF_SymLoadModule64      pfSymLoadModule64;
    PF_SymGetModuleInfo64   pfSymGetModuleInfo64;
    PF_SymFromName          pfSymFromName;
} ENTOUR_SYM_INFO, *PENTOUR_SYM_INFO;

PENTOUR_SYM_INFO EntourLoadImageHlp(VOID);

#endif // IMAGEAPI

#if defined(_INC_STDIO) && !defined(_CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS)
    #error entours.h must be included before stdio.h (or at least define _CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS earlier)
#endif
#define _CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS 1

#ifndef ENTOUR_TRACE
    #if ENTOUR_DEBUG
        #define ENTOUR_TRACE(x) printf x
        #define ENTOUR_BREAK()  __debugbreak()
        #include <stdio.h>
        #include <limits.h>
    #else
        #define ENTOUR_TRACE(x)
        #define ENTOUR_BREAK()
    #endif
#endif

#if 1 || defined(ENTOURS_IA64)

// IA64 instructions are 41 bits, 3 per bundle, plus 5 bit bundle template => 128 bits per bundle.

#define ENTOUR_IA64_INSTRUCTIONS_PER_BUNDLE (3)

#define ENTOUR_IA64_TEMPLATE_OFFSET (0)
#define ENTOUR_IA64_TEMPLATE_SIZE   (5)

#define ENTOUR_IA64_INSTRUCTION_SIZE (41)
#define ENTOUR_IA64_INSTRUCTION0_OFFSET (ENTOUR_IA64_TEMPLATE_SIZE)
#define ENTOUR_IA64_INSTRUCTION1_OFFSET (ENTOUR_IA64_TEMPLATE_SIZE + ENTOUR_IA64_INSTRUCTION_SIZE)
#define ENTOUR_IA64_INSTRUCTION2_OFFSET (ENTOUR_IA64_TEMPLATE_SIZE + ENTOUR_IA64_INSTRUCTION_SIZE + ENTOUR_IA64_INSTRUCTION_SIZE)

C_ASSERT(ENTOUR_IA64_TEMPLATE_SIZE + ENTOUR_IA64_INSTRUCTIONS_PER_BUNDLE * ENTOUR_IA64_INSTRUCTION_SIZE == 128);

struct ENTOURS_ALIGNAS(16) ENTOUR_IA64_BUNDLE
{
  public:
    union
    {
        BYTE    data[16];
        UINT64  wide[2];
    };

    enum {
        A_UNIT  = 1u,
        I_UNIT  = 2u,
        M_UNIT  = 3u,
        B_UNIT  = 4u,
        F_UNIT  = 5u,
        L_UNIT  = 6u,
        X_UNIT  = 7u,
    };
    struct ENTOUR_IA64_METADATA
    {
        ULONG       nTemplate       : 8;    // Instruction template.
        ULONG       nUnit0          : 4;    // Unit for slot 0
        ULONG       nUnit1          : 4;    // Unit for slot 1
        ULONG       nUnit2          : 4;    // Unit for slot 2
    };

  protected:
    static const ENTOUR_IA64_METADATA s_rceCopyTable[33];

    UINT RelocateBundle(_Inout_ ENTOUR_IA64_BUNDLE* pDst, _Inout_opt_ ENTOUR_IA64_BUNDLE* pBundleExtra) const;

    bool RelocateInstruction(_Inout_ ENTOUR_IA64_BUNDLE* pDst,
                             _In_ BYTE slot,
                             _Inout_opt_ ENTOUR_IA64_BUNDLE* pBundleExtra) const;

    // 120 112 104 96 88 80 72 64 56 48 40 32 24 16  8  0
    //  f.  e.  d. c. b. a. 9. 8. 7. 6. 5. 4. 3. 2. 1. 0.

    //                                      00
    // f.e. d.c. b.a. 9.8. 7.6. 5.4. 3.2. 1.0.
    // 0000 0000 0000 0000 0000 0000 0000 001f : Template [4..0]
    // 0000 0000 0000 0000 0000 03ff ffff ffe0 : Zero [ 41..  5]
    // 0000 0000 0000 0000 0000 3c00 0000 0000 : Zero [ 45.. 42]
    // 0000 0000 0007 ffff ffff c000 0000 0000 : One  [ 82.. 46]
    // 0000 0000 0078 0000 0000 0000 0000 0000 : One  [ 86.. 83]
    // 0fff ffff ff80 0000 0000 0000 0000 0000 : Two  [123.. 87]
    // f000 0000 0000 0000 0000 0000 0000 0000 : Two  [127..124]
    BYTE    GetTemplate() const;
    // Get 4 bit opcodes.
    BYTE    GetInst0() const;
    BYTE    GetInst1() const;
    BYTE    GetInst2() const;
    BYTE    GetUnit(BYTE slot) const;
    BYTE    GetUnit0() const;
    BYTE    GetUnit1() const;
    BYTE    GetUnit2() const;
    // Get 37 bit data.
    UINT64  GetData0() const;
    UINT64  GetData1() const;
    UINT64  GetData2() const;

    // Get/set the full 41 bit instructions.
    UINT64  GetInstruction(BYTE slot) const;
    UINT64  GetInstruction0() const;
    UINT64  GetInstruction1() const;
    UINT64  GetInstruction2() const;
    void    SetInstruction(BYTE slot, UINT64 instruction);
    void    SetInstruction0(UINT64 instruction);
    void    SetInstruction1(UINT64 instruction);
    void    SetInstruction2(UINT64 instruction);

    // Get/set bitfields.
    static UINT64 GetBits(UINT64 Value, UINT64 Offset, UINT64 Count);
    static UINT64 SetBits(UINT64 Value, UINT64 Offset, UINT64 Count, UINT64 Field);

    // Get specific read-only fields.
    static UINT64 GetOpcode(UINT64 instruction); // 4bit opcode
    static UINT64 GetX(UINT64 instruction); // 1bit opcode extension
    static UINT64 GetX3(UINT64 instruction); // 3bit opcode extension
    static UINT64 GetX6(UINT64 instruction); // 6bit opcode extension

    // Get/set specific fields.
    static UINT64 GetImm7a(UINT64 instruction);
    static UINT64 SetImm7a(UINT64 instruction, UINT64 imm7a);
    static UINT64 GetImm13c(UINT64 instruction);
    static UINT64 SetImm13c(UINT64 instruction, UINT64 imm13c);
    static UINT64 GetSignBit(UINT64 instruction);
    static UINT64 SetSignBit(UINT64 instruction, UINT64 signBit);
    static UINT64 GetImm20a(UINT64 instruction);
    static UINT64 SetImm20a(UINT64 instruction, UINT64 imm20a);
    static UINT64 GetImm20b(UINT64 instruction);
    static UINT64 SetImm20b(UINT64 instruction, UINT64 imm20b);

    static UINT64 SignExtend(UINT64 Value, UINT64 Offset);

    BOOL    IsMovlGp() const;

    VOID    SetInst(BYTE Slot, BYTE nInst);
    VOID    SetInst0(BYTE nInst);
    VOID    SetInst1(BYTE nInst);
    VOID    SetInst2(BYTE nInst);
    VOID    SetData(BYTE Slot, UINT64 nData);
    VOID    SetData0(UINT64 nData);
    VOID    SetData1(UINT64 nData);
    VOID    SetData2(UINT64 nData);
    BOOL    SetNop(BYTE Slot);
    BOOL    SetNop0();
    BOOL    SetNop1();
    BOOL    SetNop2();

  public:
    BOOL    IsBrl() const;
    VOID    SetBrl();
    VOID    SetBrl(UINT64 target);
    UINT64  GetBrlTarget() const;
    VOID    SetBrlTarget(UINT64 target);
    VOID    SetBrlImm(UINT64 imm);
    UINT64  GetBrlImm() const;

    UINT64  GetMovlGp() const;
    VOID    SetMovlGp(UINT64 gp);

    VOID    SetStop();

    UINT    Copy(_Out_ ENTOUR_IA64_BUNDLE *pDst, _Inout_opt_ ENTOUR_IA64_BUNDLE* pBundleExtra = NULL) const;
};
#endif // ENTOURS_IA64

#ifdef ENTOURS_ARM
    #define ENTOURS_PFUNC_TO_PBYTE(p)  ((PBYTE)(((ULONG_PTR)(p)) & ~(ULONG_PTR)1))
    #define ENTOURS_PBYTE_TO_PFUNC(p)  ((PBYTE)(((ULONG_PTR)(p)) | (ULONG_PTR)1))
#endif // ENTOURS_ARM

//////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define ENTOUR_OFFLINE_LIBRARY(x)                                       \
PVOID WINAPI EntourCopyInstruction##x(_In_opt_ LPCVOID pDst,              \
                                      _Inout_opt_ PVOID *ppDstPool,     \
                                      _In_ LPCVOID pSrc,            \
                                      _Out_opt_ PVOID *ppTarget,        \
                                      _Out_opt_ LONG *plExtra);         \
                                                                        \
BOOL WINAPI EntourSetCodeModule##x(_In_ HMODULE hModule,                \
                                   _In_ BOOL fLimitReferencesToModule); \

ENTOUR_OFFLINE_LIBRARY(X86)
ENTOUR_OFFLINE_LIBRARY(X64)
ENTOUR_OFFLINE_LIBRARY(ARM)
ENTOUR_OFFLINE_LIBRARY(ARM64)
ENTOUR_OFFLINE_LIBRARY(IA64)

#undef ENTOUR_OFFLINE_LIBRARY

//////////////////////////////////////////////////////////////////////////////
// Helpers for manipulating page protection.

_Success_(return != FALSE)
BOOL WINAPI EntourVirtualProtectSameExecuteEx(_In_  HANDLE hProcess,
                                              _In_  PVOID pAddress,
                                              _In_  SIZE_T nSize,
                                              _In_  DWORD dwNewProtect,
                                              _Out_ PDWORD pdwOldProtect);

_Success_(return != FALSE)
BOOL WINAPI EntourVirtualProtectSameExecute(_In_  PVOID pAddress,
                                            _In_  SIZE_T nSize,
                                            _In_  DWORD dwNewProtect,
                                            _Out_ PDWORD pdwOldProtect);
#ifdef __cplusplus
}
#endif // __cplusplus

//////////////////////////////////////////////////////////////////////////////

#define MM_ALLOCATION_GRANULARITY 0x10000

#endif // ENTOURS_INTERNAL
#endif // __cplusplus

#endif // _ENTOURS_H_
