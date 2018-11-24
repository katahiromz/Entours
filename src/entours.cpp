// Core Entours Functionality (entours.cpp of entours.lib)
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Copyright (c) 2018 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>.

#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1
#include <windows.h>

//#define ENTOUR_DEBUG 1
#define ENTOURS_INTERNAL

#include "entours.h"

#if ENTOURS_VERSION != 0x4c0c1   // 0xMAJORcMINORcPATCH
    #error entours.h version mismatch
#endif

#define NOTHROW

//////////////////////////////////////////////////////////////////////////////

struct _ENTOUR_ALIGN
{
    BYTE    obTarget        : 3;
    BYTE    obTrampoline    : 5;
};

C_ASSERT(sizeof(_ENTOUR_ALIGN) == 1);

//////////////////////////////////////////////////////////////////////////////
// Region reserved for system DLLs, which cannot be used for trampolines.

static PVOID    s_pSystemRegionLowerBound   = (PVOID)(ULONG_PTR)0x70000000;
static PVOID    s_pSystemRegionUpperBound   = (PVOID)(ULONG_PTR)0x80000000;

//////////////////////////////////////////////////////////////////////////////

static bool entour_is_imported(PBYTE pbCode, PBYTE pbAddress)
{
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery((PVOID)pbCode, &mbi, sizeof(mbi));
    __try {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mbi.AllocationBase;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
                                                          pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        if (pbAddress >= ((PBYTE)pDosHeader +
                          pNtHeader->OptionalHeader
                          .DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress) &&
            pbAddress < ((PBYTE)pDosHeader +
                         pNtHeader->OptionalHeader
                         .DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress +
                         pNtHeader->OptionalHeader
                         .DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size)) {
            return true;
        }
    }
    __except(GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
             EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return false;
    }
    return false;
}

inline ULONG_PTR entour_2gb_below(ULONG_PTR address)
{
    return (address > (ULONG_PTR)0x7ff80000) ? address - 0x7ff80000 : 0x80000;
}

inline ULONG_PTR entour_2gb_above(ULONG_PTR address)
{
#if defined(ENTOURS_64BIT)
    return (address < (ULONG_PTR)0xffffffff80000000) ? address + 0x7ff80000 : (ULONG_PTR)0xfffffffffff80000;
#else
    return (address < (ULONG_PTR)0x80000000) ? address + 0x7ff80000 : (ULONG_PTR)0xfff80000;
#endif
}

///////////////////////////////////////////////////////////////////////// X86.

#ifdef ENTOURS_X86

struct _ENTOUR_TRAMPOLINE
{
    BYTE            rbCode[30];     // target code + jmp to pbRemain
    BYTE            cbCode;         // size of moved target code.
    BYTE            cbCodeBreak;    // padding to make debugging easier.
    BYTE            rbRestore[22];  // original target code.
    BYTE            cbRestore;      // size of original target code.
    BYTE            cbRestoreBreak; // padding to make debugging easier.
    _ENTOUR_ALIGN   rAlign[8];      // instruction alignment array.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbEntour;       // first instruction of entour function.
};

C_ASSERT(sizeof(_ENTOUR_TRAMPOLINE) == 72);

enum {
    SIZE_OF_JMP = 5
};

inline PBYTE entour_gen_jmp_immediate(PBYTE pbCode, PBYTE pbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 5;
    *pbCode++ = 0xE9;   // jmp +imm32
    *((INT32*&)pbCode)++ = (INT32)(pbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE entour_gen_jmp_indirect(PBYTE pbCode, PBYTE *ppbJmpVal)
{
    *pbCode++ = 0xff;   // jmp [+imm32]
    *pbCode++ = 0x25;
    *((INT32*&)pbCode)++ = (INT32)((PBYTE)ppbJmpVal);
    return pbCode;
}

inline PBYTE entour_gen_brk(PBYTE pbCode, PBYTE pbLimit)
{
    while (pbCode < pbLimit) {
        *pbCode++ = 0xcc;   // brk;
    }
    return pbCode;
}

inline PBYTE entour_skip_jmp(PBYTE pbCode, PVOID *ppGlobals)
{
    if (pbCode == NULL) {
        return NULL;
    }
    if (ppGlobals != NULL) {
        *ppGlobals = NULL;
    }

    // First, skip over the import vector if there is one.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [imm32]
        // Looks like an import alias jump, then get the code it points to.
        PBYTE pbTarget = *(UNALIGNED PBYTE *)&pbCode[2];
        if (entour_is_imported(pbCode, pbTarget)) {
            PBYTE pbNew = *(UNALIGNED PBYTE *)pbTarget;
            ENTOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
            pbCode = pbNew;
        }
    }

    // Then, skip over a patch jump
    if (pbCode[0] == 0xeb) {   // jmp +imm8
        PBYTE pbNew = pbCode + 2 + *(CHAR *)&pbCode[1];
        ENTOUR_TRACE(("%p->%p: skipped over short jump.\n", pbCode, pbNew));
        pbCode = pbNew;

        // First, skip over the import vector if there is one.
        if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [imm32]
            // Looks like an import alias jump, then get the code it points to.
            PBYTE pbTarget = *(UNALIGNED PBYTE *)&pbCode[2];
            if (entour_is_imported(pbCode, pbTarget)) {
                pbNew = *(UNALIGNED PBYTE *)pbTarget;
                ENTOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
                pbCode = pbNew;
            }
        }
        // Finally, skip over a long jump if it is the target of the patch jump.
        else if (pbCode[0] == 0xe9) {   // jmp +imm32
            pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];
            ENTOUR_TRACE(("%p->%p: skipped over long jump.\n", pbCode, pbNew));
            pbCode = pbNew;
        }
    }
    return pbCode;
}

inline void entour_find_jmp_bounds(PBYTE pbCode,
                                   PENTOUR_TRAMPOLINE *ppLower,
                                   PENTOUR_TRAMPOLINE *ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = entour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = entour_2gb_above((ULONG_PTR)pbCode);
    ENTOUR_TRACE(("[%p..%p..%p]\n", lo, pbCode, hi));

    // And, within +/- 2GB of relative jmp targets.
    if (pbCode[0] == 0xe9) {   // jmp +imm32
        PBYTE pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];

        if (pbNew < pbCode) {
            hi = entour_2gb_above((ULONG_PTR)pbNew);
        }
        else {
            lo = entour_2gb_below((ULONG_PTR)pbNew);
        }
        ENTOUR_TRACE(("[%p..%p..%p] +imm32\n", lo, pbCode, hi));
    }

    *ppLower = (PENTOUR_TRAMPOLINE)lo;
    *ppUpper = (PENTOUR_TRAMPOLINE)hi;
}

inline BOOL entour_does_code_end_function(PBYTE pbCode)
{
    if (pbCode[0] == 0xeb ||    // jmp +imm8
        pbCode[0] == 0xe9 ||    // jmp +imm32
        pbCode[0] == 0xe0 ||    // jmp eax
        pbCode[0] == 0xc2 ||    // ret +imm8
        pbCode[0] == 0xc3 ||    // ret
        pbCode[0] == 0xcc) {    // brk
        return TRUE;
    }
    else if (pbCode[0] == 0xf3 && pbCode[1] == 0xc3) {  // rep ret
        return TRUE;
    }
    else if (pbCode[0] == 0xff && pbCode[1] == 0x25) {  // jmp [+imm32]
        return TRUE;
    }
    else if ((pbCode[0] == 0x26 ||      // jmp es:
              pbCode[0] == 0x2e ||      // jmp cs:
              pbCode[0] == 0x36 ||      // jmp ss:
              pbCode[0] == 0x3e ||      // jmp ds:
              pbCode[0] == 0x64 ||      // jmp fs:
              pbCode[0] == 0x65) &&     // jmp gs:
             pbCode[1] == 0xff &&       // jmp [+imm32]
             pbCode[2] == 0x25) {
        return TRUE;
    }
    return FALSE;
}

inline ULONG entour_is_code_filler(PBYTE pbCode)
{
    // 1-byte through 11-byte NOPs.
    if (pbCode[0] == 0x90) {
        return 1;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x90) {
        return 2;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x00) {
        return 3;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x40 &&
        pbCode[3] == 0x00) {
        return 4;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x44 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00) {
        return 5;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x44 && pbCode[4] == 0x00 && pbCode[5] == 0x00) {
        return 6;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x80 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00) {
        return 7;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x84 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00) {
        return 8;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x84 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00) {
        return 9;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x0F &&
        pbCode[3] == 0x1F && pbCode[4] == 0x84 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00) {
        return 10;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x66 &&
        pbCode[3] == 0x0F && pbCode[4] == 0x1F && pbCode[5] == 0x84 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00 && pbCode[10] == 0x00) {
        return 11;
    }

    // int 3.
    if (pbCode[0] == 0xcc) {
        return 1;
    }
    return 0;
}

#endif // ENTOURS_X86

///////////////////////////////////////////////////////////////////////// X64.

#ifdef ENTOURS_X64

struct _ENTOUR_TRAMPOLINE
{
    // An X64 instuction can be 15 bytes long.
    // In practice 11 seems to be the limit.
    BYTE            rbCode[30];     // target code + jmp to pbRemain.
    BYTE            cbCode;         // size of moved target code.
    BYTE            cbCodeBreak;    // padding to make debugging easier.
    BYTE            rbRestore[30];  // original target code.
    BYTE            cbRestore;      // size of original target code.
    BYTE            cbRestoreBreak; // padding to make debugging easier.
    _ENTOUR_ALIGN   rAlign[8];      // instruction alignment array.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbEntour;       // first instruction of entour function.
    BYTE            rbCodeIn[8];    // jmp [pbEntour]
};

C_ASSERT(sizeof(_ENTOUR_TRAMPOLINE) == 96);

enum {
    SIZE_OF_JMP = 5
};

inline PBYTE entour_gen_jmp_immediate(PBYTE pbCode, PBYTE pbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 5;
    *pbCode++ = 0xE9;   // jmp +imm32
    *((INT32*&)pbCode)++ = (INT32)(pbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE entour_gen_jmp_indirect(PBYTE pbCode, PBYTE *ppbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 6;
    *pbCode++ = 0xff;   // jmp [+imm32]
    *pbCode++ = 0x25;
    *((INT32*&)pbCode)++ = (INT32)((PBYTE)ppbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE entour_gen_brk(PBYTE pbCode, PBYTE pbLimit)
{
    while (pbCode < pbLimit) {
        *pbCode++ = 0xcc;   // brk;
    }
    return pbCode;
}

inline PBYTE entour_skip_jmp(PBYTE pbCode, PVOID *ppGlobals)
{
    if (pbCode == NULL) {
        return NULL;
    }
    if (ppGlobals != NULL) {
        *ppGlobals = NULL;
    }

    // First, skip over the import vector if there is one.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [+imm32]
        // Looks like an import alias jump, then get the code it points to.
        PBYTE pbTarget = pbCode + 6 + *(UNALIGNED INT32 *)&pbCode[2];
        if (entour_is_imported(pbCode, pbTarget)) {
            PBYTE pbNew = *(UNALIGNED PBYTE *)pbTarget;
            ENTOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
            pbCode = pbNew;
        }
    }

    // Then, skip over a patch jump
    if (pbCode[0] == 0xeb) {   // jmp +imm8
        PBYTE pbNew = pbCode + 2 + *(CHAR *)&pbCode[1];
        ENTOUR_TRACE(("%p->%p: skipped over short jump.\n", pbCode, pbNew));
        pbCode = pbNew;

        // First, skip over the import vector if there is one.
        if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [+imm32]
            // Looks like an import alias jump, then get the code it points to.
            PBYTE pbTarget = pbCode + 6 + *(UNALIGNED INT32 *)&pbCode[2];
            if (entour_is_imported(pbCode, pbTarget)) {
                pbNew = *(UNALIGNED PBYTE *)pbTarget;
                ENTOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
                pbCode = pbNew;
            }
        }
        // Finally, skip over a long jump if it is the target of the patch jump.
        else if (pbCode[0] == 0xe9) {   // jmp +imm32
            pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];
            ENTOUR_TRACE(("%p->%p: skipped over long jump.\n", pbCode, pbNew));
            pbCode = pbNew;
        }
    }
    return pbCode;
}

inline void entour_find_jmp_bounds(PBYTE pbCode,
                                   PENTOUR_TRAMPOLINE *ppLower,
                                   PENTOUR_TRAMPOLINE *ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = entour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = entour_2gb_above((ULONG_PTR)pbCode);
    ENTOUR_TRACE(("[%p..%p..%p]\n", lo, pbCode, hi));

    // And, within +/- 2GB of relative jmp vectors.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [+imm32]
        PBYTE pbNew = pbCode + 6 + *(UNALIGNED INT32 *)&pbCode[2];

        if (pbNew < pbCode) {
            hi = entour_2gb_above((ULONG_PTR)pbNew);
        }
        else {
            lo = entour_2gb_below((ULONG_PTR)pbNew);
        }
        ENTOUR_TRACE(("[%p..%p..%p] [+imm32]\n", lo, pbCode, hi));
    }
    // And, within +/- 2GB of relative jmp targets.
    else if (pbCode[0] == 0xe9) {   // jmp +imm32
        PBYTE pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];

        if (pbNew < pbCode) {
            hi = entour_2gb_above((ULONG_PTR)pbNew);
        }
        else {
            lo = entour_2gb_below((ULONG_PTR)pbNew);
        }
        ENTOUR_TRACE(("[%p..%p..%p] +imm32\n", lo, pbCode, hi));
    }

    *ppLower = (PENTOUR_TRAMPOLINE)lo;
    *ppUpper = (PENTOUR_TRAMPOLINE)hi;
}

inline BOOL entour_does_code_end_function(PBYTE pbCode)
{
    if (pbCode[0] == 0xeb ||    // jmp +imm8
        pbCode[0] == 0xe9 ||    // jmp +imm32
        pbCode[0] == 0xe0 ||    // jmp eax
        pbCode[0] == 0xc2 ||    // ret +imm8
        pbCode[0] == 0xc3 ||    // ret
        pbCode[0] == 0xcc) {    // brk
        return TRUE;
    }
    else if (pbCode[0] == 0xf3 && pbCode[1] == 0xc3) {  // rep ret
        return TRUE;
    }
    else if (pbCode[0] == 0xff && pbCode[1] == 0x25) {  // jmp [+imm32]
        return TRUE;
    }
    else if ((pbCode[0] == 0x26 ||      // jmp es:
              pbCode[0] == 0x2e ||      // jmp cs:
              pbCode[0] == 0x36 ||      // jmp ss:
              pbCode[0] == 0x3e ||      // jmp ds:
              pbCode[0] == 0x64 ||      // jmp fs:
              pbCode[0] == 0x65) &&     // jmp gs:
             pbCode[1] == 0xff &&       // jmp [+imm32]
             pbCode[2] == 0x25) {
        return TRUE;
    }
    return FALSE;
}

inline ULONG entour_is_code_filler(PBYTE pbCode)
{
    // 1-byte through 11-byte NOPs.
    if (pbCode[0] == 0x90) {
        return 1;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x90) {
        return 2;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x00) {
        return 3;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x40 &&
        pbCode[3] == 0x00) {
        return 4;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x44 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00) {
        return 5;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x44 && pbCode[4] == 0x00 && pbCode[5] == 0x00) {
        return 6;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x80 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00) {
        return 7;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x84 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00) {
        return 8;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x84 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00) {
        return 9;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x0F &&
        pbCode[3] == 0x1F && pbCode[4] == 0x84 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00) {
        return 10;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x66 &&
        pbCode[3] == 0x0F && pbCode[4] == 0x1F && pbCode[5] == 0x84 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00 && pbCode[10] == 0x00) {
        return 11;
    }

    // int 3.
    if (pbCode[0] == 0xcc) {
        return 1;
    }
    return 0;
}

#endif // ENTOURS_X64

//////////////////////////////////////////////////////////////////////// IA64.

#ifdef ENTOURS_IA64

struct _ENTOUR_TRAMPOLINE
{
    // On the IA64, a trampoline is used for both incoming and outgoing calls.
    //
    // The trampoline contains the following bundles for the outgoing call:
    //      movl gp=target_gp;
    //      <relocated target bundle>
    //      brl  target_code;
    //
    // The trampoline contains the following bundles for the incoming call:
    //      alloc  r41=ar.pfs, b, 0, 8, 0
    //      mov    r40=rp
    //
    //      adds   r50=0, r39
    //      adds   r49=0, r38
    //      adds   r48=0, r37 ;;
    //
    //      adds   r47=0, r36
    //      adds   r46=0, r35
    //      adds   r45=0, r34
    //
    //      adds   r44=0, r33
    //      adds   r43=0, r32
    //      adds   r42=0, gp ;;
    //
    //      movl   gp=ffffffff`ffffffff ;;
    //
    //      brl.call.sptk.few rp=disas!TestCodes+20e0 (00000000`00404ea0) ;;
    //
    //      adds   gp=0, r42
    //      mov    rp=r40, +0 ;;
    //      mov.i  ar.pfs=r41
    //
    //      br.ret.sptk.many rp ;;
    //
    // This way, we only have to relocate a single bundle.
    //
    // The complicated incoming trampoline is required because we have to
    // create an additional stack frame so that we save and restore the gp.
    // We must do this because gp is a caller-saved register, but not saved
    // if the caller thinks the target is in the same DLL, which changes
    // when we insert a entour.

    ENTOUR_IA64_BUNDLE  bMovlTargetGp;  // Bundle which sets target GP
    BYTE                rbCode[sizeof(ENTOUR_IA64_BUNDLE)]; // moved bundle.
    ENTOUR_IA64_BUNDLE  bBrlRemainEip;  // Brl to pbRemain
    // This must be adjacent to bBranchIslands.

    // Each instruction in the moved bundle could be a IP-relative chk or branch or call.
    // Any such instructions are changed to point to a brl in bBranchIslands.
    // This must be adjacent to bBrlRemainEip -- see "pbPool".
    ENTOUR_IA64_BUNDLE bBranchIslands[ENTOUR_IA64_INSTRUCTIONS_PER_BUNDLE];

    // Target of brl inserted in target function
    ENTOUR_IA64_BUNDLE  bAllocFrame;    // alloc frame
    ENTOUR_IA64_BUNDLE  bSave37to39;    // save r37, r38, r39.
    ENTOUR_IA64_BUNDLE  bSave34to36;    // save r34, r35, r36.
    ENTOUR_IA64_BUNDLE  bSaveGPto33;    // save gp, r32, r33.
    ENTOUR_IA64_BUNDLE  bMovlEntourGp;  // set entour GP.
    ENTOUR_IA64_BUNDLE  bCallEntour;    // call entour.
    ENTOUR_IA64_BUNDLE  bPopFrameGp;    // pop frame and restore gp.
    ENTOUR_IA64_BUNDLE  bReturn;        // return to caller.

    PLABEL_DESCRIPTOR   pldTrampoline;

    BYTE                rbRestore[sizeof(ENTOUR_IA64_BUNDLE)]; // original target bundle.
    BYTE                cbRestore;      // size of original target code.
    BYTE                cbCode;         // size of moved target code.
    _ENTOUR_ALIGN       rAlign[14];     // instruction alignment array.
    PBYTE               pbRemain;       // first instruction after moved code. [free list]
    PBYTE               pbEntour;       // first instruction of entour function.
    PPLABEL_DESCRIPTOR  ppldEntour;     // [pbEntour,gpEntour]
    PPLABEL_DESCRIPTOR  ppldTarget;     // [pbTarget,gpEntour]
};

C_ASSERT(sizeof(ENTOUR_IA64_BUNDLE) == 16);
C_ASSERT(sizeof(_ENTOUR_TRAMPOLINE) == 256 + ENTOUR_IA64_INSTRUCTIONS_PER_BUNDLE * 16);

enum {
    SIZE_OF_JMP = sizeof(ENTOUR_IA64_BUNDLE)
};

inline PBYTE entour_skip_jmp(PBYTE pPointer, PVOID *ppGlobals)
{
    PBYTE pGlobals = NULL;
    PBYTE pbCode = NULL;

    if (pPointer != NULL) {
        PPLABEL_DESCRIPTOR ppld = (PPLABEL_DESCRIPTOR)pPointer;
        pbCode = (PBYTE)ppld->EntryPoint;
        pGlobals = (PBYTE)ppld->GlobalPointer;
    }
    if (ppGlobals != NULL) {
        *ppGlobals = pGlobals;
    }
    if (pbCode == NULL) {
        return NULL;
    }

    ENTOUR_IA64_BUNDLE *pb = (ENTOUR_IA64_BUNDLE *)pbCode;

    // IA64 Local Import Jumps look like:
    //      addl   r2=ffffffff`ffe021c0, gp ;;
    //      ld8    r2=[r2]
    //      nop.i  0 ;;
    //
    //      ld8    r3=[r2], 8 ;;
    //      ld8    gp=[r2]
    //      mov    b6=r3, +0
    //
    //      nop.m  0
    //      nop.i  0
    //      br.cond.sptk.few b6

    //                     002024000200100b
    if ((pb[0].wide[0] & 0xfffffc000603ffff) == 0x002024000200100b &&
        pb[0].wide[1] == 0x0004000000203008 &&
        pb[1].wide[0] == 0x001014180420180a &&
        pb[1].wide[1] == 0x07000830c0203008 &&
        pb[2].wide[0] == 0x0000000100000010 &&
        pb[2].wide[1] == 0x0080006000000200) {

        ULONG64 offset =
            ((pb[0].wide[0] & 0x0000000001fc0000) >> 18) |  // imm7b
            ((pb[0].wide[0] & 0x000001ff00000000) >> 25) |  // imm9d
            ((pb[0].wide[0] & 0x00000000f8000000) >> 11);   // imm5c
        if (pb[0].wide[0] & 0x0000020000000000) {           // sign
            offset |= 0xffffffffffe00000;
        }
        PBYTE pbTarget = pGlobals + offset;
        ENTOUR_TRACE(("%p: potential import jump, target=%p\n", pb, pbTarget));

        if (entour_is_imported(pbCode, pbTarget) && *(PBYTE*)pbTarget != NULL) {
            ENTOUR_TRACE(("%p: is import jump, label=%p\n", pb, *(PBYTE *)pbTarget));

            PPLABEL_DESCRIPTOR ppld = (PPLABEL_DESCRIPTOR)*(PBYTE *)pbTarget;
            pbCode = (PBYTE)ppld->EntryPoint;
            pGlobals = (PBYTE)ppld->GlobalPointer;
            if (ppGlobals != NULL) {
                *ppGlobals = pGlobals;
            }
        }
    }
    return pbCode;
}

inline void entour_find_jmp_bounds(PBYTE pbCode,
                                   PENTOUR_TRAMPOLINE *ppLower,
                                   PENTOUR_TRAMPOLINE *ppUpper)
{
    (void)pbCode;
    *ppLower = (PENTOUR_TRAMPOLINE)(ULONG_PTR)0x0000000000080000;
    *ppUpper = (PENTOUR_TRAMPOLINE)(ULONG_PTR)0xfffffffffff80000;
}

inline BOOL entour_does_code_end_function(PBYTE pbCode)
{
    // Routine not needed on IA64.
    (void)pbCode;
    return FALSE;
}

inline ULONG entour_is_code_filler(PBYTE pbCode)
{
    // Routine not needed on IA64.
    (void)pbCode;
    return 0;
}

#endif // ENTOURS_IA64

#ifdef ENTOURS_ARM

struct _ENTOUR_TRAMPOLINE
{
    // A Thumb-2 instruction can be 2 or 4 bytes long.
    BYTE            rbCode[62];     // target code + jmp to pbRemain
    BYTE            cbCode;         // size of moved target code.
    BYTE            cbCodeBreak;    // padding to make debugging easier.
    BYTE            rbRestore[22];  // original target code.
    BYTE            cbRestore;      // size of original target code.
    BYTE            cbRestoreBreak; // padding to make debugging easier.
    _ENTOUR_ALIGN   rAlign[8];      // instruction alignment array.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbEntour;       // first instruction of entour function.
};

C_ASSERT(sizeof(_ENTOUR_TRAMPOLINE) == 104);

enum {
    SIZE_OF_JMP = 8
};

inline PBYTE align4(PBYTE pValue)
{
    return (PBYTE)(((ULONG)pValue) & ~(ULONG)3u);
}

inline ULONG fetch_thumb_opcode(PBYTE pbCode)
{
    ULONG Opcode = *(UINT16 *)&pbCode[0];
    if (Opcode >= 0xe800) {
        Opcode = (Opcode << 16) | *(UINT16 *)&pbCode[2];
    }
    return Opcode;
}

inline void write_thumb_opcode(PBYTE &pbCode, ULONG Opcode)
{
    if (Opcode >= 0x10000) {
        *((UINT16*&)pbCode)++ = Opcode >> 16;
    }
    *((UINT16*&)pbCode)++ = (UINT16)Opcode;
}

PBYTE entour_gen_jmp_immediate(PBYTE pbCode, PBYTE *ppPool, PBYTE pbJmpVal)
{
    PBYTE pbLiteral;
    if (ppPool != NULL) {
        *ppPool = *ppPool - 4;
        pbLiteral = *ppPool;
    }
    else {
        pbLiteral = align4(pbCode + 6);
    }

    *((PBYTE*&)pbLiteral) = ENTOURS_PBYTE_TO_PFUNC(pbJmpVal);
    LONG delta = pbLiteral - align4(pbCode + 4);

    write_thumb_opcode(pbCode, 0xf8dff000 | delta);     // LDR PC,[PC+n]

    if (ppPool == NULL) {
        if (((ULONG)pbCode & 2) != 0) {
            write_thumb_opcode(pbCode, 0xdefe);         // BREAK
        }
        pbCode += 4;
    }
    return pbCode;
}

inline PBYTE entour_gen_brk(PBYTE pbCode, PBYTE pbLimit)
{
    while (pbCode < pbLimit) {
        write_thumb_opcode(pbCode, 0xdefe);
    }
    return pbCode;
}

inline PBYTE entour_skip_jmp(PBYTE pbCode, PVOID *ppGlobals)
{
    if (pbCode == NULL) {
        return NULL;
    }
    if (ppGlobals != NULL) {
        *ppGlobals = NULL;
    }

    // Skip over the import jump if there is one.
    pbCode = (PBYTE)ENTOURS_PFUNC_TO_PBYTE(pbCode);
    ULONG Opcode = fetch_thumb_opcode(pbCode);

    if ((Opcode & 0xfbf08f00) == 0xf2400c00) {          // movw r12,#xxxx
        ULONG Opcode2 = fetch_thumb_opcode(pbCode+4);

        if ((Opcode2 & 0xfbf08f00) == 0xf2c00c00) {      // movt r12,#xxxx
            ULONG Opcode3 = fetch_thumb_opcode(pbCode+8);
            if (Opcode3 == 0xf8dcf000) {                 // ldr  pc,[r12]
                PBYTE pbTarget = (PBYTE)(((Opcode2 << 12) & 0xf7000000) |
                                         ((Opcode2 <<  1) & 0x08000000) |
                                         ((Opcode2 << 16) & 0x00ff0000) |
                                         ((Opcode  >>  4) & 0x0000f700) |
                                         ((Opcode  >> 15) & 0x00000800) |
                                         ((Opcode  >>  0) & 0x000000ff));
                if (entour_is_imported(pbCode, pbTarget)) {
                    PBYTE pbNew = *(PBYTE *)pbTarget;
                    pbNew = ENTOURS_PFUNC_TO_PBYTE(pbNew);
                    ENTOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
                    return pbNew;
                }
            }
        }
    }
    return pbCode;
}

inline void entour_find_jmp_bounds(PBYTE pbCode,
                                   PENTOUR_TRAMPOLINE *ppLower,
                                   PENTOUR_TRAMPOLINE *ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = entour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = entour_2gb_above((ULONG_PTR)pbCode);
    ENTOUR_TRACE(("[%p..%p..%p]\n", lo, pbCode, hi));

    *ppLower = (PENTOUR_TRAMPOLINE)lo;
    *ppUpper = (PENTOUR_TRAMPOLINE)hi;
}

inline BOOL entour_does_code_end_function(PBYTE pbCode)
{
    ULONG Opcode = fetch_thumb_opcode(pbCode);
    if ((Opcode & 0xffffff87) == 0x4700 ||          // bx <reg>
        (Opcode & 0xf800d000) == 0xf0009000) {      // b <imm20>
        return TRUE;
    }
    if ((Opcode & 0xffff8000) == 0xe8bd8000) {      // pop {...,pc}
        __debugbreak();
        return TRUE;
    }
    if ((Opcode & 0xffffff00) == 0x0000bd00) {      // pop {...,pc}
        __debugbreak();
        return TRUE;
    }
    return FALSE;
}

inline ULONG entour_is_code_filler(PBYTE pbCode)
{
    if (pbCode[0] == 0x00 && pbCode[1] == 0xbf) { // nop.
        return 2;
    }
    if (pbCode[0] == 0x00 && pbCode[1] == 0x00) { // zero-filled padding.
        return 2;
    }
    return 0;
}

#endif // ENTOURS_ARM

#ifdef ENTOURS_ARM64

struct _ENTOUR_TRAMPOLINE
{
    // An ARM64 instruction is 4 bytes long.
    //
    // The overwrite is always 2 instructions plus a literal, so 16 bytes, 4 instructions.
    //
    // Copied instructions can expand.
    //
    // The scheme using MovImmediate can cause an instruction
    // to grow as much as 6 times.
    // That would be Bcc or Tbz with a large address space:
    //   4 instructions to form immediate
    //   inverted tbz/bcc
    //   br
    //
    // An expansion of 4 is not uncommon -- bl/blr and small address space:
    //   3 instructions to form immediate
    //   br or brl
    //
    // A theoretical maximum for rbCode is thefore 4*4*6 + 16 = 112 (another 16 for jmp to pbRemain).
    //
    // With literals, the maximum expansion is 5, including the literals: 4*4*5 + 16 = 96.
    //
    // The number is rounded up to 128. m_rbScratchDst should match this.

    BYTE            rbCode[128];    // target code + jmp to pbRemain
    BYTE            cbCode;         // size of moved target code.
    BYTE            cbCodeBreak[3]; // padding to make debugging easier.
    BYTE            rbRestore[24];  // original target code.
    BYTE            cbRestore;      // size of original target code.
    BYTE            cbRestoreBreak[3]; // padding to make debugging easier.
    _ENTOUR_ALIGN   rAlign[8];      // instruction alignment array.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbEntour;       // first instruction of entour function.
};

C_ASSERT(sizeof(_ENTOUR_TRAMPOLINE) == 184);

enum {
    SIZE_OF_JMP = 16
};

inline ULONG fetch_opcode(PBYTE pbCode)
{
    return *(ULONG *)pbCode;
}

inline void write_opcode(PBYTE &pbCode, ULONG Opcode)
{
    *(ULONG *)pbCode = Opcode;
    pbCode += 4;
}

PBYTE entour_gen_jmp_immediate(PBYTE pbCode, PBYTE *ppPool, PBYTE pbJmpVal)
{
    PBYTE pbLiteral;
    if (ppPool != NULL) {
        *ppPool = *ppPool - 8;
        pbLiteral = *ppPool;
    }
    else {
        pbLiteral = pbCode + 8;
    }

    *((PBYTE*&)pbLiteral) = pbJmpVal;
    LONG delta = (LONG)(pbLiteral - pbCode);

    write_opcode(pbCode, 0x58000011 | ((delta / 4) << 5));  // LDR X17,[PC+n]
    write_opcode(pbCode, 0xd61f0000 | (17 << 5));           // BR X17

    if (ppPool == NULL) {
        pbCode += 8;
    }
    return pbCode;
}

inline PBYTE entour_gen_brk(PBYTE pbCode, PBYTE pbLimit)
{
    while (pbCode < pbLimit) {
        write_opcode(pbCode, 0xd4100000 | (0xf000 << 5));
    }
    return pbCode;
}

inline INT64 entour_sign_extend(UINT64 value, UINT bits)
{
    const UINT left = 64 - bits;
    const INT64 m1 = -1;
    const INT64 wide = (INT64)(value << left);
    const INT64 sign = (wide < 0) ? (m1 << left) : 0;
    return value | sign;
}

inline PBYTE entour_skip_jmp(PBYTE pbCode, PVOID *ppGlobals)
{
    if (pbCode == NULL) {
        return NULL;
    }
    if (ppGlobals != NULL) {
        *ppGlobals = NULL;
    }

    // Skip over the import jump if there is one.
    pbCode = (PBYTE)pbCode;
    ULONG Opcode = fetch_opcode(pbCode);

    if ((Opcode & 0x9f00001f) == 0x90000010) {           // adrp  x16, IAT
        ULONG Opcode2 = fetch_opcode(pbCode + 4);

        if ((Opcode2 & 0xffe003ff) == 0xf9400210) {      // ldr   x16, [x16, IAT]
            ULONG Opcode3 = fetch_opcode(pbCode + 8);

            if (Opcode3 == 0xd61f0200) {                 // br    x16

/* https://static.docs.arm.com/ddi0487/bb/DDI0487B_b_armv8_arm.pdf
    The ADRP instruction shifts a signed, 21-bit immediate left by 12 bits, adds it to the value of the program counter with
    the bottom 12 bits cleared to zero, and then writes the result to a general-purpose register. This permits the
    calculation of the address at a 4KB aligned memory region. In conjunction with an ADD (immediate) instruction, or
    a Load/Store instruction with a 12-bit immediate offset, this allows for the calculation of, or access to, any address
    within ±4GB of the current PC.

PC-rel. addressing
    This section describes the encoding of the PC-rel. addressing instruction class. The encodings in this section are
    decoded from Data Processing -- Immediate on page C4-226.
    Add/subtract (immediate)
    This section describes the encoding of the Add/subtract (immediate) instruction class. The encodings in this section
    are decoded from Data Processing -- Immediate on page C4-226.
    Decode fields
    Instruction page
    op
    0 ADR
    1 ADRP

C6.2.10 ADRP
    Form PC-relative address to 4KB page adds an immediate value that is shifted left by 12 bits, to the PC value to
    form a PC-relative address, with the bottom 12 bits masked out, and writes the result to the destination register.
    ADRP <Xd>, <label>
    imm = SignExtend(immhi:immlo:Zeros(12), 64);

    31  30 29 28 27 26 25 24 23 5    4 0
    1   immlo  1  0  0  0  0  immhi  Rd
         9             0

Rd is hardcoded as 0x10 above.
Immediate is 21 signed bits split into 2 bits and 19 bits, and is scaled by 4K.
*/
                UINT64 const pageLow2 = (Opcode >> 29) & 3;
                UINT64 const pageHigh19 = (Opcode >> 5) & ~(~0ui64 << 19);
                INT64 const page = entour_sign_extend((pageHigh19 << 2) | pageLow2, 21) << 12;

/* https://static.docs.arm.com/ddi0487/bb/DDI0487B_b_armv8_arm.pdf

    C6.2.101 LDR (immediate)
    Load Register (immediate) loads a word or doubleword from memory and writes it to a register. The address that is
    used for the load is calculated from a base register and an immediate offset.
    The Unsigned offset variant scales the immediate offset value by the size of the value accessed before adding it
    to the base register value.

Unsigned offset
64-bit variant Applies when size == 11.
    31 30 29 28  27 26 25 24  23 22  21   10   9 5   4 0
     1  x  1  1   1  0  0  1   0  1  imm12      Rn    Rt
         F             9        4              200    10

That is, two low 5 bit fields are registers, hardcoded as 0x10 and 0x10 << 5 above,
then unsigned size-unscaled (8) 12-bit offset, then opcode bits 0xF94.
*/
                UINT64 const offset = ((Opcode2 >> 10) & ~(~0ui64 << 12)) << 3;

                PBYTE const pbTarget = (PBYTE)((ULONG64)pbCode & 0xfffffffffffff000ULL) + page + offset;

                if (entour_is_imported(pbCode, pbTarget)) {
                    PBYTE pbNew = *(PBYTE *)pbTarget;
                    ENTOUR_TRACE(("%p->%p: skipped over import table.\n", pbCode, pbNew));
                    return pbNew;
                }
            }
        }
    }
    return pbCode;
}

inline void entour_find_jmp_bounds(PBYTE pbCode,
                                   PENTOUR_TRAMPOLINE *ppLower,
                                   PENTOUR_TRAMPOLINE *ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = entour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = entour_2gb_above((ULONG_PTR)pbCode);
    ENTOUR_TRACE(("[%p..%p..%p]\n", lo, pbCode, hi));

    *ppLower = (PENTOUR_TRAMPOLINE)lo;
    *ppUpper = (PENTOUR_TRAMPOLINE)hi;
}

inline BOOL entour_does_code_end_function(PBYTE pbCode)
{
    ULONG Opcode = fetch_opcode(pbCode);
    if ((Opcode & 0xfffffc1f) == 0xd65f0000 ||      // br <reg>
        (Opcode & 0xfc000000) == 0x14000000) {      // b <imm26>
        return TRUE;
    }
    return FALSE;
}

inline ULONG entour_is_code_filler(PBYTE pbCode)
{
    if (*(ULONG *)pbCode == 0xd503201f) {   // nop.
        return 4;
    }
    if (*(ULONG *)pbCode == 0x00000000) {   // zero-filled padding.
        return 4;
    }
    return 0;
}

#endif // ENTOURS_ARM64

//////////////////////////////////////////////// Trampoline Memory Management.

struct ENTOUR_REGION
{
    ULONG               dwSignature;
    ENTOUR_REGION *     pNext;  // Next region in list of regions.
    ENTOUR_TRAMPOLINE * pFree;  // List of free trampolines in this region.
};
typedef ENTOUR_REGION * PENTOUR_REGION;

//const ULONG ENTOUR_REGION_SIGNATURE = 'Rrtd';
const ULONG ENTOUR_REGION_SIGNATURE = MAKELONG(MAKEWORD('R', 'r'), MAKEWORD('t', 'd'));
const ULONG ENTOUR_REGION_SIZE = 0x10000;
const ULONG ENTOUR_TRAMPOLINES_PER_REGION = (ENTOUR_REGION_SIZE
                                             / sizeof(ENTOUR_TRAMPOLINE)) - 1;
static PENTOUR_REGION s_pRegions = NULL;            // List of all regions.
static PENTOUR_REGION s_pRegion = NULL;             // Default region.

static DWORD entour_writable_trampoline_regions()
{
    // Mark all of the regions as writable.
    for (PENTOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext) {
        DWORD dwOld;
        if (!VirtualProtect(pRegion, ENTOUR_REGION_SIZE, PAGE_EXECUTE_READWRITE, &dwOld)) {
            return GetLastError();
        }
    }
    return NO_ERROR;
}

static void entour_runnable_trampoline_regions()
{
    HANDLE hProcess = GetCurrentProcess();

    // Mark all of the regions as executable.
    for (PENTOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext) {
        DWORD dwOld;
        VirtualProtect(pRegion, ENTOUR_REGION_SIZE, PAGE_EXECUTE_READ, &dwOld);
        FlushInstructionCache(hProcess, pRegion, ENTOUR_REGION_SIZE);
    }
}

static PBYTE entour_alloc_round_down_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (ENTOUR_REGION_SIZE - 1);
    if (extra != 0) {
        pbTry -= extra;
    }
    return pbTry;
}

static PBYTE entour_alloc_round_up_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (ENTOUR_REGION_SIZE - 1);
    if (extra != 0) {
        ULONG_PTR adjust = ENTOUR_REGION_SIZE - extra;
        pbTry += adjust;
    }
    return pbTry;
}

// Starting at pbLo, try to allocate a memory region, continue until pbHi.

static PVOID entour_alloc_region_from_lo(PBYTE pbLo, PBYTE pbHi)
{
    PBYTE pbTry = entour_alloc_round_up_to_region(pbLo);

    ENTOUR_TRACE((" Looking for free region in %p..%p from %p:\n", pbLo, pbHi, pbTry));

    for (; pbTry < pbHi;) {
        MEMORY_BASIC_INFORMATION mbi;

        if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound) {
            // Skip region reserved for system DLLs, but preserve address space entropy.
            pbTry += 0x08000000;
            continue;
        }

        ZeroMemory(&mbi, sizeof(mbi));
        if (!VirtualQuery(pbTry, &mbi, sizeof(mbi))) {
            break;
        }

        ENTOUR_TRACE(("  Try %p => %p..%p %6x\n",
                      pbTry,
                      mbi.BaseAddress,
                      (PBYTE)mbi.BaseAddress + mbi.RegionSize - 1,
                      mbi.State));

        if (mbi.State == MEM_FREE && mbi.RegionSize >= ENTOUR_REGION_SIZE) {

            PVOID pv = VirtualAlloc(pbTry,
                                    ENTOUR_REGION_SIZE,
                                    MEM_COMMIT|MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
            if (pv != NULL) {
                return pv;
            }
            pbTry += ENTOUR_REGION_SIZE;
        }
        else {
            pbTry = entour_alloc_round_up_to_region((PBYTE)mbi.BaseAddress + mbi.RegionSize);
        }
    }
    return NULL;
}

// Starting at pbHi, try to allocate a memory region, continue until pbLo.

static PVOID entour_alloc_region_from_hi(PBYTE pbLo, PBYTE pbHi)
{
    PBYTE pbTry = entour_alloc_round_down_to_region(pbHi - ENTOUR_REGION_SIZE);

    ENTOUR_TRACE((" Looking for free region in %p..%p from %p:\n", pbLo, pbHi, pbTry));

    for (; pbTry > pbLo;) {
        MEMORY_BASIC_INFORMATION mbi;

        ENTOUR_TRACE(("  Try %p\n", pbTry));
        if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound) {
            // Skip region reserved for system DLLs, but preserve address space entropy.
            pbTry -= 0x08000000;
            continue;
        }

        ZeroMemory(&mbi, sizeof(mbi));
        if (!VirtualQuery(pbTry, &mbi, sizeof(mbi))) {
            break;
        }

        ENTOUR_TRACE(("  Try %p => %p..%p %6x\n",
                      pbTry,
                      mbi.BaseAddress,
                      (PBYTE)mbi.BaseAddress + mbi.RegionSize - 1,
                      mbi.State));

        if (mbi.State == MEM_FREE && mbi.RegionSize >= ENTOUR_REGION_SIZE) {

            PVOID pv = VirtualAlloc(pbTry,
                                    ENTOUR_REGION_SIZE,
                                    MEM_COMMIT|MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
            if (pv != NULL) {
                return pv;
            }
            pbTry -= ENTOUR_REGION_SIZE;
        }
        else {
            pbTry = entour_alloc_round_down_to_region((PBYTE)mbi.AllocationBase
                                                      - ENTOUR_REGION_SIZE);
        }
    }
    return NULL;
}

static PENTOUR_TRAMPOLINE entour_alloc_trampoline(PBYTE pbTarget)
{
    // We have to place trampolines within +/- 2GB of target.

    PENTOUR_TRAMPOLINE pLo;
    PENTOUR_TRAMPOLINE pHi;

    entour_find_jmp_bounds(pbTarget, &pLo, &pHi);

    PENTOUR_TRAMPOLINE pTrampoline = NULL;

    // Insure that there is a default region.
    if (s_pRegion == NULL && s_pRegions != NULL) {
        s_pRegion = s_pRegions;
    }

    // First check the default region for an valid free block.
    if (s_pRegion != NULL && s_pRegion->pFree != NULL &&
        s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi) {

      found_region:
        pTrampoline = s_pRegion->pFree;
        // do a last sanity check on region.
        if (pTrampoline < pLo || pTrampoline > pHi) {
            return NULL;
        }
        s_pRegion->pFree = (PENTOUR_TRAMPOLINE)pTrampoline->pbRemain;
        memset(pTrampoline, 0xcc, sizeof(*pTrampoline));
        return pTrampoline;
    }

    // Then check the existing regions for a valid free block.
    for (s_pRegion = s_pRegions; s_pRegion != NULL; s_pRegion = s_pRegion->pNext) {
        if (s_pRegion != NULL && s_pRegion->pFree != NULL &&
            s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi) {
            goto found_region;
        }
    }

    // We need to allocate a new region.

    // Round pbTarget down to 64KB block.
    pbTarget = pbTarget - (PtrToUlong(pbTarget) & 0xffff);

    PVOID pbTry = NULL;

    // NB: We must always also start the search at an offset from pbTarget
    //     in order to maintain ASLR entropy.

#if defined(ENTOURS_64BIT)
    // Try looking 1GB below or lower.
    if (pbTry == NULL && pbTarget > (PBYTE)0x40000000) {
        pbTry = entour_alloc_region_from_hi((PBYTE)pLo, pbTarget - 0x40000000);
    }
    // Try looking 1GB above or higher.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000) {
        pbTry = entour_alloc_region_from_lo(pbTarget + 0x40000000, (PBYTE)pHi);
    }
    // Try looking 1GB below or higher.
    if (pbTry == NULL && pbTarget > (PBYTE)0x40000000) {
        pbTry = entour_alloc_region_from_lo(pbTarget - 0x40000000, pbTarget);
    }
    // Try looking 1GB above or lower.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000) {
        pbTry = entour_alloc_region_from_hi(pbTarget, pbTarget + 0x40000000);
    }
#endif

    // Try anything below.
    if (pbTry == NULL) {
        pbTry = entour_alloc_region_from_hi((PBYTE)pLo, pbTarget);
    }
    // try anything above.
    if (pbTry == NULL) {
        pbTry = entour_alloc_region_from_lo(pbTarget, (PBYTE)pHi);
    }

    if (pbTry != NULL) {
        s_pRegion = (ENTOUR_REGION*)pbTry;
        s_pRegion->dwSignature = ENTOUR_REGION_SIGNATURE;
        s_pRegion->pFree = NULL;
        s_pRegion->pNext = s_pRegions;
        s_pRegions = s_pRegion;
        ENTOUR_TRACE(("  Allocated region %p..%p\n\n",
                      s_pRegion, ((PBYTE)s_pRegion) + ENTOUR_REGION_SIZE - 1));

        // Put everything but the first trampoline on the free list.
        PBYTE pFree = NULL;
        pTrampoline = ((PENTOUR_TRAMPOLINE)s_pRegion) + 1;
        for (int i = ENTOUR_TRAMPOLINES_PER_REGION - 1; i > 1; i--) {
            pTrampoline[i].pbRemain = pFree;
            pFree = (PBYTE)&pTrampoline[i];
        }
        s_pRegion->pFree = (PENTOUR_TRAMPOLINE)pFree;
        goto found_region;
    }

    ENTOUR_TRACE(("Couldn't find available memory region!\n"));
    return NULL;
}

static void entour_free_trampoline(PENTOUR_TRAMPOLINE pTrampoline)
{
    PENTOUR_REGION pRegion = (PENTOUR_REGION)
        ((ULONG_PTR)pTrampoline & ~(ULONG_PTR)0xffff);

    memset(pTrampoline, 0, sizeof(*pTrampoline));
    pTrampoline->pbRemain = (PBYTE)pRegion->pFree;
    pRegion->pFree = pTrampoline;
}

static BOOL entour_is_region_empty(PENTOUR_REGION pRegion)
{
    // Stop if the region isn't a region (this would be bad).
    if (pRegion->dwSignature != ENTOUR_REGION_SIGNATURE) {
        return FALSE;
    }

    PBYTE pbRegionBeg = (PBYTE)pRegion;
    PBYTE pbRegionLim  = pbRegionBeg + ENTOUR_REGION_SIZE;

    // Stop if any of the trampolines aren't free.
    PENTOUR_TRAMPOLINE pTrampoline = ((PENTOUR_TRAMPOLINE)pRegion) + 1;
    for (int i = 0; i < (int)ENTOUR_TRAMPOLINES_PER_REGION; i++) {
        if (pTrampoline[i].pbRemain != NULL &&
            (pTrampoline[i].pbRemain < pbRegionBeg ||
             pTrampoline[i].pbRemain >= pbRegionLim)) {
            return FALSE;
        }
    }

    // OK, the region is empty.
    return TRUE;
}

static void entour_free_unused_trampoline_regions()
{
    PENTOUR_REGION *ppRegionBase = &s_pRegions;
    PENTOUR_REGION pRegion = s_pRegions;

    while (pRegion != NULL) {
        if (entour_is_region_empty(pRegion)) {
            *ppRegionBase = pRegion->pNext;

            VirtualFree(pRegion, 0, MEM_RELEASE);
            s_pRegion = NULL;
        }
        else {
            ppRegionBase = &pRegion->pNext;
        }
        pRegion = *ppRegionBase;
    }
}

///////////////////////////////////////////////////////// Transaction Structs.

struct EntourThread
{
    EntourThread *      pNext;
    HANDLE              hThread;
};

struct EntourOperation
{
    EntourOperation *   pNext;
    BOOL                fIsRemove;
    PBYTE *             ppbPointer;
    PBYTE               pbTarget;
    PENTOUR_TRAMPOLINE  pTrampoline;
    ULONG               dwPerm;
};

static BOOL                 s_fIgnoreTooSmall       = FALSE;
static BOOL                 s_fRetainRegions        = FALSE;

static LONG                 s_nPendingThreadId      = 0; // Thread owning pending transaction.
static LONG                 s_nPendingError         = NO_ERROR;
static PVOID *              s_ppPendingError        = NULL;
static EntourThread *       s_pPendingThreads       = NULL;
static EntourOperation *    s_pPendingOperations    = NULL;

//////////////////////////////////////////////////////////////////////////////

PVOID WINAPI EntourCodeFromPointer(_In_ const VOID *pPointer,
                                   _Out_opt_ PVOID *ppGlobals)
{
    return entour_skip_jmp((PBYTE)pPointer, ppGlobals);
}

//////////////////////////////////////////////////////////// Transaction APIs.

BOOL WINAPI EntourSetIgnoreTooSmall(_In_ BOOL fIgnore)
{
    BOOL fPrevious = s_fIgnoreTooSmall;
    s_fIgnoreTooSmall = fIgnore;
    return fPrevious;
}

BOOL WINAPI EntourSetRetainRegions(_In_ BOOL fRetain)
{
    BOOL fPrevious = s_fRetainRegions;
    s_fRetainRegions = fRetain;
    return fPrevious;
}

PVOID WINAPI EntourSetSystemRegionLowerBound(_In_ PVOID pSystemRegionLowerBound)
{
    PVOID pPrevious = s_pSystemRegionLowerBound;
    s_pSystemRegionLowerBound = pSystemRegionLowerBound;
    return pPrevious;
}

PVOID WINAPI EntourSetSystemRegionUpperBound(_In_ PVOID pSystemRegionUpperBound)
{
    PVOID pPrevious = s_pSystemRegionUpperBound;
    s_pSystemRegionUpperBound = pSystemRegionUpperBound;
    return pPrevious;
}

LONG WINAPI EntourTransactionBegin()
{
    // Only one transaction is allowed at a time.
_Benign_race_begin_
    if (s_nPendingThreadId != 0) {
        return ERROR_INVALID_OPERATION;
    }
_Benign_race_end_

    // Make sure only one thread can start a transaction.
    if (InterlockedCompareExchange(&s_nPendingThreadId, (LONG)GetCurrentThreadId(), 0) != 0) {
        return ERROR_INVALID_OPERATION;
    }

    s_pPendingOperations = NULL;
    s_pPendingThreads = NULL;
    s_ppPendingError = NULL;

    // Make sure the trampoline pages are writable.
    s_nPendingError = entour_writable_trampoline_regions();

    return s_nPendingError;
}

LONG WINAPI EntourTransactionAbort()
{
    if (s_nPendingThreadId != (LONG)GetCurrentThreadId()) {
        return ERROR_INVALID_OPERATION;
    }

    // Restore all of the page permissions.
    for (EntourOperation *o = s_pPendingOperations; o != NULL;) {
        // We don't care if this fails, because the code is still accessible.
        DWORD dwOld;
        VirtualProtect(o->pbTarget, o->pTrampoline->cbRestore,
                       o->dwPerm, &dwOld);

        if (!o->fIsRemove) {
            if (o->pTrampoline) {
                entour_free_trampoline(o->pTrampoline);
                o->pTrampoline = NULL;
            }
        }

        EntourOperation *n = o->pNext;
        delete o;
        o = n;
    }
    s_pPendingOperations = NULL;

    // Make sure the trampoline pages are no longer writable.
    entour_runnable_trampoline_regions();

    // Resume any suspended threads.
    for (EntourThread *t = s_pPendingThreads; t != NULL;) {
        // There is nothing we can do if this fails.
        ResumeThread(t->hThread);

        EntourThread *n = t->pNext;
        delete t;
        t = n;
    }
    s_pPendingThreads = NULL;
    s_nPendingThreadId = 0;

    return NO_ERROR;
}

LONG WINAPI EntourTransactionCommit()
{
    return EntourTransactionCommitEx(NULL);
}

static BYTE entour_align_from_trampoline(PENTOUR_TRAMPOLINE pTrampoline, BYTE obTrampoline)
{
    for (LONG n = 0; n < (LONG)ARRAYSIZE(pTrampoline->rAlign); n++) {
        if (pTrampoline->rAlign[n].obTrampoline == obTrampoline) {
            return pTrampoline->rAlign[n].obTarget;
        }
    }
    return 0;
}

static LONG entour_align_from_target(PENTOUR_TRAMPOLINE pTrampoline, LONG obTarget)
{
    for (LONG n = 0; n < (LONG)ARRAYSIZE(pTrampoline->rAlign); n++) {
        if (pTrampoline->rAlign[n].obTarget == obTarget) {
            return pTrampoline->rAlign[n].obTrampoline;
        }
    }
    return 0;
}

LONG WINAPI EntourTransactionCommitEx(_Out_opt_ PVOID **pppFailedPointer)
{
    if (pppFailedPointer != NULL) {
        // Used to get the last error.
        *pppFailedPointer = s_ppPendingError;
    }
    if (s_nPendingThreadId != (LONG)GetCurrentThreadId()) {
        return ERROR_INVALID_OPERATION;
    }

    // If any of the pending operations failed, then we abort the whole transaction.
    if (s_nPendingError != NO_ERROR) {
        ENTOUR_BREAK();
        EntourTransactionAbort();
        return s_nPendingError;
    }

    // Common variables.
    EntourOperation *o;
    EntourThread *t;
    BOOL freed = FALSE;

    // Insert or remove each of the entours.
    for (o = s_pPendingOperations; o != NULL; o = o->pNext) {
        if (o->fIsRemove) {
            CopyMemory(o->pbTarget,
                       o->pTrampoline->rbRestore,
                       o->pTrampoline->cbRestore);
#ifdef ENTOURS_IA64
            *o->ppbPointer = (PBYTE)o->pTrampoline->ppldTarget;
#endif // ENTOURS_IA64

#ifdef ENTOURS_X86
            *o->ppbPointer = o->pbTarget;
#endif // ENTOURS_X86

#ifdef ENTOURS_X64
            *o->ppbPointer = o->pbTarget;
#endif // ENTOURS_X64

#ifdef ENTOURS_ARM
            *o->ppbPointer = ENTOURS_PBYTE_TO_PFUNC(o->pbTarget);
#endif // ENTOURS_ARM

#ifdef ENTOURS_ARM64
            *o->ppbPointer = o->pbTarget;
#endif // ENTOURS_ARM
        }
        else {
            ENTOUR_TRACE(("entours: pbTramp =%p, pbRemain=%p, pbEntour=%p, cbRestore=%d\n",
                          o->pTrampoline,
                          o->pTrampoline->pbRemain,
                          o->pTrampoline->pbEntour,
                          o->pTrampoline->cbRestore));

            ENTOUR_TRACE(("entours: pbTarget=%p: "
                          "%02x %02x %02x %02x "
                          "%02x %02x %02x %02x "
                          "%02x %02x %02x %02x [before]\n",
                          o->pbTarget,
                          o->pbTarget[0], o->pbTarget[1], o->pbTarget[2], o->pbTarget[3],
                          o->pbTarget[4], o->pbTarget[5], o->pbTarget[6], o->pbTarget[7],
                          o->pbTarget[8], o->pbTarget[9], o->pbTarget[10], o->pbTarget[11]));

#ifdef ENTOURS_IA64
            ((ENTOUR_IA64_BUNDLE*)o->pbTarget)
                ->SetBrl((UINT64)&o->pTrampoline->bAllocFrame);
            *o->ppbPointer = (PBYTE)&o->pTrampoline->pldTrampoline;
#endif // ENTOURS_IA64

#ifdef ENTOURS_X64
            entour_gen_jmp_indirect(o->pTrampoline->rbCodeIn, &o->pTrampoline->pbEntour);
            PBYTE pbCode = entour_gen_jmp_immediate(o->pbTarget, o->pTrampoline->rbCodeIn);
            pbCode = entour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            *o->ppbPointer = o->pTrampoline->rbCode;
            UNREFERENCED_PARAMETER(pbCode);
#endif // ENTOURS_X64

#ifdef ENTOURS_X86
            PBYTE pbCode = entour_gen_jmp_immediate(o->pbTarget, o->pTrampoline->pbEntour);
            pbCode = entour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            *o->ppbPointer = o->pTrampoline->rbCode;
            UNREFERENCED_PARAMETER(pbCode);
#endif // ENTOURS_X86

#ifdef ENTOURS_ARM
            PBYTE pbCode = entour_gen_jmp_immediate(o->pbTarget, NULL, o->pTrampoline->pbEntour);
            pbCode = entour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            *o->ppbPointer = ENTOURS_PBYTE_TO_PFUNC(o->pTrampoline->rbCode);
            UNREFERENCED_PARAMETER(pbCode);
#endif // ENTOURS_ARM

#ifdef ENTOURS_ARM64
            PBYTE pbCode = entour_gen_jmp_immediate(o->pbTarget, NULL, o->pTrampoline->pbEntour);
            pbCode = entour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            *o->ppbPointer = o->pTrampoline->rbCode;
            UNREFERENCED_PARAMETER(pbCode);
#endif // ENTOURS_ARM64

            ENTOUR_TRACE(("entours: pbTarget=%p: "
                          "%02x %02x %02x %02x "
                          "%02x %02x %02x %02x "
                          "%02x %02x %02x %02x [after]\n",
                          o->pbTarget,
                          o->pbTarget[0], o->pbTarget[1], o->pbTarget[2], o->pbTarget[3],
                          o->pbTarget[4], o->pbTarget[5], o->pbTarget[6], o->pbTarget[7],
                          o->pbTarget[8], o->pbTarget[9], o->pbTarget[10], o->pbTarget[11]));

            ENTOUR_TRACE(("entours: pbTramp =%p: "
                          "%02x %02x %02x %02x "
                          "%02x %02x %02x %02x "
                          "%02x %02x %02x %02x\n",
                          o->pTrampoline,
                          o->pTrampoline->rbCode[0], o->pTrampoline->rbCode[1],
                          o->pTrampoline->rbCode[2], o->pTrampoline->rbCode[3],
                          o->pTrampoline->rbCode[4], o->pTrampoline->rbCode[5],
                          o->pTrampoline->rbCode[6], o->pTrampoline->rbCode[7],
                          o->pTrampoline->rbCode[8], o->pTrampoline->rbCode[9],
                          o->pTrampoline->rbCode[10], o->pTrampoline->rbCode[11]));

#ifdef ENTOURS_IA64
            ENTOUR_TRACE(("\n"));
            ENTOUR_TRACE(("entours:  &pldTrampoline  =%p\n",
                          &o->pTrampoline->pldTrampoline));
            ENTOUR_TRACE(("entours:  &bMovlTargetGp  =%p [%p]\n",
                          &o->pTrampoline->bMovlTargetGp,
                          o->pTrampoline->bMovlTargetGp.GetMovlGp()));
            ENTOUR_TRACE(("entours:  &rbCode         =%p [%p]\n",
                          &o->pTrampoline->rbCode,
                          ((ENTOUR_IA64_BUNDLE&)o->pTrampoline->rbCode).GetBrlTarget()));
            ENTOUR_TRACE(("entours:  &bBrlRemainEip  =%p [%p]\n",
                          &o->pTrampoline->bBrlRemainEip,
                          o->pTrampoline->bBrlRemainEip.GetBrlTarget()));
            ENTOUR_TRACE(("entours:  &bMovlEntourGp  =%p [%p]\n",
                          &o->pTrampoline->bMovlEntourGp,
                          o->pTrampoline->bMovlEntourGp.GetMovlGp()));
            ENTOUR_TRACE(("entours:  &bBrlEntourEip  =%p [%p]\n",
                          &o->pTrampoline->bCallEntour,
                          o->pTrampoline->bCallEntour.GetBrlTarget()));
            ENTOUR_TRACE(("entours:  pldEntour       =%p [%p]\n",
                          o->pTrampoline->ppldEntour->EntryPoint,
                          o->pTrampoline->ppldEntour->GlobalPointer));
            ENTOUR_TRACE(("entours:  pldTarget       =%p [%p]\n",
                          o->pTrampoline->ppldTarget->EntryPoint,
                          o->pTrampoline->ppldTarget->GlobalPointer));
            ENTOUR_TRACE(("entours:  pbRemain        =%p\n",
                          o->pTrampoline->pbRemain));
            ENTOUR_TRACE(("entours:  pbEntour        =%p\n",
                          o->pTrampoline->pbEntour));
            ENTOUR_TRACE(("\n"));
#endif // ENTOURS_IA64
        }
    }

    // Update any suspended threads.
    for (t = s_pPendingThreads; t != NULL; t = t->pNext) {
        CONTEXT cxt;
        cxt.ContextFlags = CONTEXT_CONTROL;

#undef ENTOURS_EIP

#ifdef ENTOURS_X86
    #define ENTOURS_EIP         Eip
#endif // ENTOURS_X86
#ifdef ENTOURS_X64
    #define ENTOURS_EIP         Rip
#endif // ENTOURS_X64
#ifdef ENTOURS_IA64
    #define ENTOURS_EIP         StIIP
#endif // ENTOURS_IA64
#ifdef ENTOURS_ARM
    #define ENTOURS_EIP         Pc
#endif // ENTOURS_ARM
#ifdef ENTOURS_ARM64
    #define ENTOURS_EIP         Pc
#endif // ENTOURS_ARM64

typedef ULONG_PTR ENTOURS_EIP_TYPE;

        if (GetThreadContext(t->hThread, &cxt)) {
            for (o = s_pPendingOperations; o != NULL; o = o->pNext) {
                if (o->fIsRemove) {
                    if (cxt.ENTOURS_EIP >= (ENTOURS_EIP_TYPE)(ULONG_PTR)o->pTrampoline &&
                        cxt.ENTOURS_EIP < (ENTOURS_EIP_TYPE)((ULONG_PTR)o->pTrampoline
                                                             + sizeof(o->pTrampoline))
                       ) {

                        cxt.ENTOURS_EIP = (ENTOURS_EIP_TYPE)
                            ((ULONG_PTR)o->pbTarget
                             + entour_align_from_trampoline(o->pTrampoline,
                                                            (BYTE)(cxt.ENTOURS_EIP
                                                                   - (ENTOURS_EIP_TYPE)(ULONG_PTR)
                                                                   o->pTrampoline)));

                        SetThreadContext(t->hThread, &cxt);
                    }
                }
                else {
                    if (cxt.ENTOURS_EIP >= (ENTOURS_EIP_TYPE)(ULONG_PTR)o->pbTarget &&
                        cxt.ENTOURS_EIP < (ENTOURS_EIP_TYPE)((ULONG_PTR)o->pbTarget
                                                             + o->pTrampoline->cbRestore)
                       ) {

                        cxt.ENTOURS_EIP = (ENTOURS_EIP_TYPE)
                            ((ULONG_PTR)o->pTrampoline
                             + entour_align_from_target(o->pTrampoline,
                                                        (BYTE)(cxt.ENTOURS_EIP
                                                               - (ENTOURS_EIP_TYPE)(ULONG_PTR)
                                                               o->pbTarget)));

                        SetThreadContext(t->hThread, &cxt);
                    }
                }
            }
        }
#undef ENTOURS_EIP
    }

    // Restore all of the page permissions and flush the icache.
    HANDLE hProcess = GetCurrentProcess();
    for (o = s_pPendingOperations; o != NULL;) {
        // We don't care if this fails, because the code is still accessible.
        DWORD dwOld;
        VirtualProtect(o->pbTarget, o->pTrampoline->cbRestore, o->dwPerm, &dwOld);
        FlushInstructionCache(hProcess, o->pbTarget, o->pTrampoline->cbRestore);

        if (o->fIsRemove && o->pTrampoline) {
            entour_free_trampoline(o->pTrampoline);
            o->pTrampoline = NULL;
            freed = true;
        }

        EntourOperation *n = o->pNext;
        delete o;
        o = n;
    }
    s_pPendingOperations = NULL;

    // Free any trampoline regions that are now unused.
    if (freed && !s_fRetainRegions) {
        entour_free_unused_trampoline_regions();
    }

    // Make sure the trampoline pages are no longer writable.
    entour_runnable_trampoline_regions();

    // Resume any suspended threads.
    for (t = s_pPendingThreads; t != NULL;) {
        // There is nothing we can do if this fails.
        ResumeThread(t->hThread);

        EntourThread *n = t->pNext;
        delete t;
        t = n;
    }
    s_pPendingThreads = NULL;
    s_nPendingThreadId = 0;

    if (pppFailedPointer != NULL) {
        *pppFailedPointer = s_ppPendingError;
    }

    return s_nPendingError;
}

LONG WINAPI EntourUpdateThread(_In_ HANDLE hThread)
{
    LONG error;

    // If any of the pending operations failed, then we don't need to do this.
    if (s_nPendingError != NO_ERROR) {
        return s_nPendingError;
    }

    // Silently (and safely) drop any attempt to suspend our own thread.
    if (hThread == GetCurrentThread()) {
        return NO_ERROR;
    }

    EntourThread *t = new NOTHROW EntourThread;
    if (t == NULL) {
        error = ERROR_NOT_ENOUGH_MEMORY;
      fail:
        if (t != NULL) {
            delete t;
            t = NULL;
        }
        s_nPendingError = error;
        s_ppPendingError = NULL;
        ENTOUR_BREAK();
        return error;
    }

    if (SuspendThread(hThread) == (DWORD)-1) {
        error = GetLastError();
        ENTOUR_BREAK();
        goto fail;
    }

    t->hThread = hThread;
    t->pNext = s_pPendingThreads;
    s_pPendingThreads = t;

    return NO_ERROR;
}

///////////////////////////////////////////////////////////// Transacted APIs.

LONG WINAPI EntourAttach(_Inout_ PVOID *ppPointer,
                         _In_ PVOID pEntour)
{
    return EntourAttachEx(ppPointer, pEntour, NULL, NULL, NULL);
}

LONG WINAPI EntourAttachEx(_Inout_ PVOID *ppPointer,
                           _In_ PVOID pEntour,
                           _Out_opt_ PENTOUR_TRAMPOLINE *ppRealTrampoline,
                           _Out_opt_ PVOID *ppRealTarget,
                           _Out_opt_ PVOID *ppRealEntour)
{
    LONG error = NO_ERROR;

    if (ppRealTrampoline != NULL) {
        *ppRealTrampoline = NULL;
    }
    if (ppRealTarget != NULL) {
        *ppRealTarget = NULL;
    }
    if (ppRealEntour != NULL) {
        *ppRealEntour = NULL;
    }
    if (pEntour == NULL) {
        ENTOUR_TRACE(("empty entour\n"));
        return ERROR_INVALID_PARAMETER;
    }

    if (s_nPendingThreadId != (LONG)GetCurrentThreadId()) {
        ENTOUR_TRACE(("transaction conflict with thread id=%d\n", s_nPendingThreadId));
        return ERROR_INVALID_OPERATION;
    }

    // If any of the pending operations failed, then we don't need to do this.
    if (s_nPendingError != NO_ERROR) {
        ENTOUR_TRACE(("pending transaction error=%d\n", s_nPendingError));
        return s_nPendingError;
    }

    if (ppPointer == NULL) {
        ENTOUR_TRACE(("ppPointer is null\n"));
        return ERROR_INVALID_HANDLE;
    }
    if (*ppPointer == NULL) {
        error = ERROR_INVALID_HANDLE;
        s_nPendingError = error;
        s_ppPendingError = ppPointer;
        ENTOUR_TRACE(("*ppPointer is null (ppPointer=%p)\n", ppPointer));
        ENTOUR_BREAK();
        return error;
    }

    PBYTE pbTarget = (PBYTE)*ppPointer;
    PENTOUR_TRAMPOLINE pTrampoline = NULL;
    EntourOperation *o = NULL;

#ifdef ENTOURS_IA64
    PPLABEL_DESCRIPTOR ppldEntour = (PPLABEL_DESCRIPTOR)pEntour;
    PPLABEL_DESCRIPTOR ppldTarget = (PPLABEL_DESCRIPTOR)pbTarget;
    PVOID pEntourGlobals = NULL;
    PVOID pTargetGlobals = NULL;

    pEntour = (PBYTE)EntourCodeFromPointer(ppldEntour, &pEntourGlobals);
    pbTarget = (PBYTE)EntourCodeFromPointer(ppldTarget, &pTargetGlobals);
    ENTOUR_TRACE(("  ppldEntour=%p, code=%p [gp=%p]\n",
                  ppldEntour, pEntour, pEntourGlobals));
    ENTOUR_TRACE(("  ppldTarget=%p, code=%p [gp=%p]\n",
                  ppldTarget, pbTarget, pTargetGlobals));
#else // ENTOURS_IA64
    pbTarget = (PBYTE)EntourCodeFromPointer(pbTarget, NULL);
    pEntour = EntourCodeFromPointer(pEntour, NULL);
#endif // !ENTOURS_IA64

    // Don't follow a jump if its destination is the target function.
    // This happens when the entour does nothing other than call the target.
    if (pEntour == (PVOID)pbTarget) {
        if (s_fIgnoreTooSmall) {
            goto stop;
        }
        else {
            ENTOUR_BREAK();
            goto fail;
        }
    }

    if (ppRealTarget != NULL) {
        *ppRealTarget = pbTarget;
    }
    if (ppRealEntour != NULL) {
        *ppRealEntour = pEntour;
    }

    o = new NOTHROW EntourOperation;
    if (o == NULL) {
        error = ERROR_NOT_ENOUGH_MEMORY;
      fail:
        s_nPendingError = error;
        ENTOUR_BREAK();
      stop:
        if (pTrampoline != NULL) {
            entour_free_trampoline(pTrampoline);
            pTrampoline = NULL;
            if (ppRealTrampoline != NULL) {
                *ppRealTrampoline = NULL;
            }
        }
        if (o != NULL) {
            delete o;
            o = NULL;
        }
        s_ppPendingError = ppPointer;
        return error;
    }

    pTrampoline = entour_alloc_trampoline(pbTarget);
    if (pTrampoline == NULL) {
        error = ERROR_NOT_ENOUGH_MEMORY;
        ENTOUR_BREAK();
        goto fail;
    }

    if (ppRealTrampoline != NULL) {
        *ppRealTrampoline = pTrampoline;
    }

    ENTOUR_TRACE(("entours: pbTramp=%p, pEntour=%p\n", pTrampoline, pEntour));

    memset(pTrampoline->rAlign, 0, sizeof(pTrampoline->rAlign));

    // Determine the number of movable target instructions.
    PBYTE pbSrc = pbTarget;
    PBYTE pbTrampoline = pTrampoline->rbCode;
#ifdef ENTOURS_IA64
    PBYTE pbPool = (PBYTE)(&pTrampoline->bBranchIslands + 1);
#else
    PBYTE pbPool = pbTrampoline + sizeof(pTrampoline->rbCode);
#endif
    ULONG cbTarget = 0;
    ULONG cbJump = SIZE_OF_JMP;
    ULONG nAlign = 0;

#ifdef ENTOURS_ARM
    // On ARM, we need an extra instruction when the function isn't 32-bit aligned.
    // Check if the existing code is another entour (or at least a similar
    // "ldr pc, [PC+0]" jump.
    if ((ULONG)pbTarget & 2) {
        cbJump += 2;

        ULONG op = fetch_thumb_opcode(pbSrc);
        if (op == 0xbf00) {
            op = fetch_thumb_opcode(pbSrc + 2);
            if (op == 0xf8dff000) { // LDR PC,[PC]
                *((PUSHORT&)pbTrampoline)++ = *((PUSHORT&)pbSrc)++;
                *((PULONG&)pbTrampoline)++ = *((PULONG&)pbSrc)++;
                *((PULONG&)pbTrampoline)++ = *((PULONG&)pbSrc)++;
                cbTarget = (LONG)(pbSrc - pbTarget);
                // We will fall through the "while" because cbTarget is now >= cbJump.
            }
        }
    }
    else {
        ULONG op = fetch_thumb_opcode(pbSrc);
        if (op == 0xf8dff000) { // LDR PC,[PC]
            *((PULONG&)pbTrampoline)++ = *((PULONG&)pbSrc)++;
            *((PULONG&)pbTrampoline)++ = *((PULONG&)pbSrc)++;
            cbTarget = (LONG)(pbSrc - pbTarget);
            // We will fall through the "while" because cbTarget is now >= cbJump.
        }
    }
#endif

    while (cbTarget < cbJump) {
        PBYTE pbOp = pbSrc;
        LONG lExtra = 0;

        ENTOUR_TRACE((" EntourCopyInstruction(%p,%p)\n",
                      pbTrampoline, pbSrc));
        pbSrc = (PBYTE)
            EntourCopyInstruction(pbTrampoline, (PVOID*)&pbPool, pbSrc, NULL, &lExtra);
        ENTOUR_TRACE((" EntourCopyInstruction() = %p (%d bytes)\n",
                      pbSrc, (int)(pbSrc - pbOp)));
        pbTrampoline += (pbSrc - pbOp) + lExtra;
        cbTarget = (LONG)(pbSrc - pbTarget);
        pTrampoline->rAlign[nAlign].obTarget = cbTarget;
        pTrampoline->rAlign[nAlign].obTrampoline = pbTrampoline - pTrampoline->rbCode;
        nAlign++;

        if (nAlign >= ARRAYSIZE(pTrampoline->rAlign)) {
            break;
        }

        if (entour_does_code_end_function(pbOp)) {
            break;
        }
    }

    // Consume, but don't duplicate padding if it is needed and available.
    while (cbTarget < cbJump) {
        LONG cFiller = entour_is_code_filler(pbSrc);
        if (cFiller == 0) {
            break;
        }

        pbSrc += cFiller;
        cbTarget = (LONG)(pbSrc - pbTarget);
    }

#if ENTOUR_DEBUG
    {
        ENTOUR_TRACE((" entours: rAlign ["));
        LONG n = 0;
        for (n = 0; n < ARRAYSIZE(pTrampoline->rAlign); n++) {
            if (pTrampoline->rAlign[n].obTarget == 0 &&
                pTrampoline->rAlign[n].obTrampoline == 0) {
                break;
            }
            ENTOUR_TRACE((" %d/%d",
                          pTrampoline->rAlign[n].obTarget,
                          pTrampoline->rAlign[n].obTrampoline
                          ));

        }
        ENTOUR_TRACE((" ]\n"));
    }
#endif

    if (cbTarget < cbJump || nAlign > ARRAYSIZE(pTrampoline->rAlign)) {
        // Too few instructions.

        error = ERROR_INVALID_BLOCK;
        if (s_fIgnoreTooSmall) {
            goto stop;
        }
        else {
            ENTOUR_BREAK();
            goto fail;
        }
    }

    if (pbTrampoline > pbPool) {
        __debugbreak();
    }

    pTrampoline->cbCode = (BYTE)(pbTrampoline - pTrampoline->rbCode);
    pTrampoline->cbRestore = (BYTE)cbTarget;
    CopyMemory(pTrampoline->rbRestore, pbTarget, cbTarget);

#if !defined(ENTOURS_IA64)
    if (cbTarget > sizeof(pTrampoline->rbCode) - cbJump) {
        // Too many instructions.
        error = ERROR_INVALID_HANDLE;
        ENTOUR_BREAK();
        goto fail;
    }
#endif // !ENTOURS_IA64

    pTrampoline->pbRemain = pbTarget + cbTarget;
    pTrampoline->pbEntour = (PBYTE)pEntour;

#ifdef ENTOURS_IA64
    pTrampoline->ppldEntour = ppldEntour;
    pTrampoline->ppldTarget = ppldTarget;
    pTrampoline->pldTrampoline.EntryPoint = (UINT64)&pTrampoline->bMovlTargetGp;
    pTrampoline->pldTrampoline.GlobalPointer = (UINT64)pEntourGlobals;

    ((ENTOUR_IA64_BUNDLE *)pTrampoline->rbCode)->SetStop();

    pTrampoline->bMovlTargetGp.SetMovlGp((UINT64)pTargetGlobals);
    pTrampoline->bBrlRemainEip.SetBrl((UINT64)pTrampoline->pbRemain);

    // Alloc frame:      alloc r41=ar.pfs,11,0,8,0; mov r40=rp
    pTrampoline->bAllocFrame.wide[0] = 0x00000580164d480c;
    pTrampoline->bAllocFrame.wide[1] = 0x00c4000500000200;
    // save r36, r37, r38.
    pTrampoline->bSave37to39.wide[0] = 0x031021004e019001;
    pTrampoline->bSave37to39.wide[1] = 0x8401280600420098;
    // save r34,r35,r36: adds r47=0,r36; adds r46=0,r35; adds r45=0,r34
    pTrampoline->bSave34to36.wide[0] = 0x02e0210048017800;
    pTrampoline->bSave34to36.wide[1] = 0x84011005a042008c;
    // save gp,r32,r33"  adds r44=0,r33; adds r43=0,r32; adds r42=0,gp ;;
    pTrampoline->bSaveGPto33.wide[0] = 0x02b0210042016001;
    pTrampoline->bSaveGPto33.wide[1] = 0x8400080540420080;
    // set entour GP.
    pTrampoline->bMovlEntourGp.SetMovlGp((UINT64)pEntourGlobals);
    // call entour:      brl.call.sptk.few rp=entour ;;
    pTrampoline->bCallEntour.wide[0] = 0x0000000100000005;
    pTrampoline->bCallEntour.wide[1] = 0xd000001000000000;
    pTrampoline->bCallEntour.SetBrlTarget((UINT64)pEntour);
    // pop frame & gp:   adds gp=0,r42; mov rp=r40,+0;; mov.i ar.pfs=r41
    pTrampoline->bPopFrameGp.wide[0] = 0x4000210054000802;
    pTrampoline->bPopFrameGp.wide[1] = 0x00aa029000038005;
    // return to caller: br.ret.sptk.many rp ;;
    pTrampoline->bReturn.wide[0] = 0x0000000100000019;
    pTrampoline->bReturn.wide[1] = 0x0084000880000200;

    ENTOUR_TRACE(("entours: &bMovlTargetGp=%p\n", &pTrampoline->bMovlTargetGp));
    ENTOUR_TRACE(("entours: &bMovlEntourGp=%p\n", &pTrampoline->bMovlEntourGp));
#endif // ENTOURS_IA64

    pbTrampoline = pTrampoline->rbCode + pTrampoline->cbCode;
#ifdef ENTOURS_X64
    pbTrampoline = entour_gen_jmp_indirect(pbTrampoline, &pTrampoline->pbRemain);
    pbTrampoline = entour_gen_brk(pbTrampoline, pbPool);
#endif // ENTOURS_X64

#ifdef ENTOURS_X86
    pbTrampoline = entour_gen_jmp_immediate(pbTrampoline, pTrampoline->pbRemain);
    pbTrampoline = entour_gen_brk(pbTrampoline, pbPool);
#endif // ENTOURS_X86

#ifdef ENTOURS_ARM
    pbTrampoline = entour_gen_jmp_immediate(pbTrampoline, &pbPool, pTrampoline->pbRemain);
    pbTrampoline = entour_gen_brk(pbTrampoline, pbPool);
#endif // ENTOURS_ARM

#ifdef ENTOURS_ARM64
    pbTrampoline = entour_gen_jmp_immediate(pbTrampoline, &pbPool, pTrampoline->pbRemain);
    pbTrampoline = entour_gen_brk(pbTrampoline, pbPool);
#endif // ENTOURS_ARM64

    (void)pbTrampoline;

    DWORD dwOld = 0;
    if (!VirtualProtect(pbTarget, cbTarget, PAGE_EXECUTE_READWRITE, &dwOld)) {
        error = GetLastError();
        ENTOUR_BREAK();
        goto fail;
    }

    ENTOUR_TRACE(("entours: pbTarget=%p: "
                  "%02x %02x %02x %02x "
                  "%02x %02x %02x %02x "
                  "%02x %02x %02x %02x\n",
                  pbTarget,
                  pbTarget[0], pbTarget[1], pbTarget[2], pbTarget[3],
                  pbTarget[4], pbTarget[5], pbTarget[6], pbTarget[7],
                  pbTarget[8], pbTarget[9], pbTarget[10], pbTarget[11]));
    ENTOUR_TRACE(("entours: pbTramp =%p: "
                  "%02x %02x %02x %02x "
                  "%02x %02x %02x %02x "
                  "%02x %02x %02x %02x\n",
                  pTrampoline,
                  pTrampoline->rbCode[0], pTrampoline->rbCode[1],
                  pTrampoline->rbCode[2], pTrampoline->rbCode[3],
                  pTrampoline->rbCode[4], pTrampoline->rbCode[5],
                  pTrampoline->rbCode[6], pTrampoline->rbCode[7],
                  pTrampoline->rbCode[8], pTrampoline->rbCode[9],
                  pTrampoline->rbCode[10], pTrampoline->rbCode[11]));

    o->fIsRemove = FALSE;
    o->ppbPointer = (PBYTE*)ppPointer;
    o->pTrampoline = pTrampoline;
    o->pbTarget = pbTarget;
    o->dwPerm = dwOld;
    o->pNext = s_pPendingOperations;
    s_pPendingOperations = o;

    return NO_ERROR;
}

LONG WINAPI EntourDetach(_Inout_ PVOID *ppPointer,
                         _In_ const VOID *pEntour)
{
    LONG error = NO_ERROR;

    if (s_nPendingThreadId != (LONG)GetCurrentThreadId()) {
        return ERROR_INVALID_OPERATION;
    }

    // If any of the pending operations failed, then we don't need to do this.
    if (s_nPendingError != NO_ERROR) {
        return s_nPendingError;
    }

    if (pEntour == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    if (ppPointer == NULL) {
        return ERROR_INVALID_HANDLE;
    }
    if (*ppPointer == NULL) {
        error = ERROR_INVALID_HANDLE;
        s_nPendingError = error;
        s_ppPendingError = ppPointer;
        ENTOUR_BREAK();
        return error;
    }

    EntourOperation *o = new NOTHROW EntourOperation;
    if (o == NULL) {
        error = ERROR_NOT_ENOUGH_MEMORY;
      fail:
        s_nPendingError = error;
        ENTOUR_BREAK();
      stop:
        if (o != NULL) {
            delete o;
            o = NULL;
        }
        s_ppPendingError = ppPointer;
        return error;
    }


#ifdef ENTOURS_IA64
    PPLABEL_DESCRIPTOR ppldTrampo = (PPLABEL_DESCRIPTOR)*ppPointer;
    PPLABEL_DESCRIPTOR ppldEntour = (PPLABEL_DESCRIPTOR)pEntour;
    PVOID pEntourGlobals = NULL;
    PVOID pTrampoGlobals = NULL;

    pEntour = (PBYTE)EntourCodeFromPointer(ppldEntour, &pEntourGlobals);
    PENTOUR_TRAMPOLINE pTrampoline = (PENTOUR_TRAMPOLINE)
        EntourCodeFromPointer(ppldTrampo, &pTrampoGlobals);
    ENTOUR_TRACE(("  ppldEntour=%p, code=%p [gp=%p]\n",
                  ppldEntour, pEntour, pEntourGlobals));
    ENTOUR_TRACE(("  ppldTrampo=%p, code=%p [gp=%p]\n",
                  ppldTrampo, pTrampoline, pTrampoGlobals));


    ENTOUR_TRACE(("\n"));
    ENTOUR_TRACE(("entours:  &pldTrampoline  =%p\n",
                  &pTrampoline->pldTrampoline));
    ENTOUR_TRACE(("entours:  &bMovlTargetGp  =%p [%p]\n",
                  &pTrampoline->bMovlTargetGp,
                  pTrampoline->bMovlTargetGp.GetMovlGp()));
    ENTOUR_TRACE(("entours:  &rbCode         =%p [%p]\n",
                  &pTrampoline->rbCode,
                  ((ENTOUR_IA64_BUNDLE&)pTrampoline->rbCode).GetBrlTarget()));
    ENTOUR_TRACE(("entours:  &bBrlRemainEip  =%p [%p]\n",
                  &pTrampoline->bBrlRemainEip,
                  pTrampoline->bBrlRemainEip.GetBrlTarget()));
    ENTOUR_TRACE(("entours:  &bMovlEntourGp  =%p [%p]\n",
                  &pTrampoline->bMovlEntourGp,
                  pTrampoline->bMovlEntourGp.GetMovlGp()));
    ENTOUR_TRACE(("entours:  &bBrlEntourEip  =%p [%p]\n",
                  &pTrampoline->bCallEntour,
                  pTrampoline->bCallEntour.GetBrlTarget()));
    ENTOUR_TRACE(("entours:  pldEntour       =%p [%p]\n",
                  pTrampoline->ppldEntour->EntryPoint,
                  pTrampoline->ppldEntour->GlobalPointer));
    ENTOUR_TRACE(("entours:  pldTarget       =%p [%p]\n",
                  pTrampoline->ppldTarget->EntryPoint,
                  pTrampoline->ppldTarget->GlobalPointer));
    ENTOUR_TRACE(("entours:  pbRemain        =%p\n",
                  pTrampoline->pbRemain));
    ENTOUR_TRACE(("entours:  pbEntour        =%p\n",
                  pTrampoline->pbEntour));
    ENTOUR_TRACE(("\n"));
#else // !ENTOURS_IA64
    PENTOUR_TRAMPOLINE pTrampoline =
        (PENTOUR_TRAMPOLINE)EntourCodeFromPointer(*ppPointer, NULL);
    pEntour = EntourCodeFromPointer(pEntour, NULL);
#endif // !ENTOURS_IA64

    ////////////////////////////////////// Verify that Trampoline is in place.
    //
    LONG cbTarget = pTrampoline->cbRestore;
    PBYTE pbTarget = pTrampoline->pbRemain - cbTarget;
    if (cbTarget == 0 || (SIZE_T)cbTarget > sizeof(pTrampoline->rbCode)) {
        error = ERROR_INVALID_BLOCK;
        if (s_fIgnoreTooSmall) {
            goto stop;
        }
        else {
            ENTOUR_BREAK();
            goto fail;
        }
    }

    if (pTrampoline->pbEntour != pEntour) {
        error = ERROR_INVALID_BLOCK;
        if (s_fIgnoreTooSmall) {
            goto stop;
        }
        else {
            ENTOUR_BREAK();
            goto fail;
        }
    }

    DWORD dwOld = 0;
    if (!VirtualProtect(pbTarget, cbTarget,
                        PAGE_EXECUTE_READWRITE, &dwOld)) {
        error = GetLastError();
        ENTOUR_BREAK();
        goto fail;
    }

    o->fIsRemove = TRUE;
    o->ppbPointer = (PBYTE*)ppPointer;
    o->pTrampoline = pTrampoline;
    o->pbTarget = pbTarget;
    o->dwPerm = dwOld;
    o->pNext = s_pPendingOperations;
    s_pPendingOperations = o;

    return NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////////
// Helpers for manipulating page protection.

// For reference:
//   PAGE_NOACCESS          0x01
//   PAGE_READONLY          0x02
//   PAGE_READWRITE         0x04
//   PAGE_WRITECOPY         0x08
//   PAGE_EXECUTE           0x10
//   PAGE_EXECUTE_READ      0x20
//   PAGE_EXECUTE_READWRITE 0x40
//   PAGE_EXECUTE_WRITECOPY 0x80
//   PAGE_GUARD             ...
//   PAGE_NOCACHE           ...
//   PAGE_WRITECOMBINE      ...

#define ENTOUR_PAGE_EXECUTE_ALL    (PAGE_EXECUTE |              \
                                    PAGE_EXECUTE_READ |         \
                                    PAGE_EXECUTE_READWRITE |    \
                                    PAGE_EXECUTE_WRITECOPY)

#define ENTOUR_PAGE_NO_EXECUTE_ALL (PAGE_NOACCESS |             \
                                    PAGE_READONLY |             \
                                    PAGE_READWRITE |            \
                                    PAGE_WRITECOPY)

#define ENTOUR_PAGE_ATTRIBUTES     (~(ENTOUR_PAGE_EXECUTE_ALL | ENTOUR_PAGE_NO_EXECUTE_ALL))

C_ASSERT((ENTOUR_PAGE_NO_EXECUTE_ALL << 4) == ENTOUR_PAGE_EXECUTE_ALL);

static DWORD EntourPageProtectAdjustExecute(_In_  DWORD dwOldProtect,
                                            _In_  DWORD dwNewProtect)
//  Copy EXECUTE from dwOldProtect to dwNewProtect.
{
    bool const fOldExecute = ((dwOldProtect & ENTOUR_PAGE_EXECUTE_ALL) != 0);
    bool const fNewExecute = ((dwNewProtect & ENTOUR_PAGE_EXECUTE_ALL) != 0);

    if (fOldExecute && !fNewExecute) {
        dwNewProtect = ((dwNewProtect & ENTOUR_PAGE_NO_EXECUTE_ALL) << 4)
            | (dwNewProtect & ENTOUR_PAGE_ATTRIBUTES);
    }
    else if (!fOldExecute && fNewExecute) {
        dwNewProtect = ((dwNewProtect & ENTOUR_PAGE_EXECUTE_ALL) >> 4)
            | (dwNewProtect & ENTOUR_PAGE_ATTRIBUTES);
    }
    return dwNewProtect;
}

_Success_(return != FALSE)
BOOL WINAPI EntourVirtualProtectSameExecuteEx(_In_  HANDLE hProcess,
                                              _In_  PVOID pAddress,
                                              _In_  SIZE_T nSize,
                                              _In_  DWORD dwNewProtect,
                                              _Out_ PDWORD pdwOldProtect)
// Some systems do not allow executability of a page to change. This function applies
// dwNewProtect to [pAddress, nSize), but preserving the previous executability.
// This function is meant to be a drop-in replacement for some uses of VirtualProtectEx.
// When "restoring" page protection, there is no need to use this function.
{
    MEMORY_BASIC_INFORMATION mbi;

    // Query to get existing execute access.

    ZeroMemory(&mbi, sizeof(mbi));

    if (VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi)) == 0) {
        return FALSE;
    }
    return VirtualProtectEx(hProcess, pAddress, nSize,
                            EntourPageProtectAdjustExecute(mbi.Protect, dwNewProtect),
                            pdwOldProtect);
}

_Success_(return != FALSE)
BOOL WINAPI EntourVirtualProtectSameExecute(_In_  PVOID pAddress,
                                            _In_  SIZE_T nSize,
                                            _In_  DWORD dwNewProtect,
                                            _Out_ PDWORD pdwOldProtect)
{
    return EntourVirtualProtectSameExecuteEx(GetCurrentProcess(),
                                             pAddress, nSize, dwNewProtect, pdwOldProtect);
}

//////////////////////////////////////////////////////////////////////////////
