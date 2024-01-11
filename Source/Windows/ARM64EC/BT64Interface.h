#pragma once

#include <windef.h>
#include <ntstatus.h>
#include <winternl.h>

extern "C" {
void STDMETHODCALLTYPE ProcessInit();
void STDMETHODCALLTYPE ProcessTerm();
NTSTATUS STDMETHODCALLTYPE ThreadInit();
NTSTATUS STDMETHODCALLTYPE ThreadTerm(HANDLE Thread);
void STDMETHODCALLTYPE BeginSimulation();

NTSTATUS STDMETHODCALLTYPE ResetToConsistentState(EXCEPTION_POINTERS *Ptrs);
void STDMETHODCALLTYPE BTCpu64FlushInstructionCache(const void *Address, SIZE_T Size);
void STDMETHODCALLTYPE NotifyMemoryAlloc(void *Address, SIZE_T Size, ULONG Type, ULONG Prot);
void STDMETHODCALLTYPE NotifyMemoryProtect(void *Address, SIZE_T Size, ULONG NewProt);
void STDMETHODCALLTYPE NotifyMemoryFree(void *Address, SIZE_T Size, ULONG FreeType);
void STDMETHODCALLTYPE NotifyUnmapViewOfSection(void *Address, ULONG Flags);
BOOLEAN STDMETHODCALLTYPE BTCpu64IsProcessorFeaturePresent(UINT Feature);
void STDMETHODCALLTYPE UpdateProcessorInformation(SYSTEM_CPU_INFORMATION *Info);

/*UNK*/
void STDMETHODCALLTYPE FlushInstructionCacheHeavy();
void STDMETHODCALLTYPE NotifyMapViewOfSection();

}
