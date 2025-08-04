#ifndef SYSCALL_HOOK_H
#define SYSCALL_HOOK_H

#include <ntddk.h>
#include "include/ept.h" // For EPT_HOOK_ENTRY

// Undocumented structure for the System Service Table.
typedef struct _SYSTEM_SERVICE_TABLE {
    PVOID ServiceTableBase;
    PVOID ServiceCounterTableBase;
    ULONG NumberOfServices;
    PVOID ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

// Global state for all syscall traces.
typedef struct _SYSCALL_TRACE_STATE
{
    LIST_ENTRY      TraceList;
    KSPIN_LOCK      TraceListLock;
    BOOLEAN         IsEnabled;

} SYSCALL_TRACE_STATE, *PSYSCALL_TRACE_STATE;


// Public Function Prototypes
VOID VhInitializeSyscallTrace();
VOID VhCleanupSyscallTrace();
NTSTATUS VhTraceSyscall(PEPT_STATE EptState, ULONG ServiceIndex);

#endif
