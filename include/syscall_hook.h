#ifndef SYSCALL_HOOK_H
#define SYSCALL_HOOK_H

#include <ntddk.h>

// Undocumented structure for the System Service Table.
typedef struct _SYSTEM_SERVICE_TABLE {
    PVOID ServiceTableBase;
    PVOID ServiceCounterTableBase;
    ULONG NumberOfServices;
    PVOID ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;


// Public Function Prototypes
NTSTATUS VhTraceSyscall(ULONG ServiceIndex);

#endif
