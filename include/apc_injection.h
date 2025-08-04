#ifndef APC_INJECTION_H
#define APC_INJECTION_H

#include <ntddk.h>
#include "include/vmcall_codes.h"

// Holds the state required for an APC-based VMCALL.
typedef struct _APC_STATE
{
    VMCALL_CODE VmcallNumber;
    PVOID       VmcallContext;
    KEVENT      ApcCompletedEvent;

} APC_STATE, *PAPC_STATE;


// Public Function Prototypes
NTSTATUS VhQueueApcVmcall(UINT32 TargetPid, VMCALL_CODE VmcallNumber, PVOID VmcallContext);

#endif
