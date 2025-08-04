#ifndef VMX_COMM_H
#define VMX_COMM_H

#include <Windows.h>
#include "../include/vmcall_codes.h"

// Context structure for the RDTSC spoofing VMCALL.
typedef struct _VMCALL_CONTEXT_RDTSC
{
    UINT64 Multiplier;
    UINT64 Offset;

} VMCALL_CONTEXT_RDTSC, *PVMCALL_CONTEXT_RDTSC;


// Public Function Prototypes
HANDLE HvConnect();
VOID HvDisconnect(HANDLE hDevice);
BOOLEAN HvIssueVmcall(HANDLE hDevice, VMCALL_CODE VmcallNumber, UINT64 Context);

#endif
