#ifndef COMMON_H
#define COMMON_H

// IOCTL code for user-mode to kernel-mode communication.
#define IOCTL_VMCALL_DISPATCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structure for passing VMCALL data from user-mode.
typedef struct _VMCALL_INPUT
{
    UINT32      TargetPid;      // PID of the process to inject the APC into.
    VMCALL_CODE VmcallNumber;   // The VMCALL command code.
    UINT64      Context;        // Generic context/parameter for the VMCALL.

} VMCALL_INPUT, *PVMCALL_INPUT;

#endif
