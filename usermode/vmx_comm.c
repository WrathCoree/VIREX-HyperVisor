/*
 * vmx_comm.c
 *
 *  Provides a simple C API for user-mode applications to communicate
 *  with the hypervisor driver via IOCTLs.
 */

#include "vmx_comm.h"
#include "../include/common.h"
#include <stdio.h>

/*
 * Establishes a connection to the hypervisor driver.
 */
HANDLE HvConnect()
{
    return CreateFileW(L"\\\\.\\VirexHypervisor",
                       GENERIC_READ | GENERIC_WRITE,
                       0,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
}

/*
 * Closes the connection to the hypervisor driver.
 */
VOID HvDisconnect(HANDLE hDevice)
{
    if (hDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hDevice);
    }
}

/*
 * Sends a VMCALL command to the hypervisor via an IOCTL request.
 */
BOOLEAN HvIssueVmcall(HANDLE hDevice, VMCALL_CODE VmcallNumber, UINT64 Context)
{
    VMCALL_INPUT input = { 0 };
    DWORD bytesReturned;

    input.TargetPid = GetCurrentProcessId();
    input.VmcallNumber = VmcallNumber;
    input.Context = Context;

    return DeviceIoControl(hDevice,
                           IOCTL_VMCALL_DISPATCH,
                           &input,
                           sizeof(input),
                           NULL,
                           0,
                           &bytesReturned,
                           NULL);
}
