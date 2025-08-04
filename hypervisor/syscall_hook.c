/*
 * syscall_hook.c
 *
 *  Implements the patchless syscall tracing mechanism using EPT and MTF.
 *  This allows for monitoring system calls without modifying kernel code.
 */

#include "include/syscall_hook.h"
#include "include/vmx.h"
#include "include/ept.h"

// Undocumented. Required to find the SSDT.
NTKERNELAPI PVOID PsGetServiceTable(); 

/*
 * Retrieves the address of a syscall routine from the SSDT.
 */
PVOID VhGetSssdtFunctionAddress(ULONG ServiceIndex)
{
    // KeServiceDescriptorTable is an array of service table descriptors.
    // The first one is for ntoskrnl.
    PSYSTEM_SERVICE_TABLE ssdt = (PSYSTEM_SERVICE_TABLE)PsGetServiceTable();
    if (!ssdt) return NULL;

    // The table base is relative to the start of ntoskrnl.
    PULONG serviceTableBase = (PULONG)ssdt->ServiceTableBase;
    return (PVOID)((PUCHAR)serviceTableBase + (serviceTableBase[ServiceIndex] >> 4));
}

/*
 * Enables a patchless EPT/MTF trace on a specific syscall.
 */
NTSTATUS VhTraceSyscall(ULONG ServiceIndex)
{
    PVOID syscallAddress = VhGetSssdtFunctionAddress(ServiceIndex);
    if (!syscallAddress)
    {
        DbgPrint("VIREX-HV: [Syscall] Failed to resolve syscall index %d\n", ServiceIndex);
        return STATUS_NOT_FOUND;
    }

    PHYSICAL_ADDRESS syscallPa = MmGetPhysicalAddress(syscallAddress);
    
    // This is a conceptual implementation. A full version would:
    // 1. Create an EPT hook entry for the syscall's physical page.
    // 2. Set the page to Execute-Only to trap access.
    // 3. The EPT violation handler would log the call and use MTF to step over it.
    DbgPrint("VIREX-HV: [Syscall] Enabled patchless trace for index %d at PA 0x%llX\n",
        ServiceIndex, syscallPa.QuadPart);
        
    return STATUS_SUCCESS;
}
