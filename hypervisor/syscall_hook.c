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

// Global state for the syscall tracing subsystem.
static SYSCALL_TRACE_STATE g_SyscallTraceState;

/*
 * Initializes the syscall tracing subsystem.
 */
VOID VhInitializeSyscallTrace()
{
    InitializeListHead(&g_SyscallTraceState.TraceList);
    KeInitializeSpinLock(&g_SyscallTraceState.TraceListLock);
    g_SyscallTraceState.IsEnabled = TRUE;
    DbgPrint("VIREX-HV: [Syscall] Syscall tracing subsystem initialized.\n");
}

/*
 * Cleans up all allocated memory for syscall tracing.
 */
VOID VhCleanupSyscallTrace()
{
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_SyscallTraceState.TraceListLock, &lockHandle);
    
    while (!IsListEmpty(&g_SyscallTraceState.TraceList))
    {
        PEPT_HOOK_ENTRY entry = CONTAINING_RECORD(g_SyscallTraceState.TraceList.Flink, EPT_HOOK_ENTRY, Link);
        RemoveEntryList(&entry->Link);
        ExFreePoolWithTag(entry, 'sc');
    }
    
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    DbgPrint("VIREX-HV: [Syscall] Syscall tracing subsystem cleaned up.\n");
}


/*
 * Retrieves the address of a syscall routine from the SSDT.
 */
PVOID VhGetSssdtFunctionAddress(ULONG ServiceIndex)
{
    // KeServiceDescriptorTable is an array of service table descriptors.
    // The first one is for ntoskrnl.
    PSYSTEM_SERVICE_TABLE ssdt = (PSYSTEM_SERVICE_TABLE)PsGetServiceTable();
    if (!ssdt || ServiceIndex >= ssdt->NumberOfServices) return NULL;

    // The table base is relative to the start of the SSDT.
    PULONG serviceTableBase = (PULONG)ssdt->ServiceTableBase;
    return (PVOID)((PUCHAR)serviceTableBase + (serviceTableBase[ServiceIndex] >> 4));
}

/*
 * Enables a patchless EPT/MTF trace on a specific syscall.
 */
NTSTATUS VhTraceSyscall(PEPT_STATE EptState, ULONG ServiceIndex)
{
    PVOID syscallAddress = VhGetSssdtFunctionAddress(ServiceIndex);
    if (!syscallAddress)
    {
        DbgPrint("VIREX-HV: [Syscall] Failed to resolve syscall index %d\n", ServiceIndex);
        return STATUS_NOT_FOUND;
    }
    
    // Create a generic EPT hook on the page of the syscall.
    // The EPT violation handler will be responsible for logging the access.
    PHYSICAL_ADDRESS syscallPa = MmGetPhysicalAddress(syscallAddress);
    PHYSICAL_ADDRESS pageBase;
    pageBase.QuadPart = syscallPa.QuadPart & ~0xFFF;
    
    // This uses the same mechanism as INT3 cloaking but for a different purpose.
    NTSTATUS status = VhCloakInt3Breakpoint(EptState, pageBase, 0); // OriginalByte is not used here.
    if (NT_SUCCESS(status))
    {
        DbgPrint("VIREX-HV: [Syscall] Enabled patchless trace for index %d at PA 0x%llX\n",
            ServiceIndex, syscallPa.QuadPart);
    }
    
    return status;
}
