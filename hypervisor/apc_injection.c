/*
 * apc_injection.c
 *
 *  Implements a robust Kernel APC injection mechanism to trigger VMCALLs
 *  from a user-mode process context.
 */

#include "include/apc_injection.h"

// Global APC state structure.
STATIC APC_STATE g_ApcState = { 0 };

/*
 * Kernel routine for the injected APC. Executes VMCALL.
 */
VOID VhApcKernelRoutine(
    _In_ struct _KAPC* Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // Execute the VMCALL. The hypervisor will handle the rest.
    __vmx_vmcall(g_ApcState.VmcallNumber, g_ApcState.VmcallContext, 0, 0);
    
    // Free the KAPC object.
    ExFreePoolWithTag(Apc, 'APC');

    // Signal completion.
    KeSetEvent(&g_ApcState.ApcCompletedEvent, 0, FALSE);
}

/*
 * Triggers a VMCALL by queuing a Kernel APC to a target thread.
 */
NTSTATUS VhQueueApcVmcall(UINT32 TargetPid, VMCALL_CODE VmcallNumber, PVOID VmcallContext)
{
    NTSTATUS status;
    PEPROCESS targetProcess = NULL;
    PETHREAD targetThread = NULL;

    // Get a reference to the target process.
    status = PsLookupProcessByProcessId((HANDLE)TargetPid, &targetProcess);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("VIREX-HV: [APC] Could not find target process PID: %d\n", TargetPid);
        return status;
    }

    // For simplicity, we target the first thread of the process.
    // A more robust implementation would find a suitable, alertable thread.
    targetThread = PsGetNextProcessThread(targetProcess, NULL);
    if (!targetThread)
    {
        ObDereferenceObject(targetProcess);
        return STATUS_NOT_FOUND;
    }

    // Allocate a KAPC object.
    PKAPC apc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'APC');
    if (!apc)
    {
        ObDereferenceObject(targetThread);
        ObDereferenceObject(targetProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize the KAPC.
    KeInitializeApc(apc,
                    targetThread,
                    OriginalApcEnvironment,
                    VhApcKernelRoutine,
                    NULL,
                    NULL,
                    KernelMode,
                    NULL);
                    
    // Store VMCALL info and initialize completion event.
    g_ApcState.VmcallNumber = VmcallNumber;
    g_ApcState.VmcallContext = VmcallContext;
    KeInitializeEvent(&g_ApcState.ApcCompletedEvent, NotificationEvent, FALSE);

    // Queue the APC. If the thread is in an alertable state, it will execute.
    if (!KeInsertQueueApc(apc, NULL, NULL, 0))
    {
        DbgPrint("VIREX-HV: [APC] Failed to queue APC.\n");
        ExFreePoolWithTag(apc, 'APC');
        status = STATUS_UNSUCCESSFUL;
    }
    else
    {
        // Wait for the APC to complete execution.
        KeWaitForSingleObject(&g_ApcState.ApcCompletedEvent, Executive, KernelMode, FALSE, NULL);
        status = STATUS_SUCCESS;
    }
    
    // Cleanup.
    ObDereferenceObject(targetThread);
    ObDereferenceObject(targetProcess);
    
    return status;
}
