/*
 * cloak_int3.c
 *
 *  Implements the advanced EPT/MTF-based INT3 breakpoint cloaking.
 */

#include "include/vmx.h"
#include "include/ept.h"

// Global state for the INT3 cloaking subsystem.
static EPT_HOOK_STATE g_CloakState;

/*
 * Initializes the INT3 cloaking subsystem.
 */
VOID VhInitializeInt3Cloaking()
{
    InitializeListHead(&g_CloakState.HookList);
    KeInitializeSpinLock(&g_CloakState.HookListLock);
    g_CloakState.IsEnabled = TRUE;
    DbgPrint("VIREX-HV: [Cloak] INT3 cloaking subsystem initialized.\n");
}

/*
 * Cleans up all allocated memory for INT3 cloaking.
 */
VOID VhCleanupInt3Cloaking()
{
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_CloakState.HookListLock, &lockHandle);
    
    while (!IsListEmpty(&g_CloakState.HookList))
    {
        PEPT_HOOK_ENTRY entry = CONTAINING_RECORD(g_CloakState.HookList.Flink, EPT_HOOK_ENTRY, Link);
        RemoveEntryList(&entry->Link);
        ExFreePoolWithTag(entry, 'hk');
    }
    
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    DbgPrint("VIREX-HV: [Cloak] INT3 cloaking subsystem cleaned up.\n");
}

/*
 * Restores EPT permissions and removes the temporary shadow page mapping.
 */
VOID VhRestoreEptHook(PEPT_HOOK_ENTRY Hook)
{
    // Change page permissions back to Execute-Only.
    VhSetPageAccessPermissions(Hook->EptState, Hook->PhysicalBaseAddress, EPT_ACCESS_EXECUTE);

    // Invalidate TLB for this address.
    INVEPT_DESCRIPTOR inv_desc = { 0 };
    inv_desc.EptPointer = Hook->EptState->EptPointer.All;
    __invept(1, &inv_desc);

    Hook->IsExecuting = FALSE;
}

/*
 * Handles a Monitor Trap Flag VM-Exit to complete the cloaking cycle.
 */
VOID VhHandleMtfTrap()
{
    ULONG processorIndex = KeGetCurrentProcessorNumberEx(NULL);
    PEPT_STATE eptState = &g_VmxData[processorIndex].EptState;
    KLOCK_QUEUE_HANDLE lockHandle;
    
    // Disable MTF in the VMCS.
    IA32_VMX_PROCBASED_CTLS_MSR proc_ctls = { __readmsr(MSR_IA32_VMX_PROCBASED_CTLS) };
    proc_ctls.Allowed_0_Settings.MonitorTrapFlag = 0;
    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, proc_ctls.Allowed_1_Settings.All);

    // Find the active hook that triggered this trap and restore it.
    KeAcquireInStackQueuedSpinLock(&g_CloakState.HookListLock, &lockHandle);
    PLIST_ENTRY entry;
    for (entry = g_CloakState.HookList.Flink; entry != &g_CloakState.HookList; entry = entry->Flink)
    {
        PEPT_HOOK_ENTRY hook = CONTAINING_RECORD(entry, EPT_HOOK_ENTRY, Link);
        if (hook->IsExecuting && hook->EptState == eptState)
        {
            VhRestoreEptHook(hook);
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

/*
 * Handles an EPT violation to initiate an INT3 cloak.
 */
VOID VhHandleEptViolationForCloak(PEPT_STATE EptState)
{
    size_t fault_pa = 0;
    __vmx_vmread(GUEST_PHYSICAL_ADDRESS, &fault_pa);

    KLOCK_QUEUE_HANDLE lockHandle;
    PEPT_HOOK_ENTRY hook = NULL;
    
    // Find the hook corresponding to the faulting physical address.
    KeAcquireInStackQueuedSpinLock(&g_CloakState.HookListLock, &lockHandle);
    PLIST_ENTRY entry;
    for (entry = g_CloakState.HookList.Flink; entry != &g_CloakState.HookList; entry = entry->Flink)
    {
        PEPT_HOOK_ENTRY current_hook = CONTAINING_RECORD(entry, EPT_HOOK_ENTRY, Link);
        if (current_hook->PhysicalBaseAddress == (fault_pa & ~0xFFF) && current_hook->EptState == EptState)
        {
            hook = current_hook;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (!hook) return;

    // The guest is trying to access the hooked page.
    // Give Read/Write access temporarily and set the MTF.
    hook->IsExecuting = TRUE;
    VhSetPageAccessPermissions(EptState, hook->PhysicalBaseAddress, EPT_ACCESS_READ_WRITE);

    // Invalidate TLB for this address.
    INVEPT_DESCRIPTOR inv_desc = { 0 };
    inv_desc.EptPointer = EptState->EptPointer.All;
    __invept(1, &inv_desc);

    // Enable the Monitor Trap Flag to regain control after one instruction.
    IA32_VMX_PROCBASED_CTLS_MSR proc_ctls = { __readmsr(MSR_IA32_VMX_PROCBASED_CTLS) };
    proc_ctls.Allowed_0_Settings.MonitorTrapFlag = 1;
    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, proc_ctls.Allowed_1_Settings.All);
}

/*
 * Creates an INT3 cloak on a specific physical page.
 */
NTSTATUS VhCloakInt3Breakpoint(PEPT_STATE EptState, PHYSICAL_ADDRESS PhysicalAddress, UCHAR OriginalByte)
{
    PEPT_HOOK_ENTRY new_hook = ExAllocatePoolWithTag(NonPagedPool, sizeof(EPT_HOOK_ENTRY), 'hk');
    if (!new_hook)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    KLOCK_QUEUE_HANDLE lockHandle;
    PHYSICAL_ADDRESS pageBase;
    pageBase.QuadPart = PhysicalAddress.QuadPart & ~0xFFF;
    
    // Set up the hook entry.
    new_hook->PhysicalBaseAddress = pageBase.QuadPart;
    new_hook->OriginalByte = OriginalByte;
    new_hook->IsExecuting = FALSE;
    new_hook->EptState = EptState;

    // Add to the global list.
    KeAcquireInStackQueuedSpinLock(&g_CloakState.HookListLock, &lockHandle);
    InsertTailList(&g_CloakState.HookList, &new_hook->Link);
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    // Make the page Execute-Only to trigger a VM-Exit on read/write.
    VhSetPageAccessPermissions(EptState, pageBase, EPT_ACCESS_EXECUTE);

    DbgPrint("VIREX-HV: [Cloak] INT3 cloak enabled for PA: 0x%llX\n", pageBase.QuadPart);

    return STATUS_SUCCESS;
}

/*
 * Removes an active INT3 cloak.
 */
NTSTATUS VhUncloakInt3Breakpoint(PEPT_STATE EptState, PHYSICAL_ADDRESS PhysicalAddress)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PEPT_HOOK_ENTRY hook = NULL;
    PHYSICAL_ADDRESS pageBase;
    pageBase.QuadPart = PhysicalAddress.QuadPart & ~0xFFF;

    // Find the hook to remove.
    KeAcquireInStackQueuedSpinLock(&g_CloakState.HookListLock, &lockHandle);
    PLIST_ENTRY entry;
    for (entry = g_CloakState.HookList.Flink; entry != &g_CloakState.HookList; entry = entry->Flink)
    {
        PEPT_HOOK_ENTRY current_hook = CONTAINING_RECORD(entry, EPT_HOOK_ENTRY, Link);
        if (current_hook->PhysicalBaseAddress == pageBase.QuadPart && current_hook->EptState == EptState)
        {
            hook = current_hook;
            RemoveEntryList(&hook->Link);
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    
    if (hook)
    {
        // Restore full access and free the hook entry.
        VhSetPageAccessPermissions(EptState, pageBase, EPT_ACCESS_ALL);
        ExFreePoolWithTag(hook, 'hk');
        DbgPrint("VIREX-HV: [Cloak] INT3 cloak disabled for PA: 0x%llX\n", pageBase.QuadPart);
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}
