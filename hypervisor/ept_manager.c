/*
 * ept_manager.c
 *
 *  Manages all Extended Page Table (EPT) operations, including identity
 *  mapping, permission changes, and memory hiding.
 */

#include "include/ept.h"
#include "include/vmx.h"
#include "include/intercepts.h" // For VhHandleEptViolationForCloak

/*
 * Retrieves the EPT Page Table Entry (PTE) for a given physical address.
 */
PEPT_PTE VhGetPteForPhysicalAddress(PEPT_STATE EptState, PHYSICAL_ADDRESS PhysicalAddress)
{
    // EPT table walk to find the final PTE.
    PEPT_PML4E pml4e = &EptState->Pml4[PhysicalAddress.QuadPart >> 39 & 0x1FF];
    if (!pml4e->Read) return NULL;

    PEPT_PDPTE pdpte = &((PEPT_PDPTE)MmGetVirtualForPhysical(PHYSICAL_ADDRESS_FROM_PTE(pml4e)))[PhysicalAddress.QuadPart >> 30 & 0x1FF];
    if (!pdpte->Read) return NULL;

    PEPT_PDE pde = &((PEPT_PDE)MmGetVirtualForPhysical(PHYSICAL_ADDRESS_FROM_PTE(pdpte)))[PhysicalAddress.QuadPart >> 21 & 0x1FF];
    if (!pde->Read) return NULL;

    PEPT_PTE pte = &((PEPT_PTE)MmGetVirtualForPhysical(PHYSICAL_ADDRESS_FROM_PTE(pde)))[PhysicalAddress.QuadPart >> 12 & 0x1FF];
    return pte;
}

/*
 * Sets the access permissions (Read/Write/Execute) for a physical page.
 */
NTSTATUS VhSetPageAccessPermissions(PEPT_STATE EptState, PHYSICAL_ADDRESS PageBaseAddress, EPT_ACCESS_RIGHTS DesiredAccess)
{
    PEPT_PTE pte = VhGetPteForPhysicalAddress(EptState, PageBaseAddress);
    if (!pte)
    {
        return STATUS_NOT_FOUND;
    }

    // Modify the PTE with the new permissions.
    pte->Read = (DesiredAccess & EPT_ACCESS_READ) ? 1 : 0;
    pte->Write = (DesiredAccess & EPT_ACCESS_WRITE) ? 1 : 0;
    pte->Execute = (DesiredAccess & EPT_ACCESS_EXECUTE) ? 1 : 0;

    // Invalidate TLB for the modified address.
    INVEPT_DESCRIPTOR inv_desc = { 0 };
    inv_desc.EptPointer = EptState->EptPointer.All;
    __invept(1, &inv_desc);

    return STATUS_SUCCESS;
}

/*
 * Creates an identity EPT map for all physical memory.
 */
BOOLEAN VhBuildEptIdentityMap(PEPT_STATE EptState)
{
    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = MAXULONG64;

    // Allocate EPT tables (PML4, PDPT, PD, PT).
    EptState->Pml4 = MmAllocateContiguousNodeMemory(PAGE_SIZE, maxAddr, maxAddr, maxAddr, PAGE_READWRITE, MM_ANY_NODE_OK);
    EptState->Pdpt = MmAllocateContiguousNodeMemory(PAGE_SIZE, maxAddr, maxAddr, maxAddr, PAGE_READWRITE, MM_ANY_NODE_OK);
    EptState->Pd = MmAllocateContiguousNodeMemory(PAGE_SIZE * 512, maxAddr, maxAddr, maxAddr, PAGE_READWRITE, MM_ANY_NODE_OK);

    if (!EptState->Pml4 || !EptState->Pdpt || !EptState->Pd)
    {
        // Cleanup on failure.
        if (EptState->Pml4) MmFreeContiguousMemory(EptState->Pml4);
        if (EptState->Pdpt) MmFreeContiguousMemory(EptState->Pdpt);
        if (EptState->Pd) MmFreeContiguousMemory(EptState->Pd);
        return FALSE;
    }
    RtlZeroMemory(EptState->Pml4, PAGE_SIZE);
    RtlZeroMemory(EptState->Pdpt, PAGE_SIZE);
    RtlZeroMemory(EptState->Pd, PAGE_SIZE * 512);

    // Link the top-level tables.
    EptState->Pml4[0].PageFrameNumber = MmGetPhysicalAddress(EptState->Pdpt).QuadPart >> 12;
    EptState->Pml4[0].Read = EptState->Pml4[0].Write = EptState->Pml4[0].Execute = 1;

    for (int i = 0; i < 512; i++)
    {
        EptState->Pdpt[i].PageFrameNumber = (MmGetPhysicalAddress(EptState->Pd).QuadPart >> 12) + i;
        EptState->Pdpt[i].Read = EptState->Pdpt[i].Write = EptState->Pdpt[i].Execute = 1;
    }

    // Map 512 GB of physical memory with 2MB pages.
    PEPT_PDE pde = (PEPT_PDE)EptState->Pd;
    for (UINT64 i = 0; i < 512 * 512; i++)
    {
        pde[i].Read = pde[i].Write = pde[i].Execute = 1;
        pde[i].LargePage = 1;
        pde[i].PageFrameNumber = i;
    }

    DbgPrint("VIREX-HV: EPT identity map for 512GB created.\n");
    return TRUE;
}

/*
 * Enables EPT in the VMCS.
 */
VOID VhEnableEpt(PPER_CPU_VMX_DATA VmxData)
{
    VmxData->EptState.EptPointer.All = 0;
    VmxData->EptState.EptPointer.PageWalkLength = 3; // 4-level page walk
    VmxData->EptState.EptPointer.PageFrameNumber = MmGetPhysicalAddress(VmxData->EptState.Pml4).QuadPart >> 12;

    __vmx_vmwrite(EPT_POINTER, VmxData->EptState.EptPointer.All);
}

/*
 * Handles EPT violation VM-Exits.
 */
VOID VhHandleEptViolation(PGUEST_REGS GuestRegs)
{
    UNREFERENCED_PARAMETER(GuestRegs);
    ULONG processorIndex = KeGetCurrentProcessorNumberEx(NULL);
    PEPT_STATE eptState = &g_VmxData[processorIndex].EptState;

    // Check if the violation was caused by our INT3 cloaking mechanism.
    VhHandleEptViolationForCloak(eptState);
}

/*
 * Hides the hypervisor's own driver image in memory using EPT.
 */
VOID VhHideHypervisorMemory(PVOID DriverBase, ULONG DriverSize)
{
    ULONG_PTR baseAddr = (ULONG_PTR)DriverBase;
    ULONG processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    // For each page of the driver image, change its EPT permissions to be inaccessible.
    for (ULONG i = 0; i < (DriverSize + PAGE_SIZE - 1) / PAGE_SIZE; i++)
    {
        PHYSICAL_ADDRESS pagePa = MmGetPhysicalAddress((PVOID)(baseAddr + i * PAGE_SIZE));
        
        for (ULONG cpu = 0; cpu < processorCount; cpu++)
        {
            VhSetPageAccessPermissions(&g_VmxData[cpu].EptState, pagePa, EPT_ACCESS_NONE);
        }
    }

    DbgPrint("VIREX-HV: Hypervisor memory is now hidden via EPT.\n");
}

/*
 * Cleans up all allocated EPT structures.
 */
VOID VhCleanupEpt(PEPT_STATE EptState)
{
    if (EptState->Pml4) MmFreeContiguousMemory(EptState->Pml4);
    if (EptState->Pdpt) MmFreeContiguousMemory(EptState->Pdpt);
    if (EptState->Pd) MmFreeContiguousMemory(EptState->Pd);
}
