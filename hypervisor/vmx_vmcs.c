/*
 * vmx_vmcs.c
 *
 *  Manages the setup and configuration of the Virtual Machine Control
 *  Structure (VMCS) for each virtualized processor.
 */

#include "include/vmx.h"
#include "include/ept.h"
#include "include/intercepts.h"

// External reference to the main VM-Exit handler.
VOID VhVmexitHandler(VOID);

/*
 * Allocates a 4KB VMCS region for a logical processor.
 */
VOID VhAllocateVmcsRegion(PPER_CPU_VMX_DATA VmxData)
{
    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = MAXULONG64;

    // VMCS region must be 4KB aligned.
    VmxData->VmcsRegion = MmAllocateContiguousNodeMemory(VMCS_SIZE,
        maxAddr,
        maxAddr,
        maxAddr,
        PAGE_READWRITE,
        MM_ANY_NODE_OK);

    if (VmxData->VmcsRegion)
    {
        RtlSecureZeroMemory(VmxData->VmcsRegion, VMCS_SIZE);
        
        // Write the VMCS revision ID from the MSR.
        IA32_VMX_BASIC_MSR vmx_basic_msr = { __readmsr(MSR_IA32_VMX_BASIC) };
        RtlCopyMemory(VmxData->VmcsRegion, &vmx_basic_msr.VmcsRevisionId, sizeof(UINT32));

        VmxData->VmcsRegionPa = MmGetPhysicalAddress(VmxData->VmcsRegion);
    }
}

/*
 * Reads a segment register's properties and stores them in a structure.
 */
VOID VhFillGuestSelectorData(
    _Out_ PVOID GdtBase,
    _In_ UINT16 Selector,
    _Out_ PVMX_SEGMENT_SELECTOR VmxSelector
)
{
    SEGMENT_SELECTOR seg_selector = { .All = Selector };
    SEGMENT_DESCRIPTOR_64* descriptor;

    VmxSelector->Selector = Selector;

    if (Selector == 0)
    {
        VmxSelector->AccessRights.All = 0x10000; // Unusable
        VmxSelector->Limit = 0;
        VmxSelector->Base = 0;
        return;
    }

    descriptor = (SEGMENT_DESCRIPTOR_64*)( (PUCHAR)GdtBase + seg_selector.Index * sizeof(SEGMENT_DESCRIPTOR_64));
    
    VmxSelector->AccessRights.All = ((descriptor->High.Bits.Present & 1) << 7) |
                                    ((descriptor->High.Bits.Dpl & 3) << 5) |
                                    ((descriptor->High.Bits.Type & 1) << 4) |
                                    (descriptor->High.Bits.Type & 0xF) |
                                    ((descriptor->High.Bits.System & 1) << 4);

    if (!VmxSelector->AccessRights.Bits.Present)
    {
        VmxSelector->AccessRights.Bits.Unusable = TRUE;
    }

    VmxSelector->Limit = (descriptor->Low.Bits.LimitHigh << 16) | descriptor->Low.Bits.LimitLow;
    if (descriptor->High.Bits.Granularity)
    {
        VmxSelector->Limit = (VmxSelector->Limit << 12) | 0xFFF;
    }

    VmxSelector->Base = (UINT64)descriptor->Low.Bits.BaseLow |
                        ((UINT64)descriptor->High.Bits.BaseMid << 16) |
                        ((UINT64)descriptor->High.Bits.BaseHigh << 24);
}

/*
 * Configures the VMCS with guest, host, and control state.
 */
VOID VhSetupVmcs(PPER_CPU_VMX_DATA VmxData)
{
    KDESCRIPTOR gdt_desc = { 0 };
    KDESCRIPTOR idt_desc = { 0 };
    VMX_SEGMENT_SELECTOR vmx_seg = { 0 };

    __sgdt(&gdt_desc);
    __sidt(&idt_desc);

    // Guest state setup
    __vmx_vmwrite(GUEST_CR0, __readcr0());
    __vmx_vmwrite(GUEST_CR3, __readcr3());
    __vmx_vmwrite(GUEST_CR4, __readcr4());
    __vmx_vmwrite(GUEST_DR7, __readdr(7));

    __vmx_vmwrite(GUEST_GDTR_BASE, gdt_desc.Base);
    __vmx_vmwrite(GUEST_IDTR_BASE, idt_desc.Base);
    __vmx_vmwrite(GUEST_GDTR_LIMIT, gdt_desc.Limit);
    __vmx_vmwrite(GUEST_IDTR_LIMIT, idt_desc.Limit);

    __vmx_vmwrite(GUEST_RSP, (size_t)VmxData->GuestStack + GUEST_STACK_SIZE);
    __vmx_vmwrite(GUEST_RIP, (size_t)VhGuestEntry);

    // Guest segment selectors
    VhFillGuestSelectorData((PVOID)gdt_desc.Base, GetEs(), &vmx_seg);
    __vmx_vmwrite(GUEST_ES_SELECTOR, vmx_seg.Selector);
    __vmx_vmwrite(GUEST_ES_BASE, vmx_seg.Base);
    __vmx_vmwrite(GUEST_ES_LIMIT, vmx_seg.Limit);
    __vmx_vmwrite(GUEST_ES_AR_BYTES, vmx_seg.AccessRights.All);

    VhFillGuestSelectorData((PVOID)gdt_desc.Base, GetCs(), &vmx_seg);
    __vmx_vmwrite(GUEST_CS_SELECTOR, vmx_seg.Selector);
    __vmx_vmwrite(GUEST_CS_BASE, vmx_seg.Base);
    __vmx_vmwrite(GUEST_CS_LIMIT, vmx_seg.Limit);
    __vmx_vmwrite(GUEST_CS_AR_BYTES, vmx_seg.AccessRights.All);

    VhFillGuestSelectorData((PVOID)gdt_desc.Base, GetSs(), &vmx_seg);
    __vmx_vmwrite(GUEST_SS_SELECTOR, vmx_seg.Selector);
    __vmx_vmwrite(GUEST_SS_BASE, vmx_seg.Base);
    __vmx_vmwrite(GUEST_SS_LIMIT, vmx_seg.Limit);
    __vmx_vmwrite(GUEST_SS_AR_BYTES, vmx_seg.AccessRights.All);

    VhFillGuestSelectorData((PVOID)gdt_desc.Base, GetDs(), &vmx_seg);
    __vmx_vmwrite(GUEST_DS_SELECTOR, vmx_seg.Selector);
    __vmx_vmwrite(GUEST_DS_BASE, vmx_seg.Base);
    __vmx_vmwrite(GUEST_DS_LIMIT, vmx_seg.Limit);
    __vmx_vmwrite(GUEST_DS_AR_BYTES, vmx_seg.AccessRights.All);

    VhFillGuestSelectorData((PVOID)gdt_desc.Base, GetFs(), &vmx_seg);
    __vmx_vmwrite(GUEST_FS_SELECTOR, vmx_seg.Selector);
    __vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
    __vmx_vmwrite(GUEST_FS_LIMIT, vmx_seg.Limit);
    __vmx_vmwrite(GUEST_FS_AR_BYTES, vmx_seg.AccessRights.All);

    VhFillGuestSelectorData((PVOID)gdt_desc.Base, GetGs(), &vmx_seg);
    __vmx_vmwrite(GUEST_GS_SELECTOR, vmx_seg.Selector);
    __vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
    __vmx_vmwrite(GUEST_GS_LIMIT, vmx_seg.Limit);
    __vmx_vmwrite(GUEST_GS_AR_BYTES, vmx_seg.AccessRights.All);

    __vmx_vmwrite(GUEST_LDTR_SELECTOR, 0);
    __vmx_vmwrite(GUEST_LDTR_AR_BYTES, 0x10000); // Unusable

    __vmx_vmwrite(GUEST_TR_SELECTOR, GetTr());
    VhFillGuestSelectorData((PVOID)gdt_desc.Base, GetTr(), &vmx_seg);
    __vmx_vmwrite(GUEST_TR_BASE, vmx_seg.Base);
    __vmx_vmwrite(GUEST_TR_LIMIT, vmx_seg.Limit);
    __vmx_vmwrite(GUEST_TR_AR_BYTES, vmx_seg.AccessRights.All);

    __vmx_vmwrite(GUEST_RFLAGS, __readeflags());

    // Host state setup
    __vmx_vmwrite(HOST_CR0, __readcr0());
    __vmx_vmwrite(HOST_CR3, __readcr3());
    __vmx_vmwrite(HOST_CR4, __readcr4());
    __vmx_vmwrite(HOST_RIP, (size_t)VhVmexitHandler);
    __vmx_vmwrite(HOST_RSP, (size_t)VmxData->VmxonRegion + VMXON_SIZE);

    __vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & ~RPL_MASK);
    __vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & ~RPL_MASK);
    __vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & ~RPL_MASK);
    __vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & ~RPL_MASK);
    __vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & ~RPL_MASK);
    __vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & ~RPL_MASK);
    __vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & ~RPL_MASK);

    __vmx_vmwrite(HOST_GDTR_BASE, gdt_desc.Base);
    __vmx_vmwrite(HOST_IDTR_BASE, idt_desc.Base);
    __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
    __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));

    // VM-Execution control fields
    IA32_VMX_PINBASED_CTLS_MSR pin_based_ctls = { __readmsr(MSR_IA32_VMX_PINBASED_CTLS) };
    IA32_VMX_PROCBASED_CTLS_MSR proc_based_ctls = { __readmsr(MSR_IA32_VMX_PROCBASED_CTLS) };
    IA32_VMX_PROCBASED_CTLS2_MSR proc_based_ctls2 = { __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2) };
    IA32_VMX_EXIT_CTLS_MSR exit_ctls = { __readmsr(MSR_IA32_VMX_EXIT_CTLS) };
    IA32_VMX_ENTRY_CTLS_MSR entry_ctls = { __readmsr(MSR_IA32_VMX_ENTRY_CTLS) };

    pin_based_ctls.Allowed_0_Settings.ExternalInterruptExiting = 1;
    proc_based_ctls.Allowed_0_Settings.UseMsrBitmaps = 1;
    proc_based_ctls.Allowed_0_Settings.ActivateSecondaryControls = 1;
    proc_based_ctls2.Allowed_0_Settings.EnableEpt = 1;
    exit_ctls.Allowed_0_Settings.HostAddressSpaceSize = 1;
    entry_ctls.Allowed_0_Settings.Ia32eModeGuest = 1;

    __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin_based_ctls.Allowed_1_Settings.All);
    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, proc_based_ctls.Allowed_1_Settings.All);
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, proc_based_ctls2.Allowed_1_Settings.All);
    __vmx_vmwrite(VM_EXIT_CONTROLS, exit_ctls.Allowed_1_Settings.All);
    __vmx_vmwrite(VM_ENTRY_CONTROLS, entry_ctls.Allowed_1_Settings.All);

    // Set up MSR bitmap (currently allows all MSR access).
    __vmx_vmwrite(MSR_BITMAP, 0);

    // Enable EPT.
    VhEnableEpt(VmxData);
}

/*
 * Entry point for launching the virtual machine on a processor.
 */
VOID VhLaunchVm(ULONG ProcessorIndex)
{
    PPER_CPU_VMX_DATA vmxData = &g_VmxData[ProcessorIndex];

    // Clear the current VMCS.
    if (__vmx_vmclear(&vmxData->VmcsRegionPa.QuadPart))
    {
        DbgPrint("VIREX-HV: [Core %d] __vmx_vmclear failed.\n", ProcessorIndex);
        return;
    }

    // Make the current VMCS active and resident.
    if (__vmx_vmptrld(&vmxData->VmcsRegionPa.QuadPart))
    {
        DbgPrint("VIREX-HV: [Core %d] __vmx_vmptrld failed.\n", ProcessorIndex);
        return;
    }

    // Build the EPT identity map.
    if (!VhBuildEptIdentityMap(&vmxData->EptState))
    {
        DbgPrint("VIREX-HV: [Core %d] Failed to build EPT identity map.\n", ProcessorIndex);
        return;
    }

    // Configure all VMCS fields.
    VhSetupVmcs(vmxData);
    DbgPrint("VIREX-HV: [Core %d] VMCS configured.\n", ProcessorIndex);

    // Launch the guest.
    __vmx_vmlaunch();

    // This part is only reached if VMLAUNCH fails.
    size_t errorCode;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &errorCode);
    DbgPrint("VIREX-HV: [Core %d] VMLAUNCH failed with error: 0x%llX\n", ProcessorIndex, errorCode);
    KeBugCheckEx(HYPERVISOR_ERROR, (ULONG_PTR)errorCode, 0, 0, 0);
}

/*
 * Assembly stub to resume guest execution after VMLAUNCH.
 */
VOID VhGuestEntry()
{
    // After VMLAUNCH, control is transferred here.
    // The original execution context is restored in the VM-Exit handler
    // before VMRESUME, so we just need to return to allow that to happen.
    // This function effectively acts as a placeholder for the initial RIP.
    return;
}
