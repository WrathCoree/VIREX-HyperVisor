/*
 * vmx_init.c
 *
 *  Handles the initialization and termination of VMX operation on all
 *  logical processors in the system.
 */

#include "include/vmx.h"
#include "include/ept.h"
#include "include/spoof_manager.h"
#include "include/cloak_int3.h"

// Global state for VMX across all processors.
PER_CPU_VMX_DATA* g_VmxData = NULL;
PVOID g_DriverBase = NULL;
ULONG g_DriverSize = 0;

/*
 * Checks if the processor supports VMX and if it's enabled in the BIOS.
 */
BOOLEAN VhCheckVmxSupport()
{
    CPUID_EAX_01 cpuid_eax_01 = { 0 };
    IA32_FEATURE_CONTROL_MSR feature_control_msr = { 0 };

    // VMX support is indicated by CPUID.1:ECX.VMX[bit 5] = 1.
    __cpuid((int*)&cpuid_eax_01, 1);
    if (!cpuid_eax_01.VirtualMachineExtensions)
    {
        DbgPrint("VIREX-HV: VMX feature not supported.\n");
        return FALSE;
    }

    // VMXON is enabled only if IA32_FEATURE_CONTROL MSR is configured correctly.
    feature_control_msr.All = __readmsr(MSR_IA32_FEATURE_CONTROL);
    if (!feature_control_msr.LockBit)
    {
        // If Lock Bit is 0, we can attempt to enable VMX.
        feature_control_msr.EnableVmxonOutsideSmx = TRUE;
        __writemsr(MSR_IA32_FEATURE_CONTROL, feature_control_msr.All);
    }
    else if (!feature_control_msr.EnableVmxonOutsideSmx)
    {
        DbgPrint("VIREX-HV: VMX disabled by BIOS.\n");
        return FALSE;
    }

    return TRUE;
}

/*
 * Allocates a single 4KB VMXON region for a logical processor.
 */
PVOID VhAllocateVmxonRegion()
{
    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = MAXULONG64;
    
    // VMXON region must be 4KB aligned.
    PVOID vmxonRegion = MmAllocateContiguousNodeMemory(VMXON_SIZE,
                                                       maxAddr,
                                                       maxAddr,
                                                       maxAddr,
                                                       PAGE_READWRITE,
                                                       MM_ANY_NODE_OK);
    if (vmxonRegion)
    {
        RtlSecureZeroMemory(vmxonRegion, VMXON_SIZE);
    }
    return vmxonRegion;
}

/*
 * DPC callback to initialize VMX on a specific logical processor.
 */
VOID VhVmxInitializationCallback(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    ULONG processorIndex = KeGetCurrentProcessorNumberEx(NULL);
    PHYSICAL_ADDRESS vmxonRegionPa;
    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = MAXULONG64;

    // Set the VMXE bit in CR4 to enable VMX.
    __writecr4(__readcr4() | CR4_VMX_ENABLE_BIT);
    DbgPrint("VIREX-HV: [Core %d] VMXE bit enabled in CR4.\n", processorIndex);

    // Get the VMX revision identifier and write it to the VMXON region.
    IA32_VMX_BASIC_MSR vmx_basic_msr = { .All = __readmsr(MSR_IA32_VMX_BASIC) };
    RtlCopyMemory(g_VmxData[processorIndex].VmxonRegion, &vmx_basic_msr.VmcsRevisionId, sizeof(UINT32));

    // Execute VMXON instruction.
    vmxonRegionPa = MmGetPhysicalAddress(g_VmxData[processorIndex].VmxonRegion);
    if (__vmx_on(&vmxonRegionPa.QuadPart))
    {
        DbgPrint("VIREX-HV: [Core %d] __vmx_on failed.\n", processorIndex);
        return;
    }

    g_VmxData[processorIndex].IsVmxon = TRUE;
    DbgPrint("VIREX-HV: [Core %d] VMXON successful.\n", processorIndex);

    // Allocate and set up the VMCS, Stacks, and MSR Bitmap for this processor.
    VhAllocateVmcsRegion(&g_VmxData[processorIndex]);
    g_VmxData[processorIndex].GuestStack = ExAllocatePoolWithTag(NonPagedPool, GUEST_STACK_SIZE, 'GS');
    g_VmxData[processorIndex].HostStack = ExAllocatePoolWithTag(NonPagedPool, HOST_STACK_SIZE, 'HS');
    g_VmxData[processorIndex].MsrBitmap = MmAllocateContiguousNodeMemory(MSR_BITMAP_SIZE, maxAddr, maxAddr, maxAddr, PAGE_READWRITE, MM_ANY_NODE_OK);

    if (!g_VmxData[processorIndex].GuestStack || !g_VmxData[processorIndex].HostStack || !g_VmxData[processorIndex].MsrBitmap)
    {
        DbgPrint("VIREX-HV: [Core %d] Failed to allocate guest/host stack or MSR bitmap.\n", processorIndex);
        if (g_VmxData[processorIndex].GuestStack) ExFreePoolWithTag(g_VmxData[processorIndex].GuestStack, 'GS');
        if (g_VmxData[processorIndex].HostStack) ExFreePoolWithTag(g_VmxData[processorIndex].HostStack, 'HS');
        if (g_VmxData[processorIndex].MsrBitmap) MmFreeContiguousMemory(g_VmxData[processorIndex].MsrBitmap);
        __vmx_off();
        return;
    }
    g_VmxData[processorIndex].MsrBitmapPa = MmGetPhysicalAddress(g_VmxData[processorIndex].MsrBitmap);
    RtlSecureZeroMemory(g_VmxData[processorIndex].MsrBitmap, MSR_BITMAP_SIZE);

    // Trap on writes to IA32_LSTAR to monitor for syscall hook attempts.
    PUCHAR msr_bitmap_rw = (PUCHAR)g_VmxData[processorIndex].MsrBitmap + 2048;
    msr_bitmap_rw[(MSR_IA32_LSTAR - 0xC0000000) / 8] |= (1 << ((MSR_IA32_LSTAR - 0xC0000000) % 8));

    // Proceed to launch the VM on this processor.
    VhLaunchVm(processorIndex);
}

/*
 * Main entry point to initialize the hypervisor on all system cores.
 */
NTSTATUS HvInitializeVmx(PVOID DriverBase, ULONG DriverSize)
{
    if (!VhCheckVmxSupport())
    {
        return STATUS_NOT_SUPPORTED;
    }

    LONG processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    g_DriverBase = DriverBase;
    g_DriverSize = DriverSize;

    // Allocate state structure for each CPU.
    g_VmxData = ExAllocatePoolWithTag(NonPagedPool, sizeof(PER_CPU_VMX_DATA) * processorCount, 'VMX');
    if (!g_VmxData)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlSecureZeroMemory(g_VmxData, sizeof(PER_CPU_VMX_DATA) * processorCount);

    // Allocate a VMXON region for each CPU.
    for (LONG i = 0; i < processorCount; i++)
    {
        g_VmxData[i].VmxonRegion = VhAllocateVmxonRegion();
        if (!g_VmxData[i].VmxonRegion)
        {
            // Cleanup on failure.
            for (LONG j = 0; j < i; j++)
            {
                MmFreeContiguousMemory(g_VmxData[j].VmxonRegion);
            }
            ExFreePoolWithTag(g_VmxData, 'VMX');
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    
    // Initialize spoofing, cloaking and other subsystems.
    VhInitializeSpoofManager();
    VhInitializeInt3Cloaking();
    VhInitializeSyscallTrace();
    
    // Execute VMX initialization on all cores via DPC.
    KeGenericCallDpc(VhVmxInitializationCallback, NULL);
    
    // Hide the hypervisor's own memory via EPT.
    VhHideHypervisorMemory(g_DriverBase, g_DriverSize);

    DbgPrint("VIREX-HV: Hypervisor initialization complete on all cores.\n");
    return STATUS_SUCCESS;
}

/*
 * Shuts down the hypervisor and turns off VMX on all cores.
 */
VOID HvShutdownVmx()
{
    LONG processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    // Execute VMXOFF and cleanup on all cores.
    for (LONG i = 0; i < processorCount; i++)
    {
        if (g_VmxData[i].IsVmxon)
        {
            __vmx_off();
        }
        if (g_VmxData[i].VmcsRegion)
        {
            MmFreeContiguousMemory(g_VmxData[i].VmcsRegion);
        }
        if (g_VmxData[i].VmxonRegion)
        {
            MmFreeContiguousMemory(g_VmxData[i].VmxonRegion);
        }
        if (g_VmxData[i].GuestStack)
        {
            ExFreePoolWithTag(g_VmxData[i].GuestStack, 'GS');
        }
        if (g_VmxData[i].HostStack)
        {
            ExFreePoolWithTag(g_VmxData[i].HostStack, 'HS');
        }
        if (g_VmxData[i].MsrBitmap)
        {
            MmFreeContiguousMemory(g_VmxData[i].MsrBitmap);
        }
        VhCleanupEpt(&g_VmxData[i].EptState);
    }

    // Cleanup global subsystems.
    VhCleanupSpoofManager();
    VhCleanupInt3Cloaking();
    VhCleanupSyscallTrace();

    if (g_VmxData)
    {
        ExFreePoolWithTag(g_VmxData, 'VMX');
    }

    DbgPrint("VIREX-HV: Hypervisor shutdown complete.\n");
}
