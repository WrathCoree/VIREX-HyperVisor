/*
 * intercept_cpuid.c
 *
 *  Handles VM-Exits caused by the CPUID instruction. This allows for
 *  spoofing CPU features and identity.
 */

#include "include/vmx.h"
#include "include/spoof_manager.h"

/*
 * Intercepts and potentially modifies the result of a CPUID instruction.
 */
VOID VhHandleCpuid(PGUEST_REGS GuestRegs)
{
    int cpu_info[4];
    UINT32 leaf = (UINT32)GuestRegs->rax;
    UINT32 subleaf = (UINT32)GuestRegs->rcx;

    // Execute the real CPUID instruction to get baseline values.
    __cpuidex(cpu_info, leaf, subleaf);

    // Check dynamic spoofing rules for a full-leaf replacement.
    CPUID_SPOOF_VALUES spoof_values;
    if (VhFindCpuidSpoofFull(leaf, subleaf, &spoof_values))
    {
        cpu_info[0] = spoof_values.Eax;
        cpu_info[1] = spoof_values.Ebx;
        cpu_info[2] = spoof_values.Ecx;
        cpu_info[3] = spoof_values.Edx;
    }
    else
    {
        // Apply a default static spoof if no dynamic rule exists.
        if (leaf == 1)
        {
            // Hide the hypervisor-present bit (bit 31 of ECX).
            cpu_info[2] &= ~(1 << 31);
        }
    }

    // Pass the (potentially modified) results back to the guest.
    GuestRegs->rax = cpu_info[0];
    GuestRegs->rbx = cpu_info[1];
    GuestRegs->rcx = cpu_info[2];
    GuestRegs->rdx = cpu_info[3];
}
