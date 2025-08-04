/*
 * intercept_msr.c
 *
 *  Handles VM-Exits caused by RDMSR and WRMSR instructions, allowing for
 *  interception and spoofing of Model-Specific Registers.
 */

#include "include/vmx.h"
#include "include/spoof_manager.h"

/*
 * Handles guest attempts to read an MSR.
 */
VOID VhHandleMsrRead(PGUEST_REGS GuestRegs)
{
    UINT32 msr_index = (UINT32)GuestRegs->rcx;
    UINT64 msr_value;

    // Check for a dynamic spoofing rule first.
    if (VhFindMsrSpoof(msr_index, &msr_value))
    {
        // A rule was found, return the spoofed value.
        GuestRegs->rax = msr_value & 0xFFFFFFFF;
        GuestRegs->rdx = msr_value >> 32;
    }
    else
    {
        // No rule, perform the real MSR read.
        // A try/except block is critical here as some MSRs may not exist.
        __try
        {
            msr_value = __readmsr(msr_index);
            GuestRegs->rax = msr_value & 0xFFFFFFFF;
            GuestRegs->rdx = msr_value >> 32;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // Inject a #GP fault into the guest.
            VMX_VMEVENT_INJECTION injection_info = { 0 };
            injection_info.InterruptionType = HARDWARE_EXCEPTION;
            injection_info.Vector = GP_EXCEPTION;
            injection_info.DeliverErrorCode = 1;
            __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, injection_info.All);
        }
    }
}

/*
 * Handles guest attempts to write to an MSR.
 */
VOID VhHandleMsrWrite(PGUEST_REGS GuestRegs)
{
    UINT32 msr_index = (UINT32)GuestRegs->rcx;
    UINT64 msr_value = (GuestRegs->rdx << 32) | GuestRegs->rax;

    // For security, we can choose to block writes to certain critical MSRs.
    // For now, we allow the write to proceed.
    // A try/except block is critical here.
    __try
    {
        __writemsr(msr_index, msr_value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Inject a #GP fault into the guest for invalid writes.
        VMX_VMEVENT_INJECTION injection_info = { 0 };
        injection_info.InterruptionType = HARDWARE_EXCEPTION;
        injection_info.Vector = GP_EXCEPTION;
        injection_info.DeliverErrorCode = 1;
        __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, injection_info.All);
    }
}
