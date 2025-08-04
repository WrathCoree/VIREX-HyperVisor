/*
 * vmexit_handler.c
 *
 *  Contains the central VM-Exit dispatcher, which is the primary entry
 *  point from guest to host.
 */

#include "include/vmx.h"
#include "include/intercepts.h"

/*
 * The C-level VM-Exit handler. Invoked by the assembly stub.
 */
VOID VmexitHandlerC(PGUEST_REGS GuestRegs)
{
    size_t exitReason = 0;
    __vmx_vmread(VM_EXIT_REASON, &exitReason);

    // Dispatch to the appropriate sub-handler based on the exit reason.
    switch (exitReason & 0xFFFF)
    {
        case EXIT_REASON_CPUID:
            VhHandleCpuid(GuestRegs);
            break;

        case EXIT_REASON_MSR_READ:
            VhHandleMsrRead(GuestRegs);
            break;

        case EXIT_REASON_MSR_WRITE:
            VhHandleMsrWrite(GuestRegs);
            break;

        case EXIT_REASON_EPT_VIOLATION:
            VhHandleEptViolation(GuestRegs);
            break;
            
        case EXIT_REASON_MONITOR_TRAP_FLAG:
            VhHandleMtfTrap();
            break;
            
        case EXIT_REASON_RDTSC:
            VhHandleRdtsc(GuestRegs, FALSE);
            break;
            
        case EXIT_REASON_RDTSCP:
            VhHandleRdtsc(GuestRegs, TRUE);
            break;
            
        case EXIT_REASON_VMCALL:
            VhHandleVmcall(GuestRegs);
            break;
            
        default:
        {
            // Unhandled VM-Exit, log information for debugging.
            size_t qual, rip, rsp;
            __vmx_vmread(VM_EXIT_QUALIFICATION, &qual);
            __vmx_vmread(GUEST_RIP, &rip);
            __vmx_vmread(GUEST_RSP, &rsp);
            DbgPrint("VIREX-HV: Unhandled VM-Exit! Reason: 0x%llX, Qual: 0x%llX, RIP: 0x%llX\n",
                exitReason, qual, rip);
            KeBugCheckEx(HYPERVISOR_ERROR, exitReason, qual, rip, rsp);
            break;
        }
    }
}

/*
 * Handles a failed __vmx_vmresume attempt.
 */
VOID VhHandleVmresumeFailure(PGUEST_REGS GuestRegs)
{
    // This is a critical failure. The hypervisor state is likely corrupt.
    // We read the VMX instruction error and bugcheck the system.
    size_t errorCode;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &errorCode);
    DbgPrint("VIREX-HV: VMRESUME failed! Error: 0x%llX\n", errorCode);
    KeBugCheckEx(HYPERVISOR_ERROR, (ULONG_PTR)errorCode, (ULONG_PTR)GuestRegs, 0, 0);
}
