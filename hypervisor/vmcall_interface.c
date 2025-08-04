/*
 * vmcall_interface.c
 *
 *  Acts as the main API dispatcher for commands sent to the hypervisor
 *  via the VMCALL instruction from a user-mode application.
 */

#include "include/vmx.h"
#include "include/intercepts.h"
#include "include/vmcall_codes.h"
#include "include/security_checks.h"
#include "include/syscall_hook.h"
#include "include/spoof_manager.h"

/*
 * Main VMCALL handler. Routes commands to the appropriate subsystem.
 */
VOID VhHandleVmcall(PGUEST_REGS GuestRegs)
{
    VMCALL_CODE vmcallNumber = (VMCALL_CODE)GuestRegs->rax;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG processorIndex = KeGetCurrentProcessorNumberEx(NULL);
    PEPT_STATE eptState = &g_VmxData[processorIndex].EptState;

    UINT64 param1 = GuestRegs->rcx;
    UINT64 param2 = GuestRegs->rdx;
    UINT64 param3 = GuestRegs->r8;

    switch (vmcallNumber)
    {
        case VMCALL_GET_STATUS:
            GuestRegs->rax = 0xDEADBEEF; // Magic number for 'hypervisor running'.
            break;

        case VMCALL_CLOAK_INT3_PAGE:
            status = VhCloakInt3Breakpoint(eptState, (PHYSICAL_ADDRESS)param1, (UCHAR)param2);
            GuestRegs->rax = status;
            break;

        case VMCALL_UNCLOAK_INT3_PAGE:
            status = VhUncloakInt3Breakpoint(eptState, (PHYSICAL_ADDRESS)param1);
            GuestRegs->rax = status;
            break;
            
        case VMCALL_SET_MSR_SPOOF:
            status = VhSetMsrSpoof((UINT32)param1, param2);
            GuestRegs->rax = status;
            break;

        case VMCALL_SET_CPUID_SPOOF:
            status = VhSetCpuidSpoofFull((UINT32)param1, 0, (PCPUID_SPOOF_VALUES)param2);
            GuestRegs->rax = status;
            break;
        
        case VMCALL_RUN_NTOSKRNL_PATCH_SCAN:
            status = VhCheckNtoskrnlPatches();
            GuestRegs->rax = status;
            break;

        case VMCALL_RUN_DRIVER_OBJECT_SCAN:
            status = VhCheckDriverObjects();
            GuestRegs->rax = status;
            break;
        
        case VMCALL_TRACE_SYSCALL:
            status = VhTraceSyscall(eptState, (ULONG)param1);
            GuestRegs->rax = status;
            break;

        case VMCALL_SET_RDTSC_SPOOF:
            status = VhSetRdtscSpoof((UINT64)param1, (UINT64)param2);
            GuestRegs->rax = status;
            break;

        default:
            GuestRegs->rax = STATUS_INVALID_PARAMETER;
            break;
    }
}
