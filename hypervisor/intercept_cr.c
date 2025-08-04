/*
 * intercept_cr.c
 *
 *  Handles VM-Exits caused by guest access to control registers (CRs),
 *  now with enhanced logging for process context switches.
 */

#include "include/vmx.h"
#include <ntddk.h>

// Keep track of the last known CR3 to detect changes.
static ULONG_PTR g_LastKnownCr3[256] = { 0 }; // Per-processor

/*
 * Intercepts guest access to control registers.
 */
VOID VhHandleCrAccess(PGUEST_REGS GuestRegs)
{
    size_t qualification = 0;
    __vmx_vmread(VM_EXIT_QUALIFICATION, &qualification);
    
    ULONG processorIndex = KeGetCurrentProcessorNumberEx(NULL);
    ULONG cr_number = (ULONG)(qualification & 0xF);
    ULONG access_type = (ULONG)((qualification >> 4) & 3);
    ULONG reg_index = (ULONG)((qualification >> 8) & 0xF);
    
    // Pointer to the register involved in the access (e.g., RAX, RBX).
    PULONG_PTR pReg = (PULONG_PTR)((PUCHAR)GuestRegs + (reg_index * sizeof(ULONG_PTR)));

    switch (access_type)
    {
        case 0: // MOV to CR
            if (cr_number == 3)
            {
                // Guest is writing a new page table base into CR3.
                // This indicates a process context switch.
                if (g_LastKnownCr3[processorIndex] != *pReg)
                {
                    PEPROCESS currentProcess = PsGetCurrentProcess();
                    HANDLE currentPid = PsGetProcessId(currentProcess);
                    DbgPrint("VIREX-HV: [CR] Context switch on Core %d to PID: %llu, New CR3: 0x%llX\n",
                        processorIndex,
                        (UINT64)currentPid,
                        *pReg);

                    g_LastKnownCr3[processorIndex] = *pReg;
                }
                __vmx_vmwrite(GUEST_CR3, *pReg);
            }
            break;
        case 1: // MOV from CR
            if (cr_number == 3)
            {
                // Guest is reading CR3. Provide the value from the VMCS.
                size_t guest_cr3;
                __vmx_vmread(GUEST_CR3, &guest_cr3);
                *pReg = guest_cr3;
            }
            break;
    }
}
