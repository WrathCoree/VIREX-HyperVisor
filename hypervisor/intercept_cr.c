/*
 * intercept_cr.c
 *
 *  Handles VM-Exits caused by guest access to control registers (CRs).
 */

#include "include/vmx.h"

/*
 * Intercepts guest access to control registers.
 */
VOID VhHandleCrAccess(PGUEST_REGS GuestRegs)
{
    size_t qualification = 0;
    __vmx_vmread(VM_EXIT_QUALIFICATION, &qualification);

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
                // Guest is writing to CR3. Update the shadow and guest CR3.
                __vmx_vmwrite(GUEST_CR3, *pReg);
                DbgPrint("VIREX-HV: [CR] CR3 write to 0x%llX by guest.\n", *pReg);
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
