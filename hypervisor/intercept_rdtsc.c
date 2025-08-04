/*
 * intercept_rdtsc.c
 *
 *  This file is a new addition to handle the RDTSC and RDTSCP instructions.
 *  It allows for advanced time-based spoofing, a key technique in
 *  researching timing-based virtual machine detection.
 */

#include "include/vmx.h"
#include "include/spoof_manager.h"

/*
 * Handles VM-Exits from RDTSC or RDTSCP instructions.
 */
VOID VhHandleRdtsc(PGUEST_REGS GuestRegs, BOOLEAN IsRdtscp)
{
    UINT64 originalTsc, spoofedTsc;
    TSC_SPOOF_RULE rule;

    // Read the real Time Stamp Counter value.
    if (IsRdtscp)
    {
        UINT32 tscAux;
        originalTsc = __rdtscp(&tscAux);
        GuestRegs->rcx = tscAux; // Pass AUX value back to guest.
    }
    else
    {
        originalTsc = __rdtsc();
    }

    // Check if an active spoofing rule exists for the TSC.
    if (VhGetRdtscSpoof(&rule))
    {
        // Apply the advanced spoofing rule (scaling and offsetting).
        spoofedTsc = (originalTsc * rule.Multiplier) + rule.Offset;
    }
    else
    {
        // No rule, return the real value.
        spoofedTsc = originalTsc;
    }

    // Return the (potentially spoofed) value in EAX:EDX.
    GuestRegs->rax = spoofedTsc & 0xFFFFFFFF;
    GuestRegs->rdx = spoofedTsc >> 32;
}
