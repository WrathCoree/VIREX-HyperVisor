#ifndef INTERCEPTS_H
#define INTERCEPTS_H

#include <ntddk.h>

// Structure to hold guest general-purpose registers on VM-Exit.
typedef struct _GUEST_REGS
{
    UINT64 rax;
    UINT64 rbx;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    UINT64 r12;
    UINT64 r13;
    UINT64 r14;
    UINT64 r15;

} GUEST_REGS, *PGUEST_REGS;

// Public Function Prototypes

// Main C handler for VM-Exits, called from assembly.
VOID VmexitHandlerC(PGUEST_REGS GuestRegs);

// Handler for failed VMRESUME, called from assembly.
VOID VhHandleVmresumeFailure(PGUEST_REGS GuestRegs);

// Main assembly entry point for all VM-Exits.
extern VOID VhVmexitHandler(VOID);

// Intercept handlers for specific VM-Exit reasons.
VOID VhHandleCrAccess(PGUEST_REGS GuestRegs);
VOID VhHandleCpuid(PGUEST_REGS GuestRegs);
VOID VhHandleMsrRead(PGUEST_REGS GuestRegs);
VOID VhHandleMsrWrite(PGUEST_REGS GuestRegs);
VOID VhHandleRdtsc(PGUEST_REGS GuestRegs, BOOLEAN IsRdtscp);
VOID VhHandleEptViolation(PGUEST_REGS GuestRegs);
VOID VhHandleVmcall(PGUEST_REGS GuestRegs);

// INT3 cloaking and tracing handlers.
VOID VhInitializeInt3Cloaking();
VOID VhCleanupInt3Cloaking();
VOID VhHandleMtfTrap();

#endif
