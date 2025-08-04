.code

; External C functions that will be called from this assembly file.
EXTERN VmexitHandlerC : PROC
EXTERN VhHandleVmresumeFailure : PROC

;
; VhVmexitHandler
;
;   Purpose:
;       The low-level entry point for all VM-Exits. This is the most
;       critical and performance-sensitive part of the hypervisor.
;
;   Operation:
;       1. Saves the complete guest general-purpose register state.
;       2. Passes a pointer to the saved state to the C handler (VmexitHandlerC).
;       3. Calls the C handler to process the VM-Exit.
;       4. Restores the guest register state.
;       5. Resumes the guest using VMRESUME.
;       6. If VMRESUME fails, calls a C failure handler to bugcheck the system.
;
PUBLIC VhVmexitHandler
VhVmexitHandler proc
    push    rax
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    ; The stack now matches the GUEST_REGS structure.
    ; Move the stack pointer (a pointer to our GUEST_REGS) into RCX,
    ; which is the first argument for the x64 fastcall convention.
    mov     rcx, rsp

    ; Reserve 32 bytes of shadow space on the stack for the callee,
    ; as required by the x64 calling convention.
    sub     rsp, 32
    call    VmexitHandlerC
    add     rsp, 32

    ; Restore all guest registers from the stack.
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax

    ; Resume the guest.
    vmresume

    ; If VMRESUME fails, execution falls through to this point.
    ; This is a critical error. The stack pointer still points to GUEST_REGS.
    mov     rcx, rsp
    sub     rsp, 32
    call    VhHandleVmresumeFailure
    add     rsp, 32

    ; VhHandleVmresumeFailure should never return. If it does, halt the system.
    cli
    hlt

VhVmexitHandler endp

END
