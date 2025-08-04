// This header contains a comprehensive list of VMCS field encodings
// as defined in the Intel Software Developer's Manual (SDM), Volume 3C, Appendix A.

#ifndef VMCS_FIELDS_H
#define VMCS_FIELDS_H

// Guest-State Fields
#define GUEST_ES_SELECTOR               0x00000800
#define GUEST_CS_SELECTOR               0x00000802
#define GUEST_SS_SELECTOR               0x00000804
#define GUEST_DS_SELECTOR               0x00000806
#define GUEST_FS_SELECTOR               0x00000808
#define GUEST_GS_SELECTOR               0x0000080a
#define GUEST_LDTR_SELECTOR             0x0000080c
#define GUEST_TR_SELECTOR               0x0000080e
#define GUEST_ES_LIMIT                  0x00004800
#define GUEST_CS_LIMIT                  0x00004802
#define GUEST_SS_LIMIT                  0x00004804
#define GUEST_DS_LIMIT                  0x00004806
#define GUEST_FS_LIMIT                  0x00004808
#define GUEST_GS_LIMIT                  0x0000480a
#define GUEST_LDTR_LIMIT                0x0000480c
#define GUEST_TR_LIMIT                  0x0000480e
#define GUEST_GDTR_LIMIT                0x00004810
#define GUEST_IDTR_LIMIT                0x00004812
#define GUEST_ES_AR_BYTES               0x00004814
#define GUEST_CS_AR_BYTES               0x00004816
#define GUEST_SS_AR_BYTES               0x00004818
#define GUEST_DS_AR_BYTES               0x0000481a
#define GUEST_FS_AR_BYTES               0x0000481c
#define GUEST_GS_AR_BYTES               0x0000481e
#define GUEST_LDTR_AR_BYTES             0x00004820
#define GUEST_TR_AR_BYTES               0x00004822
#define GUEST_INTERRUPTIBILITY_INFO     0x00004824
#define GUEST_ACTIVITY_STATE            0x00004826
#define GUEST_CR0                       0x00006800
#define GUEST_CR3                       0x00006802
#define GUEST_CR4                       0x00006804
#define GUEST_ES_BASE                   0x00006806
#define GUEST_CS_BASE                   0x00006808
#define GUEST_SS_BASE                   0x0000680a
#define GUEST_DS_BASE                   0x0000680c
#define GUEST_FS_BASE                   0x0000680e
#define GUEST_GS_BASE                   0x00006810
#define GUEST_LDTR_BASE                 0x00006812
#define GUEST_TR_BASE                   0x00006814
#define GUEST_GDTR_BASE                 0x00006816
#define GUEST_IDTR_BASE                 0x00006818
#define GUEST_RSP                       0x0000681c
#define GUEST_RIP                       0x0000681e
#define GUEST_RFLAGS                    0x00006820
#define GUEST_PENDING_DBG_EXCEPTIONS    0x00006822
#define GUEST_DR7                       0x00006806

// Host-State Fields
#define HOST_ES_SELECTOR                0x00000c00
#define HOST_CS_SELECTOR                0x00000c02
#define HOST_SS_SELECTOR                0x00000c04
#define HOST_DS_SELECTOR                0x00000c06
#define HOST_FS_SELECTOR                0x00000c08
#define HOST_GS_SELECTOR                0x00000c0a
#define HOST_TR_SELECTOR                0x00000c0c
#define HOST_CR0                        0x00006c00
#define HOST_CR3                        0x00006c02
#define HOST_CR4                        0x00006c04
#define HOST_FS_BASE                    0x00006c06
#define HOST_GS_BASE                    0x00006c08
#define HOST_TR_BASE                    0x00006c0a
#define HOST_GDTR_BASE                  0x00006c0c
#define HOST_IDTR_BASE                  0x00006c0e
#define HOST_RSP                        0x00006c14
#define HOST_RIP                        0x00006c16
#define HOST_IA32_SYSENTER_CS           0x00004c00
#define HOST_IA32_SYSENTER_ESP          0x00006c0e
#define HOST_IA32_SYSENTER_EIP          0x00006c10

// VM-Execution Control Fields
#define PIN_BASED_VM_EXEC_CONTROL       0x00004000
#define CPU_BASED_VM_EXEC_CONTROL       0x00004002
#define CPU_BASED_VM_EXEC_CONTROL2      0x0000401e
#define VM_EXIT_CONTROLS                0x0000400c
#define VM_ENTRY_CONTROLS               0x00004012

// MSR specific fields
#define VMCS_LINK_POINTER               0x00002800
#define IA32_DEBUGCTL_FULL              0x00002802
#define MSR_BITMAP_ADDRESS              0x00002004
#define VM_EXIT_MSR_STORE_ADDRESS       0x00002006
#define VM_EXIT_MSR_LOAD_ADDRESS        0x00002008
#define VM_ENTRY_MSR_LOAD_ADDRESS       0x0000200A
#define VMX_PREEMPTION_TIMER_VALUE      0x0000482E

// Exit-Reason Fields (Read-Only)
#define VM_EXIT_REASON                  0x00004402
#define VM_EXIT_QUALIFICATION           0x00006400
#define EXIT_GUEST_LINEAR_ADDRESS       0x0000640A
#define GUEST_PHYSICAL_ADDRESS          0x00002400

#endif // VMCS_FIELDS_H

