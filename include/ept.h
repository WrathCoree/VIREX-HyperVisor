#ifndef EPT_H
#define EPT_H

#include <ntddk.h>
#include "include/vmcs_fields.h"

#define EPT_ACCESS_READ   1
#define EPT_ACCESS_WRITE  2
#define EPT_ACCESS_EXECUTE 4
#define EPT_ACCESS_ALL (EPT_ACCESS_READ | EPT_ACCESS_WRITE | EPT_ACCESS_EXECUTE)
#define EPT_ACCESS_NONE   0

typedef ULONG EPT_ACCESS_RIGHTS;

// Convert a PTE physical address to the page's physical address.
#define PHYSICAL_ADDRESS_FROM_PTE(Pte) ((Pte)->PageFrameNumber << 12)

// EPT table entry structures.
typedef union _EPT_PML4E {
    UINT64 All;
    struct {
        UINT64 Read : 1;
        UINT64 Write : 1;
        UINT64 Execute : 1;
        UINT64 Reserved1 : 9;
        UINT64 PageFrameNumber : 36;
        UINT64 Reserved2 : 16;
    };
} EPT_PML4E, *PEPT_PML4E;

typedef union _EPT_PDPTE {
    UINT64 All;
    struct {
        UINT64 Read : 1;
        UINT64 Write : 1;
        UINT64 Execute : 1;
        UINT64 Reserved1 : 9;
        UINT64 PageFrameNumber : 36;
        UINT64 Reserved2 : 16;
    };
} EPT_PDPTE, *PEPT_PDPTE;

typedef union _EPT_PDE {
    UINT64 All;
    struct {
        UINT64 Read : 1;
        UINT64 Write : 1;
        UINT64 Execute : 1;
        UINT64 Reserved1 : 4;
        UINT64 LargePage : 1; // Must be 1 for 2MB pages.
        UINT64 Reserved2 : 4;
        UINT64 PageFrameNumber : 36;
        UINT64 Reserved3 : 16;
    };
} EPT_PDE, *PEPT_PDE;

typedef union _EPT_PTE {
    UINT64 All;
    struct {
        UINT64 Read : 1;
        UINT64 Write : 1;
        UINT64 Execute : 1;
        UINT64 Reserved1 : 9;
        UINT64 PageFrameNumber : 36;
        UINT64 Reserved2 : 16;
    };
} EPT_PTE, *PEPT_PTE;

// Main EPT state structure.
typedef struct _EPT_STATE
{
    EPT_POINTER EptPointer;
    PEPT_PML4E  Pml4;
    PEPT_PDPTE  Pdpt;
    PEPT_PDE    Pd;
    PEPT_PTE    Pt;

} EPT_STATE, *PEPT_STATE;

// Structure for an EPT-based hook entry.
typedef struct _EPT_HOOK_ENTRY
{
    LIST_ENTRY      Link;
    UINT64          PhysicalBaseAddress;
    UCHAR           OriginalByte;
    BOOLEAN         IsExecuting;
    PEPT_STATE      EptState;

} EPT_HOOK_ENTRY, *PEPT_HOOK_ENTRY;

// Global state for all EPT hooks.
typedef struct _EPT_HOOK_STATE
{
    LIST_ENTRY      HookList;
    KSPIN_LOCK      HookListLock;
    BOOLEAN         IsEnabled;

} EPT_HOOK_STATE, *PEPT_HOOK_STATE;


// Public Function Prototypes
BOOLEAN VhBuildEptIdentityMap(PEPT_STATE EptState);
VOID VhEnableEpt(struct _PER_CPU_VMX_DATA* VmxData);
VOID VhCleanupEpt(PEPT_STATE EptState);
NTSTATUS VhSetPageAccessPermissions(PEPT_STATE EptState, PHYSICAL_ADDRESS PageBaseAddress, EPT_ACCESS_RIGHTS DesiredAccess);
VOID VhHideHypervisorMemory(PVOID DriverBase, ULONG DriverSize);

NTSTATUS VhCloakInt3Breakpoint(PEPT_STATE EptState, PHYSICAL_ADDRESS PhysicalAddress, UCHAR OriginalByte);
NTSTATUS VhUncloakInt3Breakpoint(PEPT_STATE EptState, PHYSICAL_ADDRESS PhysicalAddress);
VOID VhHandleEptViolationForCloak(PEPT_STATE EptState);
VOID VhHandleMtfTrap();

#endif
