#ifndef SPOOF_MANAGER_H
#define SPOOF_MANAGER_H

#include <ntddk.h>

// Holds values for all four registers returned by a CPUID instruction.
typedef struct _CPUID_SPOOF_VALUES {
    UINT32 Eax;
    UINT32 Ebx;
    UINT32 Ecx;
    UINT32 Edx;
} CPUID_SPOOF_VALUES, *PCPUID_SPOOF_VALUES;

// Structure for a full CPUID leaf spoofing rule.
typedef struct _CPUID_SPOOF_RULE {
    LIST_ENTRY Link;
    UINT32 Leaf;
    UINT32 SubLeaf;
    CPUID_SPOOF_VALUES Values;
} CPUID_SPOOF_RULE, *PCPUID_SPOOF_RULE;

// Structure for an MSR spoofing rule.
typedef struct _MSR_SPOOF_RULE {
    LIST_ENTRY Link;
    UINT32 MsrIndex;
    UINT64 SpoofedValue;
} MSR_SPOOF_RULE, *PMSR_SPOOF_RULE;

// Structure for the global RDTSC spoofing rule.
typedef struct _TSC_SPOOF_RULE {
    UINT64 Multiplier;
    UINT64 Offset;
    BOOLEAN IsActive;
} TSC_SPOOF_RULE, *PTSC_SPOOF_RULE;


// Public Function Prototypes

// Initialization and cleanup.
VOID VhInitializeSpoofManager();
VOID VhCleanupSpoofManager();

// MSR spoofing functions.
NTSTATUS VhSetMsrSpoof(UINT32 MsrIndex, UINT64 SpoofedValue);
BOOLEAN VhFindMsrSpoof(UINT32 MsrIndex, PUINT64 SpoofedValue);

// CPUID spoofing functions.
NTSTATUS VhSetCpuidSpoofFull(UINT32 Leaf, UINT32 SubLeaf, PCPUID_SPOOF_VALUES Values);
BOOLEAN VhFindCpuidSpoofFull(UINT32 Leaf, UINT32 SubLeaf, PCPUID_SPOOF_VALUES Values);

// RDTSC spoofing functions.
NTSTATUS VhSetRdtscSpoof(UINT64 Multiplier, UINT64 Offset);
BOOLEAN VhGetRdtscSpoof(PTSC_SPOOF_RULE Rule);

#endif // SPOOF_MANAGER_H
