/*
 * spoof_manager.c
 *
 *  Implements the dynamic MSR and CPUID spoofing manager. This allows
 *  user-mode to configure spoofing rules on-the-fly via VMCALLs.
 */

#include "include/spoof_manager.h"

// Global lists and locks for the spoof manager.
static LIST_ENTRY g_MsrSpoofList;
static LIST_ENTRY g_CpuidSpoofList;
static KSPIN_LOCK g_MsrSpoofLock;
static KSPIN_LOCK g_CpuidSpoofLock;
static TSC_SPOOF_RULE g_TscSpoofRule;
static KSPIN_LOCK g_TscSpoofLock;

/*
 * Initializes all lists and locks for the spoof manager.
 */
VOID VhInitializeSpoofManager()
{
    InitializeListHead(&g_MsrSpoofList);
    InitializeListHead(&g_CpuidSpoofList);
    KeInitializeSpinLock(&g_MsrSpoofLock);
    KeInitializeSpinLock(&g_CpuidSpoofLock);
    KeInitializeSpinLock(&g_TscSpoofLock);
    g_TscSpoofRule.IsActive = FALSE;
    g_TscSpoofRule.Multiplier = 1;
    g_TscSpoofRule.Offset = 0;
    DbgPrint("VIREX-HV: [Spoof] Dynamic spoofing manager initialized.\n");
}

/*
 * Cleans up all allocated memory for spoofing rules.
 */
VOID VhCleanupSpoofManager()
{
    KLOCK_QUEUE_HANDLE lockHandle;

    // Clear MSR spoof list.
    KeAcquireInStackQueuedSpinLock(&g_MsrSpoofLock, &lockHandle);
    while (!IsListEmpty(&g_MsrSpoofList))
    {
        PMSR_SPOOF_RULE entry = CONTAINING_RECORD(g_MsrSpoofList.Flink, MSR_SPOOF_RULE, Link);
        RemoveEntryList(&entry->Link);
        ExFreePoolWithTag(entry, 'msr');
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    // Clear CPUID spoof list.
    KeAcquireInStackQueuedSpinLock(&g_CpuidSpoofLock, &lockHandle);
    while (!IsListEmpty(&g_CpuidSpoofList))
    {
        PCPUID_SPOOF_RULE entry = CONTAINING_RECORD(g_CpuidSpoofList.Flink, CPUID_SPOOF_RULE, Link);
        RemoveEntryList(&entry->Link);
        ExFreePoolWithTag(entry, 'cpu');
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    
    DbgPrint("VIREX-HV: [Spoof] Dynamic spoofing manager cleaned up.\n");
}

/*
 * Sets or updates a spoofing rule for a specific MSR.
 */
NTSTATUS VhSetMsrSpoof(UINT32 MsrIndex, UINT64 SpoofedValue)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    BOOLEAN ruleExists = FALSE;

    KeAcquireInStackQueuedSpinLock(&g_MsrSpoofLock, &lockHandle);
    
    // Check if a rule for this MSR already exists.
    for (entry = g_MsrSpoofList.Flink; entry != &g_MsrSpoofList; entry = entry->Flink)
    {
        PMSR_SPOOF_RULE rule = CONTAINING_RECORD(entry, MSR_SPOOF_RULE, Link);
        if (rule->MsrIndex == MsrIndex)
        {
            // Rule exists, just update the value.
            rule->SpoofedValue = SpoofedValue;
            ruleExists = TRUE;
            break;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    // If no rule exists, create a new one.
    if (!ruleExists)
    {
        PMSR_SPOOF_RULE new_rule = ExAllocatePoolWithTag(NonPagedPool, sizeof(MSR_SPOOF_RULE), 'msr');
        if (!new_rule)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        new_rule->MsrIndex = MsrIndex;
        new_rule->SpoofedValue = SpoofedValue;

        KeAcquireInStackQueuedSpinLock(&g_MsrSpoofLock, &lockHandle);
        InsertTailList(&g_MsrSpoofList, &new_rule->Link);
        KeReleaseInStackQueuedSpinLock(&lockHandle);
    }

    DbgPrint("VIREX-HV: [Spoof] Set/updated MSR rule for 0x%X.\n", MsrIndex);
    return STATUS_SUCCESS;
}

/*
 * Finds an active spoofing rule for an MSR.
 */
BOOLEAN VhFindMsrSpoof(UINT32 MsrIndex, PUINT64 SpoofedValue)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    BOOLEAN found = FALSE;

    KeAcquireInStackQueuedSpinLock(&g_MsrSpoofLock, &lockHandle);
    for (entry = g_MsrSpoofList.Flink; entry != &g_MsrSpoofList; entry = entry->Flink)
    {
        PMSR_SPOOF_RULE rule = CONTAINING_RECORD(entry, MSR_SPOOF_RULE, Link);
        if (rule->MsrIndex == MsrIndex)
        {
            *SpoofedValue = rule->SpoofedValue;
            found = TRUE;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    
    return found;
}

/*
 * Sets or updates a spoofing rule for a full CPUID leaf.
 */
NTSTATUS VhSetCpuidSpoofFull(UINT32 Leaf, UINT32 SubLeaf, PCPUID_SPOOF_VALUES Values)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    BOOLEAN ruleExists = FALSE;

    KeAcquireInStackQueuedSpinLock(&g_CpuidSpoofLock, &lockHandle);

    // Check if a rule for this CPUID leaf/subleaf already exists.
    for (entry = g_CpuidSpoofList.Flink; entry != &g_CpuidSpoofList; entry = entry->Flink)
    {
        PCPUID_SPOOF_RULE rule = CONTAINING_RECORD(entry, CPUID_SPOOF_RULE, Link);
        if (rule->Leaf == Leaf && rule->SubLeaf == SubLeaf)
        {
            rule->Values = *Values;
            ruleExists = TRUE;
            break;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    
    // If no rule exists, create a new one.
    if (!ruleExists)
    {
        PCPUID_SPOOF_RULE new_rule = ExAllocatePoolWithTag(NonPagedPool, sizeof(CPUID_SPOOF_RULE), 'cpu');
        if (!new_rule)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        new_rule->Leaf = Leaf;
        new_rule->SubLeaf = SubLeaf;
        new_rule->Values = *Values;

        KeAcquireInStackQueuedSpinLock(&g_CpuidSpoofLock, &lockHandle);
        InsertTailList(&g_CpuidSpoofList, &new_rule->Link);
        KeReleaseInStackQueuedSpinLock(&lockHandle);
    }
    
    DbgPrint("VIREX-HV: [Spoof] Set/updated CPUID rule for Leaf 0x%X, Subleaf 0x%X.\n", Leaf, SubLeaf);
    return STATUS_SUCCESS;
}

/*
 * Finds an active spoofing rule for a full CPUID leaf.
 */
BOOLEAN VhFindCpuidSpoofFull(UINT32 Leaf, UINT32 SubLeaf, PCPUID_SPOOF_VALUES Values)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    BOOLEAN found = FALSE;
    
    KeAcquireInStackQueuedSpinLock(&g_CpuidSpoofLock, &lockHandle);
    for (entry = g_CpuidSpoofList.Flink; entry != &g_CpuidSpoofList; entry = entry->Flink)
    {
        PCPUID_SPOOF_RULE rule = CONTAINING_RECORD(entry, CPUID_SPOOF_RULE, Link);
        if (rule->Leaf == Leaf && rule->SubLeaf == SubLeaf)
        {
            *Values = rule->Values;
            found = TRUE;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    return found;
}

/*
 * Sets the global rule for RDTSC/RDTSCP spoofing.
 */
NTSTATUS VhSetRdtscSpoof(UINT64 Multiplier, UINT64 Offset)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_TscSpoofLock, &lockHandle);
    g_TscSpoofRule.Multiplier = Multiplier;
    g_TscSpoofRule.Offset = Offset;
    g_TscSpoofRule.IsActive = TRUE;
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    DbgPrint("VIREX-HV: [Spoof] RDTSC spoofing activated. Multiplier: %llu, Offset: %llu\n", Multiplier, Offset);
    return STATUS_SUCCESS;
}

/*
 * Retrieves the currently active RDTSC spoofing rule.
 */
BOOLEAN VhGetRdtscSpoof(PTSC_SPOOF_RULE Rule)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    BOOLEAN isActive;
    KeAcquireInStackQueuedSpinLock(&g_TscSpoofLock, &lockHandle);
    isActive = g_TscSpoofRule.IsActive;
    if (isActive)
    {
        *Rule = g_TscSpoofRule;
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return isActive;
}
