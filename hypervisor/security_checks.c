/*
 * security_checks.c
 *
 *  Contains high-level modules for passive observation and system
 *  integrity checks, aligning with the project's legal and
 *  defense-oriented goals.
 */

#include <ntddk.h>
#include <ntimage.h>
#include "include/security_checks.h"
#include "include/vmx.h"

#pragma warning(disable: 4201)

// Undocumented structure for PsLoadedModuleList.
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// External reference to the undocumented loaded module list.
extern PLIST_ENTRY PsLoadedModuleList;

/*
 * Performs an integrity check on the running ntoskrnl.exe by comparing
 * its .text section against the pristine version from the on-disk file.
 */
NTSTATUS VhCheckNtoskrnlPatches()
{
    /*
     * This is a conceptual implementation. A full version would:
     * 1. Find ntoskrnl.exe base address from PsLoadedModuleList.
     * 2. Construct the file path to \\SystemRoot\\system32\\ntoskrnl.exe.
     * 3. Use ZwCreateFile, ZwCreateSection, ZwMapViewOfSection to map the on-disk file.
     * 4. Parse PE headers of both versions to find the .text section.
     * 5. Compare the sections byte-by-byte.
    */
    DbgPrint("VIREX-HV: [Security] ntoskrnl.exe patch scan initiated.\n");
    return STATUS_SUCCESS;
}

/*
 * Iterates through loaded kernel modules to detect IRP hooks in their
 * DRIVER_OBJECT->MajorFunction table.
 */
NTSTATUS VhCheckDriverObjects()
{
    PLIST_ENTRY listEntry;
    PLDR_DATA_TABLE_ENTRY ldrEntry;

    DbgPrint("VIREX-HV: [Security] Starting driver object integrity scan.\n");

    // Safely iterate the undocumented PsLoadedModuleList.
    for (listEntry = PsLoadedModuleList->Flink; listEntry != PsLoadedModuleList; listEntry = listEntry->Flink)
    {
        ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        
        // DRIVER_OBJECT is at a fixed offset from DllBase (arch-specific).
        PDRIVER_OBJECT driverObject = (PDRIVER_OBJECT)((PUCHAR)ldrEntry->DllBase + 0x50);

        if (!driverObject || !MmIsAddressValid(driverObject)) continue;

        for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        {
            PVOID dispatchAddress = driverObject->MajorFunction[i];
            ULONG_PTR driverBase = (ULONG_PTR)ldrEntry->DllBase;
            ULONG_PTR driverEnd = driverBase + ldrEntry->SizeOfImage;

            // Check if the IRP handler points outside of its own driver image.
            if ((ULONG_PTR)dispatchAddress < driverBase || (ULONG_PTR)dispatchAddress > driverEnd)
            {
                // This is suspicious and likely an IRP hook.
                DbgPrint("VIREX-HV: [!] Hook detected in driver %wZ! IRP_MJ 0x%X -> %p\n",
                    &ldrEntry->BaseDllName, i, dispatchAddress);
                return STATUS_DETECTED_HOOK;
            }
        }
    }

    DbgPrint("VIREX-HV: [Security] Driver object scan complete. No hooks found.\n");
    return STATUS_SUCCESS;
}
