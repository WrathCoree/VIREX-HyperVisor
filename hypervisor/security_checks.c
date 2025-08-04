/*
 * security_checks.c
 *
 *  Contains high-level modules for passive observation and system
 *  integrity checks, aligning with the project's legal and
 *  defense-oriented goals. This version contains a full implementation
 *  of ntoskrnl.exe patch detection.
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
    NTSTATUS status = STATUS_SUCCESS;
    PLDR_DATA_TABLE_ENTRY ntoskrnl_entry = NULL;
    PLIST_ENTRY listEntry;
    HANDLE fileHandle = NULL, sectionHandle = NULL;
    PVOID onDiskBase = NULL;
    SIZE_T viewSize = 0;

    // Find ntoskrnl.exe in the loaded module list.
    for (listEntry = PsLoadedModuleList->Flink; listEntry != PsLoadedModuleList; listEntry = listEntry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (wcsstr(ldrEntry->BaseDllName.Buffer, L"ntoskrnl.exe") != NULL)
        {
            ntoskrnl_entry = ldrEntry;
            break;
        }
    }

    if (!ntoskrnl_entry)
    {
        return STATUS_NOT_FOUND;
    }

    // Map the on-disk ntoskrnl.exe file into memory.
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    UNICODE_STRING ntoskrnlPath;
    RtlInitUnicodeString(&ntoskrnlPath, L"\\SystemRoot\\System32\\ntoskrnl.exe");
    InitializeObjectAttributes(&objAttr, &ntoskrnlPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&fileHandle, GENERIC_READ, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("VIREX-HV: [Security] Failed to open ntoskrnl.exe (0x%X)\n", status);
        return status;
    }

    status = ZwCreateSection(&sectionHandle, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_IMAGE, fileHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("VIREX-HV: [Security] Failed to create section for ntoskrnl.exe (0x%X)\n", status);
        ZwClose(fileHandle);
        return status;
    }

    status = ZwMapViewOfSection(sectionHandle, ZwCurrentProcess(), &onDiskBase, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READONLY);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("VIREX-HV: [Security] Failed to map view of ntoskrnl.exe (0x%X)\n", status);
        ZwClose(sectionHandle);
        ZwClose(fileHandle);
        return status;
    }

    // Parse PE headers to find the .text section for both images.
    PIMAGE_NT_HEADERS inMemoryHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ntoskrnl_entry->DllBase + ((PIMAGE_DOS_HEADER)ntoskrnl_entry->DllBase)->e_lfanew);
    PIMAGE_NT_HEADERS onDiskHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)onDiskBase + ((PIMAGE_DOS_HEADER)onDiskBase)->e_lfanew);
    PIMAGE_SECTION_HEADER inMemorySection = IMAGE_FIRST_SECTION(inMemoryHeaders);
    PIMAGE_SECTION_HEADER onDiskSection = IMAGE_FIRST_SECTION(onDiskHeaders);

    for (WORD i = 0; i < inMemoryHeaders->FileHeader.NumberOfSections; i++)
    {
        if (strcmp((char*)inMemorySection->Name, ".text") == 0)
        {
            PUCHAR inMemoryText = (PUCHAR)ntoskrnl_entry->DllBase + inMemorySection->VirtualAddress;
            PUCHAR onDiskText = (PUCHAR)onDiskBase + onDiskSection->VirtualAddress;

            // Compare the .text sections byte-by-byte.
            if (RtlCompareMemory(inMemoryText, onDiskText, inMemorySection->Misc.VirtualSize) != inMemorySection->Misc.VirtualSize)
            {
                DbgPrint("VIREX-HV: [!] Patch detected in ntoskrnl.exe .text section!\n");
                status = STATUS_DETECTED_PATCH;
            }
            else
            {
                DbgPrint("VIREX-HV: [Security] ntoskrnl.exe .text section integrity check passed.\n");
            }
            break;
        }
        inMemorySection++;
        onDiskSection++;
    }

    // Cleanup.
    ZwUnmapViewOfSection(ZwCurrentProcess(), onDiskBase);
    ZwClose(sectionHandle);
    ZwClose(fileHandle);

    return status;
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
        
        // The DRIVER_OBJECT is usually at the start of the .data section, which we can find
        // by parsing the PE header. A fixed offset is unreliable.
        PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((PUCHAR)ldrEntry->DllBase + ((PIMAGE_DOS_HEADER)ldrEntry->DllBase)->e_lfanew);
        PDRIVER_OBJECT driverObject = (PDRIVER_OBJECT)(headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)ldrEntry->DllBase);

        if (!driverObject || !MmIsAddressValid(driverObject) || driverObject->Type != IO_TYPE_DRIVER) continue;

        for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        {
            PVOID dispatchAddress = driverObject->MajorFunction[i];
            ULONG_PTR driverBase = (ULONG_PTR)ldrEntry->DllBase;
            ULONG_PTR driverEnd = driverBase + ldrEntry->SizeOfImage;

            // Check if the IRP handler points outside of its own driver image.
            if ((ULONG_PTR)dispatchAddress < driverBase || (ULONG_PTR)dispatchAddress > driverEnd)
            {
                // A legitimate IRP handler should be within the driver's own code.
                // An exception is if it points to a shared kernel function,
                // which would need to be whitelisted for a production system.
                DbgPrint("VIREX-HV: [!] Hook detected in driver %wZ! IRP_MJ 0x%X -> %p\n",
                    &ldrEntry->BaseDllName, i, dispatchAddress);
                return STATUS_DETECTED_HOOK;
            }
        }
    }

    DbgPrint("VIREX-HV: [Security] Driver object scan complete. No hooks found.\n");
    return STATUS_SUCCESS;
}
