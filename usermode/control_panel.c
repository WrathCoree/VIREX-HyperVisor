/*
 * control_panel.c
 *
 *  User-mode console application for interacting with and controlling
 *  the VIREX-HYPERVISOR kernel driver. Now with a functional JSON loader.
 */

#include <stdio.h>
#include <Windows.h>
#include "vmx_comm.h"
#include "../include/vmcall_codes.h"
#include "cJSON.h"

// Simple helper to print the menu.
void PrintMenu()
{
    printf("\n--- VIREX-HYPERVISOR Control Panel ---\n");
    printf(" 1. Get Hypervisor Status\n");
    printf(" 2. Set RDTSC Spoofing\n");
    printf(" 3. Run Kernel Patch Scan\n");
    printf(" 4. Run Driver Object Hook Scan\n");
    printf(" 5. Load VMCALLs from JSON file\n");
    printf(" 9. Exit\n");
    printf("--------------------------------------\n");
    printf("Enter choice: ");
}

// Function to handle RDTSC spoofing input.
void HandleRdtscSpoof(HANDLE hDevice)
{
    UINT64 multiplier, offset;
    printf("Enter RDTSC multiplier (e.g., 1 for no change): ");
    scanf_s("%llu", &multiplier);
    printf("Enter RDTSC offset (e.g., 0 for no change): ");
    scanf_s("%llu", &offset);

    VMCALL_CONTEXT_RDTSC context = { .Multiplier = multiplier, .Offset = offset };

    if (HvIssueVmcall(hDevice, VMCALL_SET_RDTSC_SPOOF, (UINT64)&context))
    {
        printf("[SUCCESS] RDTSC spoofing rule sent to hypervisor.\n");
    }
    else
    {
        printf("[ERROR] Failed to set RDTSC spoofing rule.\n");
    }
}

// Reads the entire content of a file into a buffer.
char* ReadFileContent(const char* filename)
{
    FILE* f;
    long length;
    char* content;

    if (fopen_s(&f, filename, "rb") != 0)
    {
        perror("Error opening file");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    length = ftell(f);
    fseek(f, 0, SEEK_SET);

    content = (char*)malloc(length + 1);
    if (content)
    {
        fread(content, 1, length, f);
        content[length] = '\0';
    }
    fclose(f);
    return content;
}

// Function to load and process VMCALLs from a JSON file.
void HandleJsonLoad(HANDLE hDevice)
{
    char filename[256];
    printf("Enter JSON file path (e.g., C:\\config.json): ");
    scanf_s("%255s", filename, (unsigned)_countof(filename));

    char* json_string = ReadFileContent(filename);
    if (!json_string)
    {
        return;
    }

    cJSON* root = cJSON_Parse(json_string);
    if (!root)
    {
        printf("[ERROR] Failed to parse JSON: %s\n", cJSON_GetErrorPtr());
        free(json_string);
        return;
    }
    
    cJSON* command_item = NULL;
    cJSON_ArrayForEach(command_item, root)
    {
        cJSON* command = cJSON_GetObjectItemCaseSensitive(command_item, "command");
        cJSON* params = cJSON_GetObjectItemCaseSensitive(command_item, "params");

        if (cJSON_IsString(command) && (command->valuestring != NULL))
        {
            printf("Executing command: %s\n", command->valuestring);
            
            if (strcmp(command->valuestring, "set_rdtsc_spoof") == 0)
            {
                cJSON* multiplier = cJSON_GetObjectItemCaseSensitive(params, "multiplier");
                cJSON* offset = cJSON_GetObjectItemCaseSensitive(params, "offset");
                if (cJSON_IsNumber(multiplier) && cJSON_IsNumber(offset))
                {
                    VMCALL_CONTEXT_RDTSC context = { .Multiplier = (UINT64)multiplier->valuedouble, .Offset = (UINT64)offset->valuedouble };
                    HvIssueVmcall(hDevice, VMCALL_SET_RDTSC_SPOOF, (UINT64)&context);
                }
            }
            // Add other command handlers here (e.g., "set_msr_spoof")
        }
    }

    cJSON_Delete(root);
    free(json_string);
}


int main()
{
    HANDLE hDevice = HvConnect();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("Failed to connect to the hypervisor driver. Error: %d\n", GetLastError());
        return 1;
    }

    printf("Successfully connected to the VIREX-HYPERVISOR driver.\n");

    int choice = 0;
    while (choice != 9)
    {
        PrintMenu();
        scanf_s("%d", &choice);

        switch (choice)
        {
            case 1:
                if (HvIssueVmcall(hDevice, VMCALL_GET_STATUS, 0))
                {
                    printf("[SUCCESS] Hypervisor is running.\n");
                }
                else
                {
                    printf("[ERROR] Failed to get hypervisor status.\n");
                }
                break;
            case 2:
                HandleRdtscSpoof(hDevice);
                break;
            case 3:
                if (HvIssueVmcall(hDevice, VMCALL_RUN_NTOSKRNL_PATCH_SCAN, 0))
                {
                    printf("[SUCCESS] Kernel patch scan initiated.\n");
                }
                else
                {
                    printf("[ERROR] Failed to start kernel patch scan.\n");
                }
                break;
            case 4:
                if (HvIssueVmcall(hDevice, VMCALL_RUN_DRIVER_OBJECT_SCAN, 0))
                {
                    printf("[SUCCESS] Driver object hook scan initiated.\n");
                }
                else
                {
                    printf("[ERROR] Failed to start driver hook scan.\n");
                }
                break;
            case 5:
                HandleJsonLoad(hDevice);
                break;
            case 9:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice.\n");
                break;
        }
    }

    HvDisconnect(hDevice);
    return 0;
}
