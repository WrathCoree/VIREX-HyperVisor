/*
 * driver.c
 *
 *  The main entry point for the Windows kernel driver. Handles driver
 *  loading/unloading and IOCTL communication from user-mode.
 */

#include <ntddk.h>
#include "include/common.h"
#include "include/vmx.h"
#include "include/apc_injection.h"

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH IoCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH IoDeviceControl;

/*
 * Driver entry point. Initializes the driver and the hypervisor.
 */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING devName, dosDeviceName;

    RtlInitUnicodeString(&devName, L"\\Device\\VirexHypervisor");
    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\VirexHypervisor");

    // Create the device object.
    status = IoCreateDevice(DriverObject,
                            0,
                            &devName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &deviceObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("VIREX-HV: Failed to create device object (0x%X)\n", status);
        return status;
    }

    // Create a symbolic link for the user-mode application.
    status = IoCreateSymbolicLink(&dosDeviceName, &devName);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("VIREX-HV: Failed to create symbolic link (0x%X)\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Set up driver dispatch routines.
    DriverObject->MajorFunction[IRP_MJ_CREATE] = IoCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IoCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // Initialize the hypervisor.
    status = HvInitializeVmx(DriverObject->DriverStart, DriverObject->DriverSize);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("VIREX-HV: Failed to initialize VMX (0x%X)\n", status);
        IoDeleteSymbolicLink(&dosDeviceName);
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    DbgPrint("VIREX-HV: Driver loaded successfully.\n");
    return STATUS_SUCCESS;
}

/*
 * Driver unload routine. Shuts down the hypervisor and cleans up.
 */
VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING dosDeviceName;
    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\VirexHypervisor");

    // Shutdown the hypervisor.
    HvShutdownVmx();

    // Clean up device objects and links.
    IoDeleteSymbolicLink(&dosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("VIREX-HV: Driver unloaded.\n");
}

/*
 * Handles IRP_MJ_CREATE and IRP_MJ_CLOSE requests.
 */
NTSTATUS IoCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * Handles IOCTL requests from the user-mode control panel.
 */
NTSTATUS IoDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID ioBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;

    if (controlCode == IOCTL_VMCALL_DISPATCH)
    {
        if (inputLength >= sizeof(VMCALL_INPUT))
        {
            PVMCALL_INPUT vmcallInput = (PVMCALL_INPUT)ioBuffer;
            
            // Use APC injection to safely execute the VMCALL in a user context.
            status = VhQueueApcVmcall(vmcallInput->TargetPid,
                                      vmcallInput->VmcallNumber,
                                      (PVOID)vmcallInput->Context);
        }
        else
        {
            status = STATUS_INVALID_BUFFER_SIZE;
        }
    }
    else
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
