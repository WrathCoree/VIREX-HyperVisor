/*
 * vmx.h
 *
 *  Defines core VMX-related structures, MSRs, control bits, and
 *  function prototypes for the hypervisor.
 */

#ifndef VMX_H
#define VMX_H

#include <ntddk.h>
#include <intrin.h>
#include "include/vmcs_fields.h"
#include "include/ept.h"

#define VMXON_SIZE PAGE_SIZE
#define VMCS_SIZE  PAGE_SIZE
#define GUEST_STACK_SIZE (PAGE_SIZE * 8)
#define RPL_MASK 0x3

// MSR addresses for VMX operations.
typedef enum _VMX_MSR
{
    MSR_IA32_VMX_BASIC = 0x480,
    MSR_IA32_VMX_PINBASED_CTLS = 0x481,
    MSR_IA32_VMX_PROCBASED_CTLS = 0x482,
    MSR_IA32_VMX_EXIT_CTLS = 0x483,
    MSR_IA32_VMX_ENTRY_CTLS = 0x484,
    MSR_IA32_VMX_PROCBASED_CTLS2 = 0x48B,
    MSR_IA32_FEATURE_CONTROL = 0x3A,
    MSR_IA32_FS_BASE = 0xC0000100,
    MSR_IA32_GS_BASE = 0xC0000101
} VMX_MSR;

// Structure for CPUID EAX=1 result.
typedef union _CPUID_EAX_01
{
    UINT32 All;
    struct
    {
        UINT32 SteppingId : 4;
        UINT32 Model : 4;
        UINT32 FamilyId : 4;
        UINT32 ProcessorType : 2;
        UINT32 Reserved1 : 2;
        UINT32 ExtendedModelId : 4;
        UINT32 ExtendedFamilyId : 8;
        UINT32 Reserved2 : 4;
    } Fields;
    struct
    {
        UINT32 Reserved1 : 21;
        UINT32 VirtualMachineExtensions : 1;
        UINT32 Reserved2 : 10;
    };
} CPUID_EAX_01, *PCPUID_EAX_01;

// Structure for IA32_FEATURE_CONTROL MSR.
typedef union _IA32_FEATURE_CONTROL_MSR
{
    UINT64 All;
    struct
    {
        UINT64 LockBit : 1;
        UINT64 EnableVmxon : 1;
        UINT64 Reserved : 62;
    };
} IA32_FEATURE_CONTROL_MSR, *PIA32_FEATURE_CONTROL_MSR;

// Per-CPU data structure to hold VMX state.
typedef struct _PER_CPU_VMX_DATA
{
    PVOID       VmxonRegion;
    PVOID       VmcsRegion;
    PHYSICAL_ADDRESS VmxonRegionPa;
    PHYSICAL_ADDRESS VmcsRegionPa;
    PVOID       GuestStack;
    BOOLEAN     IsVmxon;
    EPT_STATE   EptState;
} PER_CPU_VMX_DATA, *PPER_CPU_VMX_DATA;

// Global VMX data array.
extern PER_CPU_VMX_DATA* g_VmxData;

// Assembly routine prototypes.
extern UINT16 GetEs(VOID);
extern UINT16 GetCs(VOID);
extern UINT16 GetSs(VOID);
extern UINT16 GetDs(VOID);
extern UINT16 GetFs(VOID);
extern UINT16 GetGs(VOID);
extern UINT16 GetLdtr(VOID);
extern UINT16 GetTr(VOID);
VOID VhGuestEntry(VOID);

// Public function prototypes.
NTSTATUS HvInitializeVmx(PVOID DriverBase, ULONG DriverSize);
VOID HvShutdownVmx();
VOID VhLaunchVm(ULONG ProcessorIndex);
VOID VhSetupVmcs(PPER_CPU_VMX_DATA VmxData);
VOID VhAllocateVmcsRegion(PPER_CPU_VMX_DATA VmxData);

#endif
