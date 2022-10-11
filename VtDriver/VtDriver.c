#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "Utils.h"

extern void inline AsmVmxSaveState(void);
extern S_VMX_VARS             g_vmx_vars;
NTSTATUS
MyDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

VOID
DrvUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);


#pragma alloc_text(INIT, MyDriverEntry)
#pragma alloc_text(PAGE, DrvUnload)
#pragma alloc_text(PAGE,DrvCreate)



NTSTATUS
MyDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS       NtStatus     = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING DriverName, DosDeviceName;

    DbgPrint("DriverEntry Called.");

    RtlInitUnicodeString(&DriverName, L"\\Device\\MyHypervisor");
    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisor");

    NtStatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

    if (NtStatus == STATUS_SUCCESS)
    {
        DriverObject->DriverUnload = DrvUnload;
        DeviceObject->Flags |= IO_TYPE_DEVICE;
        DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
        IoCreateSymbolicLink(&DosDeviceName, &DriverName);
    }
    
    if (IsVmxSupported())
    {
        DbgPrint("Vmx support currently \n");
        //VT
        VtEnable();

        //setup vmxOn and call __vmx_on
        SetupVmxOnRegion();

        //setup vmcs and call __vmx_clear & __vmx_load make the new vmcs active and current.
        //after this function,_vmx_write use the current vmcs to operate.
        SetupVmcxRegion();
        // Allocating MSR Bit 
        VmxAllocateMsrBitmap();

     
        DbgPrint("================================\n");
    }
    else
    {
        DbgPrint("Vmx not support currently");

    }

    AsmVmxSaveState();

    return NtStatus;
}

VOID
DrvUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING DosDeviceName;

    DbgPrint("DrvUnload Called !");

    if (g_vmx_vars.pVmcsRegion_VA)
    {
        ExFreePool(g_vmx_vars.pVmcsRegion_VA);
        g_vmx_vars.pVmcsRegion_VA = NULL;
    }
    if (g_vmx_vars.pVmxOnRegion_VA)
    {
        ExFreePool(g_vmx_vars.pVmxOnRegion_VA);
        g_vmx_vars.pVmxOnRegion_VA = NULL;
    }
    __vmx_off();
    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisor");

    IoDeleteSymbolicLink(&DosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}