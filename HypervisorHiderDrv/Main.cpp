#include "Global.h"
int NtQuerySystemInformationIndex, NtUserWindowFromPointIndex, NtUserQueryWindowIndex, NtUserFindWindowExIndex, NtUserBuildHwndListIndex, NtUserGetForegroundWindowIndex;

static void DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    NTDLL::Deinitialize();
    WIN32U::Deinitialize();
    Hook::Deinitialize();
}

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    if (!utils::init())
    {
        DBGPRINT("utils::init() failed...");
        return STATUS_UNSUCCESSFUL;
    }

    if (!kaspersky::is_klhk_loaded())
    {
        DBGPRINT("kaspersky::is_klhk_loaded() failed...");
        return STATUS_UNSUCCESSFUL;
    }

    if (!kaspersky::initialize())
    {
        DBGPRINT("kaspersky::initialize() failed...");
        return STATUS_UNSUCCESSFUL;
    }

    if (!kaspersky::hvm_init())
    {
        DBGPRINT("kaspersky::hvm_init() failed...");
        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(NTDLL::Initialize()))
    {
        DBGPRINT("NTDLL::Initialize() failed...");
        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(WIN32U::Initialize()))
    {
        DBGPRINT("WIN32U::Initialize() failed...");
        return STATUS_UNSUCCESSFUL;
    }

    Hook::Initialize();
    return STATUS_SUCCESS;
}