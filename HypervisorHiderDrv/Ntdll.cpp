#include "Ntdll.h"
#include "PEB.h"

unsigned char* NTDLL::FileData = 0;
ULONG NTDLL::FileSize = 0;

NTSTATUS NTDLL::Initialize()
{
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    RtlInitUnicodeString(&FileName, L"\\SystemRoot\\system32\\ntdll.dll");
    InitializeObjectAttributes(&ObjectAttributes, &FileName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_UNSUCCESSFUL;

    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS NtStatus = ZwCreateFile(&FileHandle,
        GENERIC_READ,
        &ObjectAttributes,
        &IoStatusBlock, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (NT_SUCCESS(NtStatus))
    {
        FILE_STANDARD_INFORMATION StandardInformation = { 0 };
        NtStatus = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
        if (NT_SUCCESS(NtStatus))
        {
            FileSize = StandardInformation.EndOfFile.LowPart;
            DBGPRINT("FileSize of ntdll.dll is %08X!", StandardInformation.EndOfFile.LowPart);
            FileData = (unsigned char*)Memory::RtlAllocateMemory(true, FileSize);

            LARGE_INTEGER ByteOffset;
            ByteOffset.LowPart = ByteOffset.HighPart = 0;
            NtStatus = ZwReadFile(FileHandle,
                NULL, NULL, NULL,
                &IoStatusBlock,
                FileData,
                FileSize,
                &ByteOffset, NULL);

            if (!NT_SUCCESS(NtStatus))
            {
                Memory::RtlFreeMemory(FileData);
                DBGPRINT("ZwReadFile failed with status %08X...", NtStatus);
            }
        }
        else
            DBGPRINT("ZwQueryInformationFile failed with status %08X...", NtStatus);
        ZwClose(FileHandle);
    }
    else
        DBGPRINT("ZwCreateFile failed with status %08X...", NtStatus);
    return NtStatus;
}

void NTDLL::Deinitialize()
{
    Memory::RtlFreeMemory(FileData);
}

int NTDLL::GetExportSsdtIndex(const char* ExportName)
{
    ULONG_PTR ExportOffset = Hypervisor::PE::GetExportOffset(FileData, FileSize, ExportName);
    if (ExportOffset == PE_ERROR_VALUE)
        return -1;

    int SsdtOffset = -1;
    unsigned char* ExportData = FileData + ExportOffset;
    for (int i = 0; i < 32 && ExportOffset + i < FileSize; i++)
    {
        if (ExportData[i] == 0xC2 || ExportData[i] == 0xC3)  //RET
            break;
        if (ExportData[i] == 0xB8)  //mov eax,X
        {
            SsdtOffset = *(int*)(ExportData + i + 1);
            break;
        }
    }

    if (SsdtOffset == -1)
        DBGPRINT("SSDT Offset for %s not found...", ExportName);

    return SsdtOffset;
}
