#pragma once
#include "Global.h"

class NTDLL
{
public:
    static NTSTATUS Initialize();
    static void Deinitialize();
    static int GetExportSsdtIndex(const char* ExportName);

private:
    static unsigned char* FileData;
    static ULONG FileSize;
};