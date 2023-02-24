#pragma once
#include "Global.h"

class WIN32U
{
public:
    static NTSTATUS Initialize();
    static void Deinitialize();
    static int GetExportShadowSsdtIndex(const char* ExportName);

private:
    static unsigned char* FileData;
    static ULONG FileSize;
};
