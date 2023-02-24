#pragma once
#define DBGPRINT( x, ... )	DbgPrintEx( NULL, NULL, "[ HypervisorHiderDrv ] " x, __VA_ARGS__ );

#include <ntifs.h>
#include <ntimage.h>
#include <windef.h>

#include "Ntdll.h"
#include "Win32u.h"
#include "Hook.h"
#include "..\\KasperskyHook/kaspersky.hpp"
#include "..\\KasperskyHook/utils.hpp"

namespace Memory
{
#define POOL_TAG 'mmt'

    inline void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize)
    {
        void* Result = ExAllocatePoolWithTag(NonPagedPool, InSize, POOL_TAG);

        if (InZeroMemory && (Result != NULL))
            RtlZeroMemory(Result, InSize);

        return Result;
    }

    inline void RtlFreeMemory(void* InPointer)
    {
        ExFreePoolWithTag(InPointer, POOL_TAG);
    }
}