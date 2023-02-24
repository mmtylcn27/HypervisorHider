#include "HookHelper.h"

bool HookHelper::IsProtectedProcess(HANDLE PID)
{
	bool bResult = false;
	UNICODE_STRING wsProcName{ };

	if (!GetProcessName(PID, &wsProcName))
		return bResult;

	if (wsProcName.Buffer)
	{
		bResult = IsProtectedProcess(wsProcName.Buffer);
		FreeUnicodeString(&wsProcName);
	}

	return bResult;
}

bool HookHelper::IsProtectedProcess(PWCH Buffer)
{
	if (!Buffer)
		return false;

	for (unsigned int i = 0; i < ARRAYSIZE(protectedProcess); ++i)
	{
		if (wcsstr(Buffer, protectedProcess[i]))
			return true;
	}

	return false;
}

bool HookHelper::IsBlacklistProcess(HANDLE PID)
{
	bool bResult = false;
	UNICODE_STRING wsProcName{ };

	if (!GetProcessName(PID, &wsProcName))
		return bResult;

	if (wsProcName.Buffer)
	{
		bResult = IsBlacklistProcess(wsProcName.Buffer);
		FreeUnicodeString(&wsProcName);
	}

	return bResult;
}

bool HookHelper::IsBlacklistProcess(PWCH Buffer)
{
	if (!Buffer)
		return false;

	for (unsigned int i = 0; i < ARRAYSIZE(blackListProcess); ++i)
	{
		if (wcsstr(Buffer, blackListProcess[i]))
			return true;
	}

	return false;
}

bool HookHelper::IsProtectDriver(CHAR* Buffer)
{
	if (!Buffer)
		return false;

	for (unsigned int i = 0; i < ARRAYSIZE(protectedDriver); ++i)
	{
		if (strstr(Buffer, protectedDriver[i]))
			return true;
	}

	return false;
}

void HookHelper::AllocateUnicodeString(PUNICODE_STRING us, USHORT Size)
{
	if (!us)
		return;

	__try
	{
		us->Length = 0;
		us->MaximumLength = 0;
		us->Buffer = PWSTR(ExAllocatePoolWithTag(NonPagedPool, Size, POOL_TAG));
		if (us->Buffer)
		{
			us->Length = 0;
			us->MaximumLength = Size;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
}

void HookHelper::FreeUnicodeString(PUNICODE_STRING us)
{
	if (!us)
		return;

	__try
	{
		if (us->MaximumLength > 0 && us->Buffer)
			ExFreePoolWithTag(us->Buffer, POOL_TAG);

		us->Length = 0;
		us->MaximumLength = 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
}

bool HookHelper::GetProcessName(HANDLE PID, PUNICODE_STRING ProcessImageName)
{
	KAPC_STATE apc{ };
	bool bReturn = false;

	if (!ProcessImageName)
		return false;

	PEPROCESS Process = nullptr;
	auto status = PsLookupProcessByProcessId(PID, &Process);
	if (!NT_SUCCESS(status))
		return false;

	KeStackAttachProcess(Process, &apc);

	//
	// Credits: iPower
	//
	wchar_t lpModuleName[MAX_PATH];
	status = ZwQueryVirtualMemory(NtCurrentProcess(), PsGetProcessSectionBaseAddress(Process), (MEMORY_INFORMATION_CLASS)2, lpModuleName, sizeof(lpModuleName), NULL);
	if (NT_SUCCESS(status))
	{
		PUNICODE_STRING pModuleName = (PUNICODE_STRING)lpModuleName;
		if (pModuleName->Length > 0)
		{
			AllocateUnicodeString(ProcessImageName, pModuleName->MaximumLength);
			RtlCopyUnicodeString(ProcessImageName, pModuleName);
			bReturn = true;
		}
	}

	KeUnstackDetachProcess(&apc);
	ObDereferenceObject(Process);

	return bReturn;
}

ULONG HookHelper::GetProcessIDFromThreadHandle(HANDLE ThreadHandle)
{
	ULONG Pid = 0;
	PETHREAD Thread;

	if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, 0, *PsThreadType, ExGetPreviousMode(), (PVOID*)&Thread, nullptr)))
	{
		Pid = (ULONG)(ULONG_PTR)PsGetProcessId(PsGetThreadProcess(Thread));
		ObDereferenceObject(Thread);
	}

	return Pid;
}