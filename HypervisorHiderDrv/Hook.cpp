#include "Hook.h"
#include "HookHelper.h"

_NtOpenProcess Hook::oNtOpenProcess;
_NtQuerySystemInformation Hook::oNtQuerySystemInformation;
_NtUserWindowFromPoint Hook::oNtUserWindowFromPoint;
_NtUserQueryWindow Hook::oNtUserQueryWindow;
_NtUserFindWindowEx Hook::oNtUserFindWindowEx;
_NtUserBuildHwndList Hook::oNtUserBuildHwndList;
_NtUserGetForegroundWindow Hook::oNtUserGetForegroundWindow;

int Hook::NtOpenProcessIndex = -1;
int Hook::NtQuerySystemInformationIndex = -1;
int Hook::NtUserWindowFromPointIndex = -1;
int Hook::NtUserQueryWindowIndex = -1;
int Hook::NtUserFindWindowExIndex = -1;
int Hook::NtUserBuildHwndListIndex = -1;
int Hook::NtUserGetForegroundWindowIndex = -1;

NTSTATUS Hook::hkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	const auto ret = oNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	const auto currentProcessId = PsGetCurrentProcessId();

	if (PsIsProtectedProcess(PsGetCurrentProcess()) || PsIsSystemProcess(PsGetCurrentProcess()) || HookHelper::IsProtectedProcess(currentProcessId))
		return ret;

	if (NT_SUCCESS(ret))
	{
		if (HookHelper::IsProtectedProcess(ClientId->UniqueProcess))
		{
			ZwClose(*ProcessHandle);
			*ProcessHandle = reinterpret_cast<HANDLE>(-1);
			return STATUS_ACCESS_DENIED;
		}
	}

	return ret;
}

NTSTATUS Hook::hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID Buffer, ULONG Length, PULONG ReturnLength)
{
	const auto ret = oNtQuerySystemInformation(SystemInformationClass, Buffer, Length, ReturnLength);
	const auto currentProcessId = PsGetCurrentProcessId();

	if (HookHelper::IsProtectedProcess(currentProcessId))
		return ret;

	if (NT_SUCCESS(ret))
	{
		switch (SystemInformationClass)
		{
		case SystemModuleInformation:
		{
			const auto pModule = static_cast<PRTL_PROCESS_MODULES>(Buffer);
			const auto pEntry = &pModule->Modules[0];

			for (unsigned i = 0; i < pModule->NumberOfModules; ++i)
			{
				if (pEntry[i].ImageBase && pEntry[i].ImageSize && strlen(reinterpret_cast<CHAR*>(pEntry[i].FullPathName)) > 2)
				{
					if (HookHelper::IsProtectDriver(reinterpret_cast<CHAR*>(pEntry[i].FullPathName)))
					{
						const auto next_entry = i + 1;

						if (next_entry < pModule->NumberOfModules)
							memcpy(&pEntry[i], &pEntry[next_entry], sizeof(RTL_PROCESS_MODULE_INFORMATION));
						else
						{
							memset(&pEntry[i], 0, sizeof(RTL_PROCESS_MODULE_INFORMATION));
							pModule->NumberOfModules--;
						}
					}
				}
			}

			break;
		}

		case SystemProcessInformation:
		case SystemSessionProcessInformation:
		case SystemExtendedProcessInformation:
		{
			PSYSTEM_PROCESS_INFO pCurr = NULL;
			auto pNext = static_cast<PSYSTEM_PROCESS_INFO>(Buffer);

			while (pNext->NextEntryOffset != 0)
			{
				pCurr = pNext;
				pNext = reinterpret_cast<PSYSTEM_PROCESS_INFO>(reinterpret_cast<PUCHAR>(pCurr) + pCurr->NextEntryOffset);

				if (pNext->ImageName.Buffer && HookHelper::IsProtectedProcess(pNext->ImageName.Buffer))
				{
					if (pNext->NextEntryOffset == 0)
						pCurr->NextEntryOffset = 0;
					else
						pCurr->NextEntryOffset += pNext->NextEntryOffset;

					pNext = pCurr;
				}
			}

			break;
		}

		case SystemHandleInformation:
		{
			const auto pHandle = static_cast<PSYSTEM_HANDLE_INFORMATION>(Buffer);
			const auto pEntry = &pHandle->Information[0];

			for (unsigned i = 0; i < pHandle->NumberOfHandles; ++i)
			{
				if (HookHelper::IsProtectedProcess(ULongToHandle(pEntry[i].ProcessId)))
				{
					const auto next_entry = i + 1;

					if (next_entry < pHandle->NumberOfHandles)
						memcpy(&pEntry[i], &pEntry[next_entry], sizeof(SYSTEM_HANDLE));
					else
					{
						memset(&pEntry[i], 0, sizeof(SYSTEM_HANDLE));
						pHandle->NumberOfHandles--;
					}
				}
			}

			break;
		}

		case SystemExtendedHandleInformation:
		{
			const auto pHandle = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(Buffer);
			const auto pEntry = &pHandle->Information[0];

			for (unsigned i = 0; i < pHandle->NumberOfHandles; ++i)
			{
				if (HookHelper::IsProtectedProcess(ULongToHandle(pEntry[i].ProcessId)))
				{
					const auto next_entry = i + 1;

					if (next_entry < pHandle->NumberOfHandles)
						memcpy(&pEntry[i], &pEntry[next_entry], sizeof(SYSTEM_HANDLE));
					else
					{
						memset(&pEntry[i], 0, sizeof(SYSTEM_HANDLE));
						pHandle->NumberOfHandles--;
					}
				}
			}

			break;
		}

		case SystemCodeIntegrityInformation:
		{
			auto Integrity = static_cast<PSYSTEM_CODEINTEGRITY_INFORMATION>(Buffer);

			// Spoof test sign flag if present
			if (Integrity->CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN)
				Integrity->CodeIntegrityOptions &= ~CODEINTEGRITY_OPTION_TESTSIGN;

			// Set as always enabled.
			Integrity->CodeIntegrityOptions |= CODEINTEGRITY_OPTION_ENABLED;

			break;
		}
		}
	}

	return ret;
}

HWND Hook::hkNtUserWindowFromPoint(LONG x, LONG y)
{
	const auto res = oNtUserWindowFromPoint(x, y);

	if (PsIsProtectedProcess(PsGetCurrentProcess()) || PsIsSystemProcess(PsGetCurrentProcess()))
		return res;

	return res;
}

HANDLE Hook::hkNtUserQueryWindow(HWND WindowHandle, HANDLE TypeInformation)
{
	const auto res = oNtUserQueryWindow(WindowHandle, TypeInformation);

	if (PsIsProtectedProcess(PsGetCurrentProcess()) || PsIsSystemProcess(PsGetCurrentProcess()))
		return res;

	auto PID = oNtUserQueryWindow(WindowHandle, 0);

	if (HookHelper::IsProtectedProcess(PID))
		return NULL;

	return res;
}

HWND Hook::hkNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType)
{
	const auto res = oNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);

	if (PsIsProtectedProcess(PsGetCurrentProcess()) || PsIsSystemProcess(PsGetCurrentProcess()))
		return res;

	if (res)
	{
		auto PID = oNtUserQueryWindow(res, 0);

		if (HookHelper::IsProtectedProcess(PID))
			return NULL;
	}

	return res;
}

NTSTATUS Hook::hkNtUserBuildHwndList(HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread, UINT cHwndMax, HWND* phwndFirst, ULONG* pcHwndNeeded)
{
	const auto res = oNtUserBuildHwndList(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);

	if (PsIsProtectedProcess(PsGetCurrentProcess()) || PsIsSystemProcess(PsGetCurrentProcess()))
		return res;

	if (fEnumChildren == 1)
	{
		auto PID = oNtUserQueryWindow(hwndNext, 0);

		if (HookHelper::IsProtectedProcess(PID))
			return STATUS_UNSUCCESSFUL;
	}

	if (NT_SUCCESS(res))
	{
		ULONG i = 0, j = 0;

		while (i < *pcHwndNeeded)
		{
			auto PID = oNtUserQueryWindow(phwndFirst[i], 0);

			if (HookHelper::IsProtectedProcess(PID))
			{
				for (j = i; j < (*pcHwndNeeded) - 1; j++)
					phwndFirst[j] = phwndFirst[j + 1];

				phwndFirst[*pcHwndNeeded - 1] = 0;
				(*pcHwndNeeded)--;

				continue;
			}

			i++;
		}
	}

	return res;
}

HWND LastForeWnd = reinterpret_cast<HWND>(-1);

HWND Hook::hkNtUserGetForegroundWindow()
{
	const auto res = oNtUserGetForegroundWindow();

	if (PsIsProtectedProcess(PsGetCurrentProcess()) || PsIsSystemProcess(PsGetCurrentProcess()))
		return res;

	auto PID = oNtUserQueryWindow(res, 0);

	if (HookHelper::IsProtectedProcess(PID))
		return LastForeWnd;
	else
		LastForeWnd = res;

	return res;
}

void Hook::Initialize()
{
	NtOpenProcessIndex = NTDLL::GetExportSsdtIndex("NtOpenProcess");

	if (NtOpenProcessIndex == -1)
	{
		DBGPRINT("NtOpenProcess == -1");
	}
	else
	{
		if (!kaspersky::hook_ssdt_routine(NtOpenProcessIndex, &hkNtOpenProcess, reinterpret_cast<void**>(&oNtOpenProcess)))
		{
			DBGPRINT("NtOpenProcess hook failed");
		}
		else
		{
			DBGPRINT("NtOpenProcess hook success");
		}
	}

	NtQuerySystemInformationIndex = NTDLL::GetExportSsdtIndex("NtQuerySystemInformation");

	if (NtQuerySystemInformationIndex == -1)
	{
		DBGPRINT("NtQuerySystemInformation == -1");
	}
	else
	{
		if (!kaspersky::hook_ssdt_routine(NtQuerySystemInformationIndex, &hkNtQuerySystemInformation, reinterpret_cast<void**>(&oNtQuerySystemInformation)))
		{
			DBGPRINT("NtQuerySystemInformation hook failed");
		}
		else
		{
			DBGPRINT("NtQuerySystemInformation hook success");
		}
	}

	NtUserWindowFromPointIndex = WIN32U::GetExportShadowSsdtIndex("NtUserWindowFromPoint");

	if (NtUserWindowFromPointIndex == -1)
	{
		DBGPRINT("NtUserWindowFromPointIndex == -1");
	}
	else
	{
		if (!kaspersky::hook_shadow_ssdt_routine(NtUserWindowFromPointIndex, &hkNtUserWindowFromPoint, reinterpret_cast<void**>(&oNtUserWindowFromPoint)))
		{
			DBGPRINT("NtUserWindowFromPoint hook failed");
		}
		else
		{
			DBGPRINT("NtUserWindowFromPoint hook success");
		}
	}

	NtUserQueryWindowIndex = WIN32U::GetExportShadowSsdtIndex("NtUserQueryWindow");

	if (NtUserQueryWindowIndex == -1)
	{
		DBGPRINT("NtUserQueryWindow == -1");
	}
	else
	{
		if (!kaspersky::hook_shadow_ssdt_routine(NtUserQueryWindowIndex, &hkNtUserQueryWindow, reinterpret_cast<void**>(&oNtUserQueryWindow)))
		{
			DBGPRINT("NtUserQueryWindow hook failed");
		}
		else
		{
			DBGPRINT("NtUserQueryWindow hook success");
		}
	}

	NtUserFindWindowExIndex = WIN32U::GetExportShadowSsdtIndex("NtUserFindWindowEx");

	if (NtUserFindWindowExIndex == -1)
	{
		DBGPRINT("NtUserFindWindowEx == -1");
	}
	else
	{
		if (!kaspersky::hook_shadow_ssdt_routine(NtUserFindWindowExIndex, &hkNtUserFindWindowEx, reinterpret_cast<void**>(&oNtUserFindWindowEx)))
		{
			DBGPRINT("NtUserFindWindowEx hook failed");
		}
		else
		{
			DBGPRINT("NtUserFindWindowEx hook success");
		}
	}

	NtUserBuildHwndListIndex = WIN32U::GetExportShadowSsdtIndex("NtUserBuildHwndList");

	if (NtUserBuildHwndListIndex == -1)
	{
		DBGPRINT("NtUserBuildHwndList == -1");
	}
	else
	{
		if (!kaspersky::hook_shadow_ssdt_routine(NtUserBuildHwndListIndex, &hkNtUserBuildHwndList, reinterpret_cast<void**>(&oNtUserBuildHwndList)))
		{
			DBGPRINT("NtUserBuildHwndList hook failed");
		}
		else
		{
			DBGPRINT("NtUserBuildHwndList hook success");
		}
	}


	NtUserGetForegroundWindowIndex = WIN32U::GetExportShadowSsdtIndex("NtUserGetForegroundWindow");

	if (NtUserGetForegroundWindowIndex == -1)
	{
		DBGPRINT("NtUserGetForegroundWindow == -1");
	}
	else
	{
		if (!kaspersky::hook_shadow_ssdt_routine(NtUserGetForegroundWindowIndex, &hkNtUserGetForegroundWindow, reinterpret_cast<void**>(&oNtUserGetForegroundWindow)))
		{
			DBGPRINT("NtUserGetForegroundWindow hook failed");
		}
		else
		{
			DBGPRINT("NtUserGetForegroundWindow hook success");
		}
	}
}

void  Hook::Deinitialize()
{
	if (kaspersky::is_klhk_loaded())
	{
		if (NtOpenProcessIndex != -1)
			kaspersky::unhook_ssdt_routine(NtOpenProcessIndex, oNtOpenProcess);

		if (NtQuerySystemInformationIndex != -1)
			kaspersky::unhook_ssdt_routine(NtQuerySystemInformationIndex, oNtQuerySystemInformation);

		if (NtUserWindowFromPointIndex != -1)
			kaspersky::unhook_shadow_ssdt_routine(NtUserWindowFromPointIndex, oNtUserWindowFromPoint);

		if (NtUserQueryWindowIndex != -1)
			kaspersky::unhook_shadow_ssdt_routine(NtUserQueryWindowIndex, oNtUserQueryWindow);

		if (NtUserFindWindowExIndex != -1)
			kaspersky::unhook_shadow_ssdt_routine(NtUserFindWindowExIndex, oNtUserFindWindowEx);

		if (NtUserBuildHwndListIndex != -1)
			kaspersky::unhook_shadow_ssdt_routine(NtUserBuildHwndListIndex, oNtUserBuildHwndList);

		if (NtUserGetForegroundWindowIndex != -1)
			kaspersky::unhook_shadow_ssdt_routine(NtUserGetForegroundWindowIndex, oNtUserGetForegroundWindow);

		LARGE_INTEGER LargeInteger{ };
		LargeInteger.QuadPart = -10000000;

		KeDelayExecutionThread(KernelMode, FALSE, &LargeInteger);
	}
}


