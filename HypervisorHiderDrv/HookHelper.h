#pragma once
#include "Global.h"

extern "C"
{
	NTSYSAPI BOOLEAN
		NTAPI
		PsIsProtectedProcess(
			_In_ PEPROCESS Process
		);

	NTSYSAPI
		BOOLEAN
		NTAPI
		PsIsSystemProcess(
			_In_ PEPROCESS Process
		);

	NTSYSAPI
		PVOID
		PsGetProcessSectionBaseAddress(
			__in PEPROCESS Process
		);
}

class HookHelper
{
public:
	static bool GetProcessName(HANDLE PID, PUNICODE_STRING ProcessImageName);
	static ULONG GetProcessIDFromThreadHandle(HANDLE ThreadHandle);
	static bool IsProtectedProcess(HANDLE PID);
	static bool IsProtectedProcess(PWCH Buffer);
	static bool IsBlacklistProcess(HANDLE PID);
	static bool IsBlacklistProcess(PWCH Buffer);
	static bool IsProtectDriver(CHAR* Buffer);
private:
	static constexpr const wchar_t* protectedProcess[] =
	{
		L"ollydbg",
		L"ida",
		L"ida64",
		L"idag",
		L"idag64",
		L"idaw",
		L"idaw64",
		L"idaq",
		L"idaq64",
		L"idau",
		L"idau64",
		L"scylla",
		L"scylla_x64",
		L"scylla_x86",
		L"protection_id",
		L"x64dbg",
		L"x32dbg",
		L"reshacker",
		L"ImportREC",
		L"devenv",
		L"ProcessHacker",
		L"tcpview",
		L"autoruns",
		L"autorunsc",
		L"filemon",
		L"procmon",
		L"regmon",
		L"wireshark",
		L"dumpcap",
		L"HookExplorer",
		L"ImportRCE",
		L"PETools",
		L"LordPE",
		L"SysInspector",
		L"proc_analyzer",
		L"sysAnalyzer",
		L"sniff_hit",
		L"joeboxcontrol",
		L"joeboxserver",
		L"ResourceHacker",
		L"fiddler",
		L"httpdebugger",
		L"procexp64",
		L"procexp",
		L"Dbgview",
		L"procmon64",
		L"cheatengine"
	};

	static constexpr const CHAR* protectedDriver[] = { "dbk64", "processhacker"};
	static constexpr const wchar_t* blackListProcess[] = { L"knightonline" };

	static void AllocateUnicodeString(PUNICODE_STRING us, USHORT Size);
	static void FreeUnicodeString(PUNICODE_STRING us);
};