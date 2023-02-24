#pragma once
#include "Global.h"
#include "Windef.h"

typedef NTSTATUS(NTAPI* _NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
typedef HWND(NTAPI* _NtUserWindowFromPoint)(LONG x, LONG y);
typedef HANDLE(NTAPI* _NtUserQueryWindow)(HWND WindowHandle, HANDLE TypeInformation);
typedef HWND(NTAPI* _NtUserFindWindowEx)(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType);
typedef NTSTATUS(NTAPI* _NtUserBuildHwndList)(HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread, UINT cHwndMax, HWND* phwndFirst, ULONG* pcHwndNeeded);
typedef HWND(NTAPI* _NtUserGetForegroundWindow)(VOID);

class Hook
{
public:
	static void Initialize();
	static void Deinitialize();


private:
	static _NtOpenProcess oNtOpenProcess;
	static _NtQuerySystemInformation oNtQuerySystemInformation;
	static _NtUserWindowFromPoint oNtUserWindowFromPoint;
	static _NtUserQueryWindow oNtUserQueryWindow;
	static _NtUserFindWindowEx oNtUserFindWindowEx;
	static _NtUserBuildHwndList oNtUserBuildHwndList;
	static _NtUserGetForegroundWindow oNtUserGetForegroundWindow;

	static NTSTATUS NTAPI hkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	static NTSTATUS NTAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
	static HWND NTAPI hkNtUserWindowFromPoint(LONG x, LONG y);
	static HANDLE NTAPI hkNtUserQueryWindow(HWND WindowHandle, HANDLE TypeInformation);
	static HWND NTAPI hkNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType);
	static NTSTATUS NTAPI hkNtUserBuildHwndList(HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread, UINT cHwndMax, HWND* phwndFirst, ULONG* pcHwndNeeded);
	static HWND NTAPI hkNtUserGetForegroundWindow(VOID);

	static int NtOpenProcessIndex,
	NtQuerySystemInformationIndex,
	NtUserWindowFromPointIndex,
	NtUserQueryWindowIndex,
	NtUserFindWindowExIndex,
	NtUserBuildHwndListIndex,
	NtUserGetForegroundWindowIndex;
};
