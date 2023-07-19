// sbiextra.cpp
////////////////
#define WIN32_LEAN_AND_MEAN
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <Tlhelp32.h>
#include <string>
#include <vector>
#include "SimpleIni.h"

using std::wstring;
using std::vector;

// constants / macros
#define DEBUG_LEN 1024
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define BitRemove(s, r) ((DWORD) \
							( \
								((DWORD)(s)) & \
								(~((DWORD)(r))) \
							) \
						)

// define structures
typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// define PIDFUNC
typedef BOOL (WINAPI *PIDFUNC)(DWORD);
// define hook function pointers
typedef NTSTATUS (NTAPI *P_NtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI *P_NtReadVirtualMemory)(HANDLE, LPVOID, LPVOID, ULONG, ULONG *);
typedef NTSTATUS (WINAPI *P_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef HANDLE (WINAPI *P_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL (WINAPI *P_BlockInput)(BOOL);
typedef int (WINAPI *P_InternalGetWindowText)(HWND, LPWSTR, int);
typedef int (WINAPI *P_GetWindowTextA)(HWND, LPSTR, int);
typedef int (WINAPI *P_GetWindowTextW)(HWND, LPWSTR, int);
typedef LRESULT (WINAPI *P_SendMessageA)(HWND, UINT, WPARAM, LPARAM);
typedef LRESULT (WINAPI *P_SendMessageW)(HWND, UINT, WPARAM, LPARAM);
// internal use
typedef NTSTATUS (WINAPI *P_NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
// Sandboxie functions
typedef void *(__stdcall *P_SbieDll_Hook)(const char *, void *, void *);
typedef LONG (__stdcall *P_SbieApi_QueryProcess)(ULONG_PTR, WCHAR *, WCHAR *, WCHAR *, ULONG *);
typedef LONG (__stdcall *P_SbieApi_GetHomePath)(WCHAR *, ULONG, WCHAR *, ULONG);

// initialize global variables
static P_NtOpenProcess pNtOpenProcess = NULL;
static P_NtReadVirtualMemory pNtReadVirtualMemory = NULL;
static P_NtQuerySystemInformation pNtQuerySystemInformation = NULL;
static P_CreateToolhelp32Snapshot pCreateToolhelp32Snapshot = NULL;
static P_NtQueryInformationProcess pNtQueryInformationProcess = NULL;
static P_BlockInput pBlockInput = NULL;
static P_InternalGetWindowText pInternalGetWindowText = NULL;
static P_GetWindowTextA pGetWindowTextA = NULL;
static P_GetWindowTextW pGetWindowTextW = NULL;
static P_SendMessageA pSendMessageA = NULL;
static P_SendMessageW pSendMessageW = NULL;
static P_SbieDll_Hook SbieDll_Hook = NULL;
static P_SbieApi_QueryProcess SbieApi_QueryProcess = NULL;
static P_SbieApi_GetHomePath SbieApi_GetHomePath = NULL;
WCHAR debug[DEBUG_LEN], curSandbox[34];
vector<wstring> SBIEProcs;
DWORD curPID;
BOOL fShowDebug = TRUE;
HMODULE g_hDllModule = NULL;

//~~ HELPER FUNCTIONS ~~//

// debug output function
static void _DebugWrite(LPWSTR debugstring) {if (fShowDebug) OutputDebugStringW(debugstring);}

// invalid parameter handler for secure CRT functions
void _invalid_param_hndler(LPCWSTR expression, LPCWSTR function, LPCWSTR file, UINT line, uintptr_t pReserved)
{
	_DebugWrite(L"    Invalid parameter handler invoked");
}

// set current sandbox in curSandbox
static void SetCurrentSandbox()
{
	WCHAR ImageName[96];
	WCHAR SidString[96];
	ULONG SessionId;
	SbieApi_QueryProcess((ULONG_PTR) curPID, curSandbox, ImageName, SidString, &SessionId);
}

// determine if intercepted PID is a sandboxed process
static BOOL IsSandboxedPID(DWORD TargetPID)
{
	WCHAR BoxName[34];
	WCHAR ImageName[96];
	WCHAR SidString[96];
	ULONG SessionId;

	SbieApi_QueryProcess((ULONG_PTR) TargetPID, BoxName, ImageName, SidString, &SessionId);
	if (fShowDebug)
	{
		_snwprintf_s(debug, DEBUG_LEN, DEBUG_LEN, L"IsSandboxedPID: %d\nBoxName: %s\nImageName: %s\nSidString: %s\nSessionId: %d",
						TargetPID, BoxName, ImageName, SidString, SessionId);
		OutputDebugStringW(debug);
	}
	if (_wcsicmp(BoxName, curSandbox) == 0)
		return TRUE;
	else
		return FALSE;
}

// determine if intercepted PID is a direct child of current process
static BOOL IsChildPID(DWORD TargetPID)
{
	BOOL retval = FALSE;
	HANDLE hProc;
	OBJECT_ATTRIBUTES oa = {0};
	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	CLIENT_ID cID = {0};
	cID.UniqueProcess = (HANDLE)TargetPID;
	PROCESS_BASIC_INFORMATION pbi = {0};
	ULONG ReturnLength;
	
	NTSTATUS success = pNtOpenProcess(&hProc, PROCESS_QUERY_INFORMATION, &oa, &cID);
	if (NT_SUCCESS(success))
	{
		success = pNtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
		if (NT_SUCCESS(success))
		{
			if ((DWORD)pbi.Reserved3 == curPID) // Reserved3 is parent PID
				retval = TRUE;
		}
		CloseHandle(hProc);
	}
	if (fShowDebug)
	{
		_snwprintf_s(debug, DEBUG_LEN, DEBUG_LEN, L"[%d] -> [%d] parent", TargetPID, (DWORD)pbi.Reserved3);
		OutputDebugStringW(debug);
		if (retval)
			OutputDebugStringW(L"Target is a child of this process");
		else
			OutputDebugStringW(L"Target is not a child of this process");
	}
	return retval;
}

// determine if it's OK to allow the function call
// is the TargetPID the current PID, or sandboxed, or a child of the current process
static BOOL OkToAllowCall(DWORD TargetPID)
{
	if ((TargetPID == curPID) || IsSandboxedPID(TargetPID) || IsChildPID(TargetPID))
		return TRUE;
	else
		return FALSE;
}

// transform process handle to PID
static DWORD HandleToPID(HANDLE hProcess)
{
	HANDLE hDupHandle = NULL;
	BOOL ret = DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &hDupHandle, PROCESS_QUERY_INFORMATION, FALSE, 0);
	if (ret && hDupHandle) // if we can't dup the handle, don't allow the call
	{
		DWORD TargetPID = GetProcessId(hDupHandle);
		CloseHandle(hDupHandle);

		return TargetPID;
	}
	return -1;
}

// strip quotes from a path
static void StripQuotes(wstring &string)
{
	wstring strtemp = string; // copy content of string to strtemp
	wstring::const_iterator it;
	string.clear(); // clear original string
	for (it = strtemp.begin(); it < strtemp.end(); it++)
		if (*it != '"')
			string.push_back(*it); // copy non-quote characters to original string
}

// build vector of Sandboxie's processes
static BOOL BuildSandboxieProcessVector(HINSTANCE SbieDll)
{
	WCHAR szSBIEPath[MAX_PATH] = L"";
	WIN32_FIND_DATAW find;
	HANDLE hFind;
	wstring strData;
	wstring findData;

	// get Sandboxie path
	// check pointer to SbieApi_GetHomePath to determine if we use the old or new method
	//if (SbieApi_GetHomePath)
	//{
	//	// new method for Sandboxie 3.51 beta+
	//	// 0=success
	//	if (!SbieApi_GetHomePath(NULL, 0, szSBIEPath, MAX_PATH))
	//	{
	//		strData = szSBIEPath; // copy path to wstring
	//		StripQuotes(strData); // remove any quotes from the string
	//		strData += L"\\";
	//	}
	//}
	//else
	//{
	//	// old method for pre Sandboxie 3.51 beta
	//	// !0=success
	//	if (GetModuleFileNameW(SbieDll, szSBIEPath, MAX_PATH))
	//	{
	//		strData = szSBIEPath; // copy path to wstring
	//		StripQuotes(strData); // remove any quotes from the string
	//		strData.erase(strData.find_last_of('\\') + 1); // remove filename
	//	}
	//}
	// new method for Sandboxie 3.51 beta+
	// 0=success
	if (!SbieApi_GetHomePath(NULL, 0, szSBIEPath, MAX_PATH))
	{
		strData = szSBIEPath; // copy path to wstring
		StripQuotes(strData); // remove any quotes from the string
		strData += L"\\";
		if (fShowDebug)
		{
			_snwprintf_s(debug, DEBUG_LEN, DEBUG_LEN, L"Sandboxie path: %s", strData.c_str());
			OutputDebugStringW(debug);
		}
		// find all *.exe files and add to the proc array
		findData = strData + L"*.exe";
		hFind = FindFirstFileW(findData.c_str(), &find);
		if (hFind != INVALID_HANDLE_VALUE)
		{
			_DebugWrite(L"---------- Sandboxie process vector ----------");
			do
			{
				SBIEProcs.push_back(strData + find.cFileName); // create EXE path and add to vector
				_DebugWrite((LPWSTR)SBIEProcs[SBIEProcs.size() - 1].c_str());
			} while (FindNextFileW(hFind, &find));
			FindClose(hFind);
			_DebugWrite(L"---------- End vector ------------------------");
			return TRUE;
		}
		else
			_DebugWrite(L"FindFirstFile failed");
	}
	_DebugWrite(L"Failed to build Sandboxie Process Vector");
	return FALSE;
}

// is the current process a Sandboxie process?
static BOOL IsSBIEProc(LPCWSTR procPath)
{
	for (UINT i = 0; i < SBIEProcs.size(); i++)
	{
		// look for process in SBIE vector
		if (procPath == SBIEProcs[i])
			return TRUE;
	}
	return FALSE;
}

//~~ HOOK FUNCTIONS ~~//

static NTSTATUS MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	_DebugWrite(L"NtOpenProcess intercepted");
	// allow opening of sandboxed processes and child processes
	// this only works if we can get PID information
	if (ClientId)
	{
		DWORD TargetPID = (DWORD)ClientId->UniqueProcess;
		if (fShowDebug)
		{
			_snwprintf_s(debug, DEBUG_LEN, DEBUG_LEN, L"Target PID: %d", TargetPID);
			OutputDebugStringW(debug);
		}
		if (OkToAllowCall(TargetPID))
		{
			_DebugWrite(L"Allowing NtOpenProcess");
			return pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}
	}
	// default to blocking if we don't get PID
	_DebugWrite(L">> Blocking NtOpenProcess");
	return STATUS_UNSUCCESSFUL;
}

static NTSTATUS MyNtReadVirtualMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, ULONG nSize, ULONG *lpNumberOfBytesRead)
{
	_DebugWrite(L"NtReadVirtualMemory intercepted");
	// allow reading of sandboxed and child processes
	if ((hProcess == GetCurrentProcess()) || OkToAllowCall(HandleToPID(hProcess)))
	{
		_DebugWrite(L"Allowing NtReadVirtualMemory");
		return pNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}
	_DebugWrite(L">> Blocking NtReadVirtualMemory");
	return STATUS_UNSUCCESSFUL;
}

static NTSTATUS MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
										   ULONG SystemInformationLength, PULONG ReturnLength)
{
	int SystemSessionInformation = 49;

	_DebugWrite(L"NtQuerySystemInformation intercepted");
	// do not allow SystemProcessInformation, SystemSessionInformation
	if ((SystemInformationClass == SystemProcessInformation) || (SystemInformationClass == SystemSessionInformation))
	{
		_DebugWrite(L">> Blocking NtQuerySystemInformation");
		return STATUS_UNSUCCESSFUL;
	}
	_DebugWrite(L"Allowing NtQuerySystemInformation");
	return pNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

static HANDLE MyCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
	_DebugWrite(L"CreateToolhelp32Snapshot intercepted");
	// remove system-wide process and thread enumeration
	if (dwFlags & TH32CS_SNAPPROCESS)
		BitRemove(dwFlags, TH32CS_SNAPPROCESS);
	if (dwFlags & TH32CS_SNAPTHREAD)
		BitRemove(dwFlags, TH32CS_SNAPTHREAD);
	// if dwFlags does not now equal 0 or TH32CS_INHERIT, test th32ProcessID for being sandboxed
	if ((dwFlags != 0) && (dwFlags != TH32CS_INHERIT))
	{
		// if th32ProcessID equals 0 (current process) or a sandboxed process or child, allow the call
		if ((th32ProcessID == 0) || OkToAllowCall(th32ProcessID))
		{
			_DebugWrite(L"Allowing CreateToolhelp32Snapshot");
			return pCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
		}
	}
	_DebugWrite(L">> Blocking CreateToolhelp32Snapshot");
	return INVALID_HANDLE_VALUE;
}

static BOOL MyBlockInput(BOOL fBlock)
{
	_DebugWrite(L">> Blocking BlockInput");
	return FALSE; // unconditionally block this function
}

// handles InternalGetWindowText calls
static int MyInternalGetWindowText(HWND hWnd, LPWSTR lpString, int nMaxCount)
{
	_DebugWrite(L"InternalGetWindowText intercepted");
	// get target window process ID
	DWORD TargetPID;
	GetWindowThreadProcessId(hWnd, &TargetPID);
	// allow reading of sandboxed and child process windows
	if (OkToAllowCall(TargetPID))
	{
		_DebugWrite(L"Allowing InternalGetWindowText");
		return pInternalGetWindowText(hWnd, lpString, nMaxCount);
	}
	_DebugWrite(L">> Blocking InternalGetWindowText");
	return 0;
}

// handles GetWindowTextA/W calls
static int MyGetWindowText(HWND hWnd, void *lpString, int nMaxCount, BOOL IsUnicode)
{
	// get target window process ID
	DWORD TargetPID;
	GetWindowThreadProcessId(hWnd, &TargetPID);
	// allow reading of sandboxed and child process windows
	if (OkToAllowCall(TargetPID))
	{
		_DebugWrite(L"Allowing GetWindowText");
		if (IsUnicode)
			return pGetWindowTextW(hWnd, (LPWSTR)lpString, nMaxCount);
		else
			return pGetWindowTextA(hWnd, (LPSTR)lpString, nMaxCount);
	}
	_DebugWrite(L">> Blocking GetWindowText");
	return 0;
}

static int MyGetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount)
{
	_DebugWrite(L"GetWindowTextA intercepted");
	return MyGetWindowText(hWnd, (void *)lpString, nMaxCount, FALSE);
}

static int MyGetWindowTextW(HWND hWnd, LPWSTR lpString, int nMaxCount)
{
	_DebugWrite(L"GetWindowTextW intercepted");
	return MyGetWindowText(hWnd, (void *)lpString, nMaxCount, TRUE);
}

// handles SendMessageA/W calls
static LRESULT MySendMessage(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, BOOL IsUnicode)
{
	// get target window process id
	DWORD TargetPID;
	if (IsWindow(hWnd) && GetWindowThreadProcessId(hWnd, &TargetPID) && !OkToAllowCall(TargetPID))
	{
		// if outside process, check the message type and conditionally block it
		switch (Msg)
		{
			case WM_GETTEXT:
				_DebugWrite(L">> Blocking WM_GETTEXT");
				return 0; // block it
		}
	}
	// allow sending to sandboxed and child windows, invalid windows (poor application coding?), and unhandled messages
	if (fShowDebug)
	{
		_snwprintf_s(debug, DEBUG_LEN, DEBUG_LEN, L"Allowing SendMessage: 0x%04X to %p", Msg, hWnd);
		OutputDebugStringW(debug);
	}
	if (IsUnicode)
		return pSendMessageW(hWnd, Msg, wParam, lParam);
	else
		return pSendMessageA(hWnd, Msg, wParam, lParam);
}

static LRESULT MySendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	_DebugWrite(L"SendMessageA intercepted");
	return MySendMessage(hWnd, Msg, wParam, lParam, FALSE);
}

static LRESULT MySendMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	_DebugWrite(L"SendMessageW intercepted");
	return MySendMessage(hWnd, Msg, wParam, lParam, TRUE);
}

//~~ UNLOAD PROCEDURE ~~//

//unloads our DLL dynamically
static DWORD FreeAndExit(LPVOID lpParameter) {FreeLibraryAndExitThread(g_hDllModule, 0);}

static void UnloadMe(void)
{
	_DebugWrite(L">> Unloading DLL.");
	CloseHandle(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) FreeAndExit, NULL, 0, NULL));
}

//~~ INJECTDLLMAIN PROCEDURE ~~//

// called by SbieDll after LoadLibrary (our DllMain) returns
// performs all initialization and hooking
__declspec(dllexport) void InjectDllMain(HINSTANCE SbieDll, ULONG_PTR UnusedParameter)
{
	WCHAR szSbieIni[MAX_PATH];
	HMODULE Ntdll, Kernel32, User32;
	CSimpleIniW ini;
	BOOL IniLoadError;

	_set_invalid_parameter_handler((_invalid_parameter_handler)_invalid_param_hndler); // set invalid parameter handles
	// load INI file
	GetModuleFileNameW(g_hDllModule, szSbieIni, MAX_PATH); // path to loaded module
	*(wcsrchr(szSbieIni, '\\') + 1) = '\0'; // strip DLL name
	wcsncat_s(szSbieIni, MAX_PATH, L"sbiextra.ini", 12); // append 'sbiextra.ini'
	IniLoadError = !(SI_OK == ini.LoadFile(szSbieIni)); // set a global flag:  if error opening INI, load all hooks
	// are we outputting debug?
	fShowDebug = (1 == ini.GetLongValue(L"sbiextra", L"ShowDebugInfo", 0));
	// get addresses of SbieDll functions
	SbieDll_Hook = (P_SbieDll_Hook) GetProcAddress(SbieDll, "SbieDll_Hook");
	SbieApi_QueryProcess = (P_SbieApi_QueryProcess) GetProcAddress(SbieDll, "SbieApi_QueryProcess");
	SbieApi_GetHomePath = (P_SbieApi_GetHomePath) GetProcAddress(SbieDll, "SbieApi_GetHomePath");
	// build vector of Sandboxie processes
	// if this fails, do not inject the DLL so we avoid running code inside SBIE's own processes
	if (!BuildSandboxieProcessVector(SbieDll))
	{
		_DebugWrite(L"Failed to build Sandboxie process vector.");
		UnloadMe();
		return;
	}
	WCHAR szProcPath[MAX_PATH];
	GetModuleFileNameW(NULL, szProcPath, MAX_PATH); // get current process path
	if (fShowDebug)
	{
		_snwprintf_s(debug, DEBUG_LEN, DEBUG_LEN, L"Current process: %s", szProcPath);
		OutputDebugStringW(debug);
	}
	// do not hook SBIE's processes
	if (IsSBIEProc(szProcPath))
	{
		UnloadMe();
		return;
	}
	// set curPID
	curPID = GetCurrentProcessId();
	if (fShowDebug)
	{
		_snwprintf_s(debug, DEBUG_LEN, DEBUG_LEN, L"----------\nInjected into process: [%d] %s", curPID, szProcPath);
		OutputDebugStringW(debug);
	}
	// set curSandbox
	SetCurrentSandbox();
	// get addresses of functions to be hooked
	// ntdll.dll
	Ntdll = GetModuleHandleW(L"ntdll.dll");
	pNtOpenProcess = (P_NtOpenProcess) GetProcAddress(Ntdll, "NtOpenProcess");
	pNtReadVirtualMemory = (P_NtReadVirtualMemory) GetProcAddress(Ntdll, "NtReadVirtualMemory");
	pNtQuerySystemInformation = (P_NtQuerySystemInformation) GetProcAddress(Ntdll, "NtQuerySystemInformation");
	// --internal use
	pNtQueryInformationProcess = (P_NtQueryInformationProcess) GetProcAddress(Ntdll, "NtQueryInformationProcess");
	// kernel32.dll
	Kernel32 = GetModuleHandleW(L"kernel32.dll");
	pCreateToolhelp32Snapshot = (P_CreateToolhelp32Snapshot) GetProcAddress(Kernel32, "CreateToolhelp32Snapshot");
	// user32.dll
	User32 = GetModuleHandleW(L"user32.dll");
	if (!User32)
		User32 = LoadLibraryW(L"user32.dll");
	pBlockInput = (P_BlockInput) GetProcAddress(User32, "BlockInput");
	pInternalGetWindowText = (P_InternalGetWindowText) GetProcAddress(User32, "InternalGetWindowText");
	pGetWindowTextA = (P_GetWindowTextA) GetProcAddress(User32, "GetWindowTextA");
	pGetWindowTextW = (P_GetWindowTextW) GetProcAddress(User32, "GetWindowTextW");
	pSendMessageA = (P_SendMessageA) GetProcAddress(User32, "SendMessageA");
	pSendMessageW = (P_SendMessageW) GetProcAddress(User32, "SendMessageW");
	// hook the functions
	if (pNtOpenProcess && (ini.GetLongValue(L"sbiextra", L"NtOpenProcess", 1) || IniLoadError))
		pNtOpenProcess = (P_NtOpenProcess) SbieDll_Hook("NtOpenProcess", pNtOpenProcess, MyNtOpenProcess);
	if (pNtReadVirtualMemory && (ini.GetLongValue(L"sbiextra", L"NtReadVirtualmemory", 1) || IniLoadError))
		pNtReadVirtualMemory = (P_NtReadVirtualMemory) SbieDll_Hook("NtReadVirtualMemory", pNtReadVirtualMemory, MyNtReadVirtualMemory);
	if (pNtQuerySystemInformation && (ini.GetLongValue(L"sbiextra", L"NtQuerySystemInformation", 1) || IniLoadError))
		pNtQuerySystemInformation = (P_NtQuerySystemInformation) SbieDll_Hook("NtQuerySystemInformation", pNtQuerySystemInformation, MyNtQuerySystemInformation);
	if (pCreateToolhelp32Snapshot && (ini.GetLongValue(L"sbiextra", L"CreateToolhelp32Snapshot", 1) || IniLoadError))
		pCreateToolhelp32Snapshot = (P_CreateToolhelp32Snapshot) SbieDll_Hook("CreateToolhelp32Snapshot", pCreateToolhelp32Snapshot, MyCreateToolhelp32Snapshot);
	if (pBlockInput && (ini.GetLongValue(L"sbiextra", L"BlockInput", 1) || IniLoadError))
		pBlockInput = (P_BlockInput) SbieDll_Hook("BlockInput", pBlockInput, MyBlockInput);
	if (pInternalGetWindowText && (ini.GetLongValue(L"sbiextra", L"InternalGetWindowText", 1) || IniLoadError))
		pInternalGetWindowText = (P_InternalGetWindowText) SbieDll_Hook("InternalGetWindowText", pInternalGetWindowText, MyInternalGetWindowText);
	if (pGetWindowTextA && (ini.GetLongValue(L"sbiextra", L"GetWindowTextA", 1) || IniLoadError))
		pGetWindowTextA = (P_GetWindowTextA) SbieDll_Hook("GetWindowTextA", pGetWindowTextA, MyGetWindowTextA);
	if (pGetWindowTextW && (ini.GetLongValue(L"sbiextra", L"GetWindowTextW", 1) || IniLoadError))
		pGetWindowTextW = (P_GetWindowTextW) SbieDll_Hook("GetWindowTextW", pGetWindowTextW, MyGetWindowTextW);
	if (pSendMessageA && (ini.GetLongValue(L"sbiextra", L"SendMessageA", 1) || IniLoadError))
		pSendMessageA = (P_SendMessageA) SbieDll_Hook("SendMessageA", pSendMessageA, MySendMessageA);
	if (pSendMessageW && (ini.GetLongValue(L"sbiextra", L"SendMessageW", 1) || IniLoadError))
		pSendMessageW = (P_SendMessageW) SbieDll_Hook("SendMessageW", pSendMessageW, MySendMessageW);
	if (fShowDebug)
	{
		_snwprintf_s(debug, DEBUG_LEN, DEBUG_LEN,
					L"Pointers:\nSbieDll_Hook: %p\nSbieApi_QueryProcess: %p\nSbieApi_GetHomePath: %p\npNtQueryInformationProcess: %p\
					\n----------\
					\npNtOpenProcess: %p\npNtReadVirtualMemory: %p\npNtQuerySystemInformation: %p\npCreateToolhelp32Snapshot: %p\
					\npBlockInput: %p\npInternalGetWindowText: %p\npGetWindowTextA: %p\npGetWindowTextW: %p\npSendMessageA: %p\npSendMessageW: %p\
					\n----------",
					SbieDll_Hook, SbieApi_QueryProcess, SbieApi_GetHomePath, pNtQueryInformationProcess,
					pNtOpenProcess, pNtReadVirtualMemory, pNtQuerySystemInformation, pCreateToolhelp32Snapshot,
					pBlockInput, pInternalGetWindowText, pGetWindowTextA, pGetWindowTextW, pSendMessageA, pSendMessageW);
		OutputDebugStringW(debug);
	}
}

//~~ ENTRY POINT ~~//

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			// copy hModule to global variable
			g_hDllModule = hModule;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}