#include "netapi32.h"
#include <iphlpapi.h>
#include <detours.h>
#include <fstream>
#include <string>
#include <sstream>
#include <comdef.h>
#include <comip.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

bool ProcNameExists(const std::string& procName) {
	std::ifstream logFile("procnames.txt");
	std::string line;

	if (logFile.is_open()) {
		while (std::getline(logFile, line)) {
			if (line == procName) {
				logFile.close();
				return true; // Procedure name exists
			}
		}
		logFile.close();
	}

	return false; // Procedure name does not exist
}



typedef int (WINAPI* MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);
MessageBoxW_t pOriginalMessageBoxW = nullptr; 

MessageBoxW_t TrueMessageBoxW = MessageBoxW; 

typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
GetProcAddress_t pOriginalGetProcAddress = NULL;

typedef BOOL (WINAPI* SetDlgItemText_t)(HWND   hDlg, int    nIDDlgItem, LPCWSTR lpStringe);
SetDlgItemText_t TrueSetDlgItemText = SetDlgItemText;

typedef BOOL(WINAPI* SetWindowTextW_t)(HWND   hWnd, LPCWSTR lpStringe);
SetWindowTextW_t TrueSetWindowTextW = SetWindowText;

typedef DWORD(WINAPI* GetAdaptersInfo_t)(
	PIP_ADAPTER_INFO pAdapterInfo,
	PULONG pOutBufLen);
GetAdaptersInfo_t TrueGetAdaptersInfo = nullptr;

typedef HRESULT(WINAPI* CoCreateInstanceEx_t)(REFCLSID Clsid, IUnknown* punkOuter, DWORD dwClsCtx, COSERVERINFO* pServerInfo, DWORD dwCount, MULTI_QI* pResults);
CoCreateInstanceEx_t TrueCoCreateInstanceEx = CoCreateInstanceEx;

typedef LSTATUS(WINAPI* RegQueryValueExW_t)(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData);
RegQueryValueExW_t TrueRegQueryValueExW = RegQueryValueExW;




ULONG WINAPI HookedGetAdaptersInfo(
	PIP_ADAPTER_INFO AdapterInfo,
	PULONG           SizePointer
) {
	MessageBoxA(NULL, "Hooked GetAdaptersInfo ", "Information", MB_OK);
	return GetAdaptersInfo(AdapterInfo, SizePointer);
}

int WINAPI HookedMessageBoxW(
	HWND hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT uType) 
{
// 	std::ofstream logFile("messageboxlog.txt", std::ios::app);
// 
// 	// Check if the file opened successfully
// 	if (logFile.is_open()) {
// 		logFile << "hooked meesageboxw is called\n" << std::endl; // Write the string to the file
// 		logFile.close(); // Close the file
// 		OutputDebugStringA("Message from hookedmessagebox logged successfully.");
// 	}
// 	else {
// 		OutputDebugStringA("Failed to open messagebox log file.");
// 	}
	// Call the original function
	return TrueMessageBoxW(hWnd, lpText, L"Hooked MessageBoxW", uType);
}

BOOL WINAPI HookedSetDlgItemText(HWND   hDlg, int    nIDDlgItem, LPCWSTR lpStringe) {
	// Call the original function
	OutputDebugStringA("HookedSetDlgItemText");
	return TrueSetDlgItemText(hDlg, nIDDlgItem, lpStringe);
}

BOOL WINAPI HookedSetWindowTextW(HWND   hDlg, LPCWSTR lpStringe) {
	// Call the original function
	OutputDebugStringA("HookedSetWindowTextW");
	return TrueSetWindowTextW(hDlg, lpStringe);
}

HRESULT WINAPI HookedCoCreateInstanceEx(REFCLSID Clsid, IUnknown* punkOuter, DWORD dwClsCtx, COSERVERINFO* pServerInfo, DWORD dwCount, MULTI_QI* pResults)
{
	// Call the original function
	OutputDebugStringA("HookedCoCreateInstanceEx");
	return TrueCoCreateInstanceEx(Clsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults);
}

HRESULT WINAPI HookedRegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData)
{
	// Call the original function
	OutputDebugStringA("HookedRegQueryValueExW");
	OutputDebugStringW(lpValueName);
	return TrueRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

FARPROC WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
// 	std::string procName(lpProcName); // Convert LPCSTR to std::string
// 	static int cnt = 0;
// 	cnt++;
// 	std::string strValue = std::to_string(cnt);
// 	LPCSTR lpcstrValue = strValue.c_str();
// 	OutputDebugStringA(lpcstrValue);
// 	// Buffer to hold the module name
// 	char moduleName[MAX_PATH];
// 
// 	// Get the module filename
// 	if (GetModuleFileNameA(hModule, moduleName, sizeof(moduleName))) {
// 		OutputDebugStringA(("Module Name: " + std::string(moduleName)).c_str());
// 	}
// 	else {
// 		OutputDebugStringA("Failed to get module name.");
// 	}
// 	OutputDebugStringA(lpProcName);
	// Check if the procedure name already exists in the log file

// 	if (!ProcNameExists(procName)) {
// 		// Log the procedure name to a file
// 		std::ofstream logFile("procnames.txt", std::ios::app); // Open in append mode
// 		if (logFile.is_open()) {
// 			logFile << procName << std::endl; // Write the procedure name to the file
// 			logFile.close(); // Close the file
// 		}
// 		else {
// 			MessageBoxA(NULL, "Failed to open log file", "Error", MB_OK);
// 		}
// 	}
	FARPROC result = pOriginalGetProcAddress(hModule, lpProcName);
	//if (result != NULL) LogToFile(hModule, lpProcName);
	// Hook for WinHttpOpen using pointer comparison

	if (result != NULL && result == (FARPROC)SetDlgItemText) {
		return (FARPROC)HookedSetDlgItemText;
	} 
	if (result != NULL && result == (FARPROC)SetWindowText) {
		return (FARPROC)HookedSetWindowTextW;
	}
	if (result != NULL && result == (FARPROC)GetAdaptersInfo) {
		OutputDebugStringA("change proc address of GetAdaptersInfo");
		return (FARPROC)HookedGetAdaptersInfo;
	}
	if (result != NULL && result == (FARPROC)CoCreateInstanceEx) {
		OutputDebugStringA("change proc address of CoCreateInstanceEx");
		return (FARPROC)HookedCoCreateInstanceEx;
	}

	return result;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {

	if (DetourIsHelperProcess()) {
		MessageBox(NULL, L"Ishelperprocess", L"Information", MB_OK);
		return TRUE;
	}

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:

		DisableThreadLibraryCalls(hModule);
		Load(NULL);
		//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Load, hModule, NULL, NULL);

		pOriginalGetProcAddress = (GetProcAddress_t)DetourFindFunction("kernel32.dll", "GetProcAddress");
		TrueGetAdaptersInfo = (GetAdaptersInfo_t)DetourFindFunction("IPHLPAPI.DLL", "GetAdaptersInfo");

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if (pOriginalGetProcAddress != NULL) {
			DetourAttach(&(PVOID&)pOriginalGetProcAddress, HookedGetProcAddress);
		}
		if (TrueGetAdaptersInfo != NULL) {
			DetourAttach(&(PVOID&)TrueGetAdaptersInfo, HookedGetAdaptersInfo);
		}
		DetourAttach(&(PVOID&)TrueMessageBoxW, HookedMessageBoxW);
		DetourAttach(&(PVOID&)TrueSetDlgItemText, HookedSetDlgItemText);
		DetourAttach(&(PVOID&)TrueSetWindowTextW, HookedSetWindowTextW);
		DetourAttach(&(PVOID&)TrueGetAdaptersInfo, HookedGetAdaptersInfo);
		DetourAttach(&(PVOID&)TrueRegQueryValueExW, HookedRegQueryValueExW);
		DetourTransactionCommit();
		//OutputDebugStringA("Hijacked");
		MessageBoxW(NULL, L"Hijacked netapi32.dll", L"Information", MB_OK);
        break;
    case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if (pOriginalGetProcAddress != NULL) {
			DetourDetach(&(PVOID&)pOriginalGetProcAddress, HookedGetProcAddress);
		}
		if (TrueGetAdaptersInfo != NULL) {
			DetourDetach(&(PVOID&)TrueGetAdaptersInfo, HookedGetAdaptersInfo);
		}
		DetourDetach(&(PVOID&)TrueMessageBoxW, HookedMessageBoxW); 
		DetourDetach(&(PVOID&)TrueSetDlgItemText, HookedSetDlgItemText);
		DetourDetach(&(PVOID&)TrueSetWindowTextW, HookedSetWindowTextW);
		DetourDetach(&(PVOID&)TrueGetAdaptersInfo, HookedGetAdaptersInfo);
		DetourDetach(&(PVOID&)TrueRegQueryValueExW, HookedRegQueryValueExW);
		DetourTransactionCommit();

        FreeLibrary(netapi32_dll);
        break;  
    }
    return TRUE; 
}
