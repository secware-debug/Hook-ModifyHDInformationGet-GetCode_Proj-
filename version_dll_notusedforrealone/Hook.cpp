#define _CRT_SECURE_NO_WARNINGS

#include "Hook.h"
#include "detours.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <shellscalingapi.h>
#include <lm.h>        // For NetWkstaGetInfo and related types
#include <intrin.h>
#include <winternl.h>
#include <sstream>
#include "Ghost.h"
DWORD64 dwVersion1DLL = 0;

extern "C" uint64_t GetRdiValue();

// Hexadecimal data to write
const BYTE brandDataToWrite[] = {
	0x49, 0x6E, 0x74, 0x65, 0x6C, 0x28, 0x52, 0x29, 0x20, 0x58, 0x65, 0x6F,
	0x6E, 0x28, 0x52, 0x29, 0x20, 0x43, 0x50, 0x55, 0x20, 0x45, 0x35, 0x2D,
	0x32, 0x36, 0x39, 0x30, 0x20, 0x76, 0x34, 0x20, 0x40, 0x20, 0x32, 0x2E,
	0x36, 0x30, 0x47, 0x48, 0x7A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const BYTE vendorDataToWrite[] = {
	0x47, 0x65, 0x6E, 0x75, 0x69, 0x6E,
	0x65, 0x49, 0x6E, 0x74, 0x65, 0x6C, 0x49, 0x6E,
	0x74, 0x65, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00
}; //prefix 0x00, 0x00, 

void Patch(DWORD dwBaseAddress, char* szData, int iSize)
{
	DWORD dwOldProtection = NULL;

	VirtualProtect((LPVOID)dwBaseAddress, iSize, PAGE_EXECUTE_READWRITE, &dwOldProtection);
	CopyMemory((LPVOID)dwBaseAddress, szData, iSize);
	VirtualProtect((LPVOID)dwBaseAddress, iSize, dwOldProtection, NULL);
}

void write_log(const char* format, ...) {
	FILE* log_file = fopen("log.txt", "a");  // Open in append mode
	if (log_file == NULL) {
		perror("Error opening log file");
		return;
	}

	// Handle variable arguments for formatted logging
	va_list args;
	va_start(args, format);
	vfprintf(log_file, format, args);
	va_end(args);

	// Add a newline to separate log entries
	fprintf(log_file, "\n");

	fclose(log_file);  // Close the file
}

typedef BOOL(WINAPI* PIsDebuggerPresent)(VOID);
PIsDebuggerPresent pOrigIsDebuggerPresent = NULL;
BOOL WINAPI MyIsDebuggerPresent()
{
	Sleep(10000000);
	return false;
}

typedef LSTATUS(WINAPI* RegQueryValueExA_t)(
	HKEY hKey,
	LPCSTR lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE lpData,
	LPDWORD lpcbData
	);
RegQueryValueExA_t TrueRegQueryValueExA = nullptr;
LSTATUS WINAPI DetourRegQueryValueExA(
	HKEY hKey,
	LPCSTR lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE lpData,
	LPDWORD lpcbData
) {
	// Log the value name and type
	//write_log2("LPTYPE %d, ValueName %s", lpType ? *lpType : 0, lpValueName);

	// Call the original function first
	LSTATUS result = TrueRegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

	// Check if the queried value is "BIOSReleaseDate" or "SystemBiosDate"
	if ((strcmp(lpValueName, "BIOSReleaseDate") == 0 || strcmp(lpValueName, "SystemBiosDate") == 0) && lpData != NULL && lpcbData != NULL) {
		const char* fakeBiosDate = "10/19/2020";
		size_t fakeBiosDateLen = strlen(fakeBiosDate) + 1; // Include the null terminator

		memcpy(lpData, fakeBiosDate, fakeBiosDateLen);
		*lpcbData = fakeBiosDateLen;
		if (lpType) {
			*lpType = REG_SZ; // Set the type as string (REG_SZ)
		}
		result = ERROR_SUCCESS;

	}

	return result;
}

DWORD mycpuid() {
	OutputDebugStringA("my cpuid function is called");
	return 0;
}

typedef BOOL(WINAPI* DeviceIoControlPtr)(
	HANDLE hDevice,
	DWORD dwIoControlCode,
	LPVOID lpInBuffer,
	DWORD nInBufferSize,
	LPVOID lpOutBuffer,
	DWORD nOutBufferSize,
	LPDWORD lpBytesReturned,
	LPOVERLAPPED lpOverlapped);

DeviceIoControlPtr OriginalDeviceIoControl = nullptr;
BOOL WINAPI MyDeviceIoControl(
	HANDLE hDevice,
	DWORD dwIoControlCode,
	LPVOID lpInBuffer,
	DWORD nInBufferSize,
	LPVOID lpOutBuffer,
	DWORD nOutBufferSize,
	LPDWORD lpBytesReturned,
	LPOVERLAPPED lpOverlapped) {

	BYTE outbuffer[1024];
	BOOL result = OriginalDeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, &outbuffer, sizeof(outbuffer), lpBytesReturned, lpOverlapped);

	if (*lpBytesReturned == 396) {
		STORAGE_DEVICE_DESCRIPTOR* deviceDescriptor = (STORAGE_DEVICE_DESCRIPTOR*)outbuffer;
		if (deviceDescriptor->SerialNumberOffset != 0) {

			deviceDescriptor->Version = 40;
			deviceDescriptor->Size = 396;
			deviceDescriptor->DeviceType = 0;  // Example value
			deviceDescriptor->DeviceTypeModifier = 0;
			deviceDescriptor->RemovableMedia = FALSE;  // No removable media
			deviceDescriptor->CommandQueueing = TRUE;  // Command queueing is enabled
			deviceDescriptor->BusType = BusTypeSata;  // Example bus type (e.g., BusTypeAta)
			deviceDescriptor->RawPropertiesLength = 0;  // No raw properties

			// Assign the Product ID
			const char* productId = "Samsung SSD 870 EVO 500GB";
			size_t productIdOffset = deviceDescriptor->ProductIdOffset;  // Right after the structure
			memcpy(outbuffer + productIdOffset, productId, strlen(productId) + 1);  // Copy with null-terminator
			deviceDescriptor->ProductIdOffset = (DWORD)productIdOffset;  // Set the offset in the structure

			// Assign the Product Revision
			const char* productRevision = "SVT02B6Q";
			size_t productRevisionOffset = deviceDescriptor->ProductRevisionOffset;  // After the Product ID
			memcpy(outbuffer + productRevisionOffset, productRevision, strlen(productRevision) + 1);  // Copy with null-terminator
			deviceDescriptor->ProductRevisionOffset = (DWORD)productRevisionOffset;  // Set the offset in the structure

			// Assign the Serial Number
			const char* serialNumber = "S6P6NL0T810040A";
			size_t serialNumberOffset = deviceDescriptor->SerialNumberOffset;  // After the Product Revision
			memcpy(outbuffer + serialNumberOffset, serialNumber, strlen(serialNumber) + 1);  // Copy with null-terminator
			deviceDescriptor->SerialNumberOffset = (DWORD)serialNumberOffset;  // Set the offset in the structure
		}
		else {
			OutputDebugStringA("No serial number available.");
		}
	}
	memcpy(lpOutBuffer, outbuffer, nOutBufferSize);
	return TRUE;
}
typedef void (*TargetFunctionType)();
TargetFunctionType OriginalFunction = nullptr;

// Hooked function that writes data to memory and then resumes original execution

void __stdcall MyHookedFunction1() {
	// Target memory addresses  0x14e4c6, 0x14e4b0
	void* brandTargetAddress = reinterpret_cast<void*>(GetRdiValue());
	void* vendorTargetAddress = reinterpret_cast<void*>(GetRdiValue() - 0x016);

	// Temporarily change memory protection to allow writing
	DWORD oldProtectBrand, oldProtectVendor;
	VirtualProtect(brandTargetAddress, sizeof(brandDataToWrite), PAGE_EXECUTE_READWRITE, &oldProtectBrand);
	VirtualProtect(vendorTargetAddress, sizeof(vendorDataToWrite), PAGE_EXECUTE_READWRITE, &oldProtectVendor);

	// Write new data directly to target addresses
	memcpy(brandTargetAddress, brandDataToWrite, sizeof(brandDataToWrite));
	memcpy(vendorTargetAddress, vendorDataToWrite, sizeof(vendorDataToWrite));

	// Restore original memory protection
	VirtualProtect(brandTargetAddress, sizeof(brandDataToWrite), oldProtectBrand, &oldProtectBrand);
	VirtualProtect(vendorTargetAddress, sizeof(vendorDataToWrite), oldProtectVendor, &oldProtectVendor);

	// Execute the original instruction
	DWORD64 returnAddress = reinterpret_cast<DWORD64>(OriginalFunction) + 6;
	BYTE originalCode[] = { 0xC7, 0xC2, 0x06, 0x00, 0x00, 0x80 };  // mov edx, 0x80000006
	DWORD oldProtectOriginal;
	VirtualProtect(reinterpret_cast<void*>(OriginalFunction), sizeof(originalCode), PAGE_EXECUTE_READWRITE, &oldProtectOriginal);
	memcpy(reinterpret_cast<void*>(OriginalFunction), originalCode, sizeof(originalCode));
	VirtualProtect(reinterpret_cast<void*>(OriginalFunction), sizeof(originalCode), oldProtectOriginal, &oldProtectOriginal);

	// Jump back to return address
	reinterpret_cast<void(*)()>(returnAddress)();
}

BOOL NewGetLogicalProcessorInformation(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer, PDWORD ReturnedLength)
{
	if (dwVersion1DLL == 0)
	{
		// Set the target address for hooking
		dwVersion1DLL = reinterpret_cast<DWORD64>(GetModuleHandle("version1.dll"));
		if (!dwVersion1DLL) {
			MessageBoxA(NULL, "Failed to get module handle for version1.dll.", "Information", MB_OK | MB_ICONWARNING);
		}

		// Calculate the target address dynamically
		DWORD64 targetAddr = dwVersion1DLL + 0x00006a0a03;

		OriginalFunction = reinterpret_cast<TargetFunctionType>(targetAddr);

		// Begin transaction and attach the hook
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)OriginalFunction, MyHookedFunction1);
		if (DetourTransactionCommit() != NO_ERROR) {
			MessageBoxA(NULL, "Failed to attach hook.", "Information", MB_OK | MB_ICONWARNING);
		}
	}

	BOOL result = GetLogicalProcessorInformation(Buffer, ReturnedLength);
	if (result == TRUE)
	{
		memset(Buffer, 0, *ReturnedLength);
	}
	return result;
}

typedef int (WINAPI* MessageBoxA_t)(
	HWND hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT uType);
MessageBoxA_t TrueMessageBoxA = nullptr;

int WINAPI DetourMessageBoxA(
	HWND hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT uType)
{
	write_log("messageboxa is called");
	//uintptr_t rsp_value = __readrsp();

	// Call the original MessageBoxW function
	return TrueMessageBoxA(hWnd, lpText, "Hooked MessageBoxW", uType);
}

typedef int (WINAPI* MessageBoxW_t)(
	HWND hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT uType);
MessageBoxW_t TrueMessageBoxW = nullptr;
int WINAPI DetourMessageBoxW(
	HWND hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT uType)
{
	write_log("messageboxw is called");
	//uintptr_t rsp_value = __readrsp();

	// Call the original MessageBoxW function
	return TrueMessageBoxW(hWnd, lpText, L"Hooked MessageBoxW", uType);
}

typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
GetProcAddress_t TrueGetProcAddress = nullptr;
FARPROC WINAPI DetourGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	//write_log("%s", lpProcName);
	if (strcmp(lpProcName, "GetLogicalProcessorInformation") == 0) {
		return (FARPROC)NewGetLogicalProcessorInformation;  // Block the API (optional).
	}
	return TrueGetProcAddress(hModule, lpProcName);
}

typedef BOOL(WINAPI* IsProcessorFeaturePresent_t)(DWORD ProcessorFeature);
IsProcessorFeaturePresent_t TrueIsProcessorFeaturePresent = nullptr;

BOOL WINAPI HookedIsProcessorFeaturePresent(DWORD ProcessorFeature) {
	// Add your custom behavior here
	if (ProcessorFeature == PF_VIRT_FIRMWARE_ENABLED) {
		write_log("Hooked: IsProcessorFeaturePresent called with PF_VIRT_FIRMWARE_ENABLED\n");
		return FALSE; // Indicate that the feature is present
	}

	// Call the original function for other cases
	return TrueIsProcessorFeaturePresent(ProcessorFeature);
}

static BOOL InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction)
{
	LoadLibraryA(dll);
	HMODULE module = GetModuleHandleA(dll);
	*originalFunction = (LPVOID)GetProcAddress(module, function);

	if (*originalFunction)
	{
		DetourAttach(originalFunction, hookedFunction);
		return true;
	}

	return false;
}

void Hook(HMODULE hModule)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	Validate(hModule);

	//InstallHook("kernel32.dll", "IsDebuggerPresent", (LPVOID*)& pOrigIsDebuggerPresent, MyIsDebuggerPresent);
	InstallHook("kernel32.dll", "IsProcessorFeaturePresent", (LPVOID*)&TrueIsProcessorFeaturePresent, HookedIsProcessorFeaturePresent);
	InstallHook("kernel32.dll", "GetProcAddress", (LPVOID*)&TrueGetProcAddress, DetourGetProcAddress);
	InstallHook("kernel32.dll", "DeviceIoControl", (LPVOID*)&OriginalDeviceIoControl, MyDeviceIoControl);
	InstallHook("Advapi32.dll", "RegQueryValueExA", (LPVOID*)&TrueRegQueryValueExA, DetourRegQueryValueExA);
	InstallHook("user32.dll", "MessageBoxW", (LPVOID*)&TrueMessageBoxW, DetourMessageBoxW);
	InstallHook("user32.dll", "MessageBoxA", (LPVOID*)&TrueMessageBoxA, DetourMessageBoxA);
	DetourTransactionCommit();
}