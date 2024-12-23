#include "version.h"
#include <filesystem>

HMODULE real_version_dll;
HMODULE version_dll;

#define WRAPPER_FUNC(name) o##name = GetProcAddress(real_version_dll, ###name)

#ifdef _M_AMD64
#pragma warning (disable: 4081)
#define STRINGIFY(name) #name
#define EXPORT_FUNCTION comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
#define WRAPPER_GENFUNC(name) \
    FARPROC o##name; \
    __declspec(dllexport) void WINAPI _##name() \
    { \
        __pragma(STRINGIFY(EXPORT_FUNCTION)); \
        o##name(); \
    }
#else
#define WRAPPER_GENFUNC(name) \
	FARPROC o##name; \
	__declspec(naked) void _##name() \
	{ \
		__asm jmp[o##name] \
	}
#endif

WRAPPER_GENFUNC(GetFileVersionInfoA);
WRAPPER_GENFUNC(GetFileVersionInfoByHandle);
WRAPPER_GENFUNC(GetFileVersionInfoExW);
WRAPPER_GENFUNC(GetFileVersionInfoExA);
WRAPPER_GENFUNC(GetFileVersionInfoSizeA);
WRAPPER_GENFUNC(GetFileVersionInfoSizeExA);
WRAPPER_GENFUNC(GetFileVersionInfoSizeExW);
//WRAPPER_GENFUNC(GetFileVersionInfoSizeW);
WRAPPER_GENFUNC(GetFileVersionInfoW);
WRAPPER_GENFUNC(VerFindFileA);
WRAPPER_GENFUNC(VerFindFileW);
WRAPPER_GENFUNC(VerInstallFileA);
WRAPPER_GENFUNC(VerInstallFileW);
WRAPPER_GENFUNC(VerLanguageNameA);
WRAPPER_GENFUNC(VerLanguageNameW);
WRAPPER_GENFUNC(VerQueryValueA);
WRAPPER_GENFUNC(VerQueryValueW);

WRAPPER_GENFUNC(VerQueryValueIndexA);
WRAPPER_GENFUNC(VerQueryValueIndexW);
WRAPPER_GENFUNC(dbkFCallWrapperAddr);
WRAPPER_GENFUNC(__dbk_fcall_wrapper);
WRAPPER_GENFUNC(TMethodImplmentationIntercept);

FARPROC oGetFileVersionInfoSizeW;
__declspec(dllexport) DWORD WINAPI _GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{ 
	DWORD(WINAPI * pGetFileVersionInfoSizeW)(LPCWSTR, LPDWORD) = reinterpret_cast<DWORD(WINAPI*)(LPCWSTR, LPDWORD)>(oGetFileVersionInfoSizeW);
	DWORD result = pGetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);
	return result;
}

char* GetExecutableDirectory()
{
	// Buffer to hold the full path
	char path[MAX_PATH];

	// Get the full path of the executable
	DWORD result = GetModuleFileNameA(NULL, path, sizeof(path));

	if (result > 0 && result < sizeof(path))
	{
		// Find the last backslash in the path
		char* lastSlash = strrchr(path, '\\');
		if (lastSlash != NULL)
		{
			// Terminate the string at the last backslash
			*lastSlash = '\0';
			// Allocate memory for the directory path
			char* directoryPath = (char*)malloc(strlen(path) + 1);
			if (directoryPath != NULL)
			{
				strcpy(directoryPath, path);
				return directoryPath; // Return the directory path
			}
		}
	}

	// Handle error (return NULL if unable to retrieve the path)
	return NULL;
}

void load_version() {
	char systemPath[MAX_PATH];
	GetSystemDirectoryA(systemPath, MAX_PATH);
	strcat_s(systemPath, "\\version.dll");
	real_version_dll = LoadLibraryA(systemPath);

	if (!real_version_dll) return;
	
	WRAPPER_FUNC(GetFileVersionInfoA);
	WRAPPER_FUNC(GetFileVersionInfoByHandle);
	WRAPPER_FUNC(GetFileVersionInfoExW);
	WRAPPER_FUNC(GetFileVersionInfoExA);
	WRAPPER_FUNC(GetFileVersionInfoSizeA);
	WRAPPER_FUNC(GetFileVersionInfoSizeExW);
	WRAPPER_FUNC(GetFileVersionInfoSizeExA);
	//WRAPPER_FUNC(GetFileVersionInfoSizeW);
	WRAPPER_FUNC(GetFileVersionInfoW);
	WRAPPER_FUNC(VerFindFileA);
	WRAPPER_FUNC(VerFindFileW);
	WRAPPER_FUNC(VerInstallFileA);
	WRAPPER_FUNC(VerInstallFileW);
	WRAPPER_FUNC(VerLanguageNameA);
	WRAPPER_FUNC(VerLanguageNameW);
	WRAPPER_FUNC(VerQueryValueA);
	WRAPPER_FUNC(VerQueryValueW);

	WRAPPER_FUNC(VerQueryValueIndexA);
	WRAPPER_FUNC(VerQueryValueIndexW);
	WRAPPER_FUNC(dbkFCallWrapperAddr);
	WRAPPER_FUNC(__dbk_fcall_wrapper);
	WRAPPER_FUNC(TMethodImplmentationIntercept);
	WRAPPER_FUNC(GetFileVersionInfoSizeW);

	char path[MAX_PATH] = { 0 };
	char* directory = GetExecutableDirectory();
	strcpy(path, directory);
	strcat_s(path, "\\version1.dll");
	version_dll = LoadLibraryA(path);
}

DWORD WINAPI Load(LPVOID lpParam) {
	load_version();
	if (!version_dll)
		return 0;

#ifdef _DEBUG
	MessageBox(NULL, L"It's working!", L"version proxy", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
#endif

	// your payload goes here

	return 0;
}
