#include "version.h"
#include "..\Hook.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
		Hook();
		Load(NULL);
        //CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Load, hModule, NULL, NULL);
        break;
    case DLL_PROCESS_DETACH:
        FreeLibrary(version_dll);
        break;
    }
    return TRUE;
}
