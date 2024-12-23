#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
//#include <LM.h>

extern HMODULE netapi32_dll;
DWORD WINAPI Load(LPVOID lpParam);