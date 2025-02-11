#include "pch.h"
#include <Windows.h>
#include <MinHook.h>
#include <iostream>

#pragma comment(lib, "libs/MinHook.lib")

// Pointer to original GetCommandLineA function
typedef LPSTR(WINAPI* GetCommandLineA_t)(void);
GetCommandLineA_t fpGetCommandLineA = NULL;

// Hex sequence to find: 55 8B EC 81 EC 04
const BYTE pattern[] = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x04 };
const size_t patternSize = sizeof(pattern);

// Patch: mov eax, 1; ret (B8 01 00 00 00 C3)
const BYTE patch[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

void ScanAndPatchMemory() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    BYTE* startAddr = (BYTE*)sysInfo.lpMinimumApplicationAddress;
    BYTE* endAddr = (BYTE*)sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    for (BYTE* addr = startAddr; addr < endAddr; addr += mbi.RegionSize) {
        if (!VirtualQuery(addr, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) {
            continue;
        }

        for (BYTE* scan = (BYTE*)mbi.BaseAddress; scan < (BYTE*)mbi.BaseAddress + mbi.RegionSize - patternSize; scan++) {
            if (memcmp(scan, pattern, patternSize) == 0) {
                // Found the pattern, patch it
                MessageBoxA(NULL, "Patching memory...", "MinHook DLL", MB_OK);
                DWORD oldProtect;
                VirtualProtect(scan, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
                memcpy(scan, patch, sizeof(patch));
                VirtualProtect(scan, sizeof(patch), oldProtect, &oldProtect);
                return;
            }
        }
    }
}

// Hooked function
LPSTR WINAPI HookedGetCommandLineA() {
    static bool firstRun = true;

    if (firstRun) {
        firstRun = false;
        ScanAndPatchMemory();

        // Disable hook after execution
        MH_DisableHook(&GetCommandLineA);
    }

    return fpGetCommandLineA();
}

// Function to set up the hook
void SetupHook() {
    if (MH_Initialize() != MH_OK) return;
    if (MH_CreateHook(&GetCommandLineA, &HookedGetCommandLineA, (LPVOID*)&fpGetCommandLineA) != MH_OK) return;
    if (MH_EnableHook(&GetCommandLineA) != MH_OK) return;
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        SetupHook();
    }
    return TRUE;
}
