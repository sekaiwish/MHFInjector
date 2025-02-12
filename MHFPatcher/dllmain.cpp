#include "pch.h"
#include <Windows.h>
#include <detours.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "libs/detours.lib")

// Logging function
void Log(const char* message) {
    std::ofstream logFile("patcher.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.close();
    }
}

// Original function pointer
typedef char* (WINAPI* GetCommandLineA_t)(void);
GetCommandLineA_t Original_GetCommandLineA = GetCommandLineA;

// The byte sequence we are looking for
const BYTE targetSequence[] = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x04 };
const BYTE patchBytes[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 }; // MOV EAX,1 ; RET

// Function to scan and patch memory
void ScanAndPatch() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    BYTE* startAddress = (BYTE*)sysInfo.lpMinimumApplicationAddress;
    BYTE* endAddress = (BYTE*)sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION memInfo;

    while (startAddress < endAddress) {
        if (VirtualQuery(startAddress, &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
            if (memInfo.State == MEM_COMMIT && (memInfo.Protect & PAGE_EXECUTE_READWRITE || memInfo.Protect & PAGE_EXECUTE_READ)) {
                BYTE* buffer = new BYTE[memInfo.RegionSize];
                SIZE_T bytesRead;

                if (ReadProcessMemory(GetCurrentProcess(), startAddress, buffer, memInfo.RegionSize, &bytesRead)) {
                    for (SIZE_T i = 0; i < bytesRead - sizeof(targetSequence); i++) {
                        if (memcmp(buffer + i, targetSequence, sizeof(targetSequence)) == 0) {
                            BYTE* patchAddress = startAddress + i;
                            if (patchAddress > (BYTE*)0x10000000) {
                                return;
                            }

                            DWORD oldProtect;
                            VirtualProtect(patchAddress, sizeof(patchBytes), PAGE_EXECUTE_READWRITE, &oldProtect);
                            WriteProcessMemory(GetCurrentProcess(), patchAddress, patchBytes, sizeof(patchBytes), nullptr);
                            VirtualProtect(patchAddress, sizeof(patchBytes), oldProtect, &oldProtect);

                            char logMessage[100];
                            sprintf_s(logMessage, "[+] Memory patched at: 0x%p", patchAddress);
                            Log(logMessage);
                            delete[] buffer;
                            return;
                        }
                    }
                }
                delete[] buffer;
            }
        }
        startAddress += memInfo.RegionSize;
    }

    Log("[-] Target sequence not found!");
}

// Hooked GetCommandLineA function
char* WINAPI Hooked_GetCommandLineA() {
	Log("[*] Hooked GetCommandLineA! Scanning for patch...");
	ScanAndPatch();
    return Original_GetCommandLineA();
}

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)Original_GetCommandLineA, Hooked_GetCommandLineA);
        DetourTransactionCommit();
	}
    return TRUE;
}
