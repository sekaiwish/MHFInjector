#include "pch.h"
#include <Windows.h>
#include "include/detours.h"
#include <iostream>
#include <fstream>

#pragma comment(lib, "libs/detours.lib")

// Logging function
void Log(const char* message) {
    std::ofstream logFile("MHFPatcher.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.close();
    }
}

// Original function pointers
typedef char* (WINAPI* GetCommandLineA_t)(void);
typedef ATOM(WINAPI* RegisterClassExA_t)(const WNDCLASSEXA*);

// Function pointers to store original functions
GetCommandLineA_t Original_GetCommandLineA = GetCommandLineA;
RegisterClassExA_t Original_RegisterClassExA = RegisterClassExA;

// Sequences and patches
const BYTE sequence1[] = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x04 };
const BYTE patch1[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 }; // MOV EAX,1 ; RET

const BYTE sequence2[] = { 0xA1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x7F, 0x32 };
const BYTE patch2[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 }; // MOV EAX,1 ; RET

// Patch function 1
bool Patch1() {
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
                    for (SIZE_T i = 0; i < bytesRead - sizeof(sequence1); i++) {
                        if (memcmp(buffer + i, sequence1, sizeof(sequence1)) == 0) {
                            BYTE* patchAddress = startAddress + i;
                            if (patchAddress > (BYTE*)0x10000000) {
                                return false;
                            }

                            DWORD oldProtect;
                            VirtualProtect(patchAddress, sizeof(patch1), PAGE_EXECUTE_READWRITE, &oldProtect);
                            WriteProcessMemory(GetCurrentProcess(), patchAddress, patch1, sizeof(patch1), nullptr);
                            VirtualProtect(patchAddress, sizeof(patch1), oldProtect, &oldProtect);

                            char logMessage[100];
                            sprintf_s(logMessage, "[+] Memory patched at: 0x%p", patchAddress);
                            Log(logMessage);
                            delete[] buffer;
                            return true;
                        }
                    }
                }
                delete[] buffer;
            }
        }
        startAddress += memInfo.RegionSize;
    }

    Log("[-] Target sequence not found!");
	return false;
}

// Patch function 2
bool Patch2() {
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
					for (SIZE_T i = 0; i < bytesRead - sizeof(sequence2); i++) {
                        bool match = true;

                        // Check each byte, allowing wildcards (0x00 means "any byte")
                        for (SIZE_T j = 0; j < sizeof(sequence2); j++) {
                            if (sequence2[j] != 0x00 && buffer[i + j] != sequence2[j]) {
                                match = false;
                                break;
                            }
                        }

                        if (match) {
                            BYTE* patchAddress = startAddress + i;

                            DWORD oldProtect;
                            VirtualProtect(patchAddress, sizeof(patch2), PAGE_EXECUTE_READWRITE, &oldProtect);
                            WriteProcessMemory(GetCurrentProcess(), patchAddress, patch2, sizeof(patch2), nullptr);
                            VirtualProtect(patchAddress, sizeof(patch2), oldProtect, &oldProtect);

                            char logMessage[100];
                            sprintf_s(logMessage, "[+] Memory patched at: 0x%p", patchAddress);
                            Log(logMessage);
                            delete[] buffer;
                            return true;
                        }
					}
				}
				delete[] buffer;
			}
		}
		startAddress += memInfo.RegionSize;
	}
	Log("[-] Target sequence not found!");
	return false;
}

// Hooked GetCommandLineA function
char* WINAPI Hooked_GetCommandLineA() {
	Log("[*] Hooked GetCommandLineA");
    if (Patch1()) {
		DetourTransactionBegin();
        DetourDetach(&(PVOID&)Original_GetCommandLineA, Hooked_GetCommandLineA);
		DetourTransactionCommit();
    }
    return Original_GetCommandLineA();
}

// Hooked RegisterClassExA function
ATOM WINAPI Hooked_RegisterClassExA(const WNDCLASSEXA* lpwcx) {
    Log("[*] Hooked RegisterClassExA");
    if (strcmp(lpwcx->lpszClassName, " M H F ") == 0) {
        Log("[*] Hooked M H F Class");
        if (Patch2()) {
			DetourTransactionBegin();
			DetourDetach(&(PVOID&)Original_RegisterClassExA, Hooked_RegisterClassExA);
			DetourTransactionCommit();
        }
    }
    return Original_RegisterClassExA(lpwcx);
}

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)Original_GetCommandLineA, Hooked_GetCommandLineA);
		DetourAttach(&(PVOID&)Original_RegisterClassExA, Hooked_RegisterClassExA);
        DetourTransactionCommit();
	}
    return TRUE;
}
