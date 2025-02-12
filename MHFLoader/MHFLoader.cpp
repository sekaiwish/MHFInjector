#include <Windows.h>
#include <iostream>

void InjectDLL(HANDLE hProcess, const char* dllPath) {
    void* allocMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (allocMem == NULL) {
		std::cout << "Failed to allocate memory in target process!\n";
		return;
	}
    WriteProcessMemory(hProcess, allocMem, dllPath, strlen(dllPath) + 1, NULL);

	HMODULE hModule = GetModuleHandleA("kernel32.dll");
	if (hModule == NULL) {
		std::cout << "Failed to get handle to kernel32.dll!\n";
		return;
	}

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryA"),
        allocMem, 0, NULL);
	if (hThread == NULL) {
		std::cout << "Failed to create remote thread!\n";
		return;
	}

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
}

int main() {
    char exePath[MAX_PATH];
    char dllPath[MAX_PATH];

    // Get the directory of the current executable
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string directory = std::string(exePath).substr(0, std::string(exePath).find_last_of("\\/"));

    // Construct full paths
    std::string exeFullPath = directory + "\\mhf.exe";
    std::string dllFullPath = directory + "\\MHFPatcher.dll";

    // Convert to C-style strings
    strcpy_s(exePath, exeFullPath.c_str());
    strcpy_s(dllPath, dllFullPath.c_str());

    // Optional: Print the paths for debugging.
    std::cout << "EXE: " << exePath << std::endl;
    std::cout << "DLL: " << dllPath << std::endl;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessA(NULL, (LPSTR)exePath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        InjectDLL(pi.hProcess, dllPath);
        ResumeThread(pi.hThread);
        std::cout << "Process started and DLL injected!\n";
    }
    else {
        std::cout << "Failed to start process!\n";
    }

    return 0;
}
