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
    /*
    // Get the full path to the loader executable.
    char modulePath[MAX_PATH];
    GetModuleFileNameA(NULL, modulePath, MAX_PATH);
    std::string fullPath(modulePath);

    // Extract the folder from the full path.
    size_t pos = fullPath.find_last_of("\\/");
    std::string folderPath = (pos != std::string::npos) ? fullPath.substr(0, pos + 1) : "";

    // Build full paths for mhf.exe and MHFPatcher.dll located in the same directory.
    std::string targetExePath = folderPath + "mhf.exe";
    std::string dllPath = folderPath + "MHFPatcher.dll";

    // Optional: Print the paths for debugging.
    std::cout << "Target EXE: " << targetExePath << std::endl;
    std::cout << "DLL: " << dllPath << std::endl;
    */
    const char* exePath = "F:\\Games\\Monster Hunter Frontier\\Monster Hunter Frontier Z Zenith\\mhf.exe";
    const char* dllPath = "C:\\Users\\wish\\source\\repos\\GGB\\Release\\MHFPatcher.dll";

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
