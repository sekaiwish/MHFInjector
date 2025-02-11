#include <Windows.h>
#include <iostream>

void InjectDLL(HANDLE hProcess, const char* dllPath) {
    // Allocate memory in the target process for the DLL path
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cout << "Failed to allocate memory in target process\n";
        return;
    }

    // Write the DLL path into the allocated memory
    WriteProcessMemory(hProcess, remoteMem, dllPath, strlen(dllPath) + 1, NULL);

    // Get LoadLibraryA function address
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // Create a remote thread to call LoadLibraryA(dllPath)
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remoteMem, 0, NULL);
    if (!hThread) {
        std::cout << "Failed to create remote thread\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return;
    }

    // Wait for the DLL to be loaded
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
}

void LaunchAndInject(const std::wstring& exePath, const std::string& dllPath) {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Start the process in a suspended state
    if (!CreateProcess(exePath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cout << "Error creating process: " << GetLastError() << std::endl;
        return;
    }

    // Inject the DLL
    InjectDLL(pi.hProcess, dllPath.c_str());

    // Resume the process after injection
    ResumeThread(pi.hThread);

    // Close process handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int main() {
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

    // Convert targetExePath to a wide string for CreateProcess.
    std::wstring wTargetExePath(targetExePath.begin(), targetExePath.end());

    LaunchAndInject(wTargetExePath, dllPath);

    return 0;
}
