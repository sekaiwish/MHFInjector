#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ShlObj.h>

const std::string HOSTS_FILE = R"(C:\Windows\System32\drivers\etc\hosts)";
const std::string COMMENT_TAG = "# Added by MHFInjector";
const std::vector<std::string> HOSTS_ENTRIES = {
    "155.248.202.187 srv-mhf.capcom-networks.jp",
    "155.248.202.187 cog-members.mhf-g.jp cog-members.mhf-z.jp"
};

bool EntryExists(const std::string& file, const std::string& entry) {
    std::ifstream in(file);
    std::string line;
    while (std::getline(in, line)) {
        if (line.find(entry) != std::string::npos) return true;
    }
    return false;
}

void AddEntries() {
    std::ofstream out(HOSTS_FILE, std::ios::app);
    if (!EntryExists(HOSTS_FILE, HOSTS_ENTRIES[0])) {
        out << "\n" << COMMENT_TAG << "\n";
        for (const auto& entry : HOSTS_ENTRIES) out << entry << "\n";
		std::cout << "Hosts file entries added!\n";
    }
}

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

int main(int argc, char* argv[]) {
    BOOL isAdmin = IsUserAnAdmin();
    if (!isAdmin) {
        std::cerr << "MHFInjector must be run as an administrator.\n";
        return 1;
    }

	// Add entries to hosts file
	AddEntries();

    char exePath[MAX_PATH];
    char dllPath[MAX_PATH];

    // Get the directory of the current executable
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string directory = std::string(exePath).substr(0, std::string(exePath).find_last_of("\\/"));

    // Construct full paths
    std::string exeFullPath = directory + "\\mhf.exe";
    std::string dllFullPath = directory + "\\MHFPatcher.dll";

    // Check command-line arguments for -exe
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "-exe" && i + 1 < argc) {
            exeFullPath = argv[i + 1];
            break;
        }
    }

	// Check command-line arguments for -dll
	for (int i = 1; i < argc; i++) {
		if (std::string(argv[i]) == "-dll" && i + 1 < argc) {
			dllFullPath = argv[i + 1];
			break;
		}
	}

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
