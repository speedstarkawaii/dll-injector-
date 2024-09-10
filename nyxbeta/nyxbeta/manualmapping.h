#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <tlhelp32.h>

std::vector<char> ReadDllFile(const std::string& dllPath) {
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (file.read(buffer.data(), size)) {
        return buffer;
    }
    else {
        throw std::runtime_error("Failed to read DLL file.");
    }
}

bool ManualMapWithoutCRT(DWORD processID, const std::string& dllPath) {
    std::vector<char> dllData = ReadDllFile(dllPath);

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllData.data());
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(dllData.data() + dosHeader->e_lfanew);

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Allocate memory in the target process for the DLL
    LPVOID pTargetBaseAddr = VirtualAllocEx(hProcess, nullptr, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBaseAddr) {
        std::cerr << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write headers to the target process
    if (!WriteProcessMemory(hProcess, pTargetBaseAddr, dllData.data(), ntHeaders->OptionalHeader.SizeOfHeaders, nullptr)) {
        std::cerr << "Failed to write headers. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pTargetBaseAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Write sections to the target process
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        if (!WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)pTargetBaseAddr + sectionHeader[i].VirtualAddress), dllData.data() + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData, nullptr)) {
            std::cerr << "Failed to write section " << sectionHeader[i].Name << ". Error: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pTargetBaseAddr, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
    }

    // Get the context of the main thread
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pTargetBaseAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    DWORD mainThreadID = 0;
    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processID) {
                mainThreadID = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    CloseHandle(hThreadSnap);

    if (!mainThreadID) {
        std::cerr << "Failed to find the main thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pTargetBaseAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, mainThreadID);
    if (!hThread) {
        std::cerr << "Failed to open thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pTargetBaseAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        std::cerr << "Failed to get thread context. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pTargetBaseAddr, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Save the original entry point
    LPVOID pEntryPoint = (LPVOID)((uintptr_t)pTargetBaseAddr + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    // Write the entry point to the target process's EIP/RIP
#ifdef _WIN64
    ctx.Rip = (DWORD64)pEntryPoint;
#else
    ctx.Eip = (DWORD)pEntryPoint;
#endif

    if (!SetThreadContext(hThread, &ctx)) {
        std::cerr << "Failed to set thread context. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pTargetBaseAddr, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Resume the thread
    if (ResumeThread(hThread) == -1) {
        std::cerr << "Failed to resume thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pTargetBaseAddr, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

int inject(DWORD processID, std::string dllPath) {


    if (ManualMapWithoutCRT(processID, dllPath)) {
        MessageBoxA(0, "good!", 0, 0);
        //std::cout << "DLL injected successfully." << std::endl;
    }
    else {
        MessageBoxA(0, "uhh!", 0, 0);
        //std::cerr << "Failed to inject DLL." << std::endl;
    }

    return 0;
}
