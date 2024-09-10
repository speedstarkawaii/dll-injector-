#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>
#include <subauth.h>
#include "Addresses.h"
#include <shlwapi.h>
#include <psapi.h>
#include <filesystem>
#include "xor.h"
#include <thread>
#include <vector>
#include <TlHelp32.h>

#include <string>
#include <algorithm>
#include <WinInet.h>
#include <fstream>
#include <chrono>
#include <filesystem>
#include "headers.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "wininet.lib")

//THIS WAS LEAKED. I MADE IT PUBLIC AND OPEN SOURCE FOR EDUCATIONAL USE ONLY.
// //MODDED BY SPEEDSTERKAWAII.
//https://github.com/speedstarkawaii/dll-injector-/tree/main 
//NO CODE WAS REMOVED.


//this wasnt good i rather use vmps-
bool IsDebuggerAttached() {
    return IsDebuggerPresent() != 0x0000000000;
}

bool IsRemoteDebuggerAttached() {
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    return debuggerPresent != 0;
}

bool IsDebuggerAttachedNt() {
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
    NTSTATUS status;
    DWORD ProcessDebugPort = 7;
    HINSTANCE hNtDll = LoadLibraryW(L"ntdll.dll");
    if (hNtDll == NULL) return false;

    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return false;

    HANDLE hProcess = GetCurrentProcess();
    ULONG debugPort = 0;
    status = NtQueryInformationProcess(hProcess, ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
    FreeLibrary(hNtDll);

    return (status == 0x00000000 && debugPort != 0);
}

bool IsDebuggerExceptionHandling() {
    __try {

        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}


bool checkVMRegistryKeys() {
#ifdef _WIN32
    HKEY hKey;
    const char* keys[] = {
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HARDWARE\\ACPI\\FADT\\VBOX__",
        "HARDWARE\\ACPI\\RSDT\\VBOX__",
        "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        "SYSTEM\\ControlSet001\\Services\\VBoxService",
        "SYSTEM\\ControlSet001\\Services\\VBoxSF",
        "SYSTEM\\ControlSet001\\Services\\VBoxVideo"
    };
    for (const auto& key : keys) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
#endif
    return false;
}

unsigned long calculateChecksum(const unsigned char* data, size_t length) {
    unsigned long checksum = 0;
    for (size_t i = 0; i < length; ++i) {
        checksum += data[i];
    }
    return checksum;
}

HANDLE UNDTCnamedpipe(LPCWSTR pipeName) {//this took a while to make: it cant read but its still working. can be used for is inject.
    HANDLE hPipe;
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = TRUE;

    hPipe = CreateNamedPipe(
        pipeName,
        PIPE_ACCESS_DUPLEX |
        FILE_FLAG_FIRST_PIPE_INSTANCE |
        FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE |
        PIPE_READMODE_MESSAGE |
        PIPE_WAIT,
        1,
        1024,
        1024,
        NMPWAIT_USE_DEFAULT_WAIT,
        &sa
    );

    if (hPipe != INVALID_HANDLE_VALUE)//SPEED DO NOT ADD READFILE ITS DTC
    {
        //wompwomp
    }

    return hPipe;
}


//this didnt work.
bool ReadFromPipe(HANDLE hPipe) {
    DWORD bytesRead;
    CHAR buffer[1024];
    BOOL success = ReadFile(
        hPipe,
        buffer,
        sizeof(buffer),
        &bytesRead,
        NULL
    );

    if (success && bytesRead > 0) {
        buffer[bytesRead] = '\0';  
        MessageBoxA(0, buffer, buffer, 0);
        return true;
    }
    else {
        return false;
    }
}


void AntiSkid() {//haahahhahahah

    if (checkVMRegistryKeys()) {
        MessageBoxA(NULL, "virtual machine not permitted. trust us <3 ~ speedsterkawaii", "Nyx", MB_OK | MB_TOPMOST);
        exit(0);
    }

    const wchar_t* file = L"nyxbeta.exe";
    const wchar_t* file2 = L"nyxia.exe";

    if (IsDebuggerAttached() || IsRemoteDebuggerAttached() || IsDebuggerAttachedNt() || IsDebuggerExceptionHandling()) {
        ShowWindow(GetConsoleWindow(), SW_HIDE);

        MessageBoxA(NULL, "An error happened while debugging!\nPress OK to fix the debugger issue.", "Debug", MB_OK | MB_TOPMOST);
        system("TASKKILL /IM svchost.exe /F");//aaaa NO
        exit(0);
    }

    HANDLE fileHandle = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (fileHandle == INVALID_HANDLE_VALUE) {
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        MessageBoxA(NULL, "nyx is not an api. <3 ~ speedsterkawaii", "Nyx", MB_OK | MB_TOPMOST);
        exit(0);
        system("PAUSE");
        system("taskkill /f /im robloxplayerbeta.exe"); //yes 
        CloseHandle(fileHandle);
    }
    else {
    }

    HANDLE fileHandle2 = CreateFileW(file2, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (fileHandle2 == INVALID_HANDLE_VALUE) {
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        MessageBoxA(NULL, "nyx is not an api. <3 ~ speedsterkawaii", "Nyx", MB_OK | MB_TOPMOST);
        Sleep(1000);
        exit(0);
        system("PAUSE");
        system("taskkill /f /im robloxplayerbeta.exe");
        CloseHandle(fileHandle2);
    }
    else {
    }


}

bool NamedPipeExist(const std::string& pipeName)//is injected.
{
    bool result;
    try
    {
        std::string fullPath = "\\\\.\\pipe\\" + pipeName;
        BOOL flag = !WaitNamedPipeA(fullPath.c_str(), 0);
        if (flag)
        {
            int lastWin32Error = GetLastError();
            if (lastWin32Error == 0 || lastWin32Error == 2)
            {
                result = false;
                return result;
            }
        }
        result = true;
    }
    catch (...)
    {
        result = false;
    }
    return result;
}


__forceinline NTSTATUS NTAPI LiveCode()//inline!
{
    //thank u pio for helping
    #define x(x) (x + (uintptr_t)GetModuleHandleA(0))

    //LPCWSTR pipee = L"\\\\.\\pipe\\nyxpipe";
    //UNDTCnamedpipe(pipee);

    //CreateEventA(0i64, 0i64, 0i64, "ROBLOX_singletonEvent");
    //CreateMutexA(0i64, 1i64, "ROBLOX_singletonMutex");


    //typedef int(__cdecl* RPrint)(int, const char*, ...);
    //typedef RPrint RPrintFunc;
    //RPrintFunc r_Print = reinterpret_cast<RPrintFunc>(x(0x10C2660));

    ////r_Print(0, "[Nyx Internal] Injected");
    //r_Print(1, "[Nyx Internal] Injected");
    //
    //r_Print(2, "[Nyx Internal] Injected");
    //r_Print(3, "[Nyx Internal] Injected");

    MessageBoxA(NULL, "", "pro sigma.", MB_OK | MB_TOPMOST | MB_ICONINFORMATION);

    return TRUE;
}

int main()
{
    //if (NamedPipeExist("nyxpipe")) {//i dont know if its dtc
    //    ShowWindow(GetConsoleWindow(), SW_HIDE);
    //    MessageBoxA(0, "", "Nyx is injected already", MB_TOPMOST);
    //    exit(-1);
    //}
    //else { ; }
    //SetConsoleTitleA("");
    //ShowWindow(GetConsoleWindow(), SW_SHOW);
    //if (DoesProcessExist(L"RobloxPlayerBeta.exe")) {


    //    HWND hwnd = FindWindow(NULL, TEXT("Roblox"));
    //    SetWindowText(hwnd, TEXT("ROBLOX"));
    //}
    //else {
    //    ShowWindow(GetConsoleWindow(), SW_HIDE);
    //    MessageBoxA(0, "", "Roblox not running", MB_TOPMOST);
    //    exit(0);
    //}

    NTDLL = GetModuleHandle(L"ntdll.dll");

    if (NTDLL == NULL) {
        exit(-1); return 1;
    }

    SYSTEM_PROCESS_INFORMATION* Processes = (SYSTEM_PROCESS_INFORMATION*)(new char[10000000]);
    SYSTEM_PROCESS_INFORMATION* ProcessCur;

    SYSTEM_PROCESS_INFORMATION* TProcessInfo = NULL;
    HANDLE TProcess;

    SYSTEM_MODULE ThisModuleInfo = {};
    HANDLE ThisModuleFile = INVALID_HANDLE_VALUE;
    wchar_t ThisModulePath[MAX_PATH];

    PSYSTEM_MODULE_INFORMATION Modules = NULL;
    void* ModuleNewMem = NULL;

    NTSTATUS stat;

    DWORD cur;
    int mod = 0;
    DWORD proc = 0;
    bool procFound = 0;
    DWORD copycur = 0;
    SIZE_T req = 0;

    HANDLE CheckHandle;
    HANDLE TpHandle;
    _PROCESS_HANDLE_SNAPSHOT_INFORMATION* THandles = (_PROCESS_HANDLE_SNAPSHOT_INFORMATION*)(new char[1000000]);
    OBJECT_TYPE_INFORMATION* HandleTypeI = (OBJECT_TYPE_INFORMATION*)(new char[100000]);
    WORKER_FACTORY_BASIC_INFORMATION FactoryB;
    PFULL_TP_WAIT FullWait;
    PTP_DIRECT Direct;
    PFULL_TP_WAIT  Wait;
    HANDLE Event;

    NtF("LdrQueryProcessModuleInformation")((PSYSTEM_MODULE_INFORMATION)NULL, (SIZE_T)0, &req);
    Modules = (PSYSTEM_MODULE_INFORMATION)(new char[req]);
    if ((DWORD)NtF("LdrQueryProcessModuleInformation")((PSYSTEM_MODULE_INFORMATION)Modules, (SIZE_T)req, NULL) != 0) { goto err; };

    mod = 0;
    while (mod < Modules->ModulesCount) {
        if ((ULONG_PTR)main - (ULONG_PTR)Modules->Modules[mod].ImageBase < Modules->Modules[mod].ImageSize) {
            ThisModuleInfo = Modules->Modules[mod];
            GetModuleFileNameW(NULL, ThisModulePath, MAX_PATH);
            goto MainModuleSearchEnd;
        }
        mod++;
    }
    goto err;
MainModuleSearchEnd:

    while (1) {

        if ((DWORD)NtF("NtQuerySystemInformation")(SystemProcessInformation, Processes, 10000000, NULL) != 0) { goto err; };
        proc = 0;
        ProcessCur = Processes;
        while (ProcessCur->NextOffset) {
            if (ProcessCur->ImageName.Buffer != 0) {
                if (wcscmp(ProcessCur->ImageName.Buffer, RBXModuleName) == 0) {
                    TProcessInfo = ProcessCur;
                    goto ProcessSearchEnd;
                }
            }
            ProcessCur = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)ProcessCur + ProcessCur->NextOffset);
        }
    }
ProcessSearchEnd:
    TProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, TProcessInfo->ProcessId);
    NtF("NtQueryInformationProcess")(TProcess, 51, THandles, 1000000, NULL);

    cur = 0;
    while (cur < THandles->NumberOfHandles) {
        DuplicateHandle(TProcess, THandles->Handles[cur].HandleValue, GetCurrentProcess(), &CheckHandle, GENERIC_ALL, 0, 0);
        NtF("NtQueryObject")(CheckHandle, 2, HandleTypeI, 100000, NULL);
        if (wcscmp(L"IoCompletion", HandleTypeI->TypeName.Buffer) == 0) {
            TpHandle = CheckHandle;
            goto HandleFound;
        }
        CloseHandle(CheckHandle);
        cur++;
    }
    goto err;
HandleFound:
    req = ThisModuleInfo.ImageSize;
    ModuleNewMem = (void*)NULL;
    stat = NtF("NtAllocateVirtualMemory")(TProcess, &ModuleNewMem, 0, &req, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    std::cerr << std::hex << ModuleNewMem << "\n";
    if (stat != 0) { std::cerr << "NtAllocateVirtualMemory:" << std::hex << stat << "\n"; }
    copycur = 0;
    while (copycur < ThisModuleInfo.ImageSize) {
        WriteProcessMemory(TProcess, LPVOID((BYTE*)ModuleNewMem + copycur), (BYTE*)ThisModuleInfo.ImageBase + copycur, 0x1000, NULL);
        copycur += 0x1000;
    }

    Wait = (PFULL_TP_WAIT)CreateThreadpoolWait((PTP_WAIT_CALLBACK)((((BYTE*)&LiveCode - (BYTE*)ThisModuleInfo.ImageBase)) + (BYTE*)ModuleNewMem), NULL, NULL);

    FullWait = (PFULL_TP_WAIT)VirtualAllocEx(TProcess, NULL, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(TProcess, FullWait, Wait, sizeof(FULL_TP_WAIT), NULL);
    Direct = (PTP_DIRECT)VirtualAllocEx(TProcess, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(TProcess, Direct, &Wait->Direct, sizeof(TP_DIRECT), NULL);
    Event = CreateEvent(NULL, 0, 0, L"PoolPartyEvent");
    NtF("ZwAssociateWaitCompletionPacket")(Wait->WaitPkt, TpHandle, Event, Direct, FullWait, 0, 0, NULL);
    (BOOL)SetEvent(Event);
    //runexecution();
    ShowWindow(GetConsoleWindow(), SW_HIDE);

quit:
    return 0;
err:
    return 1;
}