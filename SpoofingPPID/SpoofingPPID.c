#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

int main() {

    CHAR    lpPath[MAX_PATH * 2];
    CHAR    WnDr[MAX_PATH];

    SIZE_T                      sThreadAttList = NULL;
    PPROC_THREAD_ATTRIBUTE_LIST pThreadAttList = NULL;

    STARTUPINFOEXA      SiEx = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    DWORD   targetPid = 3440;  // replace with your explorer.exe pid
    HANDLE  hParent = NULL;

    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (hParent == NULL) {
        printf("[!] OpenProcess failed: %d\n", GetLastError());
        return -1;
    }

    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        printf("[!] GetEnvironmentVariableA failed: %d\n", GetLastError());
        return -1;
    }
    snprintf(lpPath, sizeof(lpPath), "%s\\System32\\%s", WnDr, "notepad.exe");

    InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);

    pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList
    );
    if (pThreadAttList == NULL) {
        printf("[!] HeapAlloc failed: %d\n", GetLastError());
        return -1;
    }

    if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
        printf("[!] InitializeProcThreadAttributeList failed: %d\n", GetLastError());
        return -1;
    }

    if (!UpdateProcThreadAttribute(
        pThreadAttList, NULL,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent, sizeof(HANDLE),
        NULL, NULL)) {
        printf("[!] UpdateProcThreadAttribute failed: %d\n", GetLastError());
        return -1;
    }

    SiEx.lpAttributeList = pThreadAttList;

    if (!CreateProcessA(
        NULL, lpPath,
        NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL,
        &SiEx.StartupInfo, &Pi)) {
        printf("[!] CreateProcessA failed: %d\n", GetLastError());
        return -1;
    }

    printf("[+] Process spawned! PID: %d\n", Pi.dwProcessId);

    DeleteProcThreadAttributeList(pThreadAttList);
    CloseHandle(hParent);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);

    return 0;
}