/*
 * Title:  get system call number that functions of ntdll.dll call (Windows)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <windows.h>

#include "struct.h"
#include "main.h"

int optstringIndex = 0;
char *optarg = NULL;


HMODULE myGetModuleHandleW(wchar_t * lpModuleName)
{
	PPEB64 pPEB = (PPEB64)__readgsqword(0x60);
	
	if(lpModuleName == NULL){
		return (HMODULE)(pPEB->ImageBaseAddress);
	}
	
	PPEB_LDR_DATA Ldr = pPEB->Ldr;
	PLIST_ENTRY ModuleList = &Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY pStartListEntry = ModuleList->Flink;
	
	for(PLIST_ENTRY pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink){
		PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pListEntry - sizeof(LIST_ENTRY));
		
		if(_wcsicmp((wchar_t *)pLdrDataTableEntry->BaseDllName.Buffer, lpModuleName) == 0){	
			return (HMODULE)pLdrDataTableEntry->DllBase;
		}
	}
	
	return NULL;
}


DWORD rvaToRaw(PIMAGE_SECTION_HEADER pSectionHeader, WORD numberOfSections, DWORD rva)
{
	DWORD raw = 0;
	
	for(WORD i=0; i<numberOfSections; i++){
		if(rva >= pSectionHeader[i].VirtualAddress && rva <= pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize){
			return rva - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
		}
	}
	
	return 0;	
}


int getopt(int argc, char **argv, char *optstring)
{

	unsigned char opt = '\0';
	unsigned char next = '\0';
	char *argtmp = NULL;

	while(1){
		opt = *(optstring + optstringIndex);
		optstringIndex++;
		if(opt == '\0'){
			break;
		}
	
		next = *(optstring + optstringIndex);
		if(next == ':'){
			optstringIndex++;
		}
	
		for(int i=1; i<argc; i++){
			argtmp = argv[i];
			if(argtmp[0] == '-'){
				if(argtmp[1] == opt){
					if(next == ':'){
						optarg = argv[i+1];
						return (int)opt;
					}else{
						return (int)opt;
					}
				}
			}
		}
	}

	return 0;
}


void usage(char *filename)
{
	printf("usage        : %s [-f (read data from C:\\windows\\system32\\ntdll.dll)] [-h (help)]\n", filename);
	printf("example      : %s\n", filename);
	printf("             : %s -f\n", filename);
}


int main(int argc, char** argv)
{
	int opt;
	char optstring[] = "fh";
	int fileFlag = 0;
	
	while((opt=getopt(argc, argv, optstring)) > 0){
		switch(opt){
		case 'f':
			fileFlag = 1;
			break;
			
		case 'h':
			usage(argv[0]);
			exit(1);
			
		default:
			usage(argv[0]);
			exit(1);
		}
	}
	
	HANDLE hNtdll = NULL;
	DWORD fileSize = 0;
	LPVOID pBuffer = NULL;
	wchar_t strNtdll[] = L"NTDLL.DLL";
	PBYTE pNtdllImageBase = NULL;
	
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	WORD numberOfSections = 0;
	
	DWORD ordinalBase = 0;
	DWORD numberOfFunctions = 0;
	DWORD numberOfNames = 0;
	DWORD d = 0;
	PDWORD pAddressOfFunctions = NULL;
	PDWORD pAddressOfNames = NULL;
	PWORD pAddressOfNameOrdinals = NULL;
	PCHAR pFunctionName = NULL;
	PBYTE pFunctionAddress = NULL;
	WORD ordinal = 0;
	WORD systemCallNumber = 0;
	
	
	if(fileFlag == 1){	// from file
		printf("[I] Read data from C:\\windows\\system32\\ntdll.dll\n");
		
		hNtdll = CreateFileA("C:\\windows\\system32\\ntdll.dll", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
		if(hNtdll == NULL){
#ifdef _DEBUG
			printf("[E] CreateFileA error\n");
#endif
			return -1;
		}
		
		fileSize = GetFileSize(hNtdll, NULL);
		pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
		ReadFile(hNtdll, pBuffer, fileSize, NULL, NULL);
		pNtdllImageBase = (PBYTE)pBuffer;
		
		pDosHeader = (PIMAGE_DOS_HEADER)pNtdllImageBase;
		if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
#ifdef _DEBUG
			printf("[E] Invalid dos format\n");
#endif
			return -1;
		}
		
		pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
		if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE){
#ifdef _DEBUG
			printf("[E] Invalid pe format\n");
#endif
			return -1;
		}
		
		pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;
		if(!(pFileHeader->Characteristics & IMAGE_FILE_DLL)){
#ifdef _DEBUG
			printf("[E] Invalid dll data\n");
#endif
			return -1;
		}
		
		pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&pNtHeaders->OptionalHeader;
		
		pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
		numberOfSections = pFileHeader->NumberOfSections;
				
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDosHeader + rvaToRaw(pSectionHeader, numberOfSections, pOptionalHeader->DataDirectory[0].VirtualAddress));
		
		ordinalBase = (DWORD)pExportDirectory->Base;
		numberOfFunctions = (DWORD)pExportDirectory->NumberOfFunctions;
		numberOfNames = (DWORD)pExportDirectory->NumberOfNames;
		d = numberOfFunctions - numberOfNames;
		if(d < 0){
			d = 0;
		}
		
		pAddressOfFunctions = (PDWORD)((PBYTE)pNtdllImageBase + rvaToRaw(pSectionHeader, numberOfSections, pExportDirectory->AddressOfFunctions));
		pAddressOfNames = (PDWORD)((PBYTE)pNtdllImageBase + rvaToRaw(pSectionHeader, numberOfSections, pExportDirectory->AddressOfNames));
		pAddressOfNameOrdinals = (PWORD)((PBYTE)pNtdllImageBase + rvaToRaw(pSectionHeader, numberOfSections, pExportDirectory->AddressOfNameOrdinals));
		
		for(DWORD i=0; i<numberOfNames; i++){
			pFunctionName = (PCHAR)((PBYTE)pNtdllImageBase + rvaToRaw(pSectionHeader, numberOfSections, pAddressOfNames[i]));
			pFunctionAddress = (PBYTE)((PBYTE)pNtdllImageBase + rvaToRaw(pSectionHeader, numberOfSections, pAddressOfFunctions[i+d]));
			ordinal = (WORD)ordinalBase + pAddressOfNameOrdinals[i];
			
			if(*((PBYTE)pFunctionAddress + 0x03) == 0xb8 && *((PBYTE)pFunctionAddress + 0x12) == 0x0f && *((PBYTE)pFunctionAddress + 0x13) == 0x05 && *((PBYTE)pFunctionAddress + 0x14) == 0xc3){	// 0x68:MOV EAX 0x0f05:syscall 0xc3:RET
				BYTE high = *((PBYTE)pFunctionAddress + 0x05);
				BYTE low = *((PBYTE)pFunctionAddress + 0x04);
				systemCallNumber = (high << 8) | low;
				
				printf("Ordinal:%x\tSystemCall:%d\tName:%s\n", ordinal, systemCallNumber, pFunctionName);
			}
		}
	}else{	// from memory
		printf("[I] Read data from loaded ntdll.dll on memory\n");
		
		pNtdllImageBase = (PBYTE)myGetModuleHandleW(strNtdll);
		
		pDosHeader = (PIMAGE_DOS_HEADER)pNtdllImageBase;
		if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
#ifdef _DEBUG
			printf("[E] Invalid dos format\n");
#endif
			return -1;
		}
		
		pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
		if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE){
#ifdef _DEBUG
			printf("[E] Invalid pe format\n");
#endif
			return -1;
		}
		
		pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;
		if(!(pFileHeader->Characteristics & IMAGE_FILE_DLL)){
#ifdef _DEBUG
			printf("[E] Invalid dll data\n");
#endif
			return -1;
		}
		
		pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&pNtHeaders->OptionalHeader;
		
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDosHeader + pOptionalHeader->DataDirectory[0].VirtualAddress);
		
		ordinalBase = (DWORD)pExportDirectory->Base;
		numberOfFunctions = (DWORD)pExportDirectory->NumberOfFunctions;
		numberOfNames = (DWORD)pExportDirectory->NumberOfNames;
		d = numberOfFunctions - numberOfNames;
		if(d < 0){
			d = 0;
		}
		
		pAddressOfFunctions = (PDWORD)((PBYTE)pNtdllImageBase + pExportDirectory->AddressOfFunctions);
		pAddressOfNames = (PDWORD)((PBYTE)pNtdllImageBase + pExportDirectory->AddressOfNames);
		pAddressOfNameOrdinals = (PWORD)((PBYTE)pNtdllImageBase + pExportDirectory->AddressOfNameOrdinals);
		
		for(DWORD i=0; i<numberOfNames; i++){
			pFunctionName = (PCHAR)((PBYTE)pNtdllImageBase + pAddressOfNames[i]);
			pFunctionAddress = (PBYTE)((PBYTE)pNtdllImageBase + pAddressOfFunctions[i+d]);
			ordinal = (WORD)ordinalBase + pAddressOfNameOrdinals[i];
			
			if(*((PBYTE)pFunctionAddress + 0x03) == 0xb8 && *((PBYTE)pFunctionAddress + 0x12) == 0x0f && *((PBYTE)pFunctionAddress + 0x13) == 0x05 && *((PBYTE)pFunctionAddress + 0x14) == 0xc3){	// 0x68:MOV EAX 0x0f05:syscall 0xc3:RET
				BYTE high = *((PBYTE)pFunctionAddress + 0x05);
				BYTE low = *((PBYTE)pFunctionAddress + 0x04);
				systemCallNumber = (high << 8) | low;
				
				printf("Ordinal:%x\tSystemCall:%d\tName:%s\n", ordinal, systemCallNumber, pFunctionName);
			}
		}
	}
	
	return 0;
}


