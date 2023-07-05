/*
 * Title:  struct.h
 * Author: Shuichiro Endo
 */

#pragma once

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	VOID* SsHandle;
	struct _LIST_ENTRY InLoadOrderModuleList;
	struct _LIST_ENTRY InMemoryOrderModuleList;
	struct _LIST_ENTRY InInitializationOrderModuleList;
	VOID* EntryInProgress;
	UCHAR ShutdownInProgress;
	VOID* ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct PEB64
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	union
	{
		UCHAR BitField;
		struct
		{
			UCHAR ImageUsesLargePages:1;
			UCHAR IsProtectedProcess:1;
			UCHAR IsImageDynamicallyRelocated:1;
			UCHAR SkipPatchingUser32Forwarders:1;
			UCHAR IsPackagedProcess:1;
			UCHAR IsAppContainer:1;
			UCHAR IsProtectedProcessLight:1;
			UCHAR ISLongPathAwareProcess:1;
		};
	};
	UCHAR Padding0[4];
	ULONGLONG Mutant;
	LPVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	// ...
} PEB64, *PPEB64;

typedef struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
};

typedef struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	// ...
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


