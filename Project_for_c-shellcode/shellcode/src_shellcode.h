#pragma once

#include <Windows.h>
#include <intrin.h>
#include <iphlpapi.h>

#define SHELLCODE_FILE "shellcode.bin"
#define SHELLCODE_FILE_NO_XOR "shellcode_without_xor.bin"
#define SHELLCODE_SECTION "shell"

#if defined(_M_IA86)
	#define GET_PEB __readfsdword(0x30)
	#define PIMAGE_OPT_HEADER PIMAGE_OPTIONAL_HEADER32
#elif defined(_M_AMD64)
	#define GET_PEB __readgsqword(0x60)
	#define PIMAGE_OPT_HEADER PIMAGE_OPTIONAL_HEADER64
#else
	#error Architecture not supported!
#endif

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


#pragma pack(push, 1)
typedef struct _Shell_Static_Data{
	char phrase_ldrloaddll	[16];

	char phrase_ExitProcess	[16];

	wchar_t phrase_kernel32	[16];
	wchar_t phrase_msvcrt	[16];
	wchar_t phrase_iphlpapi	[16];
	wchar_t phrase_ntdll	[16];
} Shell_Static_Data, *PShell_Static_Data;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _Shell_Static_Data_function {
	char phrase_malloc		[16];
	char phrase_free		[16];

	char phrase_fopen		[16];
	char phrase_fprintf		[16];
	char phrase_fclose		[16];

	char phrase_GetIfTable	[16];
	char phrase_GetIfEntry	[16];
	
	char phrase_printf		[16];

	char phrase_name_file	[32];
	char phrase_wb			[4];

	char phrase_num_entries			[32];
	char phrase_dec					[8];
	char phrase_str					[8];
	char phrase_enter				[8];
	char phrase_GetIfEntry_failed	[64];
} Shell_Static_Data_functions, *PShell_Static_Data_functions;
#pragma pack(pop)


extern PShell_Static_Data			__stdcall get_data_struct_ptr_data_dll();
extern PShell_Static_Data_functions __stdcall get_data_struct_ptr_data_functions();

__declspec(noinline) void entry();

void *get_module_base_addr(wchar_t *mod_name);
void *get_proc_addr(void *mod_addr, char *proc_name);

typedef NTSTATUS(NTAPI	*LdrLoadDllProc)	(PWCHAR PathToFile, ULONG Flags, UNICODE_STRING *ModuleFileName, void **ModuleHandle);
//typedef int (WINAPI *MessageBoxProc)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);


//-----------------------------------------------
// xor decoder
extern __stdcall xor_decoder();
extern __stdcall xor_decoder_end();


// kernel32.dll
typedef VOID	(WINAPI		*f_ExitProcess)	(UINT uExitCode);

// msvcrt.dll
typedef void*	(__cdecl	*f_malloc)		(size_t _Size);
typedef void	(__cdecl	*f_free)		(void* _Block);

typedef int		(__CRTDECL	*f_printf)		(char const * const _Format, ...);
typedef			(__cdecl	*f_fopen)		(char const * _FileName, char const * _Mode);
typedef int		(__CRTDECL	*f_fprintf)		(void * _Stream, char const * const _Format, ...);
typedef int		(__cdecl	*f_fclose)		(void * _Stream);

// iphlpapi.dll
typedef DWORD	(WINAPI		*f_GetIfTable)	(PMIB_IFTABLE pIfTable, PULONG pdwSize, BOOL bOrder);
typedef DWORD	(WINAPI		*f_GetIfEntry)	(PMIB_IFROW pIfRow);
