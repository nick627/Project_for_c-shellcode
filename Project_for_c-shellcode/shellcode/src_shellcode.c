#include "src_shellcode.h"
#include <stdio.h>

#pragma code_seg("shell")

uintptr_t str_cmpw(wchar_t *str1, wchar_t *str2);
uintptr_t str_cmp(char *str1, char *str2);
uintptr_t str_len(char *str);
uintptr_t str_lenw(wchar_t *str);

// Shellcode entry point
__declspec(noinline) void entry()
{
	PShell_Static_Data				shelldata = (PShell_Static_Data)get_data_struct_ptr_data_dll();
	PShell_Static_Data_functions	shelldata_funcs = (PShell_Static_Data_functions)get_data_struct_ptr_data_functions();

	void *ntdll = get_module_base_addr(shelldata->phrase_ntdll);

	void *kernel32;
	void *msvcrt;
	void *iphlpapi;

	LdrLoadDllProc LdrLoadDll = (LdrLoadDllProc)get_proc_addr(ntdll, shelldata->phrase_ldrloaddll);

	f_ExitProcess	ExitProcess_func;

	f_malloc		malloc_func;
	f_free			free_func;

	f_fopen			fopen_func;
	f_fprintf		fprintf_func;
	f_fclose		fclose_func;

	f_GetIfTable	GetIfTable_func;
	f_GetIfEntry	GetIfEntry_func;

	f_printf		printf_func;

	UNICODE_STRING uni;

	uni.Buffer = shelldata->phrase_kernel32;
	uni.Length = str_lenw(uni.Buffer) * 2;
	uni.MaximumLength = uni.Length + 2;
	if (LdrLoadDll(NULL, 0, &uni, &kernel32))
	{
		return;
	}

	uni.Buffer = shelldata->phrase_msvcrt;
	uni.Length = str_lenw(uni.Buffer) * 2;
	uni.MaximumLength = uni.Length + 2;
	if (LdrLoadDll(NULL, 0, &uni, &msvcrt))
	{
		return;
	}

	uni.Buffer = shelldata->phrase_iphlpapi;
	uni.Length = str_lenw(uni.Buffer) * 2;
	uni.MaximumLength = uni.Length + 2;
	if (LdrLoadDll(NULL, 0, &uni, &iphlpapi))
	{
		return;
	}


	ExitProcess_func = (f_ExitProcess)get_proc_addr(kernel32, shelldata->phrase_ExitProcess);

	malloc_func = (f_malloc)get_proc_addr(msvcrt, shelldata_funcs->phrase_malloc);
	free_func = (f_malloc)get_proc_addr(msvcrt, shelldata_funcs->phrase_free);

	fopen_func = (f_fopen)get_proc_addr(msvcrt, shelldata_funcs->phrase_fopen);
	fprintf_func = (f_fprintf)get_proc_addr(msvcrt, shelldata_funcs->phrase_fprintf);
	fclose_func = (f_fclose)get_proc_addr(msvcrt, shelldata_funcs->phrase_fclose);

	GetIfTable_func = (f_GetIfTable)get_proc_addr(iphlpapi, shelldata_funcs->phrase_GetIfTable);
	GetIfEntry_func = (f_GetIfEntry)get_proc_addr(iphlpapi, shelldata_funcs->phrase_GetIfEntry);

	printf_func = (f_printf)get_proc_addr(msvcrt, shelldata_funcs->phrase_printf);


	FILE *file_output = fopen_func(shelldata_funcs->phrase_name_file, shelldata_funcs->phrase_wb);

	// Declare and initialize variables.
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;

	unsigned int i, j;

	// variables used for GetIfTable and GetIfEntry
	MIB_IFTABLE *pIfTable;
	MIB_IFROW *pIfRow;

	// Allocate memory for our pointers.
	pIfTable = (MIB_IFTABLE *)malloc_func(sizeof(MIB_IFTABLE));
	if (pIfTable == NULL)
	{
		fclose_func(file_output);
		ExitProcess_func(1);
	}

	// Before calling GetIfEntry, we call GetIfTable to make
	// sure there are entries to get and retrieve the interface index.

	// Make an initial call to GetIfTable to get the
	// necessary size into dwSize
	dwSize = sizeof(MIB_IFTABLE);
	//
	if (GetIfTable_func(pIfTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER)
	{
		free_func(pIfTable);
		pIfTable = (MIB_IFTABLE *)malloc_func(dwSize);
		if (pIfTable == NULL)
		{
			fclose_func(file_output);
			ExitProcess_func(1);
		}
	}

	// Make a second call to GetIfTable to get the actual
	// data we want.
	if ((dwRetVal = GetIfTable_func(pIfTable, &dwSize, 0)) == NO_ERROR)
	{
		if (pIfTable->dwNumEntries > 0)
		{
			pIfRow = (MIB_IFROW *)malloc_func(sizeof(MIB_IFROW));
			if (pIfRow == NULL)
			{
				// printf("Error allocating memory\n");

				if (pIfTable != NULL)
				{
					free_func(pIfTable);
					pIfTable = NULL;
				}

				fclose_func(file_output);
				ExitProcess_func(1);
			}

			// printf("Num Entries: %ld\n", pIfTable->dwNumEntries);
			printf_func(shelldata_funcs->phrase_num_entries, pIfTable->dwNumEntries);
			printf_func(shelldata_funcs->phrase_enter);


			fprintf_func(file_output, shelldata_funcs->phrase_num_entries, pIfTable->dwNumEntries);
			fprintf_func(file_output, shelldata_funcs->phrase_enter);

			for (i = 0; i < pIfTable->dwNumEntries; i++)
			{
				pIfRow->dwIndex = pIfTable->table[i].dwIndex;
				if ((dwRetVal = GetIfEntry_func(pIfRow)) == NO_ERROR)
				{
					// printf("%d: ", i);
					printf_func(shelldata_funcs->phrase_dec, i);
					fprintf_func(file_output, shelldata_funcs->phrase_dec, i);

					// printf("%s", pIfRow->bDescr);
					printf_func(shelldata_funcs->phrase_str, pIfRow->bDescr);
					fprintf_func(file_output, shelldata_funcs->phrase_str, pIfRow->bDescr);

					//
					//for (j = 0; j < pIfRow->dwDescrLen; j++)
					//{
						//printf("%c", pIfRow->bDescr[j]);
						//fprintf_func(file_output, shelldata_funcs->phrase_str, pIfRow->bDescr[j]);
					//}
					//

					// printf("\n");
					printf_func(shelldata_funcs->phrase_enter);
					fprintf_func(file_output, shelldata_funcs->phrase_enter);
				}
				else
				{
					// printf("GetIfEntry failed for index %d with error: %ld\n", i, dwRetVal);
					printf_func(shelldata_funcs->phrase_GetIfEntry_failed, i, dwRetVal);
					fprintf_func(file_output, shelldata_funcs->phrase_GetIfEntry_failed, i, dwRetVal);

					// Here you can use FormatMessage to find out why
					// it failed.
				}
			}
		}
		else
		{
			// printf("\tGetIfTable failed with error: %ld\n", dwRetVal);
			printf_func(shelldata_funcs->phrase_GetIfEntry_failed, -1, dwRetVal);
			fprintf_func(file_output, shelldata_funcs->phrase_GetIfEntry_failed, -1, dwRetVal);
		}
	}

	if (pIfTable != NULL)
	{
		free_func(pIfTable);
		pIfTable = NULL;
	}

	fclose_func(file_output);
	ExitProcess_func(0);
}

// Get module base address
void *get_module_base_addr(wchar_t *mod_name)
{
	PPEB peb = (PPEB)GET_PEB;
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLDR_DATA_TABLE_ENTRY ldr_entry = (PLDR_DATA_TABLE_ENTRY)((uintptr_t)ldr->InMemoryOrderModuleList.Blink - (sizeof(uintptr_t) * 2));
	PLDR_DATA_TABLE_ENTRY ldr_first;

	ldr_first = ldr_entry;
	do {
		if (ldr_entry->DllBase && str_cmpw(ldr_entry->BaseDllName.Buffer, mod_name))
		{
			return (HMODULE)ldr_entry->DllBase;
		}
		ldr_entry = (PLDR_DATA_TABLE_ENTRY)((uintptr_t)ldr_entry->InMemoryOrderLinks.Blink - (sizeof(uintptr_t) * 2));
	} while (ldr_first != ldr_entry);

	return NULL;
}

// Get export procedure address
void *get_proc_addr(void *mod_addr, char *proc_name)
{
	PIMAGE_DOS_HEADER pdos;
	PIMAGE_FILE_HEADER pimg;
	PIMAGE_OPT_HEADER popt;
	PIMAGE_EXPORT_DIRECTORY pexp;
	PDWORD pnames, pfuncs;
	PWORD pords;
	uintptr_t i;
	char *proc;

	//getting export directory
	pdos = (PIMAGE_DOS_HEADER)mod_addr;
	if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	popt = (PIMAGE_OPTIONAL_HEADER)((uintptr_t)mod_addr + pdos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	pexp = (PIMAGE_EXPORT_DIRECTORY)(popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (uintptr_t)mod_addr);
	if (!pexp) {//export not found
		return NULL;
	}

	//searching function name
	pnames = (PDWORD)(pexp->AddressOfNames + (uintptr_t)mod_addr);
	pords = (PWORD)(pexp->AddressOfNameOrdinals + (uintptr_t)mod_addr);
	pfuncs = (PDWORD)(pexp->AddressOfFunctions + (uintptr_t)mod_addr);

	for (i = 0; i < pexp->NumberOfNames; i++) {
		proc = (char *)(pnames[i] + (uintptr_t)mod_addr);
		if (str_cmp(proc, proc_name)) {
			break;
		}
	}
	if (i == pexp->NumberOfNames) {//not found
		return NULL;
	}

	return (void *)(pfuncs[pords[i]] + (uintptr_t)mod_addr);
}


// String compare (non case-sensitive)
uintptr_t str_cmp(char *str1, char *str2)
{
	int i = 0;
	char char1, char2;
	for (i = 0; ; i++) {
		char1 = str1[i];
		if (char1 >= 'A' && char1 <= 'Z') {
			char1 += 32;
		}

		char2 = str2[i];
		if (char2 >= 'A' && char2 <= 'Z') {
			char2 += 32;
		}

		if (char1 != char2) {
			break;
		}
		if (!char1) {
			return 1;
		}
	}
	return 0;
}

// Unicode string compare (non case-sensitive)
uintptr_t str_cmpw(wchar_t *str1, wchar_t *str2)
{
	int i = 0;
	wchar_t char1, char2;
	for (i = 0; ; i++) {
		char1 = str1[i];
		if (char1 >= 'A' && char1 <= 'Z') {
			char1 += 32;
		}

		char2 = str2[i];
		if (char2 >= 'A' && char2 <= 'Z') {
			char2 += 32;
		}

		if (char1 != char2) {
			break;
		}
		if (!char1) {
			return 1;
		}
	}
	return 0;
}

// String length
uintptr_t str_len(char *str)
{
	uintptr_t i = 0;
	for (i = 0; ; i++) {
		if (!str[i]) {
			return i;
		}
	}
	return 0;
}

// Unicode string length
uintptr_t str_lenw(wchar_t *str)
{
	uintptr_t i = 0;
	for (i = 0; ; i++) {
		if (!str[i]) {
			return i;
		}
	}
	return 0;
}