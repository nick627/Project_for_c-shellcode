// https://forum.reverse4you.org/showthread.php?t=2155

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
//#include <Windows.h>

#include "src_shellcode.h"

uintptr_t unpack_shellcode(char *exe_path, char *save_path)
{
	HANDLE hfile = INVALID_HANDLE_VALUE, hmap = NULL;
	uintptr_t size, offset = 0, i;
	PIMAGE_DOS_HEADER pdos;
	PIMAGE_FILE_HEADER pimg;
	PIMAGE_OPTIONAL_HEADER32 popt32;
	PIMAGE_OPTIONAL_HEADER64 popt64;
	PIMAGE_SECTION_HEADER psects, psect = NULL;
	char sect_name[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
	char *pshell_buf;
	DWORD written;
	LPVOID pview = NULL;

	__try
	{
		hfile = CreateFileA(exe_path, GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL);
		if (hfile == INVALID_HANDLE_VALUE)
		{
			printf("Error, can't open file!\n");
			return 0;
		}

		hmap = CreateFileMapping(hfile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (!hmap)
		{
			printf("Error, can't mapped file!\n");
			return 0;
		}
		CloseHandle(hfile);
		hfile = INVALID_HANDLE_VALUE;

		pview = MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 0);
		if (!pview)
		{
			printf("Error, can't mapped file!\n");
			return 0;
		}

		//parse DOS and PE header
		pdos = (PIMAGE_DOS_HEADER)pview;
		if (pdos->e_magic != IMAGE_DOS_SIGNATURE)
		{
			printf("Error, incorrect DOS header!\n");
			return 0;
		}
		offset += pdos->e_lfanew;

		if (*(DWORD *)((uintptr_t)pdos + offset) != (DWORD)IMAGE_NT_SIGNATURE)
		{
			printf("Error, incorrect PE header!\n");
			return 0;
		}
		offset += 4;

		pimg = (PIMAGE_FILE_HEADER)((uintptr_t)pdos + offset);
		offset += sizeof(IMAGE_FILE_HEADER);

		if (pimg->Machine != IMAGE_FILE_MACHINE_I386 && pimg->Machine != IMAGE_FILE_MACHINE_AMD64)
		{
			printf("Error, incorrect architecture!\n");
			return 0;
		}

		if (pimg->Machine == IMAGE_FILE_MACHINE_I386)
		{
			popt32 = (PIMAGE_OPTIONAL_HEADER32)((uintptr_t)pdos + offset);
			offset += sizeof(IMAGE_OPTIONAL_HEADER32);
		}
		else
		{
			popt64 = (PIMAGE_OPTIONAL_HEADER64)((uintptr_t)pdos + offset);
			offset += sizeof(IMAGE_OPTIONAL_HEADER64);
		}

		psects = (PIMAGE_SECTION_HEADER)((uintptr_t)pdos + offset);

		//search shell section
		for (i = 0; i < pimg->NumberOfSections; i++)
		{
			memcpy(sect_name, psects[i].Name, IMAGE_SIZEOF_SHORT_NAME);
			if (!strcmp(sect_name, SHELLCODE_SECTION))
			{
				psect = &psects[i];
				break;
			}
		}
		if (!psect)
		{
			printf("Error, shellcode section not found!\n");
			return 0;
		}

		//shink shellcode size
		size = 0;
		pshell_buf = (char *)((uintptr_t)pdos + psect->PointerToRawData);
		for (i = psect->SizeOfRawData - 1; i >= 0; i--)
		{
			if (pshell_buf[i] != 0 && pshell_buf[i] != 0xCC)
			{
				size = i + 1;
				break;
			}
		}

		//save shellcode
		hfile = CreateFileA(save_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, NULL, NULL);
		if (hfile == INVALID_HANDLE_VALUE)
		{
			printf("Error, can't open output file!\n");
			return 0;
		}

		if (!WriteFile(hfile, pshell_buf, size, &written, NULL))
		{
			printf("Error, can't write to output file!\n");
			return 0;
		}

	}
	__finally
	{
		if (hfile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hfile);

			FILE *ptr_binary_file_no_xor = fopen(save_path, "rb");
			FILE *ptr_binary_file = fopen(SHELLCODE_FILE, "wb");

			if (ptr_binary_file_no_xor == NULL || ptr_binary_file == NULL)
			{
				printf("file did not open");
				return 0;
			}

			fseek(ptr_binary_file_no_xor, 0, SEEK_SET);

			// binary insert for decode shell code
			fwrite(xor_decoder, (int)xor_decoder_end - (int)xor_decoder, 1, ptr_binary_file);

			// xor encryption shellcode
			for (i = 0; i < size; i += 4)
			{
				// xor ..., 0x43213412
				fputc(fgetc(ptr_binary_file_no_xor) ^ 0x12, ptr_binary_file);
				fputc(fgetc(ptr_binary_file_no_xor) ^ 0x34, ptr_binary_file);
				fputc(fgetc(ptr_binary_file_no_xor) ^ 0x21, ptr_binary_file);
				fputc(fgetc(ptr_binary_file_no_xor) ^ 0x43, ptr_binary_file);
			}

			for (i = 0; i < 4; i++)
			{
				fputc(0xFE, ptr_binary_file);
			}
			fputc(0x00, ptr_binary_file);

			fclose(ptr_binary_file_no_xor);
			fclose(ptr_binary_file);
		}
		if (hmap)
		{
			CloseHandle(hmap);
		}
		if (pview)
		{
			UnmapViewOfFile(pview);
		}
	}

	return 1;
}

int main(int argc, char *argv[])
{
	//*
	//unpack shellcode to file
	if (!unpack_shellcode(argv[0], SHELLCODE_FILE_NO_XOR))
	{
		return 1;
	}
	printf("Unpacking successful!\n");
	//*/

	//for compile and debug
	printf("Calling shellcode from module!\n");
	entry();

	return 0;
}