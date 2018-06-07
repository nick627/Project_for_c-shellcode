; masm syntax

;IA86 and AMD64
IFDEF _M_IA86
.386
.model flat, stdcall
ENDIF

;set code section .shell
.CODE shell

;data struct
Shell_Static_Data STRUCT 
	phrase_ldrloaddll db 16 dup(0)

	phrase_ExitProcess	db 16 dup(0)

	phrase_kernel32		dw 16 dup(0)
	phrase_msvcrt		dw 16 dup(0)
	phrase_iphlpapi		dw 16 dup(0)
	phrase_ntdll		dw 16 dup(0)
Shell_Static_Data ENDS


shelldata Shell_Static_Data <"LdrLoadDll", \
	"ExitProcess", \
	{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}, \
	{'m', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l'},	\
	{'i', 'p', 'h', 'l', 'p', 'a', 'p', 'i', '.', 'd', 'l', 'l'}, \
	{'N', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}>


;getting ptr to shelldata struct

IFDEF _M_IA86

get_data_struct_ptr_data_dll PROC
;delta
	call get_delta
get_delta:
	pop eax
;calc var
	sub eax, 5
	sub eax, sizeof shelldata
	ret
get_data_struct_ptr_data_dll ENDP


ELSEIFDEF _M_AMD64

get_data_struct_ptr_data_dll PROC
;delta
	call get_delta
get_delta:
	pop rax
;calc var
	sub rax, 5
	sub rax, sizeof shelldata
	ret
get_data_struct_ptr_data_dll ENDP

ENDIF

END