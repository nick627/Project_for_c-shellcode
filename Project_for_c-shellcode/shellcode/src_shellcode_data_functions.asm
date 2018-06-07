; masm syntax

;IA86 and AMD64
IFDEF _M_IA86
.386
.model flat, stdcall
ENDIF

;set code section .shell
.CODE shell

;data struct
Shell_Static_Data_functions STRUCT 
	phrase_malloc		db 16 dup(0)
	phrase_free			db 16 dup(0)

	phrase_fopen		db 16 dup(0)
	phrase_fprintf		db 16 dup(0)
	phrase_fclose		db 16 dup(0)

	phrase_GetIfTable	db 16 dup(0)
	phrase_GetIfEntry	db 16 dup(0)
	
	phrase_printf		db 16 dup(0)

	phrase_name_file	db 32 dup(0)
	phrase_wb			db 4  dup(0)

	phrase_num_entries			db 32 dup(0)
	phrase_dec					db 8  dup(0)
	phrase_str					db 8  dup(0)
	phrase_enter				db 8  dup(0)
	phrase_GetIfEntry_failed	db 64 dup(0)
Shell_Static_Data_functions ENDS


shelldata_funcs Shell_Static_Data_functions <\
	"malloc", \
	"free", \
	"fopen", \
	"fprintf", \
	"fclose", \
	"GetIfTable", \
	"GetIfEntry", \
	"printf", \
	"list_netints.txt", \
	"w", \
	"Num Entries: %ld", \
	"%d: ", \
	"%s", \
	{10, 13}, \ ; "\n\r"
	"GetIfEntry failed for index %d with error: %ld\n">


;getting ptr to shelldata struct

IFDEF _M_IA86

get_data_struct_ptr_data_functions PROC
;delta
	call get_delta
get_delta:
	pop eax
;calc var
	sub eax, 5
	sub eax, sizeof shelldata_funcs
	ret
get_data_struct_ptr_data_functions ENDP


ELSEIFDEF _M_AMD64

get_data_struct_ptr_data_functions PROC
;delta
	call get_delta
get_delta:
	pop rax
;calc var
	sub rax, 5
	sub rax, sizeof shelldata_funcs
	ret
get_data_struct_ptr_data_functions ENDP

ENDIF

END