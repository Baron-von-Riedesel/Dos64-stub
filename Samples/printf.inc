
strlen proc c uses rdi string:ptr
	mov rdi,string
	mov al,0
	repnz scasb
	lea rax,[rdi-1]
	sub rax,string
	ret
strlen endp

;--- convert long to string - always base 16
;--- stdcall ltoa(long n, char * s);

ltoa PROC c number:qword, tbuffer:ptr

	mov ch,0
	mov rax, number
	mov rbx,tbuffer
	add rbx,20
	mov BYTE PTR [rbx],0
	dec rbx

@@nextdigit:
	push rax
	and al,0Fh
	add al,'0'
	cmp al,'9'
	jbe @F
	add al,7+20h
@@:
	mov [rbx],al
	dec rbx
	pop rax
	shr rax,4
	and rax,rax
	jne @@nextdigit
	inc rbx
	mov rax,rbx
	ret

ltoa ENDP

handle_char proc

	pop rcx
	pop rdx
	push rcx
	cmp dl,10
	jnz @F
	push rdx
	mov dl,13
	mov ah,2
	int 21h
	pop rdx
@@:
	mov ah,2
	int 21h
	ret

handle_char endp

;--- simple printf() implementation

printf PROC c uses rbx rsi rdi fmt:ptr byte, args:VARARG

local flag:byte
local longarg:byte
local size_:dword
local fillchr:qword
local szTmp[24]:byte

	lea rdi,args
@@L335:
	mov rsi,fmt
nextchar:
	lodsb
	or al,al
	je done
	cmp al,'%'
	je formatitem
	push rax
	call handle_char
	jmp nextchar
done:
	xor eax,eax
	ret 

formatitem:
	xor edx,edx
	mov [longarg],dl
	mov bl,1
	mov cl,' '
	cmp BYTE PTR [rsi],'-'
	jne @F
	dec bl
	inc rsi
@@:
	mov [flag],bl
	cmp BYTE PTR [rsi],'0'
	jne @F
	mov cl,'0'
	inc rsi
@@:
	mov [fillchr],rcx
	mov [size_],edx
	mov ebx,edx

	.while ( byte ptr [rsi] >= '0' && byte ptr [rsi] <= '9' )
		lodsb
		sub al,'0'
		movzx rax,al
		imul rcx,rbx,10		;ecx = ebx * 10
		add rax,rcx
		mov rbx,rax
	.endw

	mov [size_],ebx
	cmp BYTE PTR [rsi],'l'
	jne @F
	mov [longarg],1
	inc rsi
@@:
	lodsb
	mov [fmt],rsi
	or al,al
	je done
	cmp al,'x'
	je handle_x
	cmp al,'X'
	je handle_x
	cmp al,'s'
	je handle_s
handle_c:
	push qword ptr [rdi]
	add rdi,8
	call handle_char
	jmp @@L335

handle_s:
	mov rsi,[rdi]
	add rdi,8
	jmp print_string

handle_x:
	cmp [longarg],0
	je @F
	mov rax,[rdi]
	add rdi,8
	jmp @@L341
@@:
	mov eax,[rdi]
	add rdi,8
@@L341:
	lea rcx,[szTmp]
	invoke ltoa, rax, rcx
	mov rsi,rax
print_string:		;print string SI
	push rsi
	call strlen
	pop rbx
	sub [size_],eax
	cmp [flag],1
	jne print_string_chars

	mov ebx,[size_]
	jmp @@L363
@@F270:
	push [fillchr]
	call handle_char	;print leading filler chars
	dec ebx
@@L363:
	or ebx,ebx
	jg @@F270
	mov [size_],ebx

print_string_chars:

	.while (byte ptr [rsi])
		lodsb
		push rax
		call handle_char	;print char of string
	.endw

	mov ebx,[size_]
@@:
	or ebx,ebx
	jle @@L335
	push [fillchr]
	call handle_char	;print trailing spaces
	dec ebx
	jmp @B

printf ENDP


