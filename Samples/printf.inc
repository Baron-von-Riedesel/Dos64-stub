
;--- printf implementation.
;--- knows:
;---  %x,  %X,  %u,  %d: dword
;--- %lx, %lX, %lu, %ld: qword
;--- %c: char
;--- %s: string

;--- convert qword to string
;--- stdcall ltoa(long long number, char * tbuffer, int base );

ltoa PROC c uses rdi number:qword, tbuffer:ptr, base:dword

	mov ch,0
	mov rax, number
	mov rbx,tbuffer
	mov edi, base
	add rbx,20
	mov BYTE PTR [rbx],0
	dec rbx
	mov ch,0
	cmp edi,-10
	jne @F
	mov edi,10
	and rax,rax
	jns @F
	neg rax
	mov ch,'-'
@@:

@@nextdigit:
	xor rdx,rdx
	div rdi
	add dl,'0'
	cmp dl,'9'
	jbe @F
	add dl,7+20h
@@:
	mov [rbx],dl
	dec rbx
	and rax, rax
	jne @@nextdigit
	cmp ch,0
	je @F
	mov [rbx],ch
	dec rbx
@@:
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
if 0
	push @@L335
else
	lea rax,@@L335
	push rax
endif
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
	cmp al,'x'
	je handle_x
	cmp al,'X'
	je handle_x
	cmp al,'s'
	je handle_s
	cmp al,'u'
	je handle_u
	cmp al,'d'
	je handle_d
	cmp al,'c'
	je handle_c
	cmp al,0
	jnz @F
	pop rax
	jmp done
handle_c:
	mov al,[rdi]
	add rdi,8
@@:
	push rax
	call handle_char
	retn

handle_s:
	mov rsi,[rdi]
	add rdi,8
	jmp print_string

handle_d:
	mov ebx,-10
	jmp @F
handle_u:
	mov ebx,10
	jmp @F
handle_x:
	mov ebx,16
@@:
	cmp [longarg],0
	je @F
	mov rax,[rdi]
	jmp @@L341
@@:
	mov eax,[rdi]
	cmp ebx,-10
	jnz @@L341
	movsxd rax,eax
@@L341:
	add rdi,8
	lea rcx,[szTmp]
	invoke ltoa, rax, rcx, ebx
	mov rsi,rax

print_string:		;print string RSI
	mov rax,rsi
	mov ebx,size_
	.while byte ptr [rsi]
		inc rsi
	.endw
	sub rsi,rax
	xchg rax,rsi
	sub ebx,eax
	.if flag == 1
		.while sdword ptr ebx > 0
			push [fillchr]
			call handle_char	;print leading filler chars
			dec ebx
		.endw
	.endif

	.while byte ptr [rsi]
		lodsb
		push rax
		call handle_char	;print char of string
	.endw

	.while sdword ptr ebx > 0
		push [fillchr]
		call handle_char	;print trailing spaces
		dec ebx
	.endw
	retn

printf ENDP


