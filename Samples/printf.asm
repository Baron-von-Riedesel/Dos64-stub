
;--- simple printf() implementation
;--- understands formats %u,%d,%x,%c,%s

	option proc:private
	option frame:auto
	option win64:1

	.code

strlen proc uses rsi string:ptr
	mov rsi,string
@@:
	lodsb
	and al,al
	jnz @B
	lea rax,[rsi-1]
	sub rax,string
	ret
strlen endp

;--- ltob(long n, char * s, int base);
;--- convert long to string

ltoa PROC uses rbx rdi number:qword, pBuffer:ptr, base:dword

	mov ch,0
	mov edi, base
	mov rax, number
	cmp edi,-10
	jne @F
	mov edi,10
	and rax,rax
	jns @F
	neg rax
	mov ch,'-'
@@:
	mov rbx,pBuffer
	add rbx,20
	mov BYTE PTR [rbx],0
	dec rbx
@@nextdigit:
	xor rdx, rdx
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

handle_char proc char:dword

	mov edx,char
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

printf PROC public frame uses rbx rsi rdi fmt:ptr byte, args:VARARG

local flag:byte
local longarg:byte
local size_:dword
local base:dword
local fillchr:dword
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
	invoke handle_char, eax
	jmp nextchar
done:
	xor eax,eax
	ret 

formatitem:
	cmp byte ptr [rsi],'%'	;%%?
	jnz @F
	lodsb
	invoke handle_char, eax
	jmp nextchar
@@:
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
	mov [fillchr],ecx
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
	inc rsi
	cmp byte ptr [rsi],'l'
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
	cmp al,'u'
	je handle_u
	cmp al,'d'
	je handle_d
	cmp al,'p'
	je handle_p
handle_c:
	invoke handle_char, dword ptr [rdi]
	add rdi,8
	jmp @@L335

handle_s:
	mov rsi,[rdi]
	add rdi,8
	jmp print_string

handle_d:
	mov base,-10
	jmp handlenum
handle_u:
	mov base,10
	jmp handlenum
handle_p:
	mov longarg,1
handle_x:
	mov base,16
handlenum:
	cmp [longarg],0
	je @F
	mov rax,[rdi]
	jmp num2str
@@:
	mov eax,[rdi]
	cmp base,-10
	jnz @F
	movsxd rax,dword ptr [rdi]
@@:
num2str:
	add rdi,8
	lea rbx,[szTmp]
	invoke ltoa, rax, rbx, base
	mov rsi,rax
print_string:		;print string RSI
	invoke strlen, rsi
	sub [size_],eax
	cmp [flag],1
	jne print_string_chars

	mov ebx,[size_]
	jmp @@L363
nextfchar:
	invoke handle_char, fillchr	;print leading filler chars
	dec ebx
@@L363:
	or ebx,ebx
	jg nextfchar
	mov [size_],ebx

print_string_chars:

	.while (byte ptr [rsi])
		lodsb
		invoke handle_char, eax	;print char of string
	.endw

	mov ebx,[size_]
@@:
	or ebx,ebx
	jle @@L335
	invoke handle_char, fillchr	;print trailing spaces
	dec ebx
	jmp @B

printf ENDP

	end
