
;--- this is a sample showing how a 64-bit binary
;--- may look that can be loaded by dos64stb.bin.
;--- needs JWasm v2.14+ (invoke register argument translation).

;--- the .x64 directive is not really needed.
;--- it is here so we don't have to use the -win64
;--- cmdline option, which also activates the Win64
;--- calling convention ( not wanted here ).

    .x64
    .model flat
    option casemap:none
    option proc:private

lf  equ 10 

?V_CMD equ 0	;1=enable 'v' cmd for testing

ifdef ?PE
%   include ?lnkdef		;for option -pe
endif

;--- define a string
CStr macro text:vararg
local sym
    .const
sym db text,0
    .code
;    lea rax,sym
;    exitm <rax>
    exitm <addr sym>	;works since jwasm v2.13
endm

    .data?
qwRsp   dq ?    ;stack pointer
address dq ?    ;next address for d-cmd
;--- keyboard buffer
buffer db 20 dup (?)
lbuffer equ $ - offset buffer

    .code

    include printf.inc

;--- this is the 64-bit entry point.
;--- it's called by the stub with registers:
;--- rbx: image base
;--- rsp: bottom of (reserved) stack

main proc

    invoke printf, CStr(<lf,"Mon64 loaded at %lX, rsp=%lX",lf>), rbx, rsp
    call set_exception_handlers
    mov address,0
nextcmd:
    invoke printf, CStr(<"(cmds: a,c,d,q,r,s or x): ">)
ifdef ?WAITINPM ;wait in protected-mode ( to test interrupts )
@@:
    mov ax,flat:[41ah]
    cmp ax,flat:[41ch]
    jnz @F
    hlt
    jmp @B
@@:
endif
    mov ah,1        ;read a key from keyboard with echo
    int 21h
    lea rcx,[nextcmd]
    push rcx
    mov qwRsp, rsp
    push rax
    invoke printf, CStr(lf)
    pop rax
    cmp al,'a'
    jz a_cmd
    cmp al,'c'
    jz c_cmd
    cmp al,'d'
    jz d_cmd
    cmp al,'q'
    jz q_cmd
    cmp al,'r'
    jz r_cmd
    cmp al,'s'
    jz s_cmd
if ?V_CMD
    cmp al,'v'
    jz v_cmd
endif
    cmp al,'x'
    jz x_cmd
    cmp al,0dh      ;ENTER?
    jz newline
    invoke printf, CStr(<"unknown cmd: %c",lf>), rax
newline:
    ret
main endp

;--- display control and debug registers

c_cmd proc
    mov rbx,cr0
    mov rcx,cr2
    invoke printf, CStr(<"cr0=%16lX  cr2=%16lX",lf>), rbx, rcx
    mov rbx,cr3
    mov rcx,cr4
    invoke printf, CStr(<"cr3=%16lX  cr4=%16lX",lf>), rbx, rcx
    mov rbx,cr8
    invoke printf, CStr(<"cr8=%16lX",lf>), rbx
    mov rbx,dr0
    mov rcx,dr1
    invoke printf, CStr(<"dr0=%16lX  dr1=%16lX",lf>), rbx, rcx
    mov rbx,dr2
    mov rcx,dr3
    invoke printf, CStr(<"dr2=%16lX  dr3=%16lX",lf>), rbx, rcx
    mov rbx,dr6
    mov rcx,dr7
    invoke printf, CStr(<"dr6=%16lX  dr7=%16lX",lf>), rbx, rcx
    ret
c_cmd endp

;--- get a line of characters
;--- rbx->buffer
;--- esi=size of buffer

getline proc
    xor edi, edi
    dec esi
nextkey:
    mov ah,1
    int 21h
    cmp al,0dh
    jz enter_pressed
    cmp al,08h
    jz backspace_pressed
    mov [rbx+rdi],al
    inc edi
    cmp edi,esi
    jnz nextkey
    mov dl,0dh
    mov ah,2
    int 21h
    jmp enter_pressed
backspace_pressed:
    mov dl,20h
    mov ah,2
    int 21h
    cmp edi,0
    jz nextkey
    dec edi
    mov dl,08h
    mov ah,2
    int 21h
    jmp nextkey
enter_pressed:    
    mov byte ptr [rbx+rdi],0
    ret
getline endp

;--- enter address (for d cmd)

a_cmd proc
    invoke printf, CStr(<"enter start address for d cmd: ">)
    lea rbx, buffer
    mov esi, lbuffer
    call getline
    and edi,edi        ;at least 1 digit entered?
    jz done
    xor edi,edi
    xor esi,esi
    .while byte ptr [rbx+rdi]
        mov al,byte ptr [rbx+rdi]
        sub al,'0'
        jc error
        cmp al,9
        jbe @F
        sub al, 27h
        cmp al, 0fh
        ja error
@@:
        movzx rax,al
        shl rsi,4
        add rsi,rax
        inc edi
    .endw
    mov rax,rsi
    shr rax,47
    and rax, rax
    jz @F
    cmp eax,1ffffh
    jz @F
    invoke printf, CStr(<"hint: magnitude of address > 48 bits, exceeds paging capacity">)
@@:
    mov address,rsi
done:
    invoke printf, CStr(lf)
    ret
error:
    invoke printf, CStr(<lf,"%s?",lf>), addr buffer
    ret

a_cmd endp

;--- display memory dump

d_cmd proc
    mov rdi,[address]
    mov ch,8
nextline:
    push rcx
    invoke printf, CStr("%012lX: "), rdi
    pop rcx
    mov cl,16
    .while cl
        push rcx
        mov dl,[rdi]
        movzx rdx,dl
        invoke printf, CStr("%02X "), rdx
        pop rcx
        inc rdi
        dec cl
    .endw
    mov dl,' '
    mov ah,2
    int 21h
    sub rdi,16
    mov cl,16
    .while cl
        mov dl,[rdi]
        cmp dl,20h
        jnc @F
        mov dl,'.'
@@:
        mov ah,2
        int 21h
        inc rdi
        dec cl
    .endw
    push rcx
    invoke printf,CStr(lf)
    pop rcx
    dec ch
    jnz nextline
    mov [address],rdi
    ret
d_cmd endp

;--- display standard registers

r_cmd proc
    invoke printf, CStr(<"rax=%16lX  rbx=%16lX",lf>), rax, rbx
    invoke printf, CStr(<"rcx=%16lX  rdx=%16lX",lf>), rcx, rdx
    invoke printf, CStr(<"rsi=%16lX  rdi=%16lX",lf>), rsi, rdi
    invoke printf, CStr(<"rbp=%16lX  rsp=%16lX",lf>), rbp, rsp
    invoke printf, CStr(<" r8=%16lX   r9=%16lX",lf>),  r8,  r9
    invoke printf, CStr(<"r10=%16lX  r11=%16lX",lf>), r10, r11
    invoke printf, CStr(<"r12=%16lX  r13=%16lX",lf>), r12, r13
    invoke printf, CStr(<"r14=%16lX  r15=%16lX",lf>), r14, r15
    pushfq
    pop rax
    mov ecx,ds
    mov edx,es
    mov ebx,fs
    mov esi,gs
    mov edi,cs
    mov ebp,ss
    invoke printf, CStr(<"flags=%lX cs=%X ss=%X ds=%X es=%X fs=%X gs=%X",lf>), rax, rdi, rbp, rcx, rdx, rbx, rsi
    lsl rax,rdi
    lar rcx,rdi
    shr rcx,8
    lsl rdx,rbp
    lar rbx,rbp
    shr rbx,8
    invoke printf, CStr(<"cslim=%X csattr=%X sslim=%X ssattr=%X",lf>), rax, rcx, rdx, rbx
    ret
r_cmd endp

;--- display system registers

?STARTINT equ 0 ;start of INTs to display

s_cmd proc
    sub rsp,16
    sgdt [rsp]
    mov rdi, [rsp+2]
    movzx rsi, word ptr [rsp]
    sldt eax
    str ecx
    invoke printf, CStr(<"GDTR base=%lX,limit=%X  LDTR=%X  TR=%X",lf>), rdi, rsi, rax, rcx
    inc rsi
    xor ebx,ebx
    .while rbx < rsi
        mov ch, [rdi+7]
        mov cl, [rdi+4]
        shl ecx,16
        mov cx, [rdi+2]
        movzx rdx, word ptr [rdi+5]
        xor eax,eax
        mov al, dh
        and al, 0Fh
        shl eax, 16
        mov ax, [rdi+0]
        test dh,80h
        jz @F
        shl rax,12
        or ax,0fffh
@@:
        invoke printf, CStr(<"%04X: base=%08lX, limit=%08lX, attr=%04X",lf>), rbx, rcx, rax, rdx
        add rdi,8
        add rbx,8
    .endw

    sidt [rsp]
    mov rdi, [rsp+2]
    movzx rsi, word ptr [rsp]
    invoke printf, CStr(<"IDTR base=%lX  limit=%X",lf>), rdi, rsi
    invoke printf, CStr(<" #    addr             attr    addr             attr    addr             attr",lf>)
if ?STARTINT
    add rdi,?STARTINT*16
endif
    lea rsi,[rdi+16*30h]
    mov bh,?STARTINT
    .while rdi < rsi
        movzx eax,bh
        invoke printf, CStr(<"%2X ">), rax
        mov bl,3
nextitem:
        mov rax,[rdi+4]
        mov ax,[rdi+0]
        movzx ecx,word ptr [rdi+2]
        movzx edx,word ptr [rdi+4]
        invoke printf, CStr(<"%2X:%016lX-%4X ">), rcx, rax, rdx
        add rdi,16
        dec bl
        jnz nextitem
        invoke printf, CStr(<lf>)
        add bh,3
    .endw
    add rsp,16
    ret
s_cmd endp

;--- for various testings
if ?V_CMD
v_cmd proc
    mov ax,0400h
    int 31h
    invoke printf, CStr(<"int 31h, ax=0400h:%X",lf>),rax
    ret
v_cmd endp
endif
;--- display xmm registers

x_cmd proc
    sub rsp,32
    movdqu [rsp+00], xmm0
    movdqu [rsp+16], xmm1
    mov rcx,[rsp+0]
    mov rdx,[rsp+8]
    mov rsi,[rsp+16]
    mov rdi,[rsp+24]
    invoke printf, CStr(<" xmm0=%016lX-%016lX  xmm1=%016lX-%016lX",lf>),rdx, rcx, rdi, rsi
    movdqu [rsp+00], xmm2
    movdqu [rsp+16], xmm3
    mov rcx,[rsp+0]
    mov rdx,[rsp+8]
    mov rsi,[rsp+16]
    mov rdi,[rsp+24]
    invoke printf, CStr(<" xmm2=%016lX-%016lX  xmm3=%016lX-%016lX",lf>),rdx, rcx, rdi, rsi
    movdqu [rsp+00], xmm4
    movdqu [rsp+16], xmm5
    mov rcx,[rsp+0]
    mov rdx,[rsp+8]
    mov rsi,[rsp+16]
    mov rdi,[rsp+24]
    invoke printf, CStr(<" xmm4=%016lX-%016lX  xmm5=%016lX-%016lX",lf>),rdx, rcx, rdi, rsi
    movdqu [rsp+00], xmm6
    movdqu [rsp+16], xmm7
    mov rcx,[rsp+0]
    mov rdx,[rsp+8]
    mov rsi,[rsp+16]
    mov rdi,[rsp+24]
    invoke printf, CStr(<" xmm6=%016lX-%016lX  xmm7=%016lX-%016lX",lf>),rdx, rcx, rdi, rsi
    movdqu [rsp+00], xmm8
    movdqu [rsp+16], xmm9
    mov rcx,[rsp+0]
    mov rdx,[rsp+8]
    mov rsi,[rsp+16]
    mov rdi,[rsp+24]
    invoke printf, CStr(<" xmm8=%016lX-%016lX  xmm9=%016lX-%016lX",lf>),rdx, rcx, rdi, rsi
    movdqu [rsp+00], xmm10
    movdqu [rsp+16], xmm11
    mov rcx,[rsp+0]
    mov rdx,[rsp+8]
    mov rsi,[rsp+16]
    mov rdi,[rsp+24]
    invoke printf, CStr(<"xmm10=%016lX-%016lX xmm11=%016lX-%016lX",lf>),rdx, rcx, rdi, rsi
    movdqu [rsp+00], xmm12
    movdqu [rsp+16], xmm13
    mov rcx,[rsp+0]
    mov rdx,[rsp+8]
    mov rsi,[rsp+16]
    mov rdi,[rsp+24]
    invoke printf, CStr(<"xmm12=%016lX-%016lX xmm13=%016lX-%016lX",lf>),rdx, rcx, rdi, rsi
    movdqu [rsp+00], xmm14
    movdqu [rsp+16], xmm15
    mov rcx,[rsp+0]
    mov rdx,[rsp+8]
    mov rsi,[rsp+16]
    mov rdi,[rsp+24]
    invoke printf, CStr(<"xmm14=%016lX-%016lX xmm15=%016lX-%016lX",lf>),rdx, rcx, rdi, rsi
    add rsp,32
    ret
x_cmd endp

;--- 'q': back to real-mode

q_cmd proc
    mov ax,4c00h
    int 21h
q_cmd endp

;--- set exception 0D+0E handlers so we 
;--- won't terminate unexpectedly

set_exception_handlers proc

    mov bl,0Dh
    lea rdx, exception0D
    mov ecx,cs
    mov ax,0203h
    int 31h
    mov bl,0Eh
    lea rdx, exception0E
    int 31h
    ret
set_exception_handlers endp

;--- handle protection and page faults

exception0D:
    sti
    mov rdx,[rsp+0]
    mov rcx,[rsp+8]
    invoke printf, CStr(<lf,"protection fault, errcode=%X rip=%lX",lf>), rdx, rcx
    mov rsp, qwRsp
    ret
exception0E:
    sti
    mov rdx,[rsp+0]
    mov rcx,[rsp+8]
    mov rbx,cr2
    invoke printf, CStr(<lf,"page fault, errcode=%X rip=%lX cr2=%lX",lf>), rdx, rcx, rbx
    mov rsp, qwRsp
    ret

    end main
