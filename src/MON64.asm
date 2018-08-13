
;--- this is a sample showing how a 64-bit binary
;--- may look that can be loaded by dos64stb.bin.

;--- the .x64 directive is not really needed.
;--- it is here so we don't have to use the Win64
;--- calling convention in INVOKE.

    .x64
    .model flat
    option casemap:none

lf  equ 10 

;--- define a string (modifies rax!)
CStr macro text:vararg
local sym
    .const
sym db text,0
    .code
	lea rax,sym
    exitm <rax>
endm

    .data

qwRsp   dq 0    ;stack pointer
address dq 0    ;next address for d-cmd

;--- keyboard buffer
buffer db 20 dup (0)
lbuffer equ $ - offset buffer

    .code

    include printf.inc

;--- this is the 64-bit entry point.
;--- it's called by the stub with registers:
;--- rbx: image base
;--- rsp: bottom of (reserved) stack

main proc

	mov rax,offset main

    call set_exception_handlers
    invoke printf, CStr(<lf,"Mon64 loaded at %lX, rsp=%lX",lf>), rbx, rsp
nextcmd:
    invoke printf, CStr(<"(cmds: a,c,d,r,q or x): ">)
    mov ah,1        ;read a key from keyboard with echo
    int 21h
    lea rcx,[nextcmd]
    push rcx
    mov qwRsp, rsp
    push rax
    mov dl,lf
    mov ah,2        ;write a char to screen
    int 21h
    pop rax
    cmp al,'a'      ; 'a'?
    jz a_cmd
    cmp al,'c'      ; 'c'?
    jz c_cmd
    cmp al,'d'      ; 'd'?
    jz d_cmd
    cmp al,'q'      ; 'q'?
    jz q_cmd
    cmp al,'r'      ; 'r'?
    jz r_cmd
    cmp al,'x'      ; 'x'?
    jz x_cmd
    cmp al,0dh      ;ENTER?
    jz newline
    mov rcx, rax
    invoke printf, CStr(<"unknown cmd: %c",lf>), rcx
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

;--- enter address (for d cmd)

a_cmd proc
    invoke printf, CStr(<"enter start address for d cmd: ">)
    mov rdi,0
    mov rbx,offset buffer
nextkey:
    mov ah,1
    int 21h
    cmp al,0dh
    jz enter_pressed
    mov [rbx+rdi],al
    inc rdi
    cmp rdi,lbuffer-1
    jnz nextkey
    mov dl,0ah
    mov ah,2
    int 21h
enter_pressed:    
    and edi,edi        ;at least 1 digit entered?
    jz done
    mov byte ptr [rbx+rdi],0
    xor edi,edi
    xor rsi,rsi
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
    shr rax,48
    and rax, rax
    jz @F
    invoke printf, CStr(<"hint: magnitude of address > 48 bits, exceeds paging capacity",lf>)
@@:
    mov [address],rsi
done:
    ret
error:
    lea rsi, [buffer]
    invoke printf, CStr(<"%s?",lf>), rsi
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
    mov dl,10
    mov ah,2
    int 21h
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
    ret
r_cmd endp

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

    sub rsp,16
    sidt [rsp]
    mov rdi,[rsp+2]
    add rsp,16
    cld
    lea rdi,[rdi+0Dh*10h]

    lea rdx, exception0D
    mov eax,edx
    stosw
    mov ax, cs
    stosw
    mov ax,8E00h
    stosd           ;store type + highword offset
    xor eax, eax
    stosd
    stosd

    lea rdx, exception0E
    mov eax,edx
    stosw
    mov ax, cs
    stosw
    mov ax,8E00h
    stosd           ;store type + highword offset
    xor eax, eax
    stosd
    stosd

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
