
;--- DOS stub program which switches to long-mode and back.
;--- Note: requires at least JWasm v2.13!
;--- Also: needs a 64bit cpu in real-mode to run.
;--- To create the binary enter:
;---  JWasm -mz DOS64stb.asm

    .model small
    .dosseg
    option casemap:none
    .stack 5120

ifndef ?IRQ0TORM
?IRQ0TORM equ 1;1=route IRQ0 (timer) to real-mode
endif

DGROUP group _TEXT	;makes a tiny model

    .x64p

    include peimage.inc
    include dpmi.inc

    option MZ:sizeof IMAGE_DOS_HEADER   ;set min size of MZ header if jwasm's -mz option is used

?PDPTE equ 64   ; entries in PDPT, mapped physical ram, size in GB (default 64 GB)
?PML4E equ ((?PDPTE-1) shr 9) + 1	;required entries in PML4
?MAXIMGSIZE equ 1024*1024	;max size of image+stack in kB (default 1 GB)
?HEAP  equ 0    ; 1=add heapsize of image to amount of memory to be allocated
?MPIC  equ 78h  ; master PIC base, remapped to 78h
?SPIC  equ 70h  ; slave PIC, isn't changed
?RESETLME equ 0 ;1=(re)set EFER.LME for temp switch to real-mode
?RESETPAE equ 1 ;1=(re)set CR4.PAE  for temp switch to real-mode
?SETCR3   equ 1 ;1=set CR3 after temp switch to real-mode

if ?PML4E gt 200h
    .err <256 TB is max. paging capacity>
endif

EMM struct  ;XMS block move help struct
_size  dd ?
srchdl dw ?
srcofs dd ?
dsthdl dw ?
dstofs dd ?
EMM ends

;--- define a string
CStr macro text:vararg
local sym
    .const
sym db text,0
    .code
    exitm <offset sym>
endm

@lgdt macro addr
;--- 16-bit variant is ok, since GDT remains in conventional memory
;    db 66h
    lgdt addr
endm
@lidt macro addr
;--- IDT may be beyond 24-bit address space!
    db 66h
    lidt addr
endm

@wait macro         ;for debugging only
local lbl1
;    push ax
lbl1:
    in al,64h       ;key from keyboard arrived?
    test al,1
    jz lbl1
    in al,60h
    cmp al,81h      ;wait for ESC released
    jnz lbl1
;    pop ax
endm

;--- 16bit start/exit code

SEL_CODE64 equ 1*8
SEL_DATA16 equ 2*8
SEL_CODE16 equ 3*8

    .code

    assume ds:DGROUP

GDT dq 0                    ; null descriptor
    dw 0FFFFh,0,9A00h,0AFh  ; 64-bit code descriptor
    dw 0FFFFh,0,9200h,0h    ; 16-bit, 64k data descriptor
    dw 0FFFFh,0,9A00h,0h    ; 16-bit, 64k code descriptor
;   dw 0FFFFh,0,9200h,0CFh  ; 32-bit flat data descriptor

    .data

GDTR label fword        ; Global Descriptors Table Register
    dw 4*8-1            ; limit of GDT (size minus one)
    dd offset GDT       ; linear address of GDT
IDTR label fword        ; IDTR in long mode
    dw 256*16-1         ; limit of IDT (size minus one)
    dd 0                ; linear address of IDT
nullidt label fword     ; IDTR for real-mode
    dw 3FFh
    dd 0
  
xmsaddr dd 0
dwCSIP  label dword
adjust  dd 0
xmshdl  dw -1
fhandle dw -1

    .data?

if ?MPIC ne 8
storedIntM label dword
        dd 8 dup (?)
endif
if ?SPIC ne 70h
storedIntS label dword
        dd 8 dup (?)
endif
nthdr   IMAGE_NT_HEADERS <>
sechdr  IMAGE_SECTION_HEADER <>
emm     EMM <>   ;xms block move structure
emm2    EMM <>   ;another one for nested calls
qwRSP    dq ?    ;saved protected-mode rsp
PhysBase dd ?    ;linear (+physical) address start of page tables (=CR3)
ImgBase dd ?     ;linear address image base
fname   dd ?     ;file name of executable
wStkBot dw ?,?
wFlags  dw ?     ;used to store flags register
if ?MPIC ne 8
bPICM   db ?     ;saved master PIC mask
endif
if ?SPIC ne 70h
bPICS   db ?     ;saved slave PIC mask
endif

    .code

start16 proc

    push cs
    pop ds
    mov ax,ss
    mov dx,es
    sub ax,dx
    mov bx,sp
    shr bx,4
    add bx,ax
    mov ax,bx
    sub ax,10h
    shl ax,4
    push ds
    pop ss
    mov sp,ax       ; make a TINY model, CS=SS=DS
    mov wStkBot+0,ax
    mov wStkBot+2,ss
    mov ah,4Ah
    int 21h         ; free unused memory

    mov es,es:[002Ch]
    xor di,di
    xor al,al
    mov cx,-1
@@:
    repnz scasb
    cmp byte ptr es:[di],0
    jnz @B
    add di,3
    mov word ptr fname+0,di
    mov word ptr fname+2,es

    mov ax,cs
    movzx eax,ax
    shl eax,4
    add dword ptr [GDTR+2], eax ; convert offset to linear address
    mov word ptr [GDT + SEL_DATA16 + 2], ax
    mov word ptr [GDT + SEL_CODE16 + 2], ax
    shr eax,16
    mov byte ptr [GDT + SEL_DATA16 + 4], al
    mov byte ptr [GDT + SEL_CODE16 + 4], al

    smsw ax
    test al,1
    mov bp,CStr("Mode is V86. Need REAL mode to switch to LONG mode!")
    jnz @@error
    xor edx,edx
    mov eax,80000001h   ; test if long-mode is supported
    cpuid
    bt edx,29
    mov bp,CStr("No 64bit cpu detected.")
    jnc @@error
    mov ax,4300h
    int 2fh         ;XMS host available?
    test al,80h
    mov bp,CStr("No XMS host detected.")
    jz @@error
    mov ax,4310h
    int 2fh
    mov word ptr [xmsaddr+0],bx
    mov word ptr [xmsaddr+2],es

    mov ah,5        ;local enable A20
    call xmsaddr

    push ds
    lds dx,fname
    mov ax,3D00h
    int 21h
    pop ds
    mov bp,CStr("cannot open file.")
    jc  @@error
    mov fhandle,ax
    mov bx,ax
;--- load the file header
    sub sp,4096
    mov cx,sizeof IMAGE_DOS_HEADER
    mov dx,sp
    mov ah,3Fh
    int 21h
    cmp ax,cx
    mov bp,CStr("invalid file format.")
    jnz @@error
    mov di,sp
    cmp word ptr [di].IMAGE_DOS_HEADER.e_magic,"ZM"
    mov bp,CStr("invalid file format (no MZ header).")
    jnz @@error
    cmp word ptr [di].IMAGE_DOS_HEADER.e_lfarlc,sizeof IMAGE_DOS_HEADER
    mov bp,CStr("invalid file format (MZ header too small).")
    jb @@error
    mov cx,word ptr [di].IMAGE_DOS_HEADER.e_lfanew+2
    mov dx,word ptr [di].IMAGE_DOS_HEADER.e_lfanew+0
    mov ax,4200h
    int 21h
    mov dx,offset nthdr
    mov cx,sizeof IMAGE_NT_HEADERS
    mov ah,3Fh
    int 21h
    cmp ax,cx
    mov bp,CStr("invalid file format (cannot locate PE header).")
    jnz @@error
    cmp dword ptr nthdr.Signature,"EP"
    mov bp,CStr("invalid file format (no PE header).")
    jnz @@error
    cmp nthdr.FileHeader.Machine,IMAGE_FILE_MACHINE_AMD64
    mov bp,CStr("not a 64-bit binary.")
    jnz @@error
    test nthdr.FileHeader.Characteristics,IMAGE_FILE_RELOCS_STRIPPED
    mov bp,CStr("relocations stripped, cannot load.")
    jnz @@error
    cmp nthdr.OptionalHeader.Subsystem,IMAGE_SUBSYSTEM_NATIVE
    mov bp,CStr("subsystem not native, cannot load.")
    jnz @@error
    cmp nthdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT*sizeof IMAGE_DATA_DIRECTORY].Size_,0
    mov bp,CStr("image contains imports, cannot load.")
    jnz @@error
    cmp dword ptr nthdr.OptionalHeader.SizeOfStackReserve+4,0
    mov bp,CStr("requested stack size of image is > 4 GB.")
    jnz @@error
if ?HEAP
    cmp dword ptr nthdr.OptionalHeader.SizeOfHeapReserve+4,0
    mov bp,CStr("requested heap size of image is > 4 GB.")
    jnz @@error
endif
    mov edx, nthdr.OptionalHeader.SizeOfImage
    mov eax, dword ptr nthdr.OptionalHeader.SizeOfStackReserve
    shr edx,10      ;convert to kB
    shr eax,10      ;convert to kB
    add edx, eax
    jc @F
if ?HEAP
    mov eax, dword ptr nthdr.OptionalHeader.SizeOfHeapReserve
    shr eax,10
    add edx, eax
    jc @F
endif
    cmp edx,?MAXIMGSIZE
    jbe memsizeok
@@:
if ?HEAP
    mov bp,CStr("image+stack+heap require more than 1 GB.")
else
    mov bp,CStr("image+stack require more than 1 GB.")
endif
    jmp @@error
memsizeok:
;--- add space for IDT and page tables
;--- needed: 1 page  for IDT
;---         1 page  for PML4 (1 PML4E, 512 GB)
;---         1 page  for PDPT (64 PDPTEs, 64 * 1GB )
;---        64 pages for PD (64 * 512 * PDEs, each 2MB )
;--- total: 67 pages = 268 kB     
    add edx, (2+?PML4E+?PDPTE)*4 + 3 ;extra 3 kB since we need to align to page boundary

;--- allocate the extended memory block needed for image + systabs
    mov ah,89h
    call xmsaddr
    cmp ax,1
    mov bp,CStr("XMS memory allocation failed.")
    jnz @@error
    mov xmshdl, dx
    mov emm.dsthdl, dx
    mov emm2.dsthdl, dx
    mov ah,0Ch      ;lock EMB 
    call xmsaddr
    cmp ax,1
    mov bp,CStr("cannot lock EMB.")
    jnz @@error
    push dx
    push bx
    pop ebx

;--- align to page boundary

    mov ax,bx
    neg ax
    add ax,1000h
    and ax,0fffh   ;0000,0400,0800,0C00 converted to 0000, 0C00, 0800, 0400
    movzx eax,ax
    mov adjust, eax
    add eax, ebx
    mov PhysBase, eax
    add eax, 1000h*(1+1+?PML4E+?PDPTE)  ;1*IDT,1*PMLE, ?PML4E*PDPT, ?PDPTE*PD
    mov ImgBase, eax

;--- prepare EMB moves
    mov emm.srchdl, 0
    mov emm2.srchdl, 0
    mov word ptr emm.srcofs+2, ds
    mov word ptr emm2.srcofs+0, sp
    mov word ptr emm2.srcofs+2, ss
    mov eax,ImgBase
    sub eax,PhysBase
    add eax,adjust
    mov emm.dstofs,eax
    mov eax, adjust
    mov emm2.dstofs, eax

    push ds
    pop es

;--- init page tables
    mov di,sp
    call createPgTabs

;--- setup ebx/rbx with linear address of _TEXT64
    mov ebx,seg long_start
    shl ebx,4
    add [llgofs], ebx
    add [llgofs2], ebx
;--- init IDT
    mov eax,ImgBase
    sub eax,1000h
    mov dword ptr [IDTR+2], eax
    call createIDT
    mov cx, 1000h
    mov si, offset emm2
    call copy2ext ;copy IDT to extended memory

    mov ecx, sizeof IMAGE_NT_HEADERS
    mov si, offset emm
    mov word ptr [si].EMM.srcofs+0, offset nthdr
    call copy2ext ;copy PE header (ecx bytes) to extended memory
    mov word ptr [si].EMM.srcofs+0, offset sechdr

;--- now read & copy section headers ony by one;
;--- for each header read & copy section data.
    mov bx,fhandle
    xor cx,cx
    xor dx,dx
    mov ax,4201h	;get current file pos in DX:AX
    int 21h
    mov cx,nthdr.FileHeader.NumberOfSections
    .while cx
        push cx
        push dx
        push ax
        mov cx,dx
        mov dx,ax
        mov ax,4200h	;set file pos
        int 21h
        mov dx,offset sechdr
        mov cx,sizeof IMAGE_SECTION_HEADER
        mov ah,3Fh
        int 21h
        cmp ax,cx
        mov bp,CStr("cannot load section headers.")
        jnz @@error
        mov si,offset emm
        call copy2ext	;copy section header to PE header in image
        call readsection
        pop ax
        pop dx
        add ax,sizeof IMAGE_SECTION_HEADER
        adc dx,0
        pop cx
        dec cx
    .endw

    add sp,4096

    mov ah,3Eh
    int 21h
    mov fhandle,-1

;--- done setup the extended memory block;
;--- page tabs, IDT and image are initialized.

;--- disable int 23h termination (myint23)
;--- or exit program (@@exit2)
;    mov dx,offset myint23
    mov dx,offset @@exit2
    mov ax,2523h
    int 21h

    call setints
if ?MPIC ne 8
    in al,21h
    mov bPICM,al
endif
if ?SPIC ne 70h
    in al,0A1h
    mov bPICS,al
endif

    cli
    mov dx,?SPIC shl 8 or ?MPIC
    call setpic
    @lgdt [GDTR]
    @lidt [IDTR]

    mov edx,PhysBase    ; 24.10.2020: set CR3 here, after all DOS/XMS stuff is done
    mov cr3,edx         ; load page-map level-4 base

;--- long_start expects linear address of image base (PE header) in ebx.
;--- obsolete, since the variables may be accessed from 64-bit directly.
;    mov ebx,ImgBase

    mov eax,cr4
    or ax,220h          ; enable PAE (bit 5) and OSFXSR (bit 9)
    mov cr4,eax

    mov ecx,0C0000080h  ; EFER MSR
    rdmsr
    or ah,1             ; enable long mode
    wrmsr

;--- enable protected-mode + paging
    mov eax,cr0
    or eax,80000001h
    mov cr0,eax

    db 66h,0eah         ; jmp far32
llgofs dd offset long_start
    dw SEL_CODE64
@@error::
    mov si,bp
nextchar:
    lodsb
    and al,al
    jz done
    mov dl,al
    mov ah,2
    int 21h
    jmp nextchar
newline db 13,10,'$'
done:
    mov dx,offset newline
    mov ah,9
    int 21
    jmp @@exit
myint23:
    iret
start16 endp

;--- copy cx bytes to extended memory

copy2ext proc
    mov [si].EMM._size,ecx
    push ecx
    push bx
    mov ah,0bh
    call xmsaddr
    pop bx
    pop ecx
    cmp ax,1
    mov bp,CStr("error copying to extended memory.")
    jnz @@error
    add [si].EMM.dstofs,ecx
    ret
copy2ext endp

;--- read a section and copy it to extended memory
;--- DI = 4 kB buffer
;--- BX = file handle
;--- sechdr = current section

readsection proc

    mov eax, sechdr.VirtualAddress
    add eax, adjust
    add eax, ImgBase
    sub eax, PhysBase
    mov emm2.dstofs, eax

    mov dx, word ptr sechdr.PointerToRawData+0
    mov cx, word ptr sechdr.PointerToRawData+2
    mov ax,4200h
    int 21h
    mov esi, sechdr.SizeOfRawData
    .while esi
        mov ecx,esi
        cmp ecx,1000h
        jb @F
        mov cx,1000h
@@:
        mov dx,di
        mov ah,3Fh
        int 21h
        cmp ax,cx
        mov bp, CStr("cannot read section data.")
        jnz @@error
        sub esi, ecx
        push si
        mov si,offset emm2
        call copy2ext
        pop si
    .endw
    ret
readsection endp

;--- switch back to real-mode and exit

backtoreal proc

    mov eax,cr0
    and eax,7ffffffeh   ; disable protected-mode & paging
    mov cr0,eax
    jmp far16 ptr @F
@@:
@@exit2::
    mov ax, cs
    mov ss, ax          ; SS=DGROUP
    mov ds, ax          ; DS=DGROUP
    @lidt [nullidt]     ; IDTR=real-mode compatible values

    mov ecx,0C0000080h  ; EFER MSR
    rdmsr
    and ah,0feh         ; disable long mode (EFER.LME=0)
    wrmsr

    mov eax,cr4
    and al,0DFh         ; reset bit 5, disable PAE paging
    mov cr4,eax

    mov dx,7008h
    call setpic
    call restoreints
@@exit::
    sti
    mov bx,fhandle
    cmp bx,-1
    jz @F
    mov ah,3Eh
    int 21h
@@:
    mov dx,xmshdl
    cmp dx,-1
    jz @F
    mov ah,0dh          ;unlock handle
    call xmsaddr
    mov ah,0Ah          ;free EMB
    mov dx,xmshdl
    call xmsaddr
@@:
    cmp xmsaddr,0
    jz @F
    mov ah,6            ;local disable A20
    call xmsaddr
@@:
    mov ax,4c00h
    int 21h
backtoreal endp

;--- switch to real-mode

switch2rm proc
;--- disable paging & protected-mode
    mov eax,cr0
    and eax,7ffffffeh
    mov cr0, eax
    jmp far16 ptr @F
@@:
;--- disable long mode
if ?RESETLME
    mov ecx,0C0000080h  ; EFER MSR
    rdmsr
    and ah,0feh
    wrmsr
endif
if ?RESETPAE
    mov eax,cr4
    and al,0DFh         ; reset bit 5, disable PAE paging
    mov cr4,eax
endif
    @lidt cs:[nullidt]  ; IDTR=real-mode compatible values
    ret
switch2rm endp

;--- switch to protected-mode

switch2pm proc
    @lgdt cs:[GDTR]
    @lidt cs:[IDTR]
;--- (re)enable long mode
if ?RESETLME
    mov ecx,0C0000080h  ; EFER MSR
    rdmsr
    or ah,1
    wrmsr
endif
if ?RESETPAE
    mov eax,cr4
    or ax,220h          ; enable PAE (bit 5) and OSFXSR (bit 9)
    mov cr4,eax
endif
if ?SETCR3
    mov eax,cr3
    cmp eax,cs:PhysBase
    jz @F
    mov eax,cs:PhysBase
    mov cr3,eax
@@:
endif
;--- enable protected-mode + paging
    mov eax,cr0
    or eax,80000001h
    mov cr0,eax
    ret
switch2pm endp

;--- call real-mode thru DPMI function ax=0x300
;--- SS=DGROUP; interrupts disabled
;--- SP->modified RMCS, without CS:IP;
;--- variable dwCSIP contains real-mode CS:IP

call_rmode proc

    call switch2rm
    popad
    pop cs:wFlags
    pop es
    pop ds
    pop fs
    pop gs
    lss sp,[esp]
    push cs:wFlags   ;make an IRET frame
    push DGROUP      ;CS still holds a selector!
    push backtopm
    jmp cs:[dwCSIP]
backtopm:
    lss sp,dword ptr cs:wStkBot
    push gs
    push fs
    push ds
    push es
    pushf
    cli
    pushad
    movzx esp,sp
    call switch2pm
    db 66h,0eah         ; jmp far32
llgofs2 dd offset back_to_long
    dw SEL_CODE64

call_rmode endp

;--- initialize interrupt gates in IDT 64-bit

make_int_gates proc
    mov eax, edx
    add eax, ebx
    stosw
    mov ax,SEL_CODE64
    stosw
    mov ax,si           ;int/trap gate
    stosd
    xor eax, eax
    stosd
    stosd
    loop make_int_gates
    ret
make_int_gates endp

;--- create IDT for long mode
;--- DI->4 KB buffer
;--- EBX->linear address of _TEXT64 segment

createIDT proc

    push di
    mov cx,32
    mov edx, offset exception
    add edx, ebx
make_exc_gates:
    mov eax,edx
    stosw
    mov ax,SEL_CODE64
    stosw
    mov ax,8E00h
    stosd
    xor eax, eax
    stosd
    stosd
    add edx,4
    loop make_exc_gates
    mov ecx,256-32
    mov edx,offset swint
    mov si, 8F00h
    call make_int_gates
    pop di

    push di
    push di
    lea di,[di+?MPIC*16]
    mov cx,8
    mov edx,offset Irq0007
    mov si, 8E00h
    call make_int_gates
    pop di
    lea di,[di+?SPIC*16]
    mov cx,8
    mov edx,offset Irq080F
    call make_int_gates
    pop di

;--- setup IRQ0, Int21, Int31

    mov si,offset tab1
    mov cx,sizetab1
nextitem:
    lodsw
    mov dx,ax
    lodsw
    movzx eax,ax
    add eax, ebx
    shl dx,4
    push di
    add di,dx
    mov [di],ax
    shr eax,16
    mov [di+6],ax
    pop di
    loop nextitem
    ret

tab1 label word
    dw ?MPIC+0, offset clock
    dw ?MPIC+1, offset kbd
    dw 21h,     offset int21
    dw 31h,     offset int31
sizetab1 equ ($-tab1) shr 2

createIDT endp

;--- setup page directories and tables
;--- DI -> 4 kB buffer
;--- example: 1.5 TB -> 3 PML4E, 3*200 PDPTE, 600*200 PDE
;--- cr3 = 4000
;---   4000: PML4.0 = 5000+000*1000 = 5000
;---   4008: PML4.1 = 5000+001*1000 = 6000
;---   4010: PML4.2 = 5000+002*1000 = 7000
;---   5000: PDPT.0   = 8000+000*1000 =   8000
;---   6000: PDPT.200 = 8000+200*1000 = 208000
;---   7000: PDPT.400 = 8000+400*1000 = 408000
;---   7FF8: PDPT.5FF = 8000+5FF*1000 = 607000
;---   8000: PD.0.0     =  00.00000000
;--- 208000: PD.200.0   = 100.00000000
;--- 408000: PD.400.0   = 200.00000000
;--- 607FF8: PD.5FF.1FF = 2FF.FFE00000

createPgTabs proc

    mov edx,PhysBase
;    mov cr3,edx            ; 24.10.2020: loading CR3 here was too early
    mov esi,1000h
    xor ebx,ebx
    add edx,esi

    xor ecx,ecx
;    or edx,111b            ;set P,R/W,U
    or edx,11b              ;set P,R/W,S
    mov cx,?PML4E           ; map PML4Es (default is 1)
    call setuppage
if ?PDPTE lt 10000h
    mov cx,?PDPTE           ; map PDPTEs (default is 64)
else
    mov ecx,?PDPTE          ; if 64 or more TB are to be mapped
endif
    call setuppages
    mov ecx,?PDPTE*512      ; map PDEs (default is 64*512)
    mov edx,80h+11b         ; set PS (bit 7 -> page size = 2 MB)
;   mov esi,200000h
    shl esi,9
setuppages:
    mov ebp,ecx
    .while ebp
        mov ecx,1000h/8
        cmp ebp,ecx
        jae @F
        mov cx,bp
@@:
        sub ebp,ecx
        call setuppage
    .endw
    ret
setuppage:
    push di
    mov ax,1000h/4
    sub ax,cx
    sub ax,cx
    push ax
@@:
    mov eax,edx
    stosd
    mov eax,ebx
    stosd
    add edx, esi
    adc ebx, 0
    loop @B
    pop cx
    xor eax,eax
    rep stosd       ;clear the rest of the page
    push si
    push bp
    mov si,offset emm2
    mov cx,1000h
    call copy2ext
    pop bp
    pop si
    pop di
    ret
createPgTabs endp

;--- restore the interrupt vectors that we have modified
;--- DS=DGROUP

restoreints proc
    push 0
    pop es
if ?MPIC ne 8
    mov cx,8
    mov di,?MPIC*4
    mov si,offset storedIntM
    rep movsd
endif
if ?SPIC ne 70h
    mov cx,8
    mov di,?SPIC*4
    mov si,offset storedIntS
    rep movsd
endif
    ret
restoreints endp

;--- set the interrupt vectors that we will
;--- use for IRQs while in long mode. This avoids
;--- having to reprogram PICs for switches to real-mode
;--- DS=DGROUP

setints proc
    push 0
    pop es
if ?MPIC ne 8
    mov cx,8
    mov bx,?MPIC*4
    mov di,offset storedIntM
@@:
    mov eax, es:[bx]
    mov [di], eax
    add bx,4
    add di,4
    loop @B
endif
if ?SPIC ne 70h
    mov cx,8
    mov bx,?SPIC*4
    mov di,offset storedIntS
@@:
    mov eax, es:[bx]
    mov [di], eax
    add bx,4
    add di,4
    loop @B
endif
    push ds
    push es
    pop ds
if ?MPIC ne 8
    mov cx,8
    mov si,8*4
    mov di,?MPIC*4
    rep movsd
endif
if ?SPIC ne 70h
    mov cx,8
    mov si,70h*4
    mov di,?SPIC*4
    rep movsd
endif
    pop ds
    ret

setints endp

;--- reprogram/restore PIC
;--- DS=DGROUP

setpic proc

;--- change IRQ 0-7 to ?MPIC
if ?MPIC ne 8
    mov al,10001b       ; ICW1: initialization
    out 20h,al
    mov al,dl           ; ICW2: IRQ 0-7: interrupts ?MPIC-?MPIC+7
    out 21h,al
    mov al,100b         ; ICW3: slave connected to IRQ2
    out 21h,al
    mov al,1            ; ICW4: Intel environment, manual EOI
    out 21h,al
    mov al,bPICM
    out 21h,al
endif
;--- change IRQ 8-F to ?SPIC
if ?SPIC ne 70h
    mov al,10001b       ; ICW1: initialization
    out 0A0h,al
    mov al,dh           ; ICW2: IRQ 8-15: interrupts ?SPIC-?SPIC+7
    out 0A1h,al
    mov al,2            ; ICW3:
    out 0A1h,al
    mov al,1            ; ICW4: Intel environment, manual EOI
    out 0A1h,al
    mov al,bPICS
    out 0A1h,al
endif
    ret
setpic endp

;--- here's the 64bit code segment.

_TEXT64 segment para use64 public 'CODE'

;    assume ds:FLAT, es:FLAT, ss:FLAT

long_start proc

;--- ensure ss is valid.
    mov ax,SEL_DATA16
    mov ss,eax

;--- linear address of image start (=PE header) should be in ebx.
;--- obsolete, since variables in DGROUP may be accessed directly.

;    mov ebx,ebx     ; clear high32 of rbx
    mov ebx, ImgBase

    mov ecx,[rbx].IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage
    add rcx,[rbx].IMAGE_NT_HEADERS.OptionalHeader.SizeOfStackReserve
    add rcx,rbx
    mov rsp,rcx
    sti             ; stack ok, interrupts can be used
    call baserelocs	; handle base relocations

    mov esi,[rbx].IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
    add rsi,rbx
    call rsi
    mov ah,4Ch
    int 21h
long_start endp

;--- handle base relocs of PE image

baserelocs proc
    mov esi, [rbx].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
    mov ecx, [rbx].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof IMAGE_DATA_DIRECTORY].Size_
    mov rdx, rbx
    sub rdx, [rbx].IMAGE_NT_HEADERS.OptionalHeader.ImageBase
    add esi, ebx    ;RVA->linear
    add ecx, esi    ;ecx=end of relocs (linear)
nextpage:
    cmp esi, ecx
    jnc reloc_done
    push rcx
    lodsd           ;get RVA of page
    lea edi, [rax+rbx]  ;convert RVA to linear address
    lodsd
    lea ecx, [rsi+rax-8];ecx=end of relocs for this page
    xor eax, eax
nextreloc:
    lodsw
    test ah,0F0h        ;must be < 1000h (size of a page)
    jz ignreloc
    and ah,0Fh			;usually it's type 0A (dir64)
    add [rax+rdi], edx
ignreloc:
    cmp esi, ecx
    jb nextreloc
    pop rcx
    jmp nextpage
reloc_done:
    ret
baserelocs endp

;--- low level screen output for default exception handlers

WriteChr proc
    push rdx
    cmp al,10
    jnz @F
    mov dl,13
    mov ah,2
    int 21h
    mov al,10
@@:
    mov dl,al
    mov ah,2
    int 21h
    pop rdx
    RET
WriteChr endp

WriteStrX proc  ;write string at rip
    push rsi
    mov rsi, [rsp+8]
    cld
@@:
    lodsb
    and al,al
    jz @F
    call WriteChr
    jmp @B
@@:
    mov [rsp+8],rsi
    pop rsi
    ret
WriteStrX endp

WriteQW:        ;write QWord in rax
    push rax
    shr rax,32
    call WriteDW
    pop rax
WriteDW:
    push rax
    shr rax,16
    call WriteW
    pop rax
WriteW:
    push rax
    shr rax,8
    call WriteB
    pop rax
WriteB:     ;write Byte in al
    push rax
    shr rax,4
    call WriteNb
    pop rax
WriteNb:
    and al,0Fh
    add al,'0'
    cmp al,'9'
    jbe @F
    add al,7
@@:
    jmp WriteChr

;--- exception handler
;--- might not work for exception 0Ch, since stack isn't switched.

exception:
excno = 0
    repeat 32
    push excno
    jmp @F
    excno = excno+1
    endm
@@:
    call WriteStrX
    db 10,"Exception ",0
    pop rax
    call WriteB
    call WriteStrX
    db " rsp=",0
    mov rax,rsp
    call WriteQW
    call WriteStrX
    db " imagebase=",0
    mov eax,[ImgBase]
    call WriteDW
if 0
    call WriteStrX
    db " rsi=",0
    mov rax,rsi
    call WriteQW
    call WriteStrX
    db " rdi=",0
    mov rax,rdi
    call WriteQW
endif
    call WriteStrX
    db 10,"[rsp]=",0
    xor ecx,ecx
@@:
    mov rax,[rsp+rcx*8]
    call WriteQW
    mov al,' '
    call WriteChr
    inc ecx
    cmp ecx,4
    jnz @B
    call WriteStrX
    db 10,"      ",0
@@:
    mov rax,[rsp+rcx*8]
    call WriteQW
    mov al,' '
    call WriteChr
    inc ecx
    cmp ecx,8
    jnz @B
    mov al,10
    call WriteChr
    mov ax,4cffh
    int 21h

;--- IRQs 0-7

;--- macro @call_rm_irq, defines 16-bit part of interrupt routing

@call_rm_irq macro procname, interrupt
procname proc
    push eax
if ?RESETLME
    push ecx
    push edx
endif
    call switch2rm  ;modifies eax [, ecx, edx]
    mov ss,cs:[wStkBot+2]	; load ss with a real-mode segment
    int interrupt
    cli
    call switch2pm  ;modifies eax [, ecx, edx]
if ?RESETLME
    pop edx
    pop ecx
endif
    pop eax
    retd
procname endp
endm

;--- macro @route_irq, defines 64-bit part of interrupt routing

@route_irq macro interrupt, prefix
    .code
    @call_rm_irq prefix&_rm,interrupt
    .data
p&prefix&_rm label fword
    dd offset prefix&_rm
    dw SEL_CODE16
    .code _TEXT64
prefix:
    mov [qwRSP],rsp
    mov sp,[wStkBot]
    call p&prefix&_rm
    mov rsp,[qwRSP]
    iretq
endm

;--- route irq 1 (kbd) to real-mode
    @route_irq 09h, kbd

;--- pit clock IRQ

if ?IRQ0TORM
;--- route irq 0 (pit clock) to real-mode
    @route_irq 08h, clock
else
clock:
    inc dword ptr flat:[46Ch]
endif
Irq0007:
    push rax
Irq0007_1:
    mov al,20h
    out 20h,al
    pop rax
swint:
    iretq
;--- IRQs 8-F
Irq080F:
    push rax
    mov al,20h
    out 0A0h,al
    jmp Irq0007_1

;--- load lower 32-bit of 64-bit regs without loosing the upper 32bits

@loadreg macro reg
    push R&reg
    mov E&reg,[rsp+8].RMCS.rE&reg
    mov [rsp],E&reg
    pop R&reg
endm

;--- simple int 21h handler.
;--- handles ah=4Ch
;--- any other DOS function is transfered to real-mode

int21 proc
    cmp ah,4Ch
    jz int21_4c
    and byte ptr [rsp+2*8],0FEh ;clear carry flag
    sub rsp,38h
    mov [rsp].RMCS.rEDI, edi
    mov [rsp].RMCS.rESI, esi
    mov [rsp].RMCS.rEBP, ebp
    mov [rsp].RMCS.rEBX, ebx
    mov [rsp].RMCS.rEDX, edx
    mov [rsp].RMCS.rECX, ecx
    mov [rsp].RMCS.rEAX, eax
    mov [rsp].RMCS.rFlags, 0202h
;    mov [rsp].RMCS.rES, STACK
;    mov [rsp].RMCS.rDS, STACK
    mov [rsp].RMCS.rES, es
    mov [rsp].RMCS.rDS, ds
    mov [rsp].RMCS.rFS, fs
    mov [rsp].RMCS.rGS, gs
    mov dword ptr [rsp].RMCS.regSP, 0
    push rdi
    lea rdi,[rsp+8]
    mov bx,21h
    mov cx,0
    mov ax,0300h
    int 31h
    pop rdi
    jc int21_carry
    mov al,byte ptr [rsp].RMCS.rFlags
    mov byte ptr [rsp+38h+2*8],al    ;set CF,ZF,...
    jmp @F
int21_carry:
    or  byte ptr [rsp+38h+2*8],1    ;set carry flag
@@:
    @loadreg DI
    @loadreg SI
    @loadreg BP
    @loadreg BX
    @loadreg DX
    @loadreg CX
    @loadreg AX
    lea rsp,[rsp+38h]
    iretq
    .data
pback_to_real label ptr far16
    dw offset backtoreal
    dw SEL_CODE16
    .code _TEXT64
int21_4c:
    cli
    mov sp,[wStkBot]
    jmp [pback_to_real]
int21 endp

int31 proc
    and byte ptr [rsp+2*8],0FEh	;clear carry flag
    cmp ax,0300h	;simulate real-mode interrupt?
    jz int31_300
    cmp ax,0203h	;set exception vector?
    jz int31_203
ret_with_carry:
    or byte ptr [rsp+2*8],1 ;set carry flag
    iretq
    .data
pcall_rmode label ptr far16
    dw offset call_rmode
    dw SEL_CODE16
    .code _TEXT64
int31_300:
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    mov rsi,rdi

;--- the contents of the RMCS has to be copied
;--- to conventional memory. We use the DGROUP stack.

    mov ecx,DGROUP
    shl ecx,4
    movzx ebx,bl
    mov eax,[rbx*4]
    mov bx,[wStkBot] 
    sub bx,30h   ;sizeof RMCS, without CS:IP 
    lea edi,[rbx+rcx]
    mov [dwCSIP],eax
    mov [qwRSP],rsp
    cld
    cli
    movsq   ;copy 2Ah bytes
    movsq
    movsq
    movsq
    movsq
    movsw
    lodsq   ;get CS:IP & SS:SP
    shr rax,32  ;skip CS:IP
    and eax,eax
    jnz @F
    mov eax,dword ptr [wStkBot]
@@:
    stosd
    mov esp,ebx	;clear highword ESP, ESP is used inside call_rmode
    jmp [pcall_rmode]
back_to_long::
    mov edx,DGROUP
    shl edx,4
    lea esi,[esp+edx]

;    mov ax,SEL_DATA16  ;SS will be restored by IRETQ
;    mov ss,eax         ;but interrupts need a valid SS
    mov rsp,[qwRSP]

    mov rdi,[rsp]
    cld
    movsq   ;copy 2Ah bytes back, don't copy CS:IP & SS:SP fields
    movsq
    movsq
    movsq
    movsq
    movsw
;    sti
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    iretq
int31_203:
    cmp bl,20h
    jae ret_with_carry
    push rax
    push rdi
;    sub rsp,16
;    sidt [rsp]
;    mov rdi,[rsp+2]
;    add rsp,16
    mov edi, dword ptr [IDTR+2]
    movzx eax,bl
    shl eax,4
    add rdi,rax
    mov rax,rdx
    cld
    stosw
    mov ax,cx
    stosw
    mov ax,8E00h
    stosd           ;+store highword edx!
    shr rax,32
    stosd
    pop rdi
    pop rax
    iretq
int31 endp

_TEXT64 ends

    end start16
