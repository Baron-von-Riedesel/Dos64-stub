
;--- DOS stub program which switches to long-mode and back.
;--- Note: requires at least JWasm v2.
;--- Also: needs a 64bit cpu in real-mode to run.
;--- To create the binary enter:
;---  JWasm -mz DOS64stb.asm

    .x64p
    option casemap:none

    include peimage.inc

    option MZ:sizeof IMAGE_DOS_HEADER   ;set min size of MZ header if jwasm's -mz option is used

EMM struct  ;XMS block move help struct
_size  dd ?
srchdl dw ?
srcofs dd ?
dsthdl dw ?
dstofs dd ?
EMM ends

@stosw macro
    db 67h
    stosw
endm
@stosd macro
    db 67h
    stosd
endm
@lodsw macro
    db 67h
    lodsw
endm
@lodsd macro
    db 67h
    lodsd
endm
@lgdt macro addr
    db 66h
    lgdt addr
endm

@wait macro
local sm1
;    push eax
sm1:
    in al,64h       ;key from keyboard arrived?
    test al,1
    jz sm1
    in al,60h
    cmp al,81h      ;wait for ESC released
    jnz sm1
;    pop eax
endm

@errorexit macro text
local sym
    mov dx,offset sym
    mov ah,9
    int 21h
    jmp exit
sym db text,13,10,'$'
endm

@fatexit macro text
local sym
    mov dx,offset sym
    mov ah,9
    int 21h
    mov ah,4Ch
    int 21h
sym db text,13,10,'$'
endm

;--- 16bit start/exit code

SEL_CODE64 equ 1*8
SEL_CODE32 equ 2*8
SEL_DATA32 equ 3*8
SEL_FLAT   equ 4*8
SEL_CODE16 equ 5*8
SEL_DATA16 equ 6*8

_TEXT16 segment use16 para public 'CODE'

    assume ds:_TEXT16
    assume es:_TEXT16

GDTR label fword        ; Global Descriptors Table Register
    dw 7*8-1            ; limit of GDT (size minus one)
    dd offset GDT       ; linear address of GDT
IDTR label fword        ; IDTR in 64-bit mode
    dw 256*16-1         ; limit of IDT (size minus one)
    dd 0                ; linear address of IDT
IDTR32 label fword      ; IDTR in 32-bit mode
    dw 16*8-1           ; limit of IDT (size minus one)
    dd offset IDT32
nullidt label fword
    dw 3FFh
    dd 0
llg label fword
llgofs dd offset long_start
    dw SEL_CODE64
  
    align 8
GDT dq 0                    ; null descriptor
    dw 0FFFFh,0,9A00h,0AFh  ; 64-bit code descriptor
    dw 0FFFFh,0,9A00h,040h  ; compatibility mode code descriptor
    dw 0FFFFh,0,9200h,040h  ; compatibility mode data descriptor
    dw 0FFFFh,0,9200h,0CFh  ; flat data descriptor
    dw 0FFFFh,0,9A00h,0h    ; 16-bit, 64k code descriptor
    dw 0FFFFh,0,9200h,0h    ; 16-bit, 64k data descriptor

IDT32 dw offset exc3200+00,SEL_CODE32,8e00h,0
      dw offset exc3200+04,SEL_CODE32,8e00h,0
      dw offset exc3200+08,SEL_CODE32,8e00h,0
      dw offset exc3200+12,SEL_CODE32,8e00h,0
      dw offset exc3200+16,SEL_CODE32,8e00h,0
      dw offset exc3200+20,SEL_CODE32,8e00h,0
      dw offset exc3200+24,SEL_CODE32,8e00h,0
      dw offset exc3200+28,SEL_CODE32,8e00h,0
      dw offset exc3200+32,SEL_CODE32,8e00h,0
      dw offset exc3200+36,SEL_CODE32,8e00h,0
      dw offset exc3200+40,SEL_CODE32,8e00h,0
      dw offset exc3200+44,SEL_CODE32,8e00h,0
      dw offset exc3200+48,SEL_CODE32,8e00h,0
      dw offset exc320D   ,SEL_CODE32,8e00h,0
      dw offset exc3200+56,SEL_CODE32,8e00h,0
      dw offset exc3200+60,SEL_CODE32,8e00h,0

nthdr   IMAGE_NT_HEADERS <>
sechdr  IMAGE_SECTION_HEADER <>
xmsaddr dd 0
PhysAdr dd 0    ;physical address of allocated EMB
ImgBase dd 0
adjust  dd 0
fname   dd 0
emm     EMM <>
emm2    EMM <>
xmshdl  dw -1
fhandle dw -1
stkbot  dw 0 

?MPIC equ 80h
?SPIC equ 88h

wPICMask dw 0   ; variable to save/restore PIC masks

start16 proc
    push cs
    pop ds
    mov ax,cs
    movzx eax,ax
    shl eax,4
    add dword ptr [GDTR+2], eax ; convert offset to linear address
    add dword ptr [IDTR32+2], eax
    mov word ptr [GDT + SEL_DATA32 + 2], ax
    mov word ptr [GDT + SEL_CODE16 + 2], ax
    shr eax,16
    mov byte ptr [GDT + SEL_DATA32 + 4], al
    mov byte ptr [GDT + SEL_CODE16 + 4], al

    mov ax,_TEXT32
    movzx eax,ax
    shl eax,4
    mov word ptr [GDT + SEL_CODE32 + 2], ax ;set base in code and data descriptor
    shr eax,16
    mov byte ptr [GDT + SEL_CODE32 + 4], al

    mov ax,ss
    mov dx,es
    sub ax,dx
    mov bx,sp
    shr bx,4
    add bx,ax
    mov ah,4Ah
    int 21h         ; free unused memory
    push cs
    pop es

    mov ax,ss
    mov dx,cs
    sub ax,dx
    shl ax,4
    add ax,sp
    push ds
    pop ss
    mov sp,ax       ; make a TINY model, CS=SS=DS=ES
    mov stkbot,sp

    smsw ax
    test al,1
    jz @F
    @fatexit "Mode is V86. Need REAL mode to switch to LONG mode!"
@@:
    xor edx,edx
    mov eax,80000001h   ; test if long-mode is supported
    cpuid
    bt edx,29
    jc @F
    @fatexit "No 64bit cpu detected."
@@:
    mov ax,4300h
    int 2fh         ;XMS host available?
    test al,80h
    jnz @F
    @fatexit "No XMS host detected."
@@:
    push es
    mov ax,4310h
    int 2fh
    mov word ptr [xmsaddr+0],bx
    mov word ptr [xmsaddr+2],es
    pop es

    mov ah,5        ;local enable A20
    call xmsaddr

    push es
    mov ah,51h
    int 21h
    mov es,bx
    mov es,es:[002Ch]
    xor di,di
    xor al,al
@@:
    repnz scasb
    cmp byte ptr es:[di],0
    jnz @B
    add di,3
    mov word ptr fname+0,di
    mov word ptr fname+2,es
    pop es
    push ds
    lds dx,fname
    mov ax,3D00h
    int 21h
    pop ds
    jnc @F
    @errorexit "cannot open file."
@@:
    mov fhandle,ax
    mov bx,ax
;--- load the file header
    sub sp,4096
    mov cx,sizeof IMAGE_DOS_HEADER
    mov dx,sp
    mov ah,3Fh
    int 21h
    cmp ax,cx
    jz @F
    @errorexit "invalid file format."
@@:
    movzx edx,dx
    cmp word ptr [edx].IMAGE_DOS_HEADER.e_magic,"ZM"
    jz @F
    @errorexit "invalid file format (no MZ header)."
@@:
    cmp word ptr [edx].IMAGE_DOS_HEADER.e_lfarlc,sizeof IMAGE_DOS_HEADER
    jnc @F
    @errorexit "invalid file format (MZ header too small)."
@@:
    mov cx,word ptr [edx].IMAGE_DOS_HEADER.e_lfanew+2
    mov dx,word ptr [edx].IMAGE_DOS_HEADER.e_lfanew+0
    mov ax,4200h
    int 21h
    mov dx,offset nthdr
    mov cx,sizeof IMAGE_NT_HEADERS
    mov ah,3Fh
    int 21h
    cmp ax,cx
    jz @F
    @errorexit "invalid file format (cannot locate PE header)."
@@:
    movzx esi,cx
    cmp dword ptr nthdr.Signature,"EP"
    jz @F
    @errorexit "invalid file format (no PE header)."
@@:
    cmp nthdr.FileHeader.Machine,IMAGE_FILE_MACHINE_AMD64
    jz @F
    @errorexit "not a 64-bit binary."
@@:
    test nthdr.FileHeader.Characteristics,IMAGE_FILE_RELOCS_STRIPPED
    jz @F
    @errorexit "relocations stripped, cannot load."
@@:
    cmp nthdr.OptionalHeader.Subsystem,IMAGE_SUBSYSTEM_NATIVE
    jz @F
    @errorexit "subsystem not native, cannot load."
@@:
    cmp nthdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT*sizeof IMAGE_DATA_DIRECTORY].Size_,0
    jz @F
    @errorexit "image contains imports, cannot load."
@@:
    cmp dword ptr nthdr.OptionalHeader.SizeOfStackReserve+4,0
    jz @F
    @errorexit "requested stack size of image is > 4 GB."
@@:
    mov edx, nthdr.OptionalHeader.SizeOfImage
    add edx, dword ptr nthdr.OptionalHeader.SizeOfStackReserve
    jc imagetoolarge
    shr edx,10      ;convert to kB
    test edx,0ffff0000h
    jz @F
imagetoolarge:
    @errorexit "image requires too much memory."
@@:
;--- add space for IDT and page tables
;--- needed: 1 page  for IDT
;---         1 page  for PML4 (1 PML4E, 512 GB)
;---         1 page  for PDPT (64 PDPTEs, 64 * 1GB )
;---        64 pages for PD (64 * 512 * PDEs, each 2MB )
;--- total: 67 pages = 268 kB     
    add dx, 268 + 3 ;extra 3 since we need to align to page boundary
    jc imagetoolarge
    mov ah,9
    call xmsaddr
    cmp ax,1
    jz @F
    @errorexit "XMS memory allocation failed."
@@:
    mov xmshdl,dx
    mov ah,0Ch      ;lock EMB 
    call xmsaddr
    cmp ax,1
    jz @F
    @errorexit "cannot lock EMB."
@@:
    mov word ptr PhysAdr+0,bx
    mov word ptr PhysAdr+2,dx
    mov word ptr ImgBase+0,bx
    mov word ptr ImgBase+2,dx
;--- copy the header into extended memory
    mov ecx, esi
    mov emm.srchdl, 0
    mov word ptr emm.srcofs+0, offset nthdr
    mov word ptr emm.srcofs+2, ds
    mov ax,xmshdl
    mov emm.dsthdl,ax
    mov emm.dstofs,0

;--- align to page boundary
    and bx,0fffh
    jz @F
    mov eax,1000h
    sub ax,bx
    mov emm.dstofs,eax
    mov adjust, eax
    add ImgBase, eax
@@:

    mov si,offset emm
    call copy2x

    mov di,sp
    mov bx,fhandle
    mov cx,nthdr.FileHeader.NumberOfSections
    .while cx
        push cx
        mov dx,offset sechdr
        mov cx,sizeof IMAGE_SECTION_HEADER
        mov ah,3Fh
        int 21h
        cmp ax,cx
        jz @F
        @errorexit "cannot load section headers."
@@:
        mov si,offset emm
        call copy2x
        call readsection
        pop cx
        dec cx
    .endw

    add sp,4096

    mov ah,3Eh
    int 21h
    mov fhandle,-1

    cli
    @lgdt [GDTR]        ; use 32-bit version of LGDT

    mov eax,cr0
    bts eax,0           ; enable pmode
    mov cr0,eax

    db 0EAh             ; set CS to SEL_CODE32
    dw offset pmode32
    dw SEL_CODE32

_TEXT32 segment use32 para public 'CODE'

    assume es:FLAT

pmode32:
    mov ax,SEL_DATA32
    mov ss,ax
    movzx esp,sp
    mov ds,ax
    mov ax,SEL_FLAT
    mov es,ax

;--- handle base relocations
    mov edi, ImgBase
    mov esi, nthdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
    mov ecx, nthdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof IMAGE_DATA_DIRECTORY].Size_
    mov edx, edi
    sub edx, dword ptr nthdr.OptionalHeader.ImageBase
    add esi, edi    ;RVA->linear
    add ecx, esi    ;ecx=end of relocs (linear)
    push ds
    mov ax,SEL_FLAT
    mov ds,ax
    assume ds:flat
nextpage:
    cmp esi, ecx
    jnc reloc_done
    push ecx
    lodsd              ;get RVA of page
    mov ebx, eax
    add ebx, edi        ;convert RVA to linear address
    lodsd
    lea ecx, [esi+eax-8];ecx=end of relocs for this page
    xor eax, eax
nextreloc:
    lodsw
    test ah,0F0h        ;must be < 1000h (size of a page)
    jz ignreloc
    and ah,0Fh			;usually it's type 0A (dir64)
    add [eax+ebx], edx	;we adjust low32 only, since we cannot load beyond 4 GB
ignreloc:
    cmp esi, ecx
    jb nextreloc
    pop ecx
    jmp nextpage
reloc_done:
    pop ds
    assume ds:_TEXT16

;--- setup ebx/rbx with linear address of _TEXT
    mov bx,_TEXT
    movzx ebx,bx
    shl ebx,4
    add [llgofs], ebx

;--- create IDT

    mov edi,ImgBase
    add edi,nthdr.OptionalHeader.SizeOfImage
    add edi,dword ptr nthdr.OptionalHeader.SizeOfStackReserve
    mov dword ptr [IDTR+2], edi

    mov ecx,32
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
    mov ecx,128-32
    mov edx,offset swint
    mov si, 8F00h
    call make_int_gates
    mov cx,8
    mov edx,offset Irq0007
    mov si, 8E00h
    call make_int_gates
    mov cx,8
    mov edx,offset Irq080F
    call make_int_gates
    mov cx,128-16
    mov edx,offset swint
    mov si, 8E00h
    call make_int_gates

    lidt [IDTR]

    sub edi, 1000h

;--- setup IRQ0, IRQ1 and Int21

    lea eax, [ebx+offset clock]
    mov es:[edi+(?MPIC+0)*16+0],ax ; set IRQ 0 handler
    shr eax,16
    mov es:[edi+(?MPIC+0)*16+6],ax

    lea eax, [ebx+offset keyboard]
    mov es:[edi+(?MPIC+1)*16+0],ax ; set IRQ 1 handler
    shr eax,16
    mov es:[edi+(?MPIC+1)*16+6],ax

    lea eax,[ebx+offset int21]
    mov es:[edi+21h*16+0],ax ; set int 21h handler
    mov word ptr es:[edi+21h*16+4],8F00h    ;change to trap gate
    shr eax,16
    mov es:[edi+21h*16+6],ax

;--- setup page directories and tables

    add edi, 1000h
    add edi, 0fffh  ;align to page boundary
    and di,0f000h
    mov cr3, edi    ; load page-map level-4 base

    push edi
    mov ecx,02000h/4
    sub eax,eax
    rep stosd       ; clear 2 pages (PML4 & PDPT)
    pop edi

;--- DI+0    : PML4
;--- DI+1000 : PDPT

    push edi
    mov eax,edi
    or eax,111b
    add eax, 1000h
    mov es:[edi+0h],eax     ; set first PML4E in PML4 (bits 38-47)
    add edi,1000h           ; let EDI point to PDPT
    mov cx,64               ; map 64 PDPTEs
    add eax, 1000h
nextpdpte:
    mov es:[edi],eax        ; set PDPTE in PDPT (bits 30-37)
    add eax, 1000h
    add edi,8
    loop nextpdpte
    pop edi
    add edi,2000h

;--- map the first 64 GBs (64 * 512 * 2MB pages)

    mov dl,16       ;16 * 4 GB
    mov esi,0
next4gb:
;--- init 4 PDEs (4 * 4 kB); this maps 4 GB
    mov cx,512*4            ; number of PDE entries in PD
    mov eax,87h             ; set PS (bit 7 -> page size = 2 MB)
@@:
    mov es:[edi+0],eax      ; set PDE in PD (bits 21-29)
    mov es:[edi+4],esi
    add edi,8
    add eax, 200000h
    loop @B
    inc esi
    dec dl
    jnz next4gb

;--- reprogram PIC: change IRQ 0-7 to INT 80h-87h, IRQ 8-15 to INT 88h-8Fh

    in al,0A1h
    mov ah,al
    in al,21h
    mov [wPICMask],ax
    mov al,10001b       ; begin PIC 1 initialization
    out 20h,al
    mov al,10001b       ; begin PIC 2 initialization
    out 0A0h,al
    mov al,?MPIC        ; IRQ 0-7: interrupts 80h-87h
    out 21h,al
    mov al,?SPIC        ; IRQ 8-15: interrupts 88h-8Fh
    out 0A1h,al
    mov al,100b         ; slave connected to IRQ2
    out 21h,al
    mov al,2
    out 0A1h,al
    mov al,1            ; Intel environment, manual EOI
    out 21h,al
    out 0A1h,al
    in al,21h
    mov al,11111100b    ; enable only clock and keyboard IRQ
    out 21h,al
    in al,0A1h
    mov al,11111111b
    out 0A1h,al

    mov eax,cr4
    bts eax,5           ; enable physical-address extensions (PAE)
    bts eax,9           ; also enable OSFXSR (no exception using SSE)
    mov cr4,eax

    mov ecx,0C0000080h  ; EFER MSR
    rdmsr
    bts eax,8           ; enable long mode
    wrmsr

;--- long_start expects:
;--- ecx = value of ESP in 64-bit
;--- esi = value of EIP in 64-bit
;--- ebx = image start

    mov ebx,ImgBase
    mov esi,nthdr.OptionalHeader.AddressOfEntryPoint
    add esi,ebx
    mov ecx,dword ptr nthdr.OptionalHeader.SizeOfStackReserve
    add ecx,nthdr.OptionalHeader.SizeOfImage
    add ecx,ebx

    mov eax,cr0
    bts eax,31
    mov cr0,eax         ; enable paging

    jmp [llg]

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

_TEXT32 ends

start16 endp

_TEXT32 segment

;--- exception handlers for 32-bit mode

excno = 0
exc3200:
    repeat 32
    push excno
    jmp @F
    excno = excno+1
    endm
@@:
    hlt    ;interrupts are disabled, so just stop

    assume ss:flat
;--- exc 0d may occur if PAE paging cannot be enabled
exc320D:
    mov word ptr ss:[0B8000h],0720h
newloop:
    add byte ptr ss:[0B8000h],1
    jmp newloop

;--- leave 64-bit (compatibility) mode
;--- disable paging, switch temporarily to PAE paging
;--- then back again to 64-bit

callv86 proc far

    cli
    mov ax,SEL_FLAT
    mov ss,eax

;--- disable paging
    mov eax,cr0
    btr eax,31
    mov cr0, eax

;--- disable long mode
    mov ecx,0C0000080h  ; EFER MSR
    rdmsr
    btr eax,8
    wrmsr

;--- let CR3 point to PDPT
    mov eax, cr3
    add eax, 1000h
    and byte ptr ss:[eax+00],01h   ;reset bits 1-7
    and byte ptr ss:[eax+08],01h   ;of all 4 PDPTEs used for PAE paging
    and byte ptr ss:[eax+16],01h
    and byte ptr ss:[eax+24],01h 
    mov cr3, eax

;--- set IDT to 32-bit modus
    mov ax,SEL_DATA32
    mov ds,eax
    lidt [IDTR32]

;--- enable PAE paging
    mov eax,cr0
    bts eax,31
    mov cr0, eax

;--- disable paging
    mov eax,cr0
    btr eax,31
    mov cr0, eax

;--- let CR3 point to PML4 again
    mov eax, cr3
    or byte ptr ss:[eax+0], 6
    or byte ptr ss:[eax+8], 6
    or byte ptr ss:[eax+16], 6
    or byte ptr ss:[eax+24], 6
    sub eax, 1000h
    mov cr3, eax

;--- (re)enable long mode
    mov ecx,0C0000080h  ; EFER MSR
    rdmsr
    bts eax,8           ; set long mode
    wrmsr

;--- (re)enable paging
    mov eax,cr0
    bts eax,31
    mov cr0, eax

;--- reset IDT to 64-bit modus
    mov ax,SEL_DATA32
    mov ds,eax
    lidt [IDTR]

    sti
    mov al,8
    retf
callv86 endp
_TEXT32 ends


;--- switch back to real-mode and exit

backtoreal proc
    cli

    mov eax,cr0
    btr eax,31          ; disable paging
    mov cr0,eax

    mov ecx,0C0000080h  ; EFER MSR
    rdmsr
    btr eax,8           ; disable long mode (EFER.LME=0)
    wrmsr

    mov eax,cr4
    btr eax,5           ; disable PAE paging
    mov cr4,eax

    mov ax,SEL_DATA16   ; set SS, DS and ES to 16bit, 64k data
    mov ds,ax
    mov es,ax
    mov ss,ax
    movzx esp,stkbot

    mov eax,cr0         ; switch to real mode
    btr eax, 0
    mov cr0,eax
    db 0eah
    dw @F
    dw _TEXT16
@@:
    mov ax,STACK        ; SS=real-mode seg
    mov ss, ax

    push cs             ; DS=real-mode _TEXT16 seg
    pop ds

    lidt [nullidt]      ; IDTR=real-mode compatible values

;--- reprogram PIC: change IRQ 0-7 to INT 08h-0Fh, IRQ 8-15 to INT 70h-77h

    mov al,10001b       ; begin PIC 1 initialization
    out 20h,al
    mov al,10001b       ; begin PIC 2 initialization
    out 0A0h,al
    mov al,08h          ; IRQ 0-7: back to ints 8h-Fh
    out 21h,al
    mov al,70h          ; IRQ 8-15: back to ints 70h-77h
    out 0A1h,al
    mov al,100b         ; slave connected to IRQ2
    out 21h,al
    mov al,2
    out 0A1h,al
    mov al,1            ; Intel environment, manual EOI
    out 21h,al
    out 0A1h,al
    in al,21h

    mov ax,[wPICMask]   ; restore PIC masks
    out 21h,al
    mov al,ah
    out 0A1h,al

exit::
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
    sti
    mov ax,4c00h
    int 21h
backtoreal endp

;--- copy cx bytes to extended memory

copy2x proc
    mov [si].EMM._size,ecx
    push ecx
    push bx
    mov ah,0bh
    call xmsaddr
    pop bx
    pop ecx
    cmp ax,1
    jz @F
    @errorexit "error copying to extended memory."
@@:
    add [si].EMM.dstofs,ecx
    ret
copy2x endp

;--- read a section and copy it to extended memory
;--- DI = 4 kB buffer
;--- BX = file handle
;--- sechdr = current section

readsection proc
    mov ax,4201h
    xor cx,cx
    xor dx,dx
    int 21h
    push dx
    push ax

    mov emm2.srchdl, 0
    mov word ptr emm2.srcofs+0, di
    mov word ptr emm2.srcofs+2, ds
    mov ax,xmshdl
    mov emm2.dsthdl, ax
    mov eax, sechdr.VirtualAddress
    add eax, adjust
    mov emm2.dstofs, eax

    mov eax, sechdr.PointerToRawData
    push eax
    pop dx
    pop cx
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
        jz @F
        @errorexit "cannot read section data."
@@:
        sub esi, ecx
        push si
        mov si,offset emm2
        call copy2x
        pop si
    .endw
    pop dx
    pop cx
    mov ax,4200h
    int 21h
    ret
readsection endp

_TEXT16 ends

;--- here's the 64bit code segment.
;--- since 64bit code is always flat but the DOS mz format is segmented,
;--- there are restrictions - because the assembler doesn't know the
;--- linear address where the 64bit segment will be loaded:
;--- + direct addressing with constants isn't possible (mov [0B8000h],rax)
;---   since the rip-relative address will be calculated wrong.
;--- + 64bit offsets (mov rax, offset <var>) must be adjusted by the linear
;---   address where the 64bit segment was loaded (is in rbx).

_TEXT segment para use64 public 'CODE'

bChar   db 0        ;keyboard "buffer"

    assume ds:FLAT, es:FLAT, ss:FLAT

long_start proc
    mov esp,ecx
    sti             ; now interrupts can be used
    call rsi
    mov ah,4Ch
    int 21h
long_start endp

;--- screen output helpers

;--- set text mode cursor
set_cursor proc
    push rbp
    push rsi
    push rcx
    push rdx
    mov ebp,400h
    MOVZX esi, BYTE PTR [ebp+62h]         ;page
    MOVZX ecx, BYTE PTR [ebp+esi*2+50h+1] ;get cursor pos ROW
    MOVZX eax, WORD PTR [ebp+4Ah]         ;cols
    MUL ecx
    MOVZX edx, BYTE PTR [ebp+esi*2+50h]   ;get cursor pos COL
    ADD eax, edx
    movzx ecx,word ptr [ebp+4eh]
    shr ecx,1
    add ecx, eax
    mov dx,[ebp+63h]
    mov ah,ch
    mov al,0Eh
    out dx,ax
    inc al
    mov ah,cl
    out dx,ax
    pop rdx
    pop rcx
    pop rsi
    pop rbp
    ret
set_cursor endp

;--- scroll screen up one line
;--- rsi = linear address start of last line
;--- rbp = linear address of BIOS area (0x400)
scroll_screen proc
    CLD
    mov edi,esi
    movzx eax,word ptr [rbp+4Ah]
    push rax
    lea rsi, [rsi+2*rax]
    MOV CL, [rbp+84h]
    mul cl
    mov ecx,eax
    rep movsw
    pop rcx
    mov ax,0720h
    rep stosw
    ret
scroll_screen endp

;--- interprets 10 (line feed)

WriteChr proc
    push rbp
    push rdi
    push rsi
    push rbx
    push rcx
    push rdx
    push rax
    MOV edi,0B8000h
    mov ebp,400h
    CMP BYTE ptr [rbp+63h],0B4h
    JNZ @F
    XOR DI,DI
@@:
    movzx ebx, WORD PTR [rbp+4Eh]
    ADD edi, ebx
    MOVZX ebx, BYTE PTR [rbp+62h]
    mov esi, edi
    MOVZX ecx, BYTE PTR [rbx*2+rbp+50h+1] ;ROW
    MOVZX eax, WORD PTR [rbp+4Ah]
    MUL ecx
    MOVZX edx, BYTE PTR [rbx*2+rbp+50h]  ;COL
    ADD eax, edx
    MOV DH,CL
    LEA edi, [rdi+rax*2]
    MOV AL, [rsp]
    CMP AL, 13
    JZ skipchar
    CMP AL, 10
    JZ newline
    MOV [rdi], AL
    MOV byte ptr [rdi+1], 07
    INC DL
    CMP DL, BYTE PTR [rbp+4Ah]
    JB @F
newline:
    MOV DL, 00
    INC DH
    CMP DH, BYTE PTR [rbp+84h]
    JBE @F
    DEC DH
    CALL scroll_screen
@@:
    MOV [rbx*2+rbp+50h],DX
skipchar:
    pop rax
    pop rdx
    pop rcx
    pop rbx
    pop rsi
    pop rdi
    pop rbp
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
    mov dl,al
    mov ah,2
    int 21h
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
    mov dl,al
    mov ah,2
    int 21h
    ret

;--- exception handler

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
    db " errcode=",0
    mov rax,[rsp+0]
    call WriteQW
    call WriteStrX
    db " rip=",0
    mov rax,[rsp+8]
    call WriteQW
    call WriteStrX
    db 10,"[rsp]=",0
    mov rax,[rsp+16]
    call WriteQW
    mov al,' '
    call WriteChr
    mov rax,[rsp+24]
    call WriteQW
    mov al,' '
    call WriteChr
    mov rax,[rsp+32]
    call WriteQW
    mov al,' '
    call WriteChr
    mov rax,[rsp+40]
    call WriteQW
    call WriteStrX
    db 10,"      ",0
    mov rax,[rsp+48]
    call WriteQW
    mov al,' '
    call WriteChr
    mov rax,[rsp+56]
    call WriteQW
    mov al,' '
    call WriteChr
    mov rax,[rsp+64]
    call WriteQW
    mov al,' '
    call WriteChr
    mov rax,[rsp+72]
    call WriteQW
    mov al,10
    call WriteChr
    sti
    mov ax,4cffh
    int 21h

;--- clock and keyboard interrupts

clock:
    push rbp
    mov ebp,400h
    inc dword ptr [rbp+6Ch]
    pop rbp
Irq0007:
    push rax
Irq0007_1:
    mov al,20h
    out 20h,al
    pop rax
swint:
    iretq
Irq080F:
    push rax
    mov al,20h
    out 0A0h,al
    jmp Irq0007_1

keyboard:
    push rax
    in al,60h
    test al,80h
    jnz @F
    push rbx
    mov bx,_TEXT
    movzx ebx,bx
    shl ebx,4
    mov [ebx+offset bChar], al
    pop rbx
@@:
    in al,61h           ; give finishing information
    out 61h,al          ; to keyboard...
    mov al,20h
    out 20h,al          ; ...and interrupt controller
    pop rax
    iretq

         ;   0   1   2   3   4   5   6   7   8   9
keycodes db 0bh,02h,03h,04h,05h,06h,07h,08h,09h,0Ah
         ;   a   b   c   d   e   f   g   h   i   j
         db 1eh,30h,2eh,20h,12h,21h,22h,23h,17h,24h
         ;   k   l   m   n   o   p   q   r   s   t
         db 25h,26h,32h,31h,18h,19h,10h,13h,1fh,14h
         ;   u   v   w   x   y   z
         db 16h,2fh,11h,2dh,15h,2ch,1ch
lkeycodes equ $ - keycodes
chars    db '0123456789'
         db 'abcdefghij'
         db 'klmnopqrst'
         db 'uvwxyz',0dh

;--- simple int 21h handler.
;--- emulates functions
;---   01h : read from stdin with echo
;---   02h : write to stdout
;---   4Ch : terminate program

int21 proc
    cmp ah,01h
    jz int21_01
    cmp ah,02h
    jz int21_02
    cmp ah,0Bh
    jz int21_0b
    cmp ah,4Ch
    jz int21_4c
    cmp ah,30h
    jz int21_30
    or byte ptr [rsp+2*8],1 ;set carry flag
    iretq
int21_01:
    call set_cursor
    push rbx
    mov bx,_TEXT
    movzx ebx,bx
    shl ebx,4
nochar:
    cmp byte ptr [ebx+ offset bChar],0
    jnz @F
    hlt
    jmp nochar
@@:
    mov al,[ebx+ offset bChar]
    mov byte ptr [ebx+offset bChar],0
;--- check if the key is a 'known' one (alphanumeric or Enter)
    push rsi
    mov rsi,0
nextkey:
    cmp al,[rbx+rsi+offset keycodes]
    jz @F
    inc rsi
    cmp rsi,lkeycodes
    jnz nextkey
    pop rsi
    pop rbx
    jmp int21_01
@@:
    mov al,[rbx+rsi+offset chars]
    push rax
    cmp al,0dh
    jnz @F
    mov al,0ah
@@:
    call WriteChr
    pop rax
    pop rsi
    pop rbx
    iretq
int21_02:
    mov al,dl
    call WriteChr
    iretq
int21_0b:
    push rbx
    mov bx,_TEXT
    movzx ebx,bx
    shl ebx,4
    mov al,[ebx+offset bChar]
    cmp al,0
    jz @F
    mov al,0FFh
@@:
    pop rbx
    iretq
int21_4c:
    jmp [bv]
bv  label ptr far32
    dd offset backtoreal
    dw SEL_CODE16
int21_30:
    mov ax,SEL_FLAT ;call to compatibility mode requires a valid SS
    mov ss,ax
    call [v86]
    iretq
v86 label ptr far32
    dd offset callv86
    dw SEL_CODE32
int21 endp

_TEXT ends

;--- 5k stack, used in 16-bit modes

STACK segment use16 para stack 'STACK'
    db 5120 dup (?)
STACK ends

    end start16
