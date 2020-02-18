
;--- some constants and structures
;--- for 64-bit PE images.

SECTION_QUERY       equ 00001h
SECTION_MAP_WRITE   equ 00002h
SECTION_MAP_READ    equ 00004h
SECTION_MAP_EXECUTE equ 00008h
SECTION_EXTEND_SIZE equ 00010h

PAGE_NOACCESS           equ     1h
PAGE_READONLY           equ     2h
PAGE_READWRITE          equ     4h
PAGE_WRITECOPY          equ     8h
PAGE_EXECUTE            equ    10h
PAGE_EXECUTE_READ       equ    20h
PAGE_EXECUTE_READWRITE  equ    40h
PAGE_EXECUTE_WRITECOPY  equ    80h
PAGE_GUARD              equ   100h
PAGE_NOCACHE            equ   200h
MEM_COMMIT              equ  1000h
MEM_RESERVE             equ  2000h
MEM_DECOMMIT            equ  4000h
MEM_RELEASE             equ  8000h
MEM_FREE                equ 10000h
MEM_PRIVATE             equ 20000h
MEM_MAPPED              equ 40000h
MEM_RESET               equ 80000h


IMAGE_DOS_HEADER STRUCT
  e_magic           WORD      ?     ; 0
  e_cblp            WORD      ?     ; 2
  e_cp              WORD      ?     ; 4
  e_crlc            WORD      ?     ; 6 number of relocation records
  e_cparhdr         WORD      ?     ; 8
  e_minalloc        WORD      ?     ; 10
  e_maxalloc        WORD      ?     ; 12
  e_ss              WORD      ?     ; 14
  e_sp              WORD      ?     ; 16
  e_csum            WORD      ?     ; 18
  e_ip              WORD      ?     ; 20
  e_cs              WORD      ?     ; 22
  e_lfarlc          WORD      ?     ; 24 begin relocation records
  e_ovno            WORD      ?     ; 26
  e_res             WORD   4 dup(?) ; 28
  e_oemid           WORD      ?     ; 36
  e_oeminfo         WORD      ?     ; 38
  e_res2            WORD  10 dup(?) ; 40
  e_lfanew          DWORD      ?    ; 60
IMAGE_DOS_HEADER ENDS


IMAGE_FILE_HEADER struct    ;size=20
Machine              dw ?   ;0
NumberOfSections     dw ?
TimeDateStamp        dd ?   ;4
PointerToSymbolTable dd ?   ;8
NumberOfSymbols      dd ?   ;12
SizeOfOptionalHeader dw ?   ;16
Characteristics      dw ?
IMAGE_FILE_HEADER ends

;*** Characteristics ***

IMAGE_FILE_RELOCS_STRIPPED     equ 0001h
IMAGE_FILE_EXECUTABLE_IMAGE    equ 0002h
IMAGE_FILE_LINE_NUMS_STRIPPED  equ 0004h
IMAGE_FILE_LOCAL_SYMS_STRIPPED equ 0008h
IMAGE_FILE_LARGE_ADDRESS_AWARE equ 0020h
IMAGE_FILE_16BIT_MACHINE       equ 0040h
IMAGE_FILE_32BIT_MACHINE       equ 0100h
IMAGE_FILE_DEBUG_STRIPPED      equ 0200h
IMAGE_FILE_SYSTEM              equ 1000h
IMAGE_FILE_DLL                 equ 2000h

IMAGE_FILE_MACHINE_UNKNOWN    equ      0h
IMAGE_FILE_MACHINE_I386       equ    14ch
IMAGE_FILE_MACHINE_AMD64      equ   8664h


IMAGE_DATA_DIRECTORY struct
VirtualAddress    DWORD   ?
Size_             DWORD   ?
IMAGE_DATA_DIRECTORY ends

IMAGE_NUMBEROF_DIRECTORY_ENTRIES equ 16

IMAGE_OPTIONAL_HEADER64 struct  ;size 112+128 = 240
Magic                   dw ?    ;0
MajorLinkerVersion      db ?
MinorLinkerVersion      db ?
SizeOfCode              dd ?    ;4
SizeOfInitializedData   dd ?    ;8
SizeOfUninitializedData dd ?    ;12
AddressOfEntryPoint     dd ?    ;16
BaseOfCode              dd ?    ;20
ImageBase               dq ?    ;24
SectionAlignment        dd ?    ;32
FileAlignment           dd ?    ;36
MajorOperatingSystemVersion dw ?;40
MinorOperatingSystemVersion dw ?
MajorImageVersion       dw ?    ;44
MinorImageVersion       dw ?    
MajorSubsystemVersion   dw ?    ;48
MinorSubsystemVersion   dw ?
Win32VersionValue       dd ?    ;52
SizeOfImage             dd ?    ;56
SizeOfHeaders           dd ?    ;60
CheckSum                dd ?    ;64
Subsystem               dw ?    ;68
DllCharacteristics      dw ?
SizeOfStackReserve      dq ?    ;72
SizeOfStackCommit       dq ?    ;80
SizeOfHeapReserve       dq ?    ;88
SizeOfHeapCommit        dq ?    ;96
LoaderFlags             dd ?    ;104
NumberOfRvaAndSizes     dd ?    ;108
DataDirectory IMAGE_DATA_DIRECTORY  IMAGE_NUMBEROF_DIRECTORY_ENTRIES dup (<>)
IMAGE_OPTIONAL_HEADER64 ends

; Subsystem Values

IMAGE_SUBSYSTEM_UNKNOWN       equ    0   ; Unknown subsystem.
IMAGE_SUBSYSTEM_NATIVE        equ    1   ; Image doesn't require a subsystem.
IMAGE_SUBSYSTEM_WINDOWS_GUI   equ    2   ; Image runs in the Windows GUI subsystem.
IMAGE_SUBSYSTEM_WINDOWS_CUI   equ    3   ; Image runs in the Windows character subsystem.

; Directory Entries

IMAGE_DIRECTORY_ENTRY_EXPORT       equ   0  ; Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT       equ   1  ; Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE     equ   2  ; Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION    equ   3  ; Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY     equ   4  ; Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC    equ   5  ; Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG        equ   6  ; Debug Directory
IMAGE_DIRECTORY_ENTRY_COPYRIGHT    equ   7  ; Description String
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE equ   7  ; Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR    equ   8  ; Machine Value (MIPS GP)
IMAGE_DIRECTORY_ENTRY_TLS          equ   9  ; TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG  equ  10  ; Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT equ  11  ; Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT          equ  12  ; Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT equ  13  ; Delay Load Import Descriptors


IMAGE_NT_HEADERS struct
Signature       dd ?
FileHeader      IMAGE_FILE_HEADER <>
OptionalHeader  IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS ends


IMAGE_SECTION_HEADER struct
Name_                db 8 dup (?)
union Misc
PhysicalAddress      dd ? ;8
VirtualSize          dd ?
ends
VirtualAddress       dd ? ;12
SizeOfRawData        dd ? ;16
PointerToRawData     dd ? ;20
PointerToRelocations dd ? ;24
PointerToLinenumbers dd ? ;28
NumberOfRelocations  dw ? ;32
NumberOfLinenumbers  dw ?
Characteristics      dd ? ;36
IMAGE_SECTION_HEADER ends

