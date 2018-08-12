

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
  e_magic           WORD      ?		;+0
  e_cblp            WORD      ?		;+2
  e_cp              WORD      ?		;+4
  e_crlc            WORD      ?		;+6		number of relocation records
  e_cparhdr         WORD      ?		;+8
  e_minalloc        WORD      ?		;+10
  e_maxalloc        WORD      ?		;+12
  e_ss              WORD      ?		;+14
  e_sp              WORD      ?		;+16
  e_csum            WORD      ?		;+18
  e_ip              WORD      ?		;+20
  e_cs              WORD      ?		;+22
  e_lfarlc          WORD      ?		;+24	begin relocation records
  e_ovno            WORD      ?		;+26
  e_res             WORD   4 dup(?)	;+28
  e_oemid           WORD      ?		;+36
  e_oeminfo         WORD      ?		;+38
  e_res2            WORD  10 dup(?)	;+40
  e_lfanew          DWORD      ?	;+60	
IMAGE_DOS_HEADER ENDS


IMAGE_FILE_HEADER struct           ;size=20
Machine				dw ?			;0
NumberOfSections	dw ?
TimeDateStamp		dd ?			;4
PointerToSymbolTable dd ?			;8
NumberOfSymbols		dd ?			;12
SizeOfOptionalHeader dw ?			;16
Characteristics		dw ?           ;flags
IMAGE_FILE_HEADER ends

;*** Characteristics ***

; 0400: If Image is on removable media, copy and run from the swap file.
; 0800: If Image is on Net, copy and run from the swap file.

IMAGE_FILE_RELOCS_STRIPPED     equ 0001h
IMAGE_FILE_EXECUTABLE_IMAGE    equ 0002h
IMAGE_FILE_LINE_NUMS_STRIPPED  equ 0004h
IMAGE_FILE_LOCAL_SYMS_STRIPPED equ 0008h
IMAGE_FILE_16BIT_MACHINE       equ 0040h
IMAGE_FILE_BYTES_REVERSED_LO   equ 0080h  ; Bytes of machine word are reversed.
IMAGE_FILE_32BIT_MACHINE       equ 0100h
IMAGE_FILE_DEBUG_STRIPPED      equ 0200h  ; Debugging info stripped from file in .DBG file
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP equ 0400h
IMAGE_FILE_NET_RUN_FROM_SWAP   equ 0800h
IMAGE_FILE_SYSTEM              equ 1000h  ; System File.
IMAGE_FILE_DLL                 equ 2000h
IMAGE_FILE_UP_SYSTEM_ONLY      equ 4000h  ; File should only be run on a UP machine
IMAGE_FILE_BYTES_REVERSED_HI   equ 8000h  ; Bytes of machine word are reversed.

IMAGE_FILE_MACHINE_UNKNOWN    equ      0h
IMAGE_FILE_MACHINE_I386       equ    14ch   ;// Intel 386.
IMAGE_FILE_MACHINE_AMD64      equ   8664h


IMAGE_DATA_DIRECTORY struct
VirtualAddress    DWORD   ?
Size_			  DWORD   ?
IMAGE_DATA_DIRECTORY ends

IMAGE_NUMBEROF_DIRECTORY_ENTRIES    equ 16



IMAGE_OPTIONAL_HEADER32  struct           ;size = 28 + 68 + 128 = 224
                         ;standard, size=28
Magic					dw ?	;0
MajorLinkerVersion		db ?
MinorLinkerVersion		db ?
SizeOfCode				dd ?	;4	
SizeOfInitializedData	dd ?	;8
SizeOfUninitializedData dd ?	;12
AddressOfEntryPoint     dd ?	;16
BaseOfCode				dd ?	;20
BaseOfData				dd ?	;24
                         ;NT specific, size = 68
ImageBase				dd ?	;28
SectionAlignment		dd ?	;32
FileAlignment			dd ?	;36
MajorOperatingSystemVersion   dw ?	;40
MinorOperatingSystemVersion   dw ?
MajorImageVersion		dw ?	;44
MinorImageVersion		dw ?	
MajorSubsystemVersion	dw ?	;48
MinorSubsystemVersion	dw ?
Win32VersionValue		dd ?	;52
SizeOfImage				dd ?	;56
SizeOfHeaders			dd ?	;60
CheckSum				dd ?	;64
Subsystem				dw ?	;68
DllCharacteristics		dw ?
SizeOfStackReserve		dd ?	;72
SizeOfStackCommit		dd ?	;76
SizeOfHeapReserve		dd ?	;80
SizeOfHeapCommit		dd ?	;84
LoaderFlags				dd ?	;88
NumberOfRvaAndSizes     dd ?	;92
DataDirectory IMAGE_DATA_DIRECTORY	IMAGE_NUMBEROF_DIRECTORY_ENTRIES dup (<>)	
IMAGE_OPTIONAL_HEADER32  ends

IMAGE_OPTIONAL_HEADER64 struct
Magic					dw ?	;0
MajorLinkerVersion		db ?
MinorLinkerVersion		db ?
SizeOfCode				dd ?	;4	
SizeOfInitializedData	dd ?	;8
SizeOfUninitializedData dd ?	;12
AddressOfEntryPoint     dd ?	;16
BaseOfCode				dd ?	;20
ImageBase				dq ?	;24
SectionAlignment		dd ?	;32
FileAlignment			dd ?	;36
MajorOperatingSystemVersion   dw ?	;40
MinorOperatingSystemVersion   dw ?
MajorImageVersion		dw ?	;44
MinorImageVersion		dw ?	
MajorSubsystemVersion	dw ?	;48
MinorSubsystemVersion	dw ?
Win32VersionValue		dd ?	;52
SizeOfImage				dd ?	;56
SizeOfHeaders			dd ?	;60
CheckSum				dd ?	;64
Subsystem				dw ?	;68
DllCharacteristics		dw ?
SizeOfStackReserve		dq ?	;72
SizeOfStackCommit		dq ?	;76
SizeOfHeapReserve		dq ?	;80
SizeOfHeapCommit		dq ?	;84
LoaderFlags				dd ?	;88
NumberOfRvaAndSizes     dd ?	;92
DataDirectory IMAGE_DATA_DIRECTORY	IMAGE_NUMBEROF_DIRECTORY_ENTRIES dup (<>)	
IMAGE_OPTIONAL_HEADER64 ends

; Subsystem Values

IMAGE_SUBSYSTEM_UNKNOWN       equ    0   ;/ Unknown subsystem.
IMAGE_SUBSYSTEM_NATIVE        equ    1   ;/ Image doesn't require a subsystem.
IMAGE_SUBSYSTEM_WINDOWS_GUI   equ    2   ;/ Image runs in the Windows GUI subsystem.
IMAGE_SUBSYSTEM_WINDOWS_CUI   equ    3   ;/ Image runs in the Windows character subsystem.
IMAGE_SUBSYSTEM_OS2_CUI       equ    5   ;/ image runs in the OS/2 character subsystem.
IMAGE_SUBSYSTEM_POSIX_CUI     equ    7   ;/ image run  in the Posix character subsystem.
IMAGE_SUBSYSTEM_RESERVED8     equ    8   ;/ image run  in the 8 subsystem.


; Directory Entries

IMAGE_DIRECTORY_ENTRY_EXPORT       equ   0  ;// Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT       equ   1  ;// Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE     equ   2  ;// Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION    equ   3  ;// Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY     equ   4  ;// Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC    equ   5  ;// Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG        equ   6  ;// Debug Directory
IMAGE_DIRECTORY_ENTRY_COPYRIGHT    equ   7  ;// Description String
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   equ   7   ;// Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR    equ   8  ;// Machine Value (MIPS GP)
IMAGE_DIRECTORY_ENTRY_TLS          equ   9  ;// TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG  equ  10  ;// Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT equ  11  ;// Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT          equ  12  ;// Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   equ  13   ;// Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR equ  14   ;// COM Runtime descriptor


IMAGE_NT_HEADERS struct
Signature		dd ?		           ;00 "PE"
FileHeader		IMAGE_FILE_HEADER <>
OptionalHeader	IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS ends



IMAGE_SECTION_HEADER struct
Name_			db 8 dup (?)	;0
union Misc
PhysicalAddress dd ?			;8
VirtualSize     dd ?
ends
VirtualAddress  dd ?			;12
SizeOfRawData   dd ?			;16
PointerToRawData dd ?			;20
PointerToRelocations dd ?		;24	points to array of IMAGE_RELOCATIONs (.OBJ)
PointerToLinenumbers  dd ?		;28
NumberOfRelocations dw ?		;32
NumberOfLinenumbers  dw ?
Characteristics  dd ?			;36
IMAGE_SECTION_HEADER ends

;//
;// Section characteristics.
;//

IMAGE_SCN_TYPE_NO_PAD            equ 00000008h ; Reserved.
                                               ;
IMAGE_SCN_CNT_CODE               equ 00000020h ; Section contains code.
IMAGE_SCN_CNT_INITIALIZED_DATA   equ 00000040h ; Section contains initialized data.
IMAGE_SCN_CNT_UNINITIALIZED_DATA equ 00000080h ; Section contains uninitialized data.
                                               ;
IMAGE_SCN_LNK_OTHER              equ 00000100h ; Reserved.
IMAGE_SCN_LNK_INFO               equ 00000200h ; Section contains comments or some other type of information.
;IMAGE_SCN_TYPE_OVER             equ 00000400h ; Reserved.
IMAGE_SCN_LNK_REMOVE             equ 00000800h ; Section contents will not become part of image.
IMAGE_SCN_LNK_COMDAT             equ 00001000h ; Section contents comdat.
;//                                  00002000h ; Reserved.
                                               ;
;IMAGE_SCN_MEM_PROTECTED - Obsolete  00004000h ;
IMAGE_SCN_MEM_FARDATA            equ 00008000h ;
;IMAGE_SCN_MEM_SYSHEAP  - Obsolete   00010000h ;
IMAGE_SCN_MEM_PURGEABLE          equ 00020000h ;
IMAGE_SCN_MEM_16BIT              equ 00020000h ;
IMAGE_SCN_MEM_LOCKED             equ 00040000h ;
IMAGE_SCN_MEM_PRELOAD            equ 00080000h ;
                                               ;
IMAGE_SCN_ALIGN_1BYTES           equ 00100000h ;
IMAGE_SCN_ALIGN_2BYTES           equ 00200000h ;
IMAGE_SCN_ALIGN_4BYTES           equ 00300000h ;
IMAGE_SCN_ALIGN_8BYTES           equ 00400000h ;
IMAGE_SCN_ALIGN_16BYTES          equ 00500000h ; Default alignment if no others are specified.
IMAGE_SCN_ALIGN_32BYTES          equ 00600000h ;
IMAGE_SCN_ALIGN_64BYTES          equ 00700000h ;
;// Unused                           00800000h ;
                                               ;
IMAGE_SCN_LNK_NRELOC_OVFL        equ 01000000h ; Section contains extended relocations.
IMAGE_SCN_MEM_DISCARDABLE        equ 02000000h ; Section can be discarded.
IMAGE_SCN_MEM_NOT_CACHED         equ 04000000h ; Section is not cachable.
IMAGE_SCN_MEM_NOT_PAGED          equ 08000000h ; Section is not pageable.
IMAGE_SCN_MEM_SHARED             equ 10000000h ; Section is shareable.
IMAGE_SCN_MEM_EXECUTE            equ 20000000h ; Section is executable.
IMAGE_SCN_MEM_READ               equ 40000000h ; Section is readable.
IMAGE_SCN_MEM_WRITE              equ 80000000h ; Section is writeable.

;//
;// Symbol format.
;//

IMAGE_SYMBOL struct
union N
ShortName   BYTE 8 dup (?)
struct Name_  
Short_  DWORD   ?	;     // if 0, use LongName
Long    DWORD   ?    ;     // offset into string table
ends
LongName DWORD 2 dup (?)
ends
Value			DWORD   ?	;08
SectionNumber   WORD    ?	;12
Type_			WORD    ?	;14
StorageClass    BYTE    ?	;16
NumberOfAuxSymbols BYTE ?	;17
IMAGE_SYMBOL ends

;//
;// Section values.
;//
;// Symbols have a section number of the section in which they are
;// defined. Otherwise, section numbers have the following meanings:
;//

IMAGE_SYM_UNDEFINED      equ     0     ;// Symbol is undefined or is common.
IMAGE_SYM_ABSOLUTE       equ     -1    ;// Symbol is an absolute value.
IMAGE_SYM_DEBUG          equ     -2    ;// Symbol is a special debug item.
IMAGE_SYM_SECTION_MAX    equ     0FEFFh;// Values 0xFF00-0xFFFF are special

;//
;// Storage classes.
;//
IMAGE_SYM_CLASS_END_OF_FUNCTION     equ -1
IMAGE_SYM_CLASS_NULL                equ 00000h
IMAGE_SYM_CLASS_AUTOMATIC           equ 00001h
IMAGE_SYM_CLASS_EXTERNAL            equ 00002h
IMAGE_SYM_CLASS_STATIC              equ 00003h
IMAGE_SYM_CLASS_REGISTER            equ 00004h
IMAGE_SYM_CLASS_EXTERNAL_DEF        equ 00005h
IMAGE_SYM_CLASS_LABEL               equ 00006h
IMAGE_SYM_CLASS_UNDEFINED_LABEL     equ 00007h
IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    equ 00008h
IMAGE_SYM_CLASS_ARGUMENT            equ 00009h
IMAGE_SYM_CLASS_STRUCT_TAG          equ 0000Ah
IMAGE_SYM_CLASS_MEMBER_OF_UNION     equ 0000Bh
IMAGE_SYM_CLASS_UNION_TAG           equ 0000Ch
IMAGE_SYM_CLASS_TYPE_DEFINITION     equ 0000Dh
IMAGE_SYM_CLASS_UNDEFINED_STATIC    equ 0000Eh
IMAGE_SYM_CLASS_ENUM_TAG            equ 0000Fh
IMAGE_SYM_CLASS_MEMBER_OF_ENUM      equ 00010h
IMAGE_SYM_CLASS_REGISTER_PARAM      equ 00011h
IMAGE_SYM_CLASS_BIT_FIELD           equ 00012h

IMAGE_SYM_CLASS_FAR_EXTERNAL        equ 00044h

IMAGE_SYM_CLASS_BLOCK               equ 00064h
IMAGE_SYM_CLASS_FUNCTION            equ 00065h
IMAGE_SYM_CLASS_END_OF_STRUCT       equ 00066h
IMAGE_SYM_CLASS_FILE                equ 00067h
;// new
IMAGE_SYM_CLASS_SECTION             equ 00068h
IMAGE_SYM_CLASS_WEAK_EXTERNAL       equ 00069h
IMAGE_SYM_CLASS_CLR_TOKEN           equ 0006Bh


IMAGE_RELOCATION struct
union 
VirtualAddress		DWORD   ?
RelocCount			DWORD   ?
ends
SymbolTableIndex	DWORD   ?
Type_				WORD    ?
IMAGE_RELOCATION ends

;//
;// I386 relocation types.
;//
IMAGE_REL_I386_ABSOLUTE    equ   00000h  ;// Reference is absolute, no relocation is necessary
IMAGE_REL_I386_DIR16       equ   00001h  ;// Direct 16-bit reference to the symbols virtual address
IMAGE_REL_I386_REL16       equ   00002h  ;// PC-relative 16-bit reference to the symbols virtual address
IMAGE_REL_I386_DIR32       equ   00006h  ;// Direct 32-bit reference to the symbols virtual address
IMAGE_REL_I386_DIR32NB     equ   00007h  ;// Direct 32-bit reference to the symbols virtual address, base not included
IMAGE_REL_I386_SEG12       equ   00009h  ;// Direct 16-bit reference to the segment-selector bits of a 32-bit virtual address
IMAGE_REL_I386_SECTION     equ   0000Ah
IMAGE_REL_I386_SECREL      equ   0000Bh
IMAGE_REL_I386_TOKEN       equ   0000Ch  ;// clr token
IMAGE_REL_I386_SECREL7     equ   0000Dh  ;// 7 bit offset from base of section containing target
IMAGE_REL_I386_REL32       equ   00014h  ;// PC-relative 32-bit reference to the symbols virtual address


IMAGE_BASE_RELOCATION struct
VirtualAddress	DWORD   ?
SizeOfBlock		DWORD   ?
IMAGE_BASE_RELOCATION ends

IMAGE_REL_BASED_ABSOLUTE             equ 0
IMAGE_REL_BASED_HIGH                 equ 1
IMAGE_REL_BASED_LOW                  equ 2
IMAGE_REL_BASED_HIGHLOW              equ 3
IMAGE_REL_BASED_HIGHADJ              equ 4
IMAGE_REL_BASED_MIPS_JMPADDR         equ 5
IMAGE_REL_BASED_MIPS_JMPADDR16       equ 9
IMAGE_REL_BASED_IA64_IMM64           equ 9
IMAGE_REL_BASED_DIR64                equ 10


IMAGE_EXPORT_DIRECTORY  struct
Characteristics 		dd ?
TimeDateStamp			dd ?
MajorVersion			dw ?
MinorVersion			dw ?
Name_					dd ?	;name of module
Base					dd ?	;base of ordinal
NumberOfFunctions		dd ?	;number of entries in EAT table
NumberOfNames			dd ?	;number of entries in name/ordinals table
AddressOfFunctions		dd ?	;RVA "export address table" (EAT)
AddressOfNames			dd ?	;RVA "name table" ()
AddressOfNameOrdinals	dd ?	;RVA "ordinals table" (WORDS)
IMAGE_EXPORT_DIRECTORY  ends

IMAGE_IMPORT_DESCRIPTOR  struct
union
Characteristics	dd ?
OriginalFirstThunk dd ?		;ILT: RVA to DWORD array
ends
TimeDateStamp	dd ?
ForwarderChain	dd ?
Name_			dd ?		;name of imported dll
FirstThunk		dd ?		;pointer to IAT if not bound (modified by loader)
IMAGE_IMPORT_DESCRIPTOR  ends

IMAGE_IMPORT_BY_NAME   struct         ;element of hintname array
Hint      dw ?           ;index to start search
Name_     db 1 dup (?)
IMAGE_IMPORT_BY_NAME   ends

IMAGE_TLS_DIRECTORY struct
StartAddressOfRawData	DWORD	?
EndAddressOfRawData		DWORD	?
AddressOfIndex			DWORD	?
AddressOfCallBacks		DWORD	?
SizeOfZeroFill			DWORD	?
Characteristics			DWORD	?
IMAGE_TLS_DIRECTORY ends

PIMAGE_TLS_DIRECTORY32 typedef ptr IMAGE_TLS_DIRECTORY

;--- exceptions

EXCEPTION_NONCONTINUABLE equ 1h    
EXCEPTION_MAXIMUM_PARAMETERS equ 15 

EXCEPTION_RECORD STRUCT
  ExceptionCode         DWORD      ?
  ExceptionFlags        DWORD      ?
  ExceptionRecord       DWORD      ?
  ExceptionAddress      DWORD      ?
  NumberParameters      DWORD      ?
  ExceptionInformation  DWORD EXCEPTION_MAXIMUM_PARAMETERS dup(?)
EXCEPTION_RECORD ENDS

PEXCEPTION_RECORD typedef ptr EXCEPTION_RECORD
PCONTEXT typedef ptr CONTEXT

EXCEPTION_POINTERS	struct 
ExceptionRecord	PEXCEPTION_RECORD	?
ContextRecord	PCONTEXT	?
EXCEPTION_POINTERS	ends

PEXCEPTION_POINTERS typedef ptr EXCEPTION_POINTERS

;------------------ resources

IMAGE_RESOURCE_DIRECTORY STRUCT
    Characteristics dd      ?
    TimeDateStamp dd        ?
    MajorVersion dw         ?
    MinorVersion dw         ?
    NumberOfNamedEntries dw ?
    NumberOfIdEntries dw    ?
IMAGE_RESOURCE_DIRECTORY ENDS

IMAGE_RESOURCE_DIRECTORY_ENTRY STRUCT
  union
    rName       RECORD NameIsString:1,NameOffset:31
    Name_ dd ?
    Id dw ?
  ends
  union
    OffsetToData dd ?
    rDirectory	RECORD DataIsDirectory:1,OffsetToDirectory:31
  ends
IMAGE_RESOURCE_DIRECTORY_ENTRY ENDS

IMAGE_RESOURCE_DIRECTORY_STRING STRUCT
    Length_ dw      ?
    NameString db   ?
IMAGE_RESOURCE_DIRECTORY_STRING ENDS

IMAGE_RESOURCE_DIR_STRING_U STRUCT
    Length_ dw      ?
    NameString dw   ?
IMAGE_RESOURCE_DIR_STRING_U ENDS

IMAGE_RESOURCE_DATA_ENTRY STRUCT
    OffsetToData dd ?
    Size_        dd ?
    CodePage     dd ?
    Reserved     dd ?
IMAGE_RESOURCE_DATA_ENTRY ENDS

