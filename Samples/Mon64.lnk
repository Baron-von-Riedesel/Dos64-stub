
;--- this include allows the image to be created without a link step,
;--- using jwasm's -pe output format.

	include peimage.inc

	option dotname
.hdr$1 segment flat public 'HDR'
%	incbin <..\build\?STUB>	;link option /stub:
.hdr$1 ends

.hdr$2 segment flat public 'HDR'

	org IMAGE_NT_HEADERS.FileHeader.Characteristics
	dw IMAGE_FILE_EXECUTABLE_IMAGE or IMAGE_FILE_32BIT_MACHINE	;link option /fixed:no

	org IMAGE_NT_HEADERS.OptionalHeader.Subsystem
	dw IMAGE_SUBSYSTEM_NATIVE	;link option /subsystem:native

	org IMAGE_NT_HEADERS.OptionalHeader.SizeOfStackReserve
	dd 4000h	;link option /stack:xxxx

	org IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeapReserve
	dd 1000h	;link option /heap:xxxx

.hdr$2 ends

