
    .x64
    .model flat
    option casemap:none
    option proc:private

cr equ 13
lf equ 10

CStr macro text:vararg
local sym
    .const
sym db text,0
    .code
    exitm <addr sym>
endm

    .code

	include printf.inc

_main proc
	invoke printf, CStr("hello",10)
	ret
_main endp

    end _main
