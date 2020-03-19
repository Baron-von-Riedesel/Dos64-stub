
# NMake makefile, makes Mon64.exe
# needs JWasm and, optionally, a 64-bit linker (MS link used here).

ODIR=..\build

all: $(ODIR) $(ODIR)\Mon64.exe

$(ODIR):
	@mkdir $(ODIR)

!if 0

# use a separate link step 
$(ODIR)\Mon64.exe: $(ODIR)\Dos64stb.bin $(ODIR)\Mon64.obj
	link /subsystem:native $*.obj /stub:$(ODIR)\Dos64stb.bin /stack:0x4000 /heap:0 /out:$*.exe /map
#	@jwlink format win pe ru native f $* n $* op q,m=$*,stub=$(ODIR)\Dos64stb.bin,stack=0x4000,heap=0x1000

$(ODIR)\Mon64.obj: Mon64.asm Mon64.lnk printf.inc
	@jwasm -nologo -Fl$* -Fo$* -Sg -coff -D?lnkdef=Mon64.lnk Mon64.asm

!else

# use jwasm's -pe option to create the binary without link step
$(ODIR)\Mon64.exe: $(ODIR)\Dos64stb.bin Mon64.asm Mon64.lnk printf.inc
	@jwasm -nologo -pe -Fl$* -Fo$* -Sg -D?PE -D?STUB=Dos64stb.bin -D?lnkdef=Mon64.lnk Mon64.asm

!endif

