
# NMake makefile, makes dos64stb.bin and mon64.exe
# needs JWasm and a 64-bit linker (MS link used here).

ODIR=Release

all: $(ODIR) $(ODIR)\mon64.exe

$(ODIR):
	@mkdir $(ODIR)

$(ODIR)\mon64.exe: $(ODIR)\dos64stb.bin $(ODIR)\mon64.obj
	link /subsystem:native $*.obj /stub:$(ODIR)\dos64stb.bin /stack:0x4000 /heap:0 /out:$*.exe
#	@jwlink format win pe ru native f $* n $* op q,m=$*,stub=$(ODIR)\dos64stb.bin,stack=0x4000,heap=0x1000

$(ODIR)\mon64.obj: mon64.asm
	@jwasm -nologo -Fl$* -Fo$* -Sg -coff mon64.asm

$(ODIR)\dos64stb.bin: dos64stb.asm
	@jwasm -nologo -mz -Sg -Fl$* -Fo$(ODIR)\dos64stb.bin dos64stb.asm
