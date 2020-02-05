
# NMake makefile, makes TestC.exe
# needs JWasm and MSVC 64-bit

ODIR=Release

all: $(ODIR) $(ODIR)\TestC.exe

$(ODIR):
	@mkdir $(ODIR)

$(ODIR)\TestC.exe: $(ODIR)\dos64stb.bin $(ODIR)\TestC.obj $(ODIR)\printf.obj
	link /subsystem:native $*.obj $(ODIR)\printf.obj /stub:$(ODIR)\dos64stb.bin /stack:0x4000 /heap:0 /out:$*.exe /map /entry:main /nodefaultlib /fixed:no
#	@jwlink format win pe ru native f $*,$(ODIR)\printf n $* op q,m=$*,stub=$(ODIR)\dos64stb.bin,stack=0x4000,heap=0x1000

$(ODIR)\TestC.obj: TestC.c
	cl -c -Fo$* TestC.c

$(ODIR)\printf.obj: printf.asm
	jwasm -win64 -Fo$* -Fl$* -Sg printf.asm
