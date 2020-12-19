
# NMake makefile, makes Mon642.exe.
# Here stub dos64stb2 is used.
# Needs JWasm

ODIR=..\build

all: $(ODIR) $(ODIR)\Mon642.exe

$(ODIR):
	@mkdir $(ODIR)

!if 0

# use a separate link step 
$(ODIR)\Mon642.exe: $(ODIR)\Dos64stb2.bin $(ODIR)\Mon642.obj
	link /subsystem:native $*.obj /stub:$(ODIR)\Dos64stb2.bin /stack:0x4000 /heap:0 /out:$*.exe /map /base:0xffff800000000000
#	@jwlink format win pe ru native f $* n $* op q,m=$*,stub=$(ODIR)\Dos64stb.bin,stack=0x4000,heap=0x1000

$(ODIR)\Mon642.obj: Mon64.asm Mon642.lnk printf.inc
	@jwasm -nologo -Fl$* -Fo$* -Sg -coff -D?lnkdef=Mon642.lnk Mon64.asm

!else

# use jwasm's -pe option to create the binary without link step
$(ODIR)\Mon642.exe: $(ODIR)\Dos64stb2.bin Mon64.asm Mon642.lnk printf.inc
	@jwasm -nologo -pe -Fl$* -Fo$* -Sg -D?WAITINPM -D?PE -D?STUB=Dos64stb2.bin -D?lnkdef=Mon642.lnk Mon64.asm

!endif

