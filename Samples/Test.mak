
# simple make file using jwasm & jwlink

ODIR=..\build

all: $(ODIR) $(ODIR)\Test.exe

$(ODIR):
	@mkdir $(ODIR)

$(ODIR)\Test.exe: $(ODIR)\dos64stb2.bin $(ODIR)\Test.obj
	@jwlink format win pe ru native f $* n $* op q,m=$*,stub=$(ODIR)\dos64stb2.bin,stack=0x4000,heap=0x1000,norelocs,start=_main

$(ODIR)\Test.obj: Test.asm Test.mak printf.inc
	@jwasm -nologo -Fl$* -Fo$* -Sg -coff Test.asm

