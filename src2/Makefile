
# NMake makefile, makes Dos64stb2.bin
# needs JWasm

ODIR=..\build

all: $(ODIR) $(ODIR)\Dos64stb2.bin

$(ODIR):
	@mkdir $(ODIR)

$(ODIR)\Dos64stb2.bin: Dos64stb2.asm
	@jwasm -nologo -mz -W3 -Sg -Fl$* -Fo$(ODIR)\Dos64stb2.bin Dos64stb2.asm
