
# NMake makefile, makes dos64stb.bin
# needs JWasm

ODIR=..\build

all: $(ODIR) $(ODIR)\Dos64stb.bin

$(ODIR):
	@mkdir $(ODIR)

$(ODIR)\Dos64stb.bin: Dos64stb.asm
	@jwasm -nologo -mz -Sg -Fl$* -Fo$(ODIR)\Dos64stb.bin Dos64stb.asm
