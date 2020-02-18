
# NMake makefile, makes Mon642.exe
# needs JWasm

ODIR=..\build

all: $(ODIR) $(ODIR)\Mon642.exe

$(ODIR):
	@mkdir $(ODIR)

# use jwasm's -pe option to create the binary without link step
$(ODIR)\Mon642.exe: $(ODIR)\Dos64stb2.bin Mon64.asm
	@jwasm -nologo -pe -Fl$* -Fo$* -Sg -D?PE -D?STUB=Dos64stb2.bin -D?lnkdef=lnkdef2.inc Mon64.asm

