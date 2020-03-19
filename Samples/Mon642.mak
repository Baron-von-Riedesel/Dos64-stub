
# NMake makefile, makes Mon642.exe.
# Here stub dos64stb2 is used.
# Needs JWasm

ODIR=..\build

all: $(ODIR) $(ODIR)\Mon642.exe

$(ODIR):
	@mkdir $(ODIR)

# use jwasm's -pe option to create the binary without link step
$(ODIR)\Mon642.exe: $(ODIR)\Dos64stb2.bin Mon64.asm Mon642.lnk printf.inc
	@jwasm -nologo -pe -Fl$* -Fo$* -Sg -D?WAITINPM -D?PE -D?STUB=Dos64stb2.bin -D?lnkdef=Mon642.lnk Mon64.asm

