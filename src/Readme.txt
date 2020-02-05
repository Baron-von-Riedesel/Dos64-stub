
  1. What is dos64stb good for?

  dos64stb is a small stub that is supposed to be added to a 64-bit 
  PE binary ( thru the link step ). It is the program that is executed
  when the binary is launched in DOS.
  dos64stb will do this:

   - check if the cpu is 64-bit
   - check if the PE image is "acceptable"
   - check if enough XMS memory is available to load the image
   - load the image into extended memory
   - setup GDT and switch to protected-mode
   - handle relocation info ( the image MUST contain base relocations )
   - setup IDT and page tables for 64-bit PAE paging
   - install a small "OS" (int 21h/31h) that allows the image to call
     real-mode DOS functions that don't need pointer translation.
   - reprogram master PIC, so IRQs 00h-07h are mapped to Int 78h-7fh
   - enable paging; call the entry point of the loaded 64-bit image


  2. Requirements
  
  to run an image with the dos64stb-stub one needs:

   - a 64-bit CPU
   - an installed DOS
   - an installed XMS host
   - enough extended memory to load the image

  3. Hot to use dos64stub?

  The stub is added to a 64-bit binary thru the link step. See file
  Makefile for how to do this with MS link or jwlink. The image must
  meet the following requirements:

   - Subsystem has to be "native"; avoids the image being loaded in Win64
   - image must contain base relocations
   - no dll references ("imports") are possible
   - base of image must be < 4 GB

  There are 2 samples supplied, Mon64.asm and TestC.c. Mon64 allows to
  display a few 64-bit resources. It also shows how the Int21 emulation
  installed by dos64stb is supposed to be used. It's possible to call
  other real-mode interrupts than int 21h - in this case one has to 
  use DPMI function int 31h, ax=300h, directly. TestC, the second sample,
  just shows how C source may be used with the stub. TestC.mak is
  supplied, which creates the binary using MSVC ( and JWasm, needed to
  assemble the micro-printf implementation in printf.asm ).

  The 64-bit binary runs in ring 0, 64-bit protected-mode. The first
  64 GB of memory are "identity mapped" by the stub. The memory that
  is "owned" by the binary is everything between the image base and 
  the stackpointer.

  4. License
  
  the source is distributed under the GNU GPL 2 license. See file
  COPYING for details. It was written by Andreas Grech.

