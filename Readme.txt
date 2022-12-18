
  1. About Dos64stb and Dos64stb2

  Dos64stb and Dos64stb2 are small stubs that are supposed to be added to a
  64-bit PE binary by the link step. Stubs are programs that are executed
  when the binary is launched in DOS. 
  
  Both stubs will do:

   - check if the cpu is 64-bit
   - check if the PE image is "acceptable"
   - check if enough XMS memory is available
   - setup IDT and page tables for 64-bit PAE paging
   - read & move the image into extended memory
   - install a small "OS" (int 21h/31h) so one may call
     real-mode DOS functions that don't need pointer translation.
   - reprogram master PIC, so IRQs 00h-07h are mapped to Int 78h-7fh
   - switch to long-mode
   - call the entry point of the loaded 64-bit image

  Dos64stb will additionally handle base relocations, it requires the binary
  to contain such relocations. Also, Dos64stb does identity-map the first 
  64 GB of physical memory, using 2MB pages, not caring at all whether the
  machine contains 64 GB of physical memory or not.

  OTOH, Dos64stb2 doesn't require the image to contain base relocations,
  because it should be able to load the image at its prefered loading address.
  Dos64stb2 maps just the memory that the image needs to run, that is:
  
   - image, stack & heap
   - conventional memory region, address 0-0xfffffh
   - IDT, mapped at 0x100000.
  
  Also, Dos64stb2 uses "normal" 4 kB pages for mapping. There are no 
  restrictions for the image's base address, it may be any valid 64-bit
  address.

  The 64-bit binary runs in ring 0, 64-bit long mode.   


  2. Requirements
  
  to run an image with Dos64stb/Dos64stb2 attached one needs:

   - a 64-bit CPU
   - an installed DOS
   - an installed XMS host
   - enough extended memory to load the image


  3. How to use the Stubs?

  The stub is added to a 64-bit binary thru the link step. See file
  Makefile for how to do this with MS link or jwlink. The image must
  meet the following requirements:

   - Subsystem has to be "native"; avoids the image being loaded in Win64
   - no dll references ("imports") are possible
   - Dos64stb only: image must contain base relocations - they must NOT be 
     "stripped".
   - Dos64stb only: base of image must be < 4 GB

  There are 2 samples supplied, Mon64.asm and TestC.c. Mon64 allows to
  display a few 64-bit resources. It also shows how the Int21 emulation
  installed by Dos64stb is supposed to be used. TestC, the second sample,
  just shows how C source may be used with the stub. TestC.mak is
  supplied, which creates the binary using MSVC ( and JWasm, needed to
  assemble the micro-printf implementation in printf.asm ).

  The stubs install a tiny subset of the DPMI API. The functions that are
  supported are:
   - int 21h, ah=4Ch: terminate program
   - int 31h, ax=203h: set exception vector BL to CX:RDX
   - int 31h, ax=300h: simulate real-mode interrupt BL, RDI=real-mode call
     structure.
  

  4. Memory Layout
 
  a). Dos64stb
 
  The first 64 GB of memory are "identity mapped". This may be adjusted
  in Dos64stb.asm. When launched, Dos64stb allocates a memory block in
  extended memory and initializes it like this (from lower to higher 
  addresses):
  
  - Paging Tables (default: 1+1+64 pages)
  - IDT (1 page)
  - 64-bit PE image
  - stack
  - heap (optionally)

  b) Dos64stb2

  Dos64stb2 doesn't map the paging tables, and the IDT is always mapped at
  0x100000h. The image itself is mapped at its prefered load address. Note
  that the valid address space is split into two parts:

   1. 0000000000000000-00007fffffffffff
   2. ffff800000000000-ffffffffffffffff

   or, in other words, the upper 17 bits of the address must be
   identical. The image, including stack and heap, must fit in
   one of those 2 parts. So, for example, an image with base 
   address 7fffffff0000 and size of image+stack+heap > 64 kB cannot
   be loaded.


  5. License
  
  the source is distributed under the GNU GPL 2 license. See file
  COPYING for details. It was written by Andreas Grech.

