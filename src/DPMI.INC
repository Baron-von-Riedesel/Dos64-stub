
;--- DPMI real mode call structure

RMCS    struct 
rEDI    dd ?  ;+0
rESI    dd ?  ;+4
rEBP    dd ?  ;+8
Rsvd    dd ?  ;+12
rEBX    dd ?  ;+16
rEDX    dd ?  ;+20
rECX    dd ?  ;+24
rEAX    dd ?  ;+28
rFlags  dw ?  ;+32
rES     dw ?  ;+34
rDS     dw ?  ;+36
rFS     dw ?  ;+38    
rGS     dw ?  ;+40  
regIP   dw ?  ;+42
rCS     dw ?  ;+44
regSP   dw ?  ;+46
rSS     dw ?  ;+48
RMCS    ends

MEMINFO struct
maxBlock      dd ?            ;0	;in bytes
freeUnlocked  dd ?            ;4	;pages
maxLockable   dd ?            ;8
totalAdrSpace dd ?            ;12
unlocked      dd ?            ;16
freePhys      dd ?            ;20
totalPhys     dd ?            ;24
freeAdrSpace  dd ?            ;28
swapFile      dd ?            ;32
res           db 12 dup (?)
MEMINFO ends

