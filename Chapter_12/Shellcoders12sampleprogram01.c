/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 12: HP Tru64 Unix Exploitation
Sample Program #1

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/


#include <alpha/regdef.h>
          .text
          .arch          generic
          .align 4
          .globl  main
          .ent           main
main:
          .frame  $sp, 0, $26

          lda  a0, -1000(sp)             #load a0 with stack address (sp – 1000)
back:
          bis  zero, 0x86, a1            #a1 equals to 0x00000086, this is the imb opcode
                                         #the imb instruction syncs the instruction cache
                                         #thus making it coherent with the main memory

                                         #1st round: store imb instruc-tion in (sp – 1000)
          stl  a1, -4(a0)                #2nd round: overwrite the following bsr instruction 
                                         #with the imb opcode so that we won’t loop again

     bsr  a0, back                       #branch the label back saving pc in a0 reg-ister
                                         #on the second round bsr will be overwritten
                                         #execution will continue with the next instruction
                                         #shellcode continues from here …

.text:200010D0      main:                                   
.text:200010D0             
.text:200010D0      18 FC 1E 22                 lda     $16, -1000($sp) 

sub_200010D4:

.text:200010D4      11 D4 F0 47                 mov     0x86, $17
.text:200010D8      FC FF 30 B2                stl     $17, -4($16)
.text:200010DC      FD FF 1F D2               bsr     $16, sub_200010D4
………

"\x18\xfc\x1e\x22"
"\x11\xd4\xf0\x47"
"\xfc\xff\x30\xb2"
"\xfd\xff\x1f\xd2"
