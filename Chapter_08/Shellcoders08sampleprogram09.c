/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 8: Windows Overflows
Sample Program #9

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

#include <stdio.h>

     int main()
     {
             __asm{
                    mov eax, dword ptr fs:[0x18]
                    push eax
                    }
            printf("TEB: %.8X\n");
     
            __asm{
                    add esp,4
                    }

            return 0;
     }
