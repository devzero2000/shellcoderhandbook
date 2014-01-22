/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 4: Introduction to Format String Bugs
Sample Program #3

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

  #include <stdio.h>
  #include <stdlib.h>

  int main()
  {
          asm("\
                  xor %eax, %eax;\
                  xor %ecx, %ecx;\
                  xor %edx, %edx;\
                  mov $0x01, %al;\
                  xor %ebx, %ebx;\
                  mov $0x02, %bl;\
                  int $0x80;\
                  ");

          return 1;
  }






