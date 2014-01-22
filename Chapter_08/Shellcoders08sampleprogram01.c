/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 8: Windows Overflows
Sample Program #1

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

#include <stdio.h>
#include <windows.h>

dword MyExceptionHandler(void)
{
             printf("In exception handler....");
             ExitProcess(1);
             return 0;
}

int main()
{
              try
              {
                   __asm
{
     // Cause an exception
                            xor eax,eax
                            call eax
}

            }
            __except(MyExceptionHandler())
            {
                    printf("oops...");
             }
             return 0;
}
