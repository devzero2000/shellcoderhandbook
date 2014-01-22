/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 8: Windows Overflows
Sample Program #12

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

#include <stdio.h>

    int foo(char *);

    int main(int argc, char *argv[])
    {
            unsigned char buffer[520]="";
            if(argc !=2)
                    return printf("Please supply an argument!\n");
            foo(argv[1]);
            return 0;
     }

     int foo(char *input)
     {
            unsigned char buffer[600]="";
            printf("%.8X\n",&buffer);
            strcpy(buffer,input);
            return 0;
     }
