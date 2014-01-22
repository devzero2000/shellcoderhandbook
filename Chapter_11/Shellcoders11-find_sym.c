/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 11: Advanced Solaris Exploitation
Sample Program #5

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <libelf.h>

u_long find_sym(char *, char *);

u_long
find_sym(char *base, char *buzzt)
{
  Elf32_Ehdr *ehdr;
  Elf32_Shdr *shdr;
  Elf32_Word *dynsym, *dynstr;
  Elf32_Sym  *sym;
  const char *s1, *s2;
  register int i = 0;

    ehdr = (Elf32_Ehdr *) base;

    shdr = (Elf32_Shdr *) ((char *)base + (Elf32_Off) ehdr->e_shoff);

    /* look for .dynsym */

    while( i < ehdr->e_shnum){

         if(shdr->sh_type == SHT_DYNSYM){
                        dynsym = (Elf32_Word *) shdr->sh_addr;
                        dynstr = (Elf32_Word *) shdr->sh_link;
                        //offset to the dynamic string table's section header
                        break;
         }

         shdr++, i++;
     }

    shdr = (Elf32_Shdr *) (base + ehdr->e_shoff);
     /* this section header represents the dynamic string table */
    shdr += (Elf32_Word) dynstr; 
    dynstr = (Elf32_Addr *) shdr->sh_addr; /*relative location of .dynstr*/

    dynstr += (Elf32_Word) base / sizeof(Elf32_Word); /* relative to virtual */
    dynsym += (Elf32_Word) base / sizeof(Elf32_Word); /* relative to virtual */

        sym = (Elf32_Sym *)  dynsym;

        while(1) {

        /* first entry is in symbol table is always empty, pass it */
                sym++; /* next entry in symbol table */

                if(ELF32_ST_TYPE(sym->st_info) != STT_FUNC)
                        continue;

                s1 = (char *) ((char *) dynstr + sym->st_name);
                s2 = buzzt;

                while (*s1 == *s2++)
                        if (*s1++ == 0)
                                return sym->st_value;
        }

}
