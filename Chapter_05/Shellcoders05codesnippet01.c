/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 5: Heap Overflows
Code Snippet #1

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

bin = bin_at(av, idx);

      for (victim = last(bin); victim != bin; victim = victim->bk) {
      size = chunksize(victim);

      if ((unsigned long)(size) >= (unsigned long)(nb)) {
       remainder_size = size - nb;
       unlink(victim, bck, fwd);

       /* Exhaust */

       if (remainder_size < MINSIZE)  {
         set_inuse_bit_at_offset(victim, size);
         if (av != &main_arena)
           victim->size |= NON_MAIN_ARENA;
         check_malloced_chunk(av, victim, nb);
         return chunk2mem(victim);
       }

       /* Split */

       else {
         remainder = chunk_at_offset(victim, nb);
         unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder;
         remainder->bk = remainder->fd = unsorted_chunks(av);
         set_head(victim, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
         set_head(remainder, remainder_size | PREV_INUSE);
         set_foot(remainder, remainder_size);
         check_malloced_chunk(av, victim, nb);
         return chunk2mem(victim);
       }
     }
      }










