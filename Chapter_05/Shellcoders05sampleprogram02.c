/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 5: Heap Overflows
Sample Program #2

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

/*basicheap.c*/

int main(int argc, char** argv) {

  char *buf;
  char *buf2;
  buf=(char*)malloc(1024);
  buf2=(char*)malloc(1024);
  printf("buf=%p buf2=%p\n",buf,buf2);
  strcpy(buf,argv[1]);
  free(buf2);

}








