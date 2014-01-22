/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 2: Stack Overflows
Sample Program #3

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

void function(int a, int b){
     int array[5];
}

main()
{
 function(1,2);

 printf("This is where the return address points”);
}


