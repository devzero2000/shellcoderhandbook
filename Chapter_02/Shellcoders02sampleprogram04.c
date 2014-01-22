/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 2: Stack Overflows
Sample Program #4

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

void return_input (void){ 
        char array[30]; 

        gets (array); 
        printf("%s\n", array); 

}


main() { 
        return_input(); 

        return 0; 

}



