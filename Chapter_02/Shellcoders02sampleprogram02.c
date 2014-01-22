/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 2: Stack Overflows
Sample Program #2

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

int main () {

    int array[5];
    int i;
    
    for (i = 0; i <= 255; ++i){
            array[i] = 10;
    }
}

