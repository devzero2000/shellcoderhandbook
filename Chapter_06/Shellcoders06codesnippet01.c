/*

The Shellcoder's Handbook: Discovering and Exploiting Security Holes
Jack Koziol, David Litchfield, Dave Aitel, Chris Anley, 
Sinan Eren, Neel Mehta, Riley Hassell
Publisher: John Wiley & Sons
ISBN: 0764544683

Chapter 6: Wild World of Windows
Sample Program #3

Please send comments/feedback to jack@infosecinstitute.com or visit http://www.infosecinstitute.com 

*/

[ uuid(e33c0cc4-0482-101a-bc0c-02608c6ba218),
  version(1.0),
  implicit_handle(handle_t rpc_binding)
] interface ???

{
  typedef struct {
    TYPE_2 element_1;
    TYPE_3 element_2;
  } TYPE_1;

...

  short Function_00(
        [in] long element_9,
        [in] [unique] [string] wchar_t *element_10,
        [in] [unique] TYPE_1 *element_11,
        [in] [unique] TYPE_1 *element_12,
        [in] [unique] TYPE_2 *element_13,
        [in] long element_14,
        [in] long element_15,
       [out] [context_handle] void *element_16
  );











