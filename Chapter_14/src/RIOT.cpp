#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "FaultInject.h"
#include "NetIO.h"

int main(int argc, char **argv)
{
	struct		audit_profile audit;

	HANDLE		resp_file;

	DWORD		resp_filesize = 0,

				filesize_high = 0,
				
				msg_size = 0,
				
				bytes_read = 0,
				
				count = 0,
				
				retcode = 0,
				
				id = 0;

	char		resp_filename[256];

	char		*resp;
	
	WSADATA		wsaData;

	if(argc != 3)
	{	
		fprintf(stderr, 
		
			"\n"
			"RIOT v0.1 - SWIFI example for Shellcoders Handbook\n"
			"Riley Hassell <rhassell@eeye.com>\n"
			"----------------------------------------------------------\n"
			"Usage: %s <target_ip> <port>\n"
			"\n"

		,argv[0],argv[0]);
		return(-1);
	}

	audit.host = argv[1];

	audit.port = atoi(argv[2]);

	/*
	 *  FIXUPS
	 *
	 *	Sometimes when inject faults we may compromise the intregity of
	 *  of our input data. Checksums, length fields, as well as other 
	 *  characteristics of the data that guarantee must be "fixed". 
	 * 
	 *  To solve these issues we can create a "fixup" function that when
	 *  supplied will recalculate neccessary checkums and lengths and store 
	 *  them in their appropriate field within the packet.
	 *  
	 */

	audit.fixup.active = TRUE;
	
	audit.fixup.fixup_func = (LPFUNC)fixup_bodydata;

	/*
	 *	Initiallize Winsock interface
	 */

	if (WSAStartup(MAKEWORD(2,1), &wsaData) != 0)
	{
		fprintf(stderr, "[%08X] Error: WSAStartup failed\n",GetLastError());
		ExitProcess(-1);
	}

	/*
	 * RETRIEVE INPUT
	 *
	 * We will iterate through each test input located in our "input_store"
	 * directory. Our input files should be named numerically starting at "1." 
	 * So if we had 3 test inputs then their fielnames would be:
	 *
	 *	1.dat
	 *	2.dat
	 *	3.dat
	 *
	 * Our testing ends when Createfile() fails to open a nonexistent test input 
	 * file. For example: If we had 3 test inputs and 4.dat did not exist, then
	 * RIOT would cleanup and exit.
	 *
	 */

	for( id = 1 ;; id++ ) 
	{
		memset(&resp_filename,0x00,sizeof(resp_filename));
		
		_snprintf(resp_filename, sizeof(resp_filename)-1,"input_store\\%d.dat",id);

		resp_filename[sizeof(resp_filename)-1] = 0;
		
		if((resp_file = CreateFile(resp_filename,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0)) == INVALID_HANDLE_VALUE)
		{
			fprintf(stderr,"[%08X] Error: Unable to open file \"%s\"\n",GetLastError(),resp_filename);
		
			break;
		}

		resp_filesize = 0;
		
		filesize_high = 0;

		if((resp_filesize = GetFileSize(resp_file,&filesize_high)) == INVALID_FILE_SIZE)
		{
			fprintf(stderr,"[%08X] Error: Unable to query filesize\n",GetLastError());
		
			break;
		}

		resp = (char *)calloc(resp_filesize+1,1);

		if(!ReadFile(resp_file,resp,resp_filesize,&bytes_read,NULL))
		{
			fprintf(stderr,"[%08X] Error: Unable to read input data from %s\n",GetLastError(),resp_filename);
		
			break;
		}

		if(!CloseHandle(resp_file))
		{
			fprintf(stderr,"[%08X] Error: Unable to close msg handle\n",GetLastError());
		
			break;
		}

		audit.vec.active	= TRUE;

		audit.vec.low		= 0;

		audit.vec.high		= bytes_read;

		audit.fixup.active = TRUE;

		audit.fixup.fixup_func = (LPFUNC)fixup_bodydata;
	
		if(audit_vuln_class(&audit,resp,bytes_read) == -1)
		{
			fprintf(stderr,"Audit Aborted\n");
			break;
		}

		free(resp);
	}

	fprintf(stderr,"Audit Complete\n");

	return(0);
}

DWORD __stdcall fixup_bodydata(
								char *mod_request, 

								DWORD *mod_req_size,

								DWORD max_mod_size)
{
	DWORD	bodydata_size = 0,

			conlen_size = 0,

			new_conlen_size = 0,

			new_session_size = 0,

			test = 0,

			x = 0;

	char	*datastart,
	
			*postdata,
			
			*pcon_len,
			
			*conlen_end;

	char	conlenbuffer[30];

	if( (*mod_req_size + 128) > max_mod_size )
		return(NO_FIXUPS);

	if((datastart = strstr(mod_request, "\r\n\r\n")) == NULL)
		return(NO_FIXUPS);
	
	datastart += 4;

	/* Get size of body data */
	bodydata_size = *mod_req_size - (datastart - mod_request);

	/* Find Content-Length: */
	if((pcon_len = strstr(mod_request,"Content-Length:")) == NULL)
			return(NO_FIXUPS);

	postdata = (char *)malloc(bodydata_size+1);

	if(postdata == NULL)
	{
		return(NO_FIXUPS);
		exit(-1);
	}

	memset(mod_request,0x00,bodydata_size+1);

	memcpy(mod_request,datastart,bodydata_size);

	if((conlen_end = strstr(pcon_len,"\r\n")) == NULL)
		return(NO_FIXUPS);

	conlen_size = (conlen_end - pcon_len);
	
	new_conlen_size = _snprintf(conlenbuffer,30-1,"Content-Length: %d",bodydata_size);

	if((test = new_conlen_size-conlen_size)<0)
		return(NO_FIXUPS);

	memmove(conlen_end+test,conlen_end,bodydata_size);

	memcpy(pcon_len,conlenbuffer,new_conlen_size);

	*mod_req_size = *mod_req_size+test;

	free(postdata);
	
	return(0);
};
