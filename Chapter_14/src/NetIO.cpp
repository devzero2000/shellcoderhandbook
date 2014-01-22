#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include "FaultInject.h"
#include "NetIO.h"

#define NETIO_DEBUG 0

DWORD	tcp_connect(
						char *host, 

						WORD port)
{	
	DWORD	SockFD = 0;

	DWORD	nb_io = 1;

	DWORD	option = 0;

	struct	linger lin;

	struct	sockaddr_in DstSAin;

	BOOL	disable_nagle;

	
	DstSAin.sin_family = AF_INET;

	DstSAin.sin_port = htons(port);

	DstSAin.sin_addr.s_addr= inet_addr(host);	

	if((SockFD = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,0,0)) == INVALID_SOCKET)
	{

		if(NETIO_DEBUG)
		fprintf(stderr,

			"[%08X] Error: Unable to allocate socket\n"

		,WSAGetLastError());
	
		return(-1);
	}

	if((WSAConnect(SockFD,(struct sockaddr *)&DstSAin, sizeof(DstSAin),NULL,NULL,NULL,NULL)) == SOCKET_ERROR)
	{
		if(NETIO_DEBUG)
		fprintf(stderr,

			"[%08X] Error: Unable to connect to %s:%d\n"
		
		,WSAGetLastError(),host,port);

		closesocket(SockFD);
	
		return(-1);
	}

	if((ioctlsocket(SockFD,FIONBIO,&nb_io)) == SOCKET_ERROR)
	{
		if(NETIO_DEBUG)
		fprintf(stderr,
			
			"[%08X] Error: Unable to set IO mode of socket %d\n"
		
		,WSAGetLastError(),SockFD);
	
		closesocket(SockFD);

		return(-1);
	}

	lin.l_onoff = 1;

	lin.l_linger = 0;

	if((setsockopt(SockFD,SOL_SOCKET,SO_LINGER,(const char *)&lin,sizeof(lin))) == SOCKET_ERROR)
	{
		if(NETIO_DEBUG)
		fprintf(stderr,
			
			"[%08X] Error: Unable to set socket option SO_LINGER on socket %d\n"
		
		,WSAGetLastError(),SockFD);
		
		closesocket(SockFD);

		return(-1);
	}

	disable_nagle = TRUE;
		
	if((setsockopt(SockFD,IPPROTO_TCP,TCP_NODELAY,(const char *)&disable_nagle,sizeof(disable_nagle))) == SOCKET_ERROR)
	{
		if(NETIO_DEBUG)
		fprintf(stderr,
			
			"[%08X] Error: Unable to set socket option TCP_NODELAY on socket %d\n"
		
		,WSAGetLastError(),SockFD);
		
		closesocket(SockFD);
		
		return(-1);
	}

	return(SockFD);
}

DWORD	GetData(	
					DWORD SockFD,

					char *buffer,

					DWORD read_size
				)
{
	WSABUF wsrecv_buff;

	DWORD	bytes_recv = 0;

	DWORD	t = 0;

	DWORD	Flags = 0;

	DWORD	errcode = 0;

	BOOL	data_start = FALSE;

	struct timeval read_timeing;

	fd_set	readfs;


	FD_ZERO(&readfs);

    FD_SET(SockFD, &readfs);

	wsrecv_buff.len = read_size;

	wsrecv_buff.buf = buffer;

	read_timeing.tv_sec = 0;

	read_timeing.tv_usec = 100;

	if((t = select(SockFD, NULL, &readfs, NULL, &read_timeing)) == SOCKET_ERROR)
	{     
		if(NETIO_DEBUG)
		fprintf(stderr,
			
			"[%08X] Select: Unable to determine status of socket %d\n",
			
		WSAGetLastError(),SockFD);
	
		return(READ_ERROR);
	} 

	if (FD_ISSET(SockFD,&readfs))
	{
		if(errcode = WSARecv(SockFD,&wsrecv_buff,1,&bytes_recv,&Flags,0,0))
		{
			errcode = GetLastError();

			if(	errcode == WSAENOTCONN		|| 
				errcode == WSAECONNRESET	|| 
				errcode == WSAETIMEDOUT		|| 
				errcode == WSAECONNABORTED	)
			
				return(READ_ERROR);

			if(errcode == WSAEWOULDBLOCK)
			
				return READ_NODATA;
		}
		
		if(bytes_recv > 0)
		{
			buffer[bytes_recv-1]='\0';
		
			return 0;
		}
		else
		{
			if(errcode)
				return READ_ERROR;
			else
				return READ_TIMEOUT;
		}
	} else
	{
		return(READ_ERROR);
	}
}

DWORD	SendData(	
					DWORD SockFD, 

					char *data,
					
					DWORD data_size)
{
	WSABUF	send_buff;

	DWORD	bytes_sent;

	DWORD	rc = 0;

	DWORD	t = 0;

	DWORD	errcode = 0;

	fd_set	writefs;

	struct timeval write_timeing;

	
	FD_ZERO(&writefs);

    FD_SET(SockFD, &writefs);

	write_timeing.tv_sec = 1;
	
	write_timeing.tv_usec = 0;

	send_buff.len = data_size;

	send_buff.buf = data;

	if((t = select(SockFD, NULL, &writefs, NULL, &write_timeing)) == SOCKET_ERROR)
	{      
		if(NETIO_DEBUG)
		fprintf(stderr,
			
			"[%08X] Select: Unable to determine status of socket %d\n"
		
		,WSAGetLastError(),SockFD);
		
		return(WRITE_ERROR);
	} 

	if (FD_ISSET(SockFD,&writefs))
	{
		if(WSASend(SockFD,&send_buff,1,&bytes_sent,0,0,0))
		{
			errcode = GetLastError();
		
			if(errcode == WSAENOTCONN || errcode == WSAECONNRESET || errcode == WSAETIMEDOUT || errcode == WSAECONNABORTED || errcode == WSAENOTSOCK)
			{
				if(NETIO_DEBUG)
				fprintf(stderr,
				
					"[%08X] Error: Unable to determine status of socket %d\n"
				
				,errcode,SockFD);
			
				return(WRITE_ERROR);
			}
		} 
	}

	return rc;
}

DWORD initialize_deliver( struct audit_profile *audit )
{
	if((audit->connected_sock = tcp_connect(audit->host, audit->port)) == -1)
	{
		if(NETIO_DEBUG)
		fprintf(stderr,
			
			"[%08X] Error: Failed to make TCP connection to remote service\n"
		
		,audit->connected_sock);
	
		return(-1);
	}

	return(0);
}

DWORD release_deliver( struct audit_profile *audit )
{
	closesocket(audit->connected_sock);

	return(0);
}

DWORD deliver_data(DWORD SockFD, char *data,DWORD data_size)
{
	char recv_buffer[1024];

	if(SendData(SockFD, data,data_size) == -1)
		return(-1);

	GetData(SockFD,(char *)&recv_buffer,sizeof(recv_buffer)-1);
	
	return(0);
}
