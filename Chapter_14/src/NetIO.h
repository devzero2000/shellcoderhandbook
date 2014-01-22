#define SOCK_ERROR		-1

#define CONN_ERROR		-2

#define READ_ERROR		-3

#define READ_TIMEOUT	-4

#define READ_NODATA		-5

#define WRITE_ERROR		-6


DWORD	initialize_deliver(struct audit_profile *audit);

DWORD	release_deliver(struct audit_profile *audit);

DWORD	deliver_data(DWORD SockFD, char *data,DWORD data_size);

DWORD	tcp_connect(char *target, WORD port);

DWORD	GetData(DWORD SockFD,char *buffer,DWORD read_size);

DWORD	SendData(DWORD SockFD, char *data,DWORD data_size);
