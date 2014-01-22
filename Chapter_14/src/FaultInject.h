#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define	ENGINE_ERROR			-1

#define ENGINE_SHUTDOWN			-2

#define NO_ENGINE_SELECTED		-3

#define FIXUP_ERROR				-4

#define NO_FIXUPS				-5

#define INVALID_VECTOR_RANGE	-6

#define MAXBLOCK				65556

#define FIXUP_PAD				128

/* Attack Classes */

#define	BUFFER_OVERFLOW			1

typedef int (WINAPI *LPFUNC)(char *,DWORD *,DWORD);

struct vector
{
	BOOL	active;

	DWORD	low;

	DWORD	high;
};

/* Post Processing Hooks */

struct fixup
{
	BOOL	active;

	LPFUNC	fixup_func;
};

struct delivery
{
	BOOL	active;

	LPFUNC	hook;
};

/* end hooks */

struct audit_profile
{
	DWORD	audit_type;

	DWORD	vuln_class;

	DWORD	connected_sock;

	char	*host;	

	WORD	port;

	DWORD	input_size;

	char	*input_session;

	struct	vector	vec;
	
	struct	fixup	fixup;
};

DWORD audit_vuln_class(struct audit_profile *audit, char *gen_request, DWORD gen_req_size);

DWORD overflow_engine(struct audit_profile *audit, char *gen_request, DWORD gen_req_size,DWORD cur_size);

DWORD mod_overflow(struct audit_profile *audit, char *gen_request, DWORD gen_req_size);

DWORD insert_mod(char *gen_data, DWORD gen_data_size, char *mod_data, DWORD mod_data_size, char *fault_obj, DWORD fault_obj_size, DWORD inj_pos);

DWORD __stdcall fixup_bodydata(char *mod_request, DWORD *mod_req_size,DWORD max_mod_size);
