#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include "FaultInject.h"
#include "NetIO.h"

DWORD	audit_vuln_class(
							struct audit_profile *audit, 

							char *gen_request, 

							DWORD gen_req_size)
{
	DWORD errcode = 0;

	errcode = mod_overflow(audit, gen_request, gen_req_size);

	return(errcode);
}

DWORD buff_size[] =
{
	32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,
	60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,
	88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,
	112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,
	133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,200,210,237,238,239,
	240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,256,257,258,259,260,
	261,262,263,264,265,266,267,268,269,270,271,272,273,274,275,276,300,310,400,410,493,
	494,495,496,497,498,499,500,501,502,503,504,505,506,507,508,509,510,511,512,513,514,
	515,516,517,518,519,520,521,522,523,524,525,526,527,528,529,530,531,532,600,610,700,
	710,800,810,900,910,981,982,983,984,985,986,987,988,989,990,991,992,993,994,995,996,
	997,998,999,1000,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1011,1012,1013,1014,
	1015,1016,1017,1018,1019,1020,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,
	1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1100,1200,1300,1400,
	1500,1600,1700,1800,1900,2000,2010,2029,2030,2031,2032,2033,2034,2035,2036,2037,2038,
	2039,2040,2041,2042,2043,2044,2045,2046,2047,2048,2049,2050,2051,2052,2053,2054,2055,
	2056,2057,2058,2059,2060,2061,2062,2063,2064,2065,2066,2067,2068,2100,3000,3010,3100,
	4000,4010,4077,4078,4079,4080,4081,4082,4083,4084,4085,4086,4087,4088,4089,4090,4091,
	4092,4093,4094,4095,4096,4097,4098,4099,4100,4101,4102,4103,4104,4105,4106,4107,4108,
	4109,4110,4111,4112,4113,4114,4115,4116,5000,5010,5100,6000,6010,6100,7000,7010,7100,
	8000,8010,8100,8173,8174,8175,8176,8177,8178,8179,8180,8181,8182,8183,8184,8185,8186,
	8187,8188,8189,8190,8191,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8203,
	8204,8205,8206,8207,8208,8209,8210,8211,8212,9000,9010,9100,9200,9300,9400,9500,9600,
	9700,9800,9900,9981,9982,9983,9984,9985,9986,9987,9988,9989,9990,9991,9992,9993,9994,
	9995,9996,9997,9998,9999,10000,10001,10002,10003,10004,10005,10006,10007,10008,10009,
	10010,10011,10012,10013,10014,10015,10016,10017,10018,10019,10020,10100,10200,10300,
	10400,10500,10600,10700,10800,10900,11000,12000,13000,14000,15000,16000,16365,16366,
	16367,16368,16369,16370,16371,16372,16373,16374,16375,16376,16377,16378,16379,16380,
	16381,16382,16383,16384,16385,16386,16387,16388,16389,16390,16391,16392,16393,16394,
	16395,16396,16397,16398,16399,16400,16401,16402,16403,16404,17000,18000,19000,20000,
	32749,32750,32751,32752,32753,32754,32755,32756,32757,32758,32759,32760,32761,32762,
	32763,32764,32765,32766,32767,32768,32769,32770,32771,32772,32773,32774,32775,32776,
	32777,32778,32779,32780,32781,32782,32783,32784,32785,32786,32787,32788,65517,65518,
	65519,65520,65521,65522,65523,65524,65525,65526,65527,65528,65529,65530,65531,65532,
	65533,65534,65535,65536,65537,65538,65539,65540,65541,65542,65543,65544,65545,65546,
	65547,65548,65549,65550,65551,65552,65553,65554,65555,65556,0
};

DWORD	mod_overflow(
						struct audit_profile *audit, 

						char *gen_request, 

						DWORD gen_req_size)
{
	DWORD	cur_size = 0,
			i = 0,
			retcode;

	if(audit->vec.high > gen_req_size || audit->vec.low < 0)

		return(INVALID_VECTOR_RANGE);

	for (i = 0 ; buff_size[i] != 0 ; i++)
	{
		cur_size=buff_size[i];

		if((retcode = overflow_engine(audit, gen_request, gen_req_size,cur_size)) == -1)
			break;
	}

	return(retcode);
}


#define 	OP_VAL	+1
#define 	CL_VAL	-1
#define		AS_VAL	 1
#define		DE_VAL	+1

DWORD	overflow_engine(	struct audit_profile *audit, 

							char *gen_request, 

							DWORD gen_req_size,

							DWORD buf_size)
{
	DWORD	shift_pos = 0,

			delim_id = 0,

			send_size = 0,

			fixed_size = 0,

			mod_req_size = 0,

			fault_inj_pos[2]	= { 0 , 0 },

			fault_cnt = 0;

	char	*mod_request;

	char	fault[MAXBLOCK];

	mod_req_size = (gen_req_size+MAXBLOCK+FIXUP_PAD);

	mod_request = (char *)calloc(mod_req_size,1);

	for(shift_pos = audit->vec.low; shift_pos < audit->vec.high; shift_pos++)
	{
		if(!isalpha(gen_request[shift_pos]) && !isdigit(gen_request[shift_pos]) && gen_request[shift_pos] < 0x7F) 
		{
			switch(gen_request[shift_pos])
			{
				case '=':
				case '-':
				case '_':
				case '^':
				case '&':
				case ' ':
				case '+':
				case ':':

						fault_inj_pos[0]	=	OP_VAL;

						fault_inj_pos[1]	=	CL_VAL;

						fault_cnt			=	2;

						break;

				case '(':
				case '{':
				case '[':
				case '<':

						fault_inj_pos[0]	=	OP_VAL;

						fault_cnt			=	1;

						break;

				case ')':
				case '}':
				case ']':
				case '>':

						fault_inj_pos[0]	=	CL_VAL;

						fault_cnt			=	1;

						break;

				default:

						fault_inj_pos[0]	=	DE_VAL;

						fault_cnt			=	1;

						break;
			}
			
			for(;fault_cnt > 0;fault_cnt--)
			{
					memset(fault,gen_request[shift_pos+fault_inj_pos[fault_cnt-1]],buf_size);

					send_size = insert_mod(		gen_request, 

												gen_req_size, 

												mod_request,

												mod_req_size, 

												fault, 

												buf_size, 
												
												shift_pos+fault_inj_pos[fault_cnt-1]
											);

				if(audit->fixup.active)
				{
					if((fixed_size = audit->fixup.fixup_func(mod_request,&send_size,mod_req_size)) != NO_FIXUPS)
						send_size = fixed_size;
				}
				
				if(initialize_deliver(audit) == -1)
				{
					fprintf(stderr,"Remote service not responding... \n");
					
					return(-1);
				} 
				
				fprintf(stderr,
					
						"Input Size: %05d  Offset: %05d  Fault Size: %05d\n",
					
						gen_req_size,
						shift_pos+fault_inj_pos[fault_cnt-1],
						buf_size,
						send_size);

				deliver_data(audit->connected_sock,mod_request,send_size);
			
				release_deliver(audit);
			}
		}
	}

	return(0);
}

DWORD insert_mod(	char *gen_data,

					DWORD gen_data_size, 

					char *mod_data, 

					DWORD mod_data_size, 

					char *fault_obj, 

					DWORD fault_obj_size, 

					DWORD inj_pos)
{
	DWORD total=0;

	DWORD block_size=0;

	memset(mod_data,0x00,mod_data_size);

	memcpy(mod_data,gen_data,inj_pos);
	
	memcpy(mod_data+inj_pos,fault_obj,fault_obj_size);
	
	memcpy(mod_data+inj_pos+fault_obj_size,&gen_data[inj_pos],gen_data_size-inj_pos);
	
	total = gen_data_size+fault_obj_size;

	return(total);
}
