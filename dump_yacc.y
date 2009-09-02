%token IPADDR IP6ADDR EMAIL TIME AUTO TARPIT GARBAGE

%{
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: dump_yacc.y,v 1.21 2009/04/19 00:55:32 manu Exp $");
#endif
#endif

#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif
#include "conf.h"
#include "pending.h"

int dump_lex(void);
void dump_error(char *);
%}

%union	{
	struct sockaddr_in ipaddr;
#ifdef AF_INET6
	struct sockaddr_in6 ip6addr;
#else
	struct sockaddr_in ip6addr;		/* XXX: for dummy */
#endif
	char email[ADDRLEN + 1];
	time_t time;
	}
%type <ipaddr> IPADDR;
%type <ip6addr> IP6ADDR;
%type <email> EMAIL;
%type <time> TIME;

%%
lines	:	lines greyentry '\n' 
	|	lines autoentry '\n'
	|	lines tarpitentry '\n'
	|	lines '\n'
	|	error '\n'		{ yyerrok; }
	|
	;
greyentry :	IPADDR EMAIL EMAIL TIME	{
			pending_get(SA(&$1), sizeof(struct sockaddr_in), $2,
			    $3, $4, 0, T_PENDING);
		}
	|	IP6ADDR EMAIL EMAIL TIME {
#ifdef AF_INET6
			pending_get(SA(&$1), sizeof(struct sockaddr_in6), $2,
			    $3, $4, 0, T_PENDING);
#else
			printf("IPv6 is not supported, ignore line %d\n",
			    dump_line);
#endif
		}
	;
autoentry :	IPADDR EMAIL EMAIL TIME AUTO { 
			pending_get(SA(&$1), sizeof(struct sockaddr_in), $2,
			    $3, $4, 0, T_AUTOWHITE);
		}
	|	IP6ADDR EMAIL EMAIL TIME AUTO {
#ifdef AF_INET6
			pending_get(SA(&$1), sizeof(struct sockaddr_in6), $2,
			    $3, $4, 0, T_AUTOWHITE);
#else
			printf("IPv6 is not supported, ignore line %d\n",
			    dump_line);
#endif
		}
	;
tarpitentry :	IPADDR EMAIL EMAIL TIME TIME TARPIT {
			pending_get(SA(&$1), sizeof(struct sockaddr_in), $2,
			    $3, $4, $5, T_TARPIT);
		}
	|	IP6ADDR EMAIL EMAIL TIME TIME TARPIT {
#ifdef AF_INET6
			pending_get(SA(&$1), sizeof(struct sockaddr_in6), $2,
			    $3, $4, $5, T_TARPIT);
#else
			printf("IPv6 is not supported, ignore line %d\n",
			    dump_line);
#endif
		}
	;
%%
#include "dump_lex.c"
