%token IPADDR EMAIL TIME AUTO

%{
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: dump_yacc.y,v 1.15 2004/05/24 21:22:02 manu Exp $");
#endif
#endif

#include <stdlib.h>
#include "pending.h"
#include "autowhite.h"

int dump_lex(void);
void dump_error(char *);
%}

%union	{
	struct in_addr ipaddr;
	char email[ADDRLEN + 1];
	time_t time;
	}
%type <ipaddr> IPADDR;
%type <email> EMAIL;
%type <time> TIME;

%%
lines	:	lines greyentry '\n' 
	|	lines autoentry '\n'
	|	lines '\n'
	|	error '\n'		{ yyerrok; }
	|
	;
greyentry :	IPADDR EMAIL EMAIL TIME	{ pending_get(&$1, $2, $3, $4); }
	;
autoentry :	IPADDR EMAIL EMAIL TIME AUTO { 
			autowhite_get(&$1, $2, $3, &$4);
		}
	;
%%
#include "dump_lex.c"
