%token IPADDR EMAIL TIME

%{
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: dump_yacc.y,v 1.3 2004/03/06 19:06:14 manu Exp $");
#endif

#include "pending.h"
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
lines	:	lines entry '\n' 
	|	lines '\n'
	|	error '\n'		{ yyerrok; }
	|
	;
entry	:	IPADDR EMAIL EMAIL TIME	{ pending_get(&$1, $2, $3, $4); }
	;
%%
#include "dump_lex.c"