%token IPADDR CIDR

%{
#include "except.h"
%}

%union	{
	struct in_addr ipaddr;
	int cidr;
	}
%type <ipaddr> IPADDR;
%type <cidr> CIDR;

%%
lines	:	lines netblock '\n' 
	|	lines '\n'
	|
	;
netblock:	IPADDR '/' CIDR	{ except_add(&$1, $3); }
	;
%%
#include "except_lex.c"
