%token ADDR IPADDR CIDR FROM RCPT EMAIL

%{
#include "except.h"
%}

%union	{
	struct in_addr ipaddr;
	int cidr;
	char *email;
	}
%type <ipaddr> IPADDR;
%type <cidr> CIDR;
%type <email> EMAIL;

%%
lines	:	lines netblock '\n' 
	|	lines fromaddr '\n' 
	|	lines rcptaddr '\n' 
	|	lines '\n'
	|
	;
netblock:	ADDR IPADDR '/' CIDR	{ except_add_netblock(&$2, $4); }
	;
fromaddr:	FROM EMAIL	{ except_add_from($2); }
	;
rcptaddr:	RCPT EMAIL	{ except_add_rcpt($2); }
	;
%%
#include "except_lex.c"
