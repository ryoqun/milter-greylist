%token ADDR IPADDR CIDR FROM RCPT EMAIL PEER

%{
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: except_yacc.y,v 1.5 2004/03/10 14:17:13 manu Exp $");
#endif

#include "except.h"
#include "sync.h"
%}

%union	{
	struct in_addr ipaddr;
	int cidr;
	char email[ADDRLEN + 1];
	}
%type <ipaddr> IPADDR;
%type <cidr> CIDR;
%type <email> EMAIL;

%%
lines	:	lines netblock '\n' 
	|	lines fromaddr '\n' 
	|	lines rcptaddr '\n' 
	|	lines peeraddr '\n' 
	|	lines '\n'
	|
	;
netblock:	ADDR IPADDR '/' CIDR	{ except_add_netblock(&$2, $4); }
	;
fromaddr:	FROM EMAIL	{ except_add_from($2); }
	;
rcptaddr:	RCPT EMAIL	{ except_add_rcpt($2); }
	;
peeraddr:	PEER IPADDR	{ peer_add(&$2); }
	;
%%
#include "except_lex.c"
