%token ADDR IPADDR CIDR FROM RCPT EMAIL PEER AUTOWHITE GREYLIST NOAUTH NOSPF QUIET TESTMODE VERBOSE PIDFILE DUMPFILE PATH DELAY SUBNETMATCH

%{
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: conf_yacc.y,v 1.7 2004/03/31 10:07:17 manu Exp $");
#endif
#endif

#include <stdlib.h>
#include "conf.h"
#include "except.h"
#include "sync.h"
#include "milter-greylist.h"

int conf_lex(void);
void conf_error(char *);
%}

%union	{
	struct in_addr ipaddr;
	int cidr;
	char email[ADDRLEN + 1];
	char path[PATHLEN + 1];
	char delay[NUMLEN + 1];
	}
%type <ipaddr> IPADDR;
%type <cidr> CIDR;
%type <email> EMAIL;
%type <delay> DELAY;
%type <path> PATH;

%%
lines	:	lines netblock '\n' 
	|	lines fromaddr '\n' 
	|	lines rcptaddr '\n' 
	|	lines peeraddr '\n' 
	|	lines verbose '\n' 
	|	lines quiet '\n' 
	|	lines noauth '\n' 
	|	lines nospf '\n' 
	|	lines testmode '\n' 
	|	lines autowhite '\n'
	|	lines greylist '\n'
	|	lines pidfile '\n'
	|	lines dumpfile '\n'
	|	lines subnetmatch '\n'
	|	lines '\n'
	|
	;
netblock:	ADDR IPADDR CIDR{ except_add_netblock(&$2, $3); }
	;
fromaddr:	FROM EMAIL	{ except_add_from($2); }
	;
rcptaddr:	RCPT EMAIL	{ except_add_rcpt($2); }
	;
peeraddr:	PEER IPADDR	{ peer_add(&$2); }
	;
autowhite:	AUTOWHITE DELAY	{ if (C_NOTFORCED(C_AUTOWHITE))
					conf.c_autowhite_validity =
					    (time_t)humanized_atoi($2);
				}
	;
greylist:	GREYLIST DELAY	{ if (C_NOTFORCED(C_DELAY))
					conf.c_delay =
					    (time_t)humanized_atoi($2);
				}
	;
verbose:	VERBOSE	{ if (C_NOTFORCED(C_DEBUG)) conf.c_debug = 1; }
	;
quiet:		QUIET	{ if (C_NOTFORCED(C_QUIET)) conf.c_quiet = 1; }
	;
noauth:		NOAUTH	{ if (C_NOTFORCED(C_NOAUTH)) conf.c_noauth = 1; }
	;
nospf:		NOSPF	{ if (C_NOTFORCED(C_NOSPF)) conf.c_nospf = 1; }
	;
testmode:	TESTMODE{ if (C_NOTFORCED(C_TESTMODE)) conf.c_testmode = 1; }
	;
pidfile:	PIDFILE PATH	{ if (C_NOTFORCED(C_PIDFILE)) 
					conf.c_pidfile = 
					    quotepath(c_pidfile, $2, PATHLEN);
				}
	;
dumpfile:	DUMPFILE PATH	{ if (C_NOTFORCED(C_DUMPFILE)) 
					conf.c_dumpfile = 
					    quotepath(c_dumpfile, $2, PATHLEN);
				}
	;
subnetmatch:	SUBNETMATCH CIDR{ if (C_NOTFORCED(C_MATCHMASK))
					cidr2mask($2, &conf.c_match_mask);
				}
	;	
%%
#include "conf_lex.c"
