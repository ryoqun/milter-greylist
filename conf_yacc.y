%token ADDR IPADDR CIDR FROM RCPT EMAIL PEER AUTOWHITE GREYLIST NOAUTH NOSPF QUIET TESTMODE VERBOSE PIDFILE GLDUMPFILE PATH TDELAY SUBNETMATCH SOCKET USER NODETACH REGEX REPORT NONE DELAYS NODELAYS ALL LAZYAW AUTOWHITEDB GREYLISTDB DUMPFREQ

%{
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: conf_yacc.y,v 1.17 2004/05/23 13:03:41 manu Exp $");
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
	char regex[REGEXLEN + 1];
	}
%type <ipaddr> IPADDR;
%type <cidr> CIDR;
%type <email> EMAIL;
%type <delay> TDELAY;
%type <path> PATH;
%type <regex> REGEX;

%%
lines	:	lines netblock '\n' 
	|	lines fromaddr '\n' 
	|	lines rcptaddr '\n' 
	|	lines fromregex '\n' 
	|	lines rcptregex '\n' 
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
	|	lines socket '\n'
	|	lines user '\n'
	|	lines nodetach '\n'
	|	lines lazyaw '\n'
	|	lines report '\n'
	|	lines dumpfreq '\n'
	|	lines greylistdb '\n'
	|	lines autowhitedb '\n'
	|	lines '\n'
	|
	;
netblock:	ADDR IPADDR CIDR{ except_add_netblock(&$2, $3); }
	|	ADDR IPADDR	{ except_add_netblock(&$2, 32); }
	;
fromaddr:	FROM EMAIL	{ except_add_from($2); }
	;
rcptaddr:	RCPT EMAIL	{ except_add_rcpt($2); }
	;
fromregex:	FROM REGEX	{ except_add_from_regex($2); }
	;
rcptregex:	RCPT REGEX	{ except_add_rcpt_regex($2); }
	;
peeraddr:	PEER IPADDR	{ peer_add(&$2); }
	;
autowhite:	AUTOWHITE TDELAY{ if (C_NOTFORCED(C_AUTOWHITE))
					conf.c_autowhite_validity =
					    (time_t)humanized_atoi($2);
				}
	;
greylist:	GREYLIST TDELAY	{ if (C_NOTFORCED(C_DELAY))
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
nodetach:	NODETACH{ if (C_NOTFORCED(C_NODETACH)) conf.c_nodetach = 1; }
	;
lazyaw:		LAZYAW	{ if (C_NOTFORCED(C_LAZYAW)) conf.c_lazyaw = 1; }
	;
pidfile:	PIDFILE PATH	{ if (C_NOTFORCED(C_PIDFILE)) 
					conf.c_pidfile = 
					    quotepath(c_pidfile, $2, PATHLEN);
				}
	;
dumpfile:	GLDUMPFILE PATH	{ if (C_NOTFORCED(C_DUMPFILE)) 
					conf.c_dumpfile = 
					    quotepath(c_dumpfile, $2, PATHLEN);
				}
	;
subnetmatch:	SUBNETMATCH CIDR{ if (C_NOTFORCED(C_MATCHMASK))
					cidr2mask($2, &conf.c_match_mask);
				}
	;	
socket:		SOCKET PATH	{ if (C_NOTFORCED(C_SOCKET)) 
					conf.c_socket = 
					    quotepath(c_socket, $2, PATHLEN);
				}
	;
user:		USER PATH	{ if (C_NOTFORCED(C_USER))
					conf.c_user =
					    quotepath(c_user, $2, PATHLEN);
				}
	;	
report:		REPORT NONE	{ conf.c_report = C_NONE; }
	|	REPORT DELAYS	{ conf.c_report = C_DELAYS; }
	|	REPORT NODELAYS	{ conf.c_report = C_NODELAYS; }
	|	REPORT ALL	{ conf.c_report = C_ALL; }
	;
autowhitedb:	AUTOWHITEDB PATH{ conf.c_autowhitedb =
				    quotepath(c_autowhitedb, $2, PATHLEN);
				}
	;
greylistdb:	GREYLISTDB PATH{ conf.c_greylistdb =
				    quotepath(c_greylistdb, $2, PATHLEN);
				}
	;
dumpfreq:	DUMPFREQ TDELAY	{ conf.c_dumpfreq = 
					    (time_t)humanized_atoi($2);
				}
	;
%%
#include "conf_lex.c"
