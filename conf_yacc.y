%token TNUMBER ADDR IPADDR IP6ADDR CIDR FROM RCPT EMAIL PEER AUTOWHITE GREYLIST NOAUTH NOSPF QUIET TESTMODE VERBOSE PIDFILE GLDUMPFILE PATH TDELAY SUBNETMATCH SUBNETMATCH6 SOCKET USER NODETACH REGEX REPORT NONE DELAYS NODELAYS ALL LAZYAW GLDUMPFREQ GLTIMEOUT DOMAIN DOMAINNAME SYNCADDR PORT STAR

%{
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: conf_yacc.y,v 1.27 2004/08/09 21:44:19 manu Exp $");
#endif
#endif

#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include "conf.h"
#include "except.h"
#include "sync.h"
#include "milter-greylist.h"

#define LEN4 sizeof(struct sockaddr_in)
#define IP4TOSTRING(ip4, str) iptostring(SA(&(ip4)), LEN4, (str), IPADDRSTRLEN)

#define LEN6 sizeof(struct sockaddr_in6)
#define IP6TOSTRING(ip6, str) iptostring(SA(&(ip6)), LEN6, (str), IPADDRSTRLEN)

int conf_lex(void);
void conf_error(char *);

%}

%union	{
	struct sockaddr_in ipaddr;
#ifdef AF_INET6
	struct sockaddr_in6 ip6addr;
#else
	struct sockaddr_in ip6addr;	/* XXX: for dummy */
#endif
	int cidr;
	char email[ADDRLEN + 1];
	char domainname[ADDRLEN + 1];
	char path[PATHLEN + 1];
	char delay[NUMLEN + 1];
	char regex[REGEXLEN + 1];
	}
%type <ipaddr> IPADDR;
%type <ip6addr> IP6ADDR;
%type <cidr> CIDR;
%type <email> EMAIL;
%type <domainname> DOMAINNAME;
%type <delay> TDELAY;
%type <delay> TNUMBER;
%type <path> PATH;
%type <regex> REGEX;

%%
lines	:	lines netblock '\n' 
	|	lines fromaddr '\n' 
	|	lines rcptaddr '\n' 
	|	lines fromregex '\n' 
	|	lines rcptregex '\n' 
	|	lines domainaddr '\n'
	|	lines domainregex '\n'
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
	|	lines subnetmatch6 '\n'
	|	lines socket '\n'
	|	lines user '\n'
	|	lines nodetach '\n'
	|	lines lazyaw '\n'
	|	lines report '\n'
	|	lines dumpfreq '\n'
	|	lines timeout '\n'
	|       lines syncaddr '\n'
	|	lines '\n'
	|
	;
netblock:	ADDR IPADDR CIDR{
			except_add_netblock(SA(&$2),
			    sizeof(struct sockaddr_in), $3);
		}
	|	ADDR IPADDR	{
			except_add_netblock(SA(&$2),
			    sizeof(struct sockaddr_in), 32);
		}
	|	ADDR IP6ADDR CIDR{
#ifdef AF_INET6
			except_add_netblock(SA(&$2),
			    sizeof(struct sockaddr_in6), $3);
#else
			printf("IPv6 is not supported, ignore line %d\n",
			    conf_line);
#endif
		}
	|	ADDR IP6ADDR	{
#ifdef AF_INET6
			except_add_netblock(SA(&$2),
			    sizeof(struct sockaddr_in6), 128);
#else
			printf("IPv6 is not supported, ignore line %d\n",
			    conf_line);
#endif
		}
	;
fromaddr:	FROM EMAIL	{ except_add_from($2); }
	;
rcptaddr:	RCPT EMAIL	{ except_add_rcpt($2); }
	;
fromregex:	FROM REGEX	{ except_add_from_regex($2); }
	;
rcptregex:	RCPT REGEX	{ except_add_rcpt_regex($2); }
	;
domainaddr:	DOMAIN DOMAINNAME { except_add_domain($2); }
	;
domainregex:	DOMAIN REGEX	 { except_add_domain_regex($2); }
	;
peeraddr:	PEER IPADDR	{
			char addr[IPADDRLEN + 1];

			if (IP4TOSTRING($2, addr) == NULL) {
				printf("invalid IPv4 address line %d\n",
				    conf_line);
				exit(EX_DATAERR);
			}
			peer_add(addr);
		}
	|	PEER IP6ADDR	{
#ifdef AF_INET6
			char addr[IPADDRSTRLEN + 1];

			if (IP6TOSTRING($2, addr) == NULL) {
				printf("invalid IPv6 address line %d\n",
				    conf_line);
				exit(EX_DATAERR);
			}
			peer_add(addr);
#else
			printf("IPv6 is not supported, ignore line %d\n",
			    conf_line);
#endif
		}
	|	PEER DOMAINNAME	{
#ifdef HAVE_GETADDRINFO
			peer_add($2);
#else
			printf("FQDN in peer is not supported, "
			    "ignore line %d\n", conf_line);
#endif
		}
	;
autowhite:	AUTOWHITE TDELAY{ if (C_NOTFORCED(C_AUTOWHITE))
					conf.c_autowhite_validity =
					    (time_t)humanized_atoi($2);
				}
	|	AUTOWHITE TNUMBER{ if (C_NOTFORCED(C_AUTOWHITE))
					conf.c_autowhite_validity =
					    (time_t)humanized_atoi($2);
				}
	;
greylist:	GREYLIST TDELAY	{ if (C_NOTFORCED(C_DELAY))
					conf.c_delay =
					    (time_t)humanized_atoi($2);
				}
	|	GREYLIST TNUMBER{ if (C_NOTFORCED(C_DELAY))
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
					prefix2mask4($2, &conf.c_match_mask);
				}
	;	
subnetmatch6:	SUBNETMATCH6 CIDR{ if (C_NOTFORCED(C_MATCHMASK6))
					prefix2mask6($2, &conf.c_match_mask6);
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
dumpfreq:	GLDUMPFREQ TDELAY { conf.c_dumpfreq =
				    (time_t)humanized_atoi($2);
				}
	|	GLDUMPFREQ TNUMBER { conf.c_dumpfreq =
				    (time_t)humanized_atoi($2);
				}
	;
timeout:	GLTIMEOUT TDELAY { conf.c_timeout =
				    (time_t)humanized_atoi($2);
				}
	|	GLTIMEOUT TNUMBER { conf.c_timeout =
				    (time_t)humanized_atoi($2);
				}
	;
syncaddr:	SYNCADDR STAR	{
				   conf.c_syncaddr = NULL;
				   conf.c_syncport = NULL;
				}
	|	SYNCADDR IPADDR	{
				if (IP4TOSTRING($2, c_syncaddr) == NULL) {
					printf("invalid IPv4 address "
					    "line %d\n", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = c_syncaddr;
				conf.c_syncport = NULL;
	                        }
	|	SYNCADDR IP6ADDR {
#ifdef AF_INET6
				if (IP6TOSTRING($2, c_syncaddr) == NULL) {
					printf("invalid IPv6 address "
					    "line %d\n", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = c_syncaddr;
				conf.c_syncport = NULL;
#else /* AF_INET6 */
				printf("IPv6 is not supported, "
				    "ignore line %d\n", conf_line);
#endif /* AF_INET6 */
				}
	|	SYNCADDR STAR PORT TNUMBER {
				conf.c_syncaddr = NULL;
				conf.c_syncport = c_syncport;
				strncpy(conf.c_syncport, $4, NUMLEN);
				conf.c_syncport[NUMLEN] = '\0';
				}
	|	SYNCADDR IPADDR PORT TNUMBER {
				if (IP4TOSTRING($2, c_syncaddr) == NULL) {
					printf("invalid IPv4 address "
					    "line %d\n", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = c_syncaddr;
				conf.c_syncport = c_syncport;
				strncpy(conf.c_syncport, $4, NUMLEN);
				conf.c_syncport[NUMLEN] = '\0';
				}
	|	SYNCADDR IP6ADDR PORT TNUMBER {
#ifdef AF_INET6
				if (IP6TOSTRING($2, c_syncaddr) == NULL) {
					printf("invalid IPv6 address "
					    "line %d\n", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = c_syncaddr;
				conf.c_syncport = c_syncport;
				strncpy(conf.c_syncport, $4, NUMLEN);
				conf.c_syncport[NUMLEN] = '\0';
#else /* AF_INET6 */
				printf("IPv6 is not supported, "
				    "ignore line %d\n", conf_line);
#endif /* AF_INET6 */
				}
	;

%%
#include "conf_lex.c"
