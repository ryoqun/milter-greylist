%token TNUMBER ADDR IPADDR IP6ADDR CIDR HELO FROM RCPT EMAIL PEER AUTOWHITE GREYLIST NOAUTH NOACCESSDB EXTENDEDREGEX NOSPF QUIET TESTMODE VERBOSE PIDFILE GLDUMPFILE QSTRING TDELAY SUBNETMATCH SUBNETMATCH6 SOCKET USER NODETACH REGEX REPORT NONE DELAYS NODELAYS ALL LAZYAW GLDUMPFREQ GLTIMEOUT DOMAIN DOMAINNAME SYNCADDR SYNCSRCADDR PORT ACL WHITELIST DEFAULT STAR DELAYEDREJECT DB NODRAC DRAC DUMP_NO_TIME_TRANSLATION LOGEXPIRED GLXDELAY DNSRBL LIST OPENLIST CLOSELIST BLACKLIST FLUSHADDR CODE ECODE MSG SM_MACRO UNSET URLCHECK RACL DACL GLHEADER BODY MAXPEEK STAT POSTMSG FORK GETPROP CLEAR PROP AUTH TLS SPF MSGSIZE RCPTCOUNT OP NO SLASH MINUS COMMA TIME GEOIPDB GEOIP PASS FAIL SOFTFAIL NEUTRAL UNKNWON ERROR SELF SPF_STATUS

%{
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: conf_yacc.y,v 1.85 2007/12/29 19:06:49 manu Exp $");
#endif
#endif

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <syslog.h>
#include <sysexits.h>
#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif
#include "conf.h"
#include "spf.h"
#include "acl.h"
#include "sync.h"
#include "list.h"
#include "macro.h"
#ifdef USE_DNSRBL
#include "dnsrbl.h"
#endif
#ifdef USE_CURL
#include "urlcheck.h"
#endif
#ifdef USE_GEOIP
#include "geoip.h"
#endif
#include "stat.h"
#include "clock.h"
#include "spf.h"
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
	char qstring[QSTRLEN + 1];
	char delay[NUMLEN + 1];
	char regex[REGEXLEN + 1];
	enum operator op; 
	char prop[QSTRLEN + 1];
	enum spf_status spf_status;
	}
%type <ipaddr> IPADDR;
%type <ip6addr> IP6ADDR;
%type <cidr> CIDR;
%type <email> EMAIL;
%type <domainname> DOMAINNAME;
%type <delay> TDELAY;
%type <delay> TNUMBER;
%type <qstring> QSTRING;
%type <regex> REGEX;
%type <op> OP;
%type <prop> PROP;
%type <spf_status> SPF_STATUS;

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
	|	lines dump_no_time_translation '\n'
	|	lines quiet '\n' 
	|	lines noauth '\n' 
	|	lines noaccessdb '\n' 
	|	lines extendedregex '\n'
	|	lines nospf '\n' 
	|	lines delayedreject '\n' 
	|	lines testmode '\n' 
	|	lines autowhite '\n'
	|	lines greylist '\n'
	|	lines pidfile '\n'
	|	lines dumpfile '\n'
	|	lines subnetmatch '\n'
	|	lines subnetmatch6 '\n'
	|	lines socket '\n'
	|	lines user '\n'
	|	lines geoipdb '\n'
	|	lines nodetach '\n'
	|	lines lazyaw '\n'
	|	lines report '\n'
	|	lines statdef '\n'
	|	lines dumpfreq '\n'
	|	lines timeout '\n'
	|       lines syncaddr '\n'
	|       lines syncsrcaddr '\n'
	|	lines access_list '\n'
	|	lines rcpt_access_list '\n'
	|	lines data_access_list '\n'
	|	lines dracdb '\n'
	|	lines maxpeek '\n'
	|	lines nodrac '\n'
	|       lines logexpired '\n'
	|	lines dnsrbldef '\n'
	|	lines macrodef '\n'
	|	lines urlcheckdef '\n'
	|	lines listdef '\n'
	|	lines '\n'
	|
	;
netblock:	ADDR IPADDR CIDR{
			struct acl_netblock_data and;

			and.addr = SA(&$2);
			and.salen = sizeof(struct sockaddr_in);
			and.cidr = $3;

			acl_add_clause(AC_NETBLOCK, &and);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	|	ADDR IPADDR	{
			struct acl_netblock_data and;

			and.addr = SA(&$2);
			and.salen = sizeof(struct sockaddr_in);
			and.cidr = 32;

			acl_add_clause(AC_NETBLOCK, &and);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	|	ADDR IP6ADDR CIDR{
#ifdef AF_INET6
			struct acl_netblock_data and;

			and.addr = SA(&$2);
			and.salen = sizeof(struct sockaddr_in6);
			and.cidr = $3;

			acl_add_clause(AC_NETBLOCK, &and);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
#else
			mg_log(LOG_INFO,
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	|	ADDR IP6ADDR	{
#ifdef AF_INET6
			struct acl_netblock_data and;

			and.addr = SA(&$2);
			and.salen = sizeof(struct sockaddr_in6);
			and.cidr = 128;

			acl_add_clause(AC_NETBLOCK, &and);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
#else
			mg_log(LOG_INFO,
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	;
fromaddr:	FROM EMAIL	{
			acl_add_clause(AC_FROM, $2);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
rcptaddr:	RCPT EMAIL	{
			acl_add_clause(AC_RCPT, $2);
			if (conf.c_testmode)
				acl_register_entry_first(AS_RCPT, A_GREYLIST);
			else
				acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}

	;
fromregex:	FROM REGEX	{
			acl_add_clause(AC_FROM_RE, $2);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
rcptregex:	RCPT REGEX	{
			acl_add_clause(AC_RCPT_RE, $2);
			if (conf.c_testmode)
				acl_register_entry_first(AS_RCPT, A_GREYLIST);
			else
				acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
domainaddr:	DOMAIN DOMAINNAME {
			acl_add_clause(AC_DOMAIN, $2);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
domainregex:	DOMAIN REGEX	 {
			acl_add_clause(AC_DOMAIN_RE, $2);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
peeraddr:	PEER IPADDR	{
			char addr[IPADDRSTRLEN];

			if (IP4TOSTRING($2, addr) == NULL) {
				mg_log(LOG_ERR,
				    "invalid IPv4 address line %d",
				    conf_line);
				exit(EX_DATAERR);
			}
			peer_add(addr);
		}
	|	PEER IP6ADDR	{
#ifdef AF_INET6
			char addr[IPADDRSTRLEN];

			if (IP6TOSTRING($2, addr) == NULL) {
				mg_log(LOG_ERR, 
				    "invalid IPv6 address line %d",
				    conf_line);
				exit(EX_DATAERR);
			}
			peer_add(addr);
#else
			mg_log(LOG_INFO,
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	|	PEER DOMAINNAME	{
#ifdef HAVE_GETADDRINFO
			peer_add($2);
#else
			mg_log(LOG_INFO,
			    "FQDN in peer is not supported, "
			    "ignore line %d", conf_line);
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
dump_no_time_translation:	DUMP_NO_TIME_TRANSLATION	{ conf.c_dump_no_time_translation = 1; }
	;
logexpired:   LOGEXPIRED { conf.c_logexpired = 1; }
	;
quiet:		QUIET	{ if (C_NOTFORCED(C_QUIET)) conf.c_quiet = 1; }
	;
noauth:		NOAUTH	{ if (C_NOTFORCED(C_NOAUTH)) conf.c_noauth = 1; }
	;
noaccessdb:	NOACCESSDB	{ conf.c_noaccessdb = 1; }
	;
extendedregex:	EXTENDEDREGEX	{ conf.c_extendedregex = 1; }
	;
nospf:		NOSPF	{ if (C_NOTFORCED(C_NOSPF)) conf.c_nospf = 1; }
	;
delayedreject:	DELAYEDREJECT	{ conf.c_delayedreject = 1; }
	;
testmode:	TESTMODE{ if (C_NOTFORCED(C_TESTMODE)) conf.c_testmode = 1; }
	;
nodetach:	NODETACH{ if (C_NOTFORCED(C_NODETACH)) conf.c_nodetach = 1; }
	;
lazyaw:		LAZYAW	{ if (C_NOTFORCED(C_LAZYAW)) conf.c_lazyaw = 1; }
	;
pidfile:	PIDFILE QSTRING	{ if (C_NOTFORCED(C_PIDFILE)) 
					conf.c_pidfile = 
					    quotepath(conf.c_pidfile_storage, 
						$2, QSTRLEN);
				}
	;
dumpfile:	GLDUMPFILE QSTRING{ if (C_NOTFORCED(C_DUMPFILE)) 
					conf.c_dumpfile = 
					    quotepath(conf.c_dumpfile_storage, 
					    $2, QSTRLEN);
				}
	|	GLDUMPFILE QSTRING TNUMBER 	{
				if (C_NOTFORCED(C_SOCKET))
					conf.c_dumpfile = 
					    quotepath(conf.c_dumpfile_storage, 
					    $2, QSTRLEN);

				conf.c_dumpfile_mode = (int)strtol($3, NULL, 8);
			}
	;
subnetmatch:	SUBNETMATCH CIDR{ if (C_NOTFORCED(C_MATCHMASK))
					prefix2mask4($2, &conf.c_match_mask);
				}
	;	
subnetmatch6:	SUBNETMATCH6 CIDR{ 
#ifdef AF_INET6
				if (C_NOTFORCED(C_MATCHMASK6))
					prefix2mask6($2, &conf.c_match_mask6);
#else
				mg_log(LOG_INFO, "IPv6 is not supported, "
				    "ignore line %d", conf_line);
#endif
				}
	;
socket:		SOCKET QSTRING	{ if (C_NOTFORCED(C_SOCKET))
					conf.c_socket = 
					    quotepath(conf.c_socket_storage, 
					    $2, QSTRLEN);
				}
	|	SOCKET QSTRING TNUMBER 	{
				int mode = atoi($3);

				if (C_NOTFORCED(C_SOCKET))
					conf.c_socket = 
					    quotepath(conf.c_socket_storage, 
					    $2, QSTRLEN);

				switch(mode) {
				case 666:
				case 660:
				case 600:
					conf.c_socket_mode = mode;
					break;
				default:
					mg_log(LOG_ERR, "socket mode %d is "
					    "not allowed, Use either 666, "
					    "660, or 600", mode);
					exit(EX_DATAERR);
				}
			}
	;
user:		USER QSTRING	{ if (C_NOTFORCED(C_USER))
					conf.c_user =
					    quotepath(conf.c_user_storage, $2, QSTRLEN);
				}
	;	
geoipdb:	GEOIPDB QSTRING	{
#ifdef USE_GEOIP
				char path[QSTRLEN + 1];

				geoip_set_db(quotepath(path, $2, QSTRLEN));
#else
				mg_log(LOG_INFO, 
				    "GeoIP support not compiled in line %d", 
				    conf_line);
#endif
				}
	;
report:		REPORT NONE	{ conf.c_report = C_GLNONE; }
	|	REPORT DELAYS	{ conf.c_report = C_DELAYS; }
	|	REPORT NODELAYS	{ conf.c_report = C_NODELAYS; }
	|	REPORT ALL	{ conf.c_report = C_ALL; }
	;

statdef:	STAT QSTRING QSTRING	{ 
				char output[QSTRLEN + 1];
				char format[QSTRLEN + 1];

				mg_stat_def(quotepath(output, $2, QSTRLEN),
					    quotepath(format, $3, QSTRLEN));
		}
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
				if (IP4TOSTRING($2, conf.c_syncaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv4 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = conf.c_syncaddr_storage;
				conf.c_syncport = NULL;
	                        }
	|	SYNCADDR IP6ADDR {
#ifdef AF_INET6
				if (IP6TOSTRING($2, conf.c_syncaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv6 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = conf.c_syncaddr_storage;
				conf.c_syncport = NULL;
#else /* AF_INET6 */
				mg_log(LOG_INFO, "IPv6 is not supported, "
				    "ignore line %d", conf_line);
#endif /* AF_INET6 */
				}
	|	SYNCADDR STAR PORT TNUMBER {
				conf.c_syncaddr = NULL;
				conf.c_syncport = conf.c_syncport_storage;
				strncpy(conf.c_syncport, $4, NUMLEN);
				conf.c_syncport[NUMLEN] = '\0';
				}
	|	SYNCADDR IPADDR PORT TNUMBER {
				if (IP4TOSTRING($2, conf.c_syncaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv4 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = conf.c_syncaddr_storage;
				conf.c_syncport = conf.c_syncport_storage;
				strncpy(conf.c_syncport, $4, NUMLEN);
				conf.c_syncport[NUMLEN] = '\0';
				}
	|	SYNCADDR IP6ADDR PORT TNUMBER {
#ifdef AF_INET6
				if (IP6TOSTRING($2, conf.c_syncaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv6 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = conf.c_syncaddr_storage;
				conf.c_syncport = conf.c_syncport_storage;
				strncpy(conf.c_syncport, $4, NUMLEN);
				conf.c_syncport[NUMLEN] = '\0';
#else /* AF_INET6 */
				mg_log(LOG_INFO, "IPv6 is not supported, "
				    "ignore line %d", conf_line);
#endif /* AF_INET6 */
				}
	;

syncsrcaddr:	SYNCSRCADDR STAR	{
				   conf.c_syncsrcaddr = NULL;
				   conf.c_syncsrcport = NULL;
				}
	|	SYNCSRCADDR IPADDR	{
				if (IP4TOSTRING($2, conf.c_syncsrcaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv4 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncsrcaddr = conf.c_syncsrcaddr_storage;
				conf.c_syncsrcport = NULL;
	                        }
	|	SYNCSRCADDR IP6ADDR {
#ifdef AF_INET6
				if (IP6TOSTRING($2, conf.c_syncsrcaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv6 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncsrcaddr = conf.c_syncsrcaddr_storage;
				conf.c_syncsrcport = NULL;
#else /* AF_INET6 */
				mg_log(LOG_INFO, "IPv6 is not supported, "
				    "ignore line %d", conf_line);
#endif /* AF_INET6 */
				}
	|	SYNCSRCADDR STAR PORT TNUMBER {
				conf.c_syncsrcaddr = NULL;
				conf.c_syncsrcport = conf.c_syncsrcport_storage;
				strncpy(conf.c_syncsrcport, $4, NUMLEN);
				conf.c_syncsrcport[NUMLEN] = '\0';
				}
	|	SYNCSRCADDR IPADDR PORT TNUMBER {
				if (IP4TOSTRING($2, conf.c_syncsrcaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv4 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncsrcaddr = conf.c_syncsrcaddr_storage;
				conf.c_syncsrcport = conf.c_syncsrcport_storage;
				strncpy(conf.c_syncsrcport, $4, NUMLEN);
				conf.c_syncsrcport[NUMLEN] = '\0';
				}
	|	SYNCSRCADDR IP6ADDR PORT TNUMBER {
#ifdef AF_INET6
				if (IP6TOSTRING($2, conf.c_syncsrcaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv6 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncsrcaddr = conf.c_syncsrcaddr_storage;
				conf.c_syncsrcport = conf.c_syncsrcport_storage;
				strncpy(conf.c_syncsrcport, $4, NUMLEN);
				conf.c_syncsrcport[NUMLEN] = '\0';
#else /* AF_INET6 */
				mg_log(LOG_INFO, "IPv6 is not supported, "
				    "ignore line %d", conf_line);
#endif /* AF_INET6 */
				}
	;

access_list:	ACL GREYLIST  acl_entry { 
			acl_register_entry_last(AS_RCPT, A_GREYLIST);
		}
	|	ACL WHITELIST acl_entry { 
			acl_register_entry_last(AS_RCPT, A_WHITELIST);
		}
	|	ACL BLACKLIST acl_entry { 
			acl_register_entry_last(AS_RCPT, A_BLACKLIST);
		}
	;

rcpt_access_list:
		RACL id GREYLIST  acl_entry { 
			acl_register_entry_last(AS_RCPT, A_GREYLIST);
		}
	|	RACL id WHITELIST acl_entry { 
			acl_register_entry_last(AS_RCPT, A_WHITELIST);
		}
	|	RACL id BLACKLIST acl_entry { 
			acl_register_entry_last(AS_RCPT, A_BLACKLIST);
		}
	;

data_access_list:
		DACL id GREYLIST  acl_entry { 
			acl_register_entry_last(AS_DATA, A_GREYLIST);
		}
	|	DACL id WHITELIST acl_entry { 
			acl_register_entry_last(AS_DATA, A_WHITELIST);
		}
	|	DACL id BLACKLIST acl_entry { 
			acl_register_entry_last(AS_DATA, A_BLACKLIST);
		}
	;

id:		QSTRING { 
			char id[QSTRLEN + 1];

			acl_add_id(quotepath(id, $1, QSTRLEN)); 
		}
	|
	;

acl_entry:	acl_default_entry 	{ conf_acl_end = 1; }
	| 	acl_plain_entry	
	;	

acl_default_entry: DEFAULT acl_values |	DEFAULT	;
acl_plain_entry: acl_clauses acl_values | acl_clauses;

acl_clauses:	acl_clause
	|	acl_clauses acl_clause
	;

acl_clause:	helo_clause
	|	heloregex_clause
	|	fromaddr_clause
	|	fromregex_clause
	|	rcptaddr_clause
	|	rcptregex_clause
	|	domainaddr_clause
	|	domainregex_clause
	|	netblock_clause
	|	dnsrbl_clause
	|	macro_clause
	|	urlcheck_clause
	|	list_clause
	|	header_clause
	|	headerregex_clause
	|	body_clause
	|	bodyregex_clause
	|	auth_clause
	|	authregex_clause
	|	tls_clause
	|	tlsregex_clause
	|	spf_clause
	|	spf_compat_clause
	|	msgsize_clause
	|	rcptcount_clause
	|	no_clause
	|	time_clause
	|	geoip_clause
	|	prop_clause
	|	propregex_clause
	;

acl_values:	acl_value
	|	acl_values acl_value
	;

acl_value:	greylist_value
	|	autowhite_value
	|	code_value
	|	ecode_value
	|	msg_value
	|	report_value
	|	flush_value
	;

greylist_value:		GLXDELAY TDELAY 
			    { acl_add_delay((time_t)humanized_atoi($2)); }
	;
autowhite_value:	AUTOWHITE TDELAY 
			    { acl_add_autowhite((time_t)humanized_atoi($2)); }
	;
flush_value:		FLUSHADDR { acl_add_flushaddr(); }
	;
code_value:		CODE QSTRING {
				char code[QSTRLEN + 1];

				acl_add_code(quotepath(code, $2, QSTRLEN));
			}
	;
ecode_value:		ECODE QSTRING {
				char ecode[QSTRLEN + 1];

				acl_add_ecode(quotepath(ecode, $2, QSTRLEN));
			}
	;
msg_value:		MSG QSTRING {
				char msg[QSTRLEN + 1];

				acl_add_msg(quotepath(msg, $2, QSTRLEN));
			}
	;
report_value:		REPORT QSTRING {
				char msg[QSTRLEN + 1];

				acl_add_report(quotepath(msg, $2, QSTRLEN));
			}
	;
no_clause:		NO { acl_negate_clause(); }
	;

time_clause:		TIME clockspec clockspec clockspec clockspec clockspec
			{ acl_add_clause(AC_CLOCKSPEC, register_clock()); }
	;

geoip_clause:		GEOIP QSTRING {
#ifdef USE_GEOIP
				char ccode[IPADDRSTRLEN + 1];

				acl_add_clause(AC_GEOIP, 
				    quotepath(ccode, $2, IPADDRSTRLEN));
#else
				mg_log(LOG_INFO, 
				    "GeoIP support not compiled in line %d", 
				    conf_line);
#endif
			}
	;

helo_clause:		HELO QSTRING {
				char string[QSTRLEN + 1];

				acl_add_clause(AC_HELO, 
				    quotepath(string, $2, QSTRLEN));
			}
	;

heloregex_clause:	HELO REGEX { acl_add_clause(AC_HELO_RE, $2); }
	;

fromaddr_clause:	FROM EMAIL { acl_add_clause(AC_FROM, $2); }
	;

fromregex_clause:	FROM REGEX { acl_add_clause(AC_FROM_RE, $2); }
	;

rcptaddr_clause:	RCPT EMAIL { acl_add_clause(AC_RCPT, $2); }
	;

rcptregex_clause:	RCPT REGEX { acl_add_clause(AC_RCPT_RE, $2); }
	;

domainaddr_clause:	DOMAIN DOMAINNAME { acl_add_clause(AC_DOMAIN, $2); }
	;

domainregex_clause:	DOMAIN REGEX { acl_add_clause(AC_DOMAIN_RE, $2); }
	;

dnsrbl_clause:		DNSRBL QSTRING { 
#ifdef USE_DNSRBL
			char path[QSTRLEN + 1];

			acl_add_clause(AC_DNSRBL, quotepath(path, $2, QSTRLEN));
#else
			mg_log(LOG_INFO, 
			    "DNSRBL support not compiled in line %d", 
			    conf_line);
#endif
			}
	;

macro_clause:	SM_MACRO QSTRING {
			char qstring[QSTRLEN + 1];

			acl_add_clause(AC_MACRO,
				       quotepath(qstring, $2, QSTRLEN));
		}
	;

header_clause:	GLHEADER QSTRING {
			char qstring[QSTRLEN + 1];

			acl_add_clause(AC_HEADER,
				       quotepath(qstring, $2, QSTRLEN));
		}
	;

headerregex_clause:	GLHEADER REGEX { acl_add_clause(AC_HEADER_RE, $2); }
	;

body_clause:		BODY QSTRING {
				char qstring[QSTRLEN + 1];

				acl_add_clause(AC_BODY,
				    quotepath(qstring, $2, QSTRLEN));
			}
	;

bodyregex_clause:	BODY REGEX { acl_add_clause(AC_BODY_RE, $2); }
	;

auth_clause:		AUTH QSTRING {
				char qstring[QSTRLEN + 1];

				acl_add_clause(AC_AUTH,
				    quotepath(qstring, $2, QSTRLEN));
				conf.c_noauth = 1; 
			}
	;

authregex_clause:	AUTH REGEX { 
				acl_add_clause(AC_AUTH_RE, $2); 
				conf.c_noauth = 1; 
			}
	;

tls_clause:		TLS QSTRING {
				char qstring[QSTRLEN + 1];

				acl_add_clause(AC_TLS,
				    quotepath(qstring, $2, QSTRLEN));
				conf.c_noauth = 1; 
			}
	;

tlsregex_clause:	TLS REGEX { 
				acl_add_clause(AC_TLS_RE, $2); 
				conf.c_noauth = 1;  
			}
	;

spf_clause:		SPF SPF_STATUS {
#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2))
				acl_add_clause(AC_SPF, &$2); 
				conf.c_nospf = 1;
#else
				mg_log(LOG_INFO, 
				    "SPF support not compiled in line %d", 
				    conf_line);
#endif
			}
	;

spf_compat_clause:	 SPF {
#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2))
				enum spf_status status = MGSPF_PASS;

				acl_add_clause(AC_SPF, &status); 
				conf.c_nospf = 1;
#else
				mg_log(LOG_INFO, 
				    "SPF support not compiled in line %d", 
				    conf_line);
#endif
			}
	;

urlcheck_clause:	URLCHECK QSTRING { 
#ifdef USE_CURL
			char path[QSTRLEN + 1];

			acl_add_clause(AC_URLCHECK, 
				       quotepath(path, $2, QSTRLEN));
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in line %d", 
			    conf_line);
#endif
			}
	;

prop_clause:		PROP QSTRING {
#ifdef USE_CURL
			struct urlcheck_prop_data upd;
			char qstring[QSTRLEN + 1];

			upd.upd_name = $1;
			upd.upd_data = quotepath(qstring, $2, QSTRLEN);

			acl_add_clause(AC_PROP, &upd);
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in line %d", 
			    conf_line);
#endif
		}
	;

propregex_clause:	PROP REGEX {
#ifdef USE_CURL
			struct urlcheck_prop_data upd;

			upd.upd_name = $1;
			upd.upd_data = $2;
			acl_add_clause(AC_PROPRE, &upd);
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in line %d", 
			    conf_line);
#endif
		}
	;

list_clause:		LIST QSTRING { 
				char path[QSTRLEN + 1];

				acl_add_clause(AC_LIST, 
					       quotepath(path, $2, QSTRLEN));
			}
	;
netblock_clause:	ADDR IPADDR CIDR {
				struct acl_netblock_data and;

				and.addr = SA(&$2);
				and.salen = sizeof(struct sockaddr_in);
				and.cidr = $3;

				acl_add_clause(AC_NETBLOCK, &and);
			}
	|		ADDR IPADDR	{
				struct acl_netblock_data and;

				and.addr = SA(&$2);
				and.salen = sizeof(struct sockaddr_in);
				and.cidr = 32;

				acl_add_clause(AC_NETBLOCK, &and);
			}
	|		ADDR IP6ADDR CIDR{
#ifdef AF_INET6
				struct acl_netblock_data and;

				and.addr = SA(&$2);
				and.salen = sizeof(struct sockaddr_in6);
				and.cidr = $3;

				acl_add_clause(AC_NETBLOCK, &and);
#else
				mg_log(LOG_INFO, 
				    "IPv6 is not supported, ignore line %d",
				    conf_line);
#endif
			}
	|		ADDR IP6ADDR	{
#ifdef AF_INET6
				struct acl_netblock_data and;

				and.addr = SA(&$2);
				and.salen = sizeof(struct sockaddr_in6);
				and.cidr = 128;

				acl_add_clause(AC_NETBLOCK, &and);
#else
				mg_log(LOG_INFO, "IPv6 is not supported, "
				     "ignore line %d", conf_line);
#endif
		}
	;

dracdb:			DRAC DB QSTRING	{ 
#ifdef USE_DRAC
				conf.c_dracdb = 
					    quotepath(conf.c_dracdb_storage, $3, QSTRLEN);
#else
				mg_log(LOG_INFO, "DRAC support not compiled "
				    "in line %d", conf_line);
#endif
		}
	;

msgsize_clause:		MSGSIZE OP TNUMBER {
				struct acl_opnum_data aond;

				aond.op = $2;
				aond.num = humanized_atoi($3);
				
				acl_add_clause(AC_MSGSIZE, &aond);
		}
	;

rcptcount_clause:	RCPTCOUNT OP TNUMBER {
				struct acl_opnum_data aond;

				aond.op = $2;
				aond.num = humanized_atoi($3);
				
				acl_add_clause(AC_RCPTCOUNT, &aond);
		}
	;


nodrac:			NODRAC	{ conf.c_nodrac = 1; }
	;

maxpeek:		MAXPEEK TNUMBER { conf.c_maxpeek = humanized_atoi($2); }
	;

dnsrbldef:	dnsrbldefip | dnsrbldefnetblock
	;

dnsrbldefip:	DNSRBL QSTRING DOMAINNAME IPADDR {
#ifdef USE_DNSRBL
			char path[QSTRLEN + 1];

			dnsrbl_source_add(quotepath(path, $2, QSTRLEN), 
			    $3, SA(&$4), 32);
#else
			mg_log(LOG_INFO, 
			    "DNSRBL support not compiled in line %d", 
			    conf_line);
#endif
		}
	;

dnsrbldefnetblock:	DNSRBL QSTRING DOMAINNAME IPADDR CIDR {
#ifdef USE_DNSRBL
			char path[QSTRLEN + 1];

			dnsrbl_source_add(quotepath(path, $2, QSTRLEN), 
			    $3, SA(&$4), $5);
#else
			mg_log(LOG_INFO, 
			    "DNSRBL support not compiled in line %d", 
			    conf_line);
#endif
		}
	;

macrodef:	macrodef_string | macrodef_regex | macrodef_unset;

macrodef_string:	SM_MACRO QSTRING QSTRING QSTRING { 
				char name[QSTRLEN + 1];
				char macro[QSTRLEN + 1];
				char value[QSTRLEN + 1];

				macro_add_string(quotepath(name, $2, QSTRLEN), 
				    quotepath(macro, $3, QSTRLEN),
				    quotepath(value, $4, QSTRLEN));
			}
	;

urlcheckdef:	URLCHECK QSTRING QSTRING TNUMBER urlcheckdef_flags {
#ifdef USE_CURL
			char path1[QSTRLEN + 1];
			char path2[QSTRLEN + 1];

			urlcheck_def_add(quotepath(path1, $2, QSTRLEN), 
			    quotepath(path2, $3, QSTRLEN), atoi($4), 
			    urlcheck_gflags);
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in line %d", 
			    conf_line);
#endif
		}
	;

urlcheckdef_flags:	urlcheckdef_flags urlcheckdef_postmsg
		|	urlcheckdef_flags urlcheckdef_getprop
		|	urlcheckdef_flags urlcheckdef_getprop urlcheckdef_clear
		|	urlcheckdef_flags urlcheckdef_fork
		|
		;

urlcheckdef_postmsg:	POSTMSG	{ 
#ifdef USE_CURL
				urlcheck_gflags |= U_POSTMSG; 
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in line %d", 
			    conf_line);
#endif
			}
		;
urlcheckdef_getprop:	GETPROP	{ 
#ifdef USE_CURL
				urlcheck_gflags |= U_GETPROP; 
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in line %d", 
			    conf_line);
#endif
			}
		;
urlcheckdef_clear:	 CLEAR { 
#ifdef USE_CURL
				urlcheck_gflags |= U_CLEARPROP; 
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in line %d", 
			    conf_line);
#endif
			}
		;
urlcheckdef_fork:	 FORK {
#ifdef USE_CURL
				urlcheck_gflags |= U_FORK;
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in line %d", 
			    conf_line);
#endif
			}
		;


macrodef_regex:		SM_MACRO QSTRING QSTRING REGEX {
				char name[QSTRLEN + 1];
				char macro[QSTRLEN + 1];

				macro_add_regex(quotepath(name, $2, QSTRLEN),
				    quotepath(macro, $3, QSTRLEN), $4); 
			}
	;

macrodef_unset:		SM_MACRO QSTRING QSTRING UNSET {
				char name[QSTRLEN + 1];
				char macro[QSTRLEN + 1];

				macro_add_unset(quotepath(name, $2, QSTRLEN),
				    quotepath(macro, $3, QSTRLEN));
			}
	;

clockspec:	clockspec_item COMMA clockspec
	|	clockspec_item	{ next_clock_spec(); }
	;
clockspec_item:	TNUMBER			
			{ add_clock_item(atoi($1), atoi($1), 0); }
	|	TNUMBER SLASH TNUMBER	
			{ add_clock_item(atoi($1), atoi($1), atoi($3));  }
	|	TNUMBER MINUS TNUMBER	
			{ add_clock_item(atoi($1), atoi($3), 0); }
	|	TNUMBER MINUS TNUMBER SLASH TNUMBER 
			{ add_clock_item(atoi($1), atoi($3), atoi($5)); }
	|	STAR			
			{ add_clock_item(-1, -1, 0);  }
	|	STAR SLASH TNUMBER	
			{ add_clock_item(-1, -1, atoi($3)); }
	;

listdef:	LIST QSTRING list_clause {
			char path[QSTRLEN + 1];

			all_list_setname(glist, quotepath(path, $2, QSTRLEN));
			glist_init();
		}
	;

list_clause:	HELO OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_HELO_LIST); }
	|	FROM OPENLIST email_list CLOSELIST
			{ all_list_settype(glist, AC_FROM_LIST); }
	|	RCPT OPENLIST email_list CLOSELIST
			{ all_list_settype(glist, AC_RCPT_LIST); }
	|	DOMAIN OPENLIST domain_list CLOSELIST
			{ all_list_settype(glist, AC_DOMAIN_LIST); }
	|	DNSRBL OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_DNSRBL_LIST); }
	|	URLCHECK OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_URLCHECK_LIST); }
	|	BODY OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_BODY_LIST); }
	|	GLHEADER OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_HEADER_LIST); }
	|	SM_MACRO OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_MACRO_LIST); }
	|	ADDR OPENLIST addr_list CLOSELIST
			{ all_list_settype(glist, AC_NETBLOCK_LIST); }
	|	AUTH OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_AUTH_LIST); }
	|	TLS OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_TLS_LIST); }
	|	TIME OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_CLOCKSPEC_LIST); }
	|	GEOIP OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_GEOIP_LIST); }
	;

email_list:	email_item
	|	email_list email_item
	;

email_item: 	EMAIL	{ list_add(glist, AC_EMAIL, $1); }
	|	REGEX 	{ list_add(glist, AC_REGEX, $1); }
	;

domain_list:	domain_item
	|	domain_list domain_item
	;

domain_item:	DOMAINNAME	{ list_add(glist, AC_DOMAIN, $1); }
	|	REGEX		{ list_add(glist, AC_REGEX, $1); }	
	;

qstring_list:	qstring_item
	|	qstring_list qstring_item
	;

qstring_item:	QSTRING		{ 
			char tmpstr[QSTRLEN + 1];

			list_add(glist, AC_STRING, 
			    quotepath(tmpstr, $1, QSTRLEN));
		}
	|	REGEX		{ list_add(glist, AC_REGEX, $1); }
	;

addr_list:	addr_item
	|	addr_list addr_item
	;

addr_item: 	IPADDR CIDR {
			struct acl_netblock_data and;

			and.addr = SA(&$1);
			and.salen = sizeof(struct sockaddr_in);
			and.cidr = $2;
			list_add(glist, AC_NETBLOCK, &and);
		}
	|	IPADDR {
			struct acl_netblock_data and;

			and.addr = SA(&$1);
			and.salen = sizeof(struct sockaddr_in);
			and.cidr = 32;
			list_add(glist, AC_NETBLOCK, &and);
		}
	|	IP6ADDR CIDR{
#ifdef AF_INET6
			struct acl_netblock_data and;

			and.addr = SA(&$1);
			and.salen = sizeof(struct sockaddr_in6);
			and.cidr = $2;
			list_add(glist, AC_NETBLOCK, &and);
#else
			mg_log(LOG_INFO,
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	|	IP6ADDR	{
#ifdef AF_INET6
			struct acl_netblock_data and;

			and.addr = SA(&$1);
			and.salen = sizeof(struct sockaddr_in6);
			and.cidr = 128;
			list_add(glist, AC_NETBLOCK, &and);
#else
			mg_log(LOG_ERR, 
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	;
%%
#include "conf_lex.c"
