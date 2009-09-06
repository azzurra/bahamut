/************************************************************************
 *   IRC - Internet Relay Chat, src/ircd.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <pwd.h>
#include <signal.h>
#include <fcntl.h>
#if defined PROFILING && defined __GLIBC__ && (__GLIBC__ >= 2)
#include <sys/gmon.h>
#endif
#include "inet.h"
#include "h.h"
#include "patchlevel.h"
#include "dh.h"

#include "dich_conf.h"
#include "throttle.h"

/* Lists to do K: line matching -Sol */
aConfList   KList1 = {0, NULL};			/* ordered */
aConfList   KList2 = {0, NULL};			/* ordered, reversed */
aConfList   KList3 = {0, NULL};			/* what we can't sort */

aConfList   ZList1 = {0, NULL};			/* ordered */

aConfList   EList1 = {0, NULL};			/* ordered */
aConfList   EList2 = {0, NULL};			/* ordered, reversed */
aConfList   EList3 = {0, NULL};			/* what we can't sort */

aConfList   FList1 = {0, NULL};			/* ordered */
aConfList   FList2 = {0, NULL};			/* ordered, reversed */
aConfList   FList3 = {0, NULL};			/* what we can't sort */

#ifdef WEBIRC
aConfList   WList1 = {0, NULL};                 /* ordered */
aConfList   WList2 = {0, NULL};                 /* ordered, reversed */
aConfList   WList3 = {0, NULL};                 /* what we can't sort */
#endif

aMotd      *motd;
aMotd      *helpfile;		/* misnomer, aMotd could be generalized */

#ifdef SHORT_MOTD
aMotd	   *shortmotd;		/* short motd */
#endif

struct tm  *motd_tm;

/* holds the information for the proxy monitor */
#ifdef WINGATE_NOTICE
char ProxyMonURL[TOPICLEN+1];
char ProxyMonHost[HOSTLEN+1];
#endif

/* this stuff by mnystrom@mit.edu */
#include "fdlist.h"

fdlist      serv_fdlist;
fdlist      oper_fdlist;
fdlist      listen_fdlist;

#ifndef NO_PRIORITY
fdlist      busycli_fdlist;	/* high-priority clients */
#endif

fdlist      default_fdlist;	/* just the number of the entry */

int         MAXCLIENTS = MAX_CLIENTS;	/* semi-configurable if
					 *  QUOTE_SET is def  */
struct Counter Count;

time_t      	 NOW;
time_t		 last_stat_save;
aClient     	 me;		/* That's me */
aClient    	*client = &me;	/* Pointer to beginning of Client list */
#ifdef  LOCKFILE
extern time_t 	 pending_kline_time;
extern struct pkl *pending_klines;
extern void 	 do_pending_klines(void);
#endif

#ifdef USE_ACTIVITY_LOG
int		activity_fd;
int		activity_open();
void		activity_close();
void		activity_log(char *, ...);
#endif

void        	server_reboot();
void        	restart(char *);
static void 	open_debugfile(), setup_signals();
static void 	io_loop();

/* externally needed functions */

extern void 	init_fdlist(fdlist *);	    /* defined in fdlist.c */
extern void	dbuf_init();	            /* defined in dbuf.c */
extern void 	read_motd(char *);	    /* defined in s_serv.c */
#ifdef SHORT_MOTD
extern void 	read_shortmotd(char *);	    /* defined in s_serv.c */
#endif
extern void 	read_help(char *);	    /* defined in s_serv.c */

char      **myargv;
int         portnum = -1;	            /* Server port number, listening this */
char       *configfile = CONFIGFILE; 	    /* Server configuration file */
#ifdef KPATH
char       *klinefile = KLINEFILE;	    /* Server kline file */
# ifdef ZLINES_IN_KPATH
char       *zlinefile = KLINEFILE;
# else
char       *zlinefile = CONFIGFILE;
# endif
#else
char       *klinefile = CONFIGFILE;
char       *zlinefile = CONFIGFILE;

#endif

int         debuglevel = -1;	   /* Server debug level */
int         bootopt = 0;	   /* Server boot option flags */
char       *debugmode = "";	   /* -"-    -"-   -"-  */
void       *sbrk0;		   /* initial sbrk(0) */ /*AZZURRA void*/
static int  dorehash = 0;
static char *dpath = DPATH;
int         rehashed = 1;
int         zline_in_progress = 0; /* killing off matching D lines */
int         noisy_htm = NOISY_HTM; /* Is high traffic mode noisy or not? */ 
time_t      nextconnect = 1;	   /* time for next try_connections call */
time_t      nextping = 1;	   /* same as above for check_pings() */
time_t      nextdnscheck = 0;	   /* next time to poll dns to force timeout */
time_t      nextexpire = 1;	   /* next expire run on the dns cache */

#ifdef AZZURRA
unsigned char *cloak_key;
unsigned char *cloak_host;
unsigned short cloak_key_len;

extern int cloak_init(void);

time_t NEXT_MIDNIGHT, NEXT_WEEKEND, NEXT_MONTH;
#endif

#if defined PROFILING && defined __GLIBC__ && (__GLIBC__ >= 2)
extern void _start, etext;

VOIDSIG s_dumpprof()
{
    char buf[32];

    sprintf(buf, "gmon.%d", (int)time(NULL));
    setenv("GMON_OUT_PREFIX", buf, 1);
    _mcleanup();
    __monstartup ((u_long) &_start, (u_long) &etext);
    setenv("GMON_OUT_PREFIX", "gmon.auto", 1);
}
#endif

VOIDSIG s_die() 
{
#ifdef SAVE_MAXCLIENT_STATS
    FILE *fp;
#endif
    dump_connections(me.fd);
#ifdef	USE_SYSLOG
    (void) syslog(LOG_CRIT, "Server killed By SIGTERM");
#endif
#ifdef SAVE_MAXCLIENT_STATS
    fp=fopen(DPATH "/.maxclients", "w");
    if(fp!=NULL) 
    {
	fprintf(fp, "%d %d %li %li %li %ld %ld %ld %ld", Count.max_loc, 
		Count.max_tot, Count.weekly, Count.monthly, 
		Count.yearly, Count.start, Count.week, Count.month, 
		Count.year);
	fclose(fp);
    }
#endif

#ifdef USE_ACTIVITY_LOG
    activity_close();
#endif

    exit(0);
}

static  VOIDSIG s_rehash() 
{
#ifdef	POSIX_SIGNALS
    struct sigaction act;
#endif
    dorehash = 1;
#ifdef	POSIX_SIGNALS
    act.sa_handler = s_rehash;
    act.sa_flags = 0;
    (void) sigemptyset(&act.sa_mask);
    (void) sigaddset(&act.sa_mask, SIGHUP);
    (void) sigaction(SIGHUP, &act, NULL);
#else
    (void) signal(SIGHUP, s_rehash);	/* sysV -argv */
#endif
}

void restart(char *mesg) 
{
    static int  was_here = NO;	/* redundant due to restarting flag below */
    if (was_here)
	abort();
    was_here = YES;
	
#ifdef	USE_SYSLOG
    (void) syslog(LOG_WARNING, "Restarting Server because: %s, sbrk(0)-etext: %d",
		  mesg, (void*)sbrk((size_t) 0) - (void*)sbrk0);
#endif
    server_reboot();
}

VOIDSIG s_restart() 
{
    static int  restarting = 0;
	
#ifdef	USE_SYSLOG
    (void) syslog(LOG_WARNING, "Server Restarting on SIGINT");
#endif
    if (restarting == 0) 
    {
	/* Send (or attempt to) a dying scream to oper if present */
	restarting = 1;
	server_reboot();
    }
}

void server_reboot() 
{
    int     i;
    FILE *err;
    sendto_ops("Aieeeee!!!  Restarting server... sbrk(0)-etext: %d",
	       (void*)sbrk((size_t) 0) - (void*)sbrk0);
	
    Debug((DEBUG_NOTICE, "Restarting server..."));
    dump_connections(me.fd);
    /*
     * fd 0 must be 'preserved' if the -x option has
     * been passed to us before restarting.
     */
#ifdef USE_SYSLOG
    (void) closelog();
#endif
    for (i = 3; i < MAXCONNECTIONS; i++)
	(void) close(i);

    if (!(bootopt & (BOOT_TTY | BOOT_DEBUG)))
	(void) close(2);

    (void) close(1);

    if ((bootopt & BOOT_CONSOLE) || isatty(0))
	(void) close(0);

    (void) execve(MYNAME, myargv, NULL);

#ifdef USE_SYSLOG
    /* Have to reopen since it has been closed above */
    openlog(myargv[0], LOG_PID | LOG_NDELAY, LOG_FACILITY);
    syslog(LOG_CRIT, "execve(%s, %s, NULL) failed: %m\n", MYNAME, myargv[0]);
    closelog();
#endif

    if((err = fopen("/dev/tty", "w")))
    {
	fprintf(err, "Couldn't restart server [execve(%s, %s, NULL)]: %s\n",
		MYNAME, myargv[0], strerror(errno));
	fclose(err);
    }
    exit(-1);
}

/*
 * try_connections 
 * 
 *      Scan through configuration and try new connections. 
 *   Returns  the calendar time when the next call to this 
 *      function should be made latest. (No harm done if this 
 *      is called earlier or later...)
 */
static time_t try_connections(time_t currenttime)
{
    aConfItem	*aconf, **pconf, *con_conf = (aConfItem *) NULL;
    aClient		*cptr;
    aClass		*cltmp;
    int			connecting = FALSE, confrq, con_class = 0;
    time_t		next = 0;

#if defined(AZZURRA) && !defined(HUB)
	int idx;
#endif


    Debug((DEBUG_NOTICE, "Connection check at: %s", myctime(currenttime)));

#if defined(AZZURRA) && !defined(HUB)
	/* Stop leaf servers from autoconnecting to other hubs if they're
	* already connected to one.
	*/
	for (idx = 0; idx <= highest_fd; ++idx) {

		if (local[idx] && IsServer(local[idx])) {

			/* We're connected to a hub, skip autoconnects for 5 minutes. */
			return (currenttime + 300);
		}
	}
#endif

	for (aconf = conf; aconf; aconf = aconf->next) {

		/* Also when already connecting! (update holdtimes) --SRB */
		if (!(aconf->status & CONF_CONNECT_SERVER) || aconf->port <= 0)
			continue;

		cltmp = Class (aconf);

		/*
		* Skip this entry if the use of it is still on hold until 
		* future. Otherwise handle this entry (and set it on hold 
		* until next time). Will reset only hold times, if already 
		* made one successful connection... [this algorithm is a bit
		* fuzzy... -- msa >;) ]
		*/

		if (aconf->hold > currenttime) {

			if ((next > aconf->hold) || (next == 0))
				next = aconf->hold;

			continue;
		}

		confrq = get_con_freq(cltmp);
		aconf->hold = currenttime + confrq;

		/* Found a CONNECT config with port specified, scan clients 
		* and see if this server is already connected?
		*/

		cptr = find_name(aconf->name, (aClient *) NULL);

		if (!cptr && (Links(cltmp) < MaxLinks(cltmp)) && (!connecting || (Class (cltmp) > con_class))) {

			con_class = Class (cltmp);

			con_conf = aconf;

			/* We connect only one at time... */
			connecting = TRUE;
		}

		if ((next > aconf->hold) || (next == 0))
			next = aconf->hold;
	}

	if (connecting) {

		if (con_conf->next) {	/* are we already last? */

			/*
			* put the current one at the end and make sure we try all
			* connections
			*/

			for (pconf = &conf; (aconf = *pconf); pconf = &(aconf->next)) {

				if (aconf == con_conf)
					*pconf = aconf->next;
			}

			(*pconf = con_conf)->next = 0;
		}

		if (connect_server(con_conf, (aClient *) NULL, (struct hostent *) NULL) == 0)
			sendto_gnotice("from %s: Connection to %s activated.", me.name, con_conf->name);
	}

	Debug((DEBUG_NOTICE, "Next connection check : %s", myctime(next)));
	return (next);
}

/* dianora's code in the new checkpings is slightly wasteful.
 * however, upon inspection (thanks seddy), when we close a connection,
 * the ordering of local[i] is NOT reordered; simply local[highest_fd] becomes
 * local[i], so we can just i--;  - lucas
 */

static time_t check_pings(time_t currenttime)
{
    aClient 	*cptr;
    aConfItem 	*aconf = (aConfItem *) NULL;
    int     	 killflag, zkillflag, ping = 0, i;
    time_t       oldest = 0; /* timeout removed, see EXPLANATION below */
    char       	*reason, *ktype, fbuf[512];
    char 		*errtxt = "No response from %s, closing link";


    for (i = 0; i <= highest_fd; i++) 
    {
	if (!(cptr = local[i]) || IsMe(cptr) || IsLog(cptr))
	    continue;

	/* Note: No need to notify opers here. It's 
	 * already done when "FLAGS_DEADSOCKET" is set.
	 */

	if (cptr->flags & FLAGS_DEADSOCKET) 
	{
	    (void) exit_client(cptr, cptr, &me, (cptr->flags & FLAGS_SENDQEX) ?
			       "SendQ exceeded" : "Dead socket");
	    i--;
	    continue;
	}

	killflag = zkillflag = NO;

	if (rehashed && IsPerson(cptr)) 
	{
	    if ((aconf = find_zkill_perm(cptr)))	
		zkillflag = YES;

            if (!zline_in_progress && !zkillflag && (aconf = find_kill_perm(cptr)))	
		killflag = YES;

	    if (killflag || zkillflag)
	    {
		ktype = zkillflag ? "Z-lined" : 
		    ((aconf->status == CONF_KILL) ? "K-lined" : "Autokilled");

		if (killflag)    
		{   
		    sendto_ops("%s active for %s",   
			       (aconf->status == CONF_KILL) ? "K-line" :   
			       "Autokill", get_client_name(cptr, FALSE));   
		    reason = aconf->passwd ? aconf->passwd : ktype;   
	    	}   
		else /* its a Z line */ 
		{ 
		    sendto_ops("Z-line active for %s",
			       get_client_name(cptr, FALSE));
		    reason = aconf->passwd ? aconf->passwd : "Z-lined";
		}
	    
		sendto_one(cptr, err_str(ERR_YOUREBANNEDCREEP),
			   me.name, cptr->name, ktype);
	    
		ircsprintf(fbuf, "%s: %s", ktype, reason);
		(void) exit_client(cptr, cptr, &me, fbuf);
		i--;   /* subtract out this fd so we check it again.. */
		continue;
	    }
	}
	
	if (IsRegistered(cptr))
	    ping = cptr->pingval;
	else
	    ping = CONNECTTIMEOUT;

	/*
	 * Ok, so goto's are ugly and can be avoided here but this code
	 * is already indented enough so I think its justified. -avalon
	 *
	 * justified by what? laziness? <g>
	 * If the client pingtime is fine (ie, not larger than the client ping) 
	 * skip over all the checks below. - lucas
	 */
	
	if (ping < (currenttime - cptr->lasttime))
	{
	    /*
	     * If the server hasnt talked to us in 2*ping seconds and it has
	     * a ping time, then close its connection. If the client is a
	     * user and a KILL line was found to be active, close this
	     * connection too.
	     */
	    if (((cptr->flags & FLAGS_PINGSENT) &&
		 ((currenttime - cptr->lasttime) >= (2 * ping))) ||
		((!IsRegistered(cptr) && 
		  (currenttime - cptr->since) >= ping))) 
	    {
		if (!IsRegistered(cptr) && (DoingDNS(cptr) || 
					    DoingAuth(cptr))) 
		{
		    if (cptr->authfd >= 0) 
		    {
			(void) close(cptr->authfd);
			cptr->authfd = -1;
			cptr->count = 0;
			*cptr->buffer = '\0';
		    }

		    Debug((DEBUG_NOTICE, "DNS/AUTH timeout %s",
			   get_client_name(cptr, TRUE)));
		    del_queries((char *) cptr);
		    ClearAuth(cptr);
		    ClearDNS(cptr);
		    SetAccess(cptr);
		    cptr->since = currenttime;
		    continue;
		}
		
		if (IsServer(cptr) || IsConnecting(cptr) || IsHandshake(cptr)) 
		{
		    ircsprintf(fbuf, "from %s: %s", me.name, errtxt);
		    sendto_gnotice(fbuf, get_client_name(cptr, HIDEME));
		    ircsprintf(fbuf, ":%s GNOTICE :%s", me.name, errtxt);
		    sendto_serv_butone(cptr, fbuf, 
				       get_client_name(cptr, HIDEME));
		}
		
		(void) exit_client(cptr, cptr, &me, "Ping timeout");
		i--;   /* subtract out this fd so we check it again.. */
		continue;
	    } /* don't send pings during a burst, as we send them already. */
	    
	    else if (!(cptr->flags & (FLAGS_PINGSENT|FLAGS_BURST))) {
		/*
		 * if we havent PINGed the connection and we havent heard from
		 * it in a while, PING it to make sure it is still alive.
		 */
		cptr->flags |= FLAGS_PINGSENT;
		/* not nice but does the job */
		cptr->lasttime = currenttime - ping;
		sendto_one(cptr, "PING :%s", me.name);
	    }
	}
	
	/* see EXPLANATION below
	 *
	 * timeout = cptr->lasttime + ping;
	 * while (timeout <= currenttime)
	 *  timeout += ping;
	 * if (timeout < oldest || !oldest)
	 *   oldest = timeout;
	 */

	/*
	 * Check UNKNOWN connections - if they have been in this state
	 * for > 100s, close them.
	 */
	if (IsUnknown(cptr))
	    if (cptr->firsttime ? ((timeofday - cptr->firsttime) > 100) : 0) 
		(void) exit_client(cptr, cptr, &me, "Connection Timed Out");
    }
    
    rehashed = 0;
    zline_in_progress = 0;
    
    /* EXPLANATION
     * on a server with a large volume of clients, at any given point
     * there may be a client which needs to be pinged the next second,
     * or even right away (a second may have passed while running
     * check_pings). Preserving CPU time is more important than
     * pinging clients out at exact times, IMO. Therefore, I am going to make
     * check_pings always return currenttime + 9. This means that it may take
     * a user up to 9 seconds more than pingfreq to timeout. Oh well.
     * Plus, the number is 9 to 'stagger' our check_pings calls out over
     * time, to avoid doing it and the other tasks ircd does at the same time
     * all the time (which are usually done on intervals of 5 seconds or so). 
     * - lucas
     *
     *  if (!oldest || oldest < currenttime)
     *     oldest = currenttime + PINGFREQUENCY;
     */

    oldest = currenttime + 9;

    Debug((DEBUG_NOTICE, "Next check_ping() call at: %s, %d %d %d",
	   myctime(oldest), ping, oldest, currenttime));

    return oldest;
}

/*
 * bad_command 
 *    This is called when the commandline is not acceptable. 
 *    Give error message and exit without starting anything.
 */
static int bad_command()
{
    (void) printf(
	"Usage: ircd %s[-h servername] [-p portnumber] [-x loglevel] "
	"[-s] [-t]\n",
#ifdef CMDLINE_CONFIG
	"[-f config] "
#else
	""
#endif
	);
    (void) printf("Server not started\n\n");
    return (-1);
}
#ifndef TRUE
#define TRUE 1
#endif

/* ripped this out of hybrid7 out of lazyness. */
static void setup_corefile()
{
   struct rlimit rlim; /* resource limits */
   
   /* Set corefilesize to maximum */
   if (!getrlimit(RLIMIT_CORE, &rlim))
   {	
	rlim.rlim_cur = rlim.rlim_max;
	setrlimit(RLIMIT_CORE, &rlim);
   }
}


/*
 * code added by mika nystrom (mnystrom@mit.edu) 
 * this flag is used to signal globally that the server is heavily
 * loaded, something which can be taken into account when processing
 * e.g. user commands and scheduling ping checks
 * Changed by Taner Halicioglu (taner@CERF.NET) 
 */

#define LOADCFREQ 5		/* every 5s */
#define LOADRECV 40		/* 40k/s    */

#ifndef HUB
int         lifesux = 1;
#else
int         lifesux = 0;
#endif
int         LRV = LOADRECV;
time_t      LCF = LOADCFREQ;
int currlife = 0;
int         HTMLOCK=NO;

FILE *dumpfp=NULL;

int main(int argc, char *argv[])
{
    uid_t         uid, euid;
    int           portarg = 0,  fd;
#ifdef SAVE_MAXCLIENT_STATS
    FILE 	*mcsfp;
#endif
#ifdef USE_SSL
    extern int    ssl_capable;
#endif
    static char star[] = "*";
    aConfItem  *aconf;
#ifndef	INET6
    u_long      vaddr;
#else
    char        vaddr[sizeof(struct IN_ADDR)];
#endif
		
	
    if ((timeofday = time(NULL)) == -1) 
    {
	(void) fprintf(stderr, "ERROR: Clock Failure (%d)\n", errno);
#ifdef USE_SYSLOGD
	syslog(LOG_ERR, "ERROR: Clock Failure [%d: %s]",
		errno, strerror(errno));
#endif
	exit(errno);
    }
	
    build_version();
    setup_corefile();
   
    Count.server = 1;		/* us */
    Count.oper = 0;
    Count.chan = 0;
    Count.local = 0;
    Count.total = 0;
    Count.invisi = 0;
    Count.unknown = 0;
    Count.max_loc = 0;
    Count.max_tot = 0;
    Count.today = 0;
    Count.weekly = 0;
    Count.monthly = 0;
    Count.yearly = 0;
    Count.start = NOW;
    Count.day = NOW;
    Count.week = NOW;
    Count.month = NOW;
    Count.year = NOW;

#ifdef SAVE_MAXCLIENT_STATS
    mcsfp=fopen(DPATH "/.maxclients", "r");
    if(mcsfp!=NULL) 
    {
	fscanf(mcsfp, "%d %d %li %li %li %ld %ld %ld %ld", &Count.max_loc, 
	       &Count.max_tot, &Count.weekly, &Count.monthly, &Count.yearly, 
	       &Count.start, &Count.week, &Count.month, &Count.year);
	fclose(mcsfp);
    }
#endif

    /*
     * this code by mika@cs.caltech.edu 
     * it is intended to keep the ircd from being swapped out. BSD
     * swapping criteria do not match the requirements of ircd
     */
	
#ifdef INITIAL_DBUFS
    dbuf_init();	/* set up some dbuf stuff to control paging */
#endif
    
    sbrk0 = sbrk((size_t) 0);
    uid = getuid();
    euid = geteuid();

#if defined PROFILING && defined __GLIBC__ && (__GLIBC__ >= 2)
    setenv("GMON_OUT_PREFIX", "gmon.out", 1);
    (void) signal(SIGUSR1, s_dumpprof);
#endif
	
    myargv = argv;
    (void) umask(077);		/* better safe than sorry --SRB  */
    memset((char *) &me, '\0', sizeof(me));
    
    setup_signals();
    /*
     * * All command line parameters have the syntax "-fstring"  or "-f
     * string" (e.g. the space is optional). String may  be empty. Flag
     * characters cannot be concatenated (like "-fxyz"), it would
     * conflict with the form "-fstring".
     */
    while (--argc > 0 && (*++argv)[0] == '-') 
    {
	char       *p = argv[0] + 1;
	int         flag = *p++;
	
        if (flag == '\0' || *p == '\0') 
	{
	    if (argc > 1 && argv[1][0] != '-') 
	    {
		p = *++argv;
		argc -= 1;
	    }
	    else
		p = "";
	}
		
	switch (flag) 
	{
	case 'c':
	    bootopt |= BOOT_CONSOLE;
	    break;
	case 'q':
	    bootopt |= BOOT_QUICK;
	    break;
	case 'd':
	    (void) setuid((uid_t) uid);
	    dpath = p;
	    break;
#ifdef CMDLINE_CONFIG
	case 'f':
	    (void) setuid((uid_t) uid);
	    configfile = p;
	    break;
			
# ifdef KPATH
	case 'k':
	    (void) setuid((uid_t) uid);
	    klinefile = p;
	    break;
# endif
			
#endif
	case 'h':
	    strncpyzt(me.name, p, sizeof(me.name));
	    break;
	case 'p':
	    if ((portarg = atoi(p)) > 0)
		portnum = portarg;
	    break;
	case 's':
	    bootopt |= BOOT_STDERR;
	    break;
	case 't':
	    (void) setuid((uid_t) uid);
	    bootopt |= BOOT_TTY;
	    break;
	case 'v':
	    (void) printf("ircd %s\n", version);
	    exit(0);
	case 'x':
#ifdef	DEBUGMODE
	    (void) setuid((uid_t) uid);
	    debuglevel = atoi(p);
	    debugmode = *p ? p : "0";
	    bootopt |= BOOT_DEBUG;
	    break;
#else
	    (void) fprintf(stderr,
			   "%s: DEBUGMODE must be defined for -x y\n",
			   myargv[0]);
	    exit(0);
#endif
	default:
	    bad_command();
	    break;
	}
    }
	
    if (chdir(dpath)) 
    {
	perror("chdir");
	fprintf(stderr, "Please ensure that your configuration directory "
		"exists and is accessable.\n");
	exit(-1);
    }
    if ((uid != euid) && !euid) 
    {
	(void) fprintf(stderr,
		       "ERROR: do not run ircd setuid root. Make it setuid "
		       "a normal user.\n");
	exit(-1);
    }
	
    if (argc > 0)
	return bad_command();	/* This should exit out  */

    if(dh_init() == -1)
	return 0;
    
    motd = (aMotd *) NULL;
    helpfile = (aMotd *) NULL;
    motd_tm = NULL;
#ifdef SHORT_MOTD
    shortmotd = NULL;
#endif
	
    read_motd(MOTD);
    read_help(HELPFILE);
#ifdef SHORT_MOTD
    read_shortmotd(SHORTMOTD);
#endif
	
    clear_client_hash_table();
    clear_channel_hash_table();
    clear_scache_hash_table();	/* server cache name table */
    clear_ip_hash_table();	/* client host ip hash table */

    /* init the throttle system -wd */
    throttle_init();

    initlists();
    initclass();
    initwhowas();
    initstats();
    init_tree_parse(msgtab);
    init_send();
    NOW = time(NULL);
    open_debugfile();
    NOW = time(NULL);
    init_fdlist(&serv_fdlist);
    init_fdlist(&oper_fdlist);
    init_fdlist(&listen_fdlist);
	
#ifndef NO_PRIORITY
    init_fdlist(&busycli_fdlist);
#endif
	
    init_fdlist(&default_fdlist);
    {
	int i;
		  
	for (i = MAXCONNECTIONS + 1; i > 0; i--) 
	{
	    default_fdlist.entry[i] = i - 1;
	}
    }

    if ((timeofday = time(NULL)) == -1) 
    {
#ifdef USE_SYSLOG
	syslog(LOG_WARNING, "Clock Failure (%d), TS can be corrupted", errno);
#endif
	sendto_ops("Clock Failure (%d), TS can be corrupted", errno);
    }

#ifdef WINGATE_NOTICE
    strcpy(ProxyMonURL, "http://");
    strncpyzt((ProxyMonURL + 7), DEFAULT_PROXY_INFO_URL, (TOPICLEN + 1) - 7);
    strncpyzt(ProxyMonHost, MONITOR_HOST, (HOSTLEN + 1));
#endif

#ifdef AZZURRA
    if(!cloak_init())
    {
	fprintf(stderr, "Failed to initialize cloak subsystem. I`m exiting now.\n");
	exit(-1);
    }
    else
	fprintf(stderr, "Cloaking subsystem succesfully initialized (%d bits key).\n",
		cloak_key_len * 8);
    
    {
        struct tm *tm = localtime(&NOW);
        struct tm t;
	/* time stuff. (needed by antispam system). */
	int days_per_month[] = { 31, 0, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

        days_per_month[1] = (tm->tm_isdst ? 28 : 29);

        memcpy(&t, tm, sizeof(struct tm));

        /* midnight block */
        if(t.tm_mday == days_per_month[t.tm_mon])
        {
	    t.tm_mon++;
	    t.tm_mday = 0;
        }
        else
	{
	    t.tm_mday++;
	}

        t.tm_sec = t.tm_hour = t.tm_min = 0;
        NEXT_MIDNIGHT = mktime(&t);

        /* week-end block */
        t.tm_mon = tm->tm_mon;
        t.tm_mday += 7 - t.tm_wday;
        t.tm_wday = 0;
        NEXT_WEEKEND = mktime(&t);

        /* end-of-month block */        
        t.tm_wday = days_per_month[t.tm_mon] / 7;
        if(t.tm_mon < 11)
	{
	    t.tm_mon++;
	}
        else
        {
	    t.tm_mon = 0;
	    t.tm_year++;
        }
        t.tm_mday = 1;
        NEXT_MONTH = mktime(&t);
    }
#endif
	
    if (portnum < 0)
	portnum = PORTNUM;
    me.port = portnum;
#ifdef USE_SSL
    fprintf(stderr, "SSL: Trying to intialize SSL support . . .\n");
    if(!(ssl_capable = initssl()))
        fprintf(stderr, "SSL: failure. (did you generate your "
                "certificate ?)\nSSL: Server running with SSL "
                "code disabled, consult the above error log for "
                "details.\n");
    else
	fprintf(stderr, "SSL: success.\n");
#endif 
    (void) init_sys();
    me.flags = FLAGS_LISTEN;
    me.fd = -1;
	
#ifdef USE_SYSLOG
# define SYSLOG_ME     "ircd"
    openlog(SYSLOG_ME, LOG_PID | LOG_NDELAY, LOG_FACILITY);
#endif
    if ((fd = openconf(configfile)) == -1) 
    {
	Debug((DEBUG_FATAL, "Failed in reading configuration file %s",
	       configfile));
	(void) printf("Couldn't open configuration file %s\n",
		      configfile);
	exit(-1);
    }
    (void) initconf(bootopt, fd);
	
    /* comstuds SEPARATE_QUOTE_KLINES_BY_DATE code */
#ifdef SEPARATE_QUOTE_KLINES_BY_DATE
    {
	struct tm  *tmptr;
	char        timebuffer[20], filename[200];
		  
	tmptr = localtime(&NOW);
	(void) strftime(timebuffer, 20, "%y%m%d", tmptr);
	ircsprintf(filename, "%s.%s", klinefile, timebuffer);
	if ((fd = openconf(filename)) == -1) 
	{
	    Debug((DEBUG_ERROR, "Failed reading kline file %s",
		   filename));
	    (void) printf("Couldn't open kline file %s\n",
			  filename);
	}
	else
	    (void) initconf(0, fd);
    }
#else
# ifdef KPATH
    if ((fd = openconf(klinefile)) == -1) 
    {
	Debug((DEBUG_ERROR, "Failed reading kline file %s", klinefile));
	(void) printf("Couldn't open kline file %s\n", klinefile);
    }
    else
	(void) initconf(0, fd);
# endif
#endif
    if ((aconf = find_me()) && portarg <= 0 && aconf->port > 0)
	portnum = aconf->port;

    Debug((DEBUG_ERROR, "Port = %d", portnum));

    if ((aconf->passwd[0] != '\0') && (aconf->passwd[0] != '*'))
#ifndef INET6
	inet_pton (AFINET, aconf->passwd, &vaddr);
#else
	inet_pton (AFINET, aconf->passwd, vaddr);
#endif
    else
#ifndef INET6
	vaddr = 0;
#else
	memset (vaddr, 0x0, sizeof(vaddr));
#endif
    if (inetport(&me, star, portnum, vaddr)) 
    {
	if (bootopt & BOOT_STDERR)
	    fprintf(stderr, "Couldn't bind to primary port %d\n", portnum);
#ifdef USE_SYSLOG
	(void) syslog(LOG_CRIT, "Couldn't bind to primary port %d\n", portnum);
#endif
	exit(1);
    }

    set_non_blocking(me.fd, &me);
    (void) get_my_name(&me, me.sockhost, sizeof(me.sockhost) - 1);
    if (me.name[0] == '\0')
	strncpyzt(me.name, me.sockhost, sizeof(me.name));
    me.hopcount = 0;
    me.authfd = -1;
    me.confs = NULL;
    me.next = NULL;
    me.user = NULL;
    me.from = &me;
    SetMe(&me);
    make_server(&me);
    me.serv->up = me.name;
    me.lasttime = me.since = me.firsttime = NOW;
    (void) add_to_client_hash_table(me.name, &me);

    check_class();
    write_pidfile();
	
    Debug((DEBUG_NOTICE, "Server ready..."));
#ifdef USE_SYSLOG
    syslog(LOG_NOTICE, "Server Ready");
#endif
    NOW = time(NULL);
	
#ifndef NO_PRIORITY
    check_fdlists();
#endif
	
    if ((timeofday = time(NULL)) == -1) 
    {
#ifdef USE_SYSLOG
	syslog(LOG_WARNING, "Clock Failure (%d), TS can be corrupted", errno);
#endif
	sendto_ops("Clock Failure (%d), TS can be corrupted", errno);
    }

#ifdef DUMP_DEBUG
    dumpfp=fopen("dump.log", "w");
#endif

#ifdef USE_ACTIVITY_LOG
    if (activity_open())
    {
#ifdef USE_SYSLOGD
	syslog(LOG_ERR, "ERROR: Opening Activity Log [%d: %s]",
		errno, strerror(errno));
#endif
    }
#endif

    io_loop();
    return 0;
}

void io_loop()
{
    char to_send[200];
#ifndef HUB
    time_t lasttime = 0;
    long lastrecvK = 0;
    int  lrv = 0;
#endif
    time_t      lasttimeofday;
    int delay = 0;

    while(1)
    {
	lasttimeofday = timeofday;
	
	if ((timeofday = time(NULL)) == -1) 
	{
#ifdef USE_SYSLOG
	    syslog(LOG_WARNING, "Clock Failure (%d), TS can be corrupted", 
		   errno);
#endif
	    sendto_ops("Clock Failure (%d), TS can be corrupted", errno);
	}

	if (timeofday < lasttimeofday) 
	{
	    ircsprintf(to_send, "System clock running backwards - (%d < %d)",
		       timeofday, lasttimeofday);
	    report_error(to_send, &me);
	}

	NOW = timeofday;

	/*
	 * This chunk of code determines whether or not "life sucks", that
	 * is to say if the traffic level is so high that standard server
	 * commands should be restricted
	 * 
	 * Changed by Taner so that it tells you what's going on as well as
	 * allows forced on (long LCF), etc...
	 */
	/* Wrapped this in #ifndef HUB as on a hub it's silly */

#ifndef HUB

	if ((timeofday - lasttime) >= LCF) 
	{
	    lrv = LRV * LCF;
	    lasttime = timeofday;
	    currlife = (me.receiveK - lastrecvK) / LCF;
	    if ((me.receiveK - lrv) > lastrecvK || HTMLOCK == YES) 
	    {
		if (!lifesux) 
		{
		    /*
		     * In the original +th code Taner had
		     * 
		     * LCF << 1;  / * add hysteresis * /
		     * 
		     * which does nothing... so, the hybrid team changed it to
		     * 
		     * LCF <<= 1;  / * add hysteresis * /
		     * 
		     * suddenly there were reports of clients mysteriously just
		     * dropping off... Neither rodder or I can see why it makes
		     * a difference, but lets try it this way...
		     * 
		     * The original dog3 code, does not have an LCF variable
		     * 
		     * -Dianora
		     * 
		     */
		    lifesux = 1;

		    if (noisy_htm) 
			sendto_ops("Entering high-traffic mode - (%dk/s > "
				   "%dk/s)", currlife, LRV);
		}
		else 
		{
		    lifesux++;		/* Ok, life really sucks! */
		    LCF += 2;		/* Wait even longer */
		    if (noisy_htm) 
			sendto_ops("Still high-traffic mode %d%s (%d delay): "
				   "%dk/s",
				   lifesux, (lifesux > 9) ? " (TURBO)" : "",
				   (int) LCF, currlife);

		    /* Reset htm here, because its been on a little too long.
		     * Bad Things tend to happen with HTM on too long -epi */

		    if (lifesux>15) 
		    {
			if (noisy_htm) 
			    sendto_ops("Resetting HTM and raising limit to: "
				       "%dk/s\n", LRV + 5);
			LCF=LOADCFREQ;
			lifesux=0;
			LRV+=5;
		    }
		}
	    }
	    else 
	    {
		LCF = LOADCFREQ;
		if (lifesux) 
		{
		    lifesux = 0;
		    if (noisy_htm)
			sendto_ops("Resuming standard operation . . . .");
		}
	    }
	    lastrecvK = me.receiveK;
	}
#endif

	/*
	 * We only want to connect if a connection is due, not every
	 * time through.  Note, if there are no active C lines, this call
	 * to Tryconnections is made once only; it will return 0. - avalon
	 */

	if (nextconnect && timeofday >= nextconnect)
	    nextconnect = try_connections(timeofday);

	/* DNS checks. One to timeout queries, one for cache expiries.*/

	if (timeofday >= nextdnscheck)
	    nextdnscheck = timeout_query_list(timeofday);
	if (timeofday >= nextexpire)
	    nextexpire = expire_cache(timeofday);

	/*
	 * take the smaller of the two 'timed' event times as the time
	 * of next event (stops us being late :) - avalon WARNING -
	 * nextconnect can return 0!
	 */

	if (nextconnect)
	    delay = MIN(nextping, nextconnect);
	else
	    delay = nextping;
	delay = MIN(nextdnscheck, delay);
	delay = MIN(nextexpire, delay);
	delay -= timeofday;

	/*
	 * Adjust delay to something reasonable [ad hoc values] (one
	 * might think something more clever here... --msa) 
	 * We don't really need to check that often and as long 
	 * as we don't delay too long, everything should be ok. 
	 * waiting too long can cause things to timeout... 
	 * i.e. PINGS -> a disconnection :( 
	 * - avalon
	 */
	if (delay < 1)
	    delay = 1;
	else
	    delay = MIN(delay, TIMESEC);
	/*
	 * We want to read servers on every io_loop, as well as "busy"
	 * clients (which again, includes servers. If "lifesux", then we
	 * read servers AGAIN, and then flush any data to servers. -Taner
	 */

#ifndef NO_PRIORITY
	read_message(0, &serv_fdlist);
	read_message(1, &busycli_fdlist);
	if (lifesux) 
	{
	    (void) read_message(1, &serv_fdlist);
	    if (lifesux > 9) 		/* life really sucks */
	    {
		(void) read_message(1, &busycli_fdlist);
		(void) read_message(1, &serv_fdlist);
	    }
	    flush_fdlist_connections(&serv_fdlist);
	}
	
	if ((timeofday = time(NULL)) == -1) 
	{
#ifdef USE_SYSLOG
	    syslog(LOG_WARNING, "Clock Failure (%d), TS can be corrupted",
		   errno);
#endif
	    sendto_ops("Clock Failure (%d), TS can be corrupted", errno);
	}
	/*
	 * CLIENT_SERVER = TRUE: If we're in normal mode, or if "lifesux"
	 * and a few seconds have passed, then read everything.
	 * CLIENT_SERVER = FALSE: If it's been more than lifesux*2 seconds
	 * (that is, at most 1 second, or at least 2s when lifesux is != 0)
	 * check everything. -Taner
	 */
	{ 
	    static time_t lasttime = 0;
	    
# ifdef CLIENT_SERVER
	    if (!lifesux || (lasttime + lifesux) < timeofday)
	    {
# else
		if ((lasttime + (lifesux + 1)) < timeofday)
		{
# endif
		    (void) read_message(delay ? delay : 1, NULL);	
		    /* check everything! */
		    lasttime = timeofday;
		}
	    }
#if 0 /* We do this to appease emacs */
	}
#endif
#else
	(void) read_message(delay, NULL);	/* check everything! */
#endif
	/*
	 * * ...perhaps should not do these loops every time, but only if
	 * there is some chance of something happening (but, note that
	 * conf->hold times may be changed elsewhere--so precomputed next
	 * event time might be too far away... (similarly with ping
	 * times) --msa
	 */
	
	if ((timeofday >= nextping))
	    nextping = check_pings(timeofday);
	
	if (dorehash && !lifesux) 
	{
	    (void) rehash(&me, &me, 1);
	    dorehash = 0;
	}
	/*
	 * 
	 * Flush output buffers on all connections now if they 
	 * have data in them (or at least try to flush)  -avalon
	 *
	 * flush_connections(me.fd);
	 *
	 * avalon, what kind of crack have you been smoking? why
	 * on earth would we flush_connections blindly when
	 * we already check to see if we can write (and do)
	 * in read_message? There is no point, as this causes
	 * lots and lots of unnecessary sendto's which 
	 * 99% of the time will fail because if we couldn't
	 * empty them in read_message we can't empty them here.
	 * one effect: during htm, output to normal lusers
	 * will lag.
	 */
	
	/* Now we've made this call a bit smarter. */
	/* Only flush non-blocked sockets. */
	
	flush_connections(me.fd);
	
#ifndef NO_PRIORITY
	check_fdlists();
#endif

	/* call the throttle timer to possibly flush extra gunk  -wd */
	throttle_timer(NOW);
	
#ifdef	LOCKFILE
	/*
	 * * If we have pending klines and CHECK_PENDING_KLINES minutes
	 * have passed, try writing them out.  -ThemBones
	 */
	
	if ((pending_klines) && ((timeofday - pending_kline_time)
				 >= (CHECK_PENDING_KLINES * 60)))
	    do_pending_klines();
#endif
#ifdef AZZURRA
	if(NOW >= NEXT_MIDNIGHT)
	{
	    Spam *s;
	    extern Spam *spam_list;

	    for(s = spam_list; s; s = s->next)
	    {
		s->daycount = 0;
	    }
            NEXT_MIDNIGHT += 84600;
	}
	if(NOW >= NEXT_WEEKEND)
	{
            Spam *s;
            extern Spam *spam_list;

            for(s = spam_list; s; s = s->next)
	    {
		s->weekcount = 0;
	    }
            NEXT_WEEKEND += 604800;
	}
	if(NOW >= NEXT_MONTH)
	{
            Spam *s;
            extern Spam *spam_list;

            for(s = spam_list; s; s = s->next)
	    {
		s->monthcount++;
	    }
            NEXT_MONTH += 2592000;
	}
#endif
    }
}

/*
 * open_debugfile
 * 
 * If the -t option is not given on the command line when the server is
 * started, all debugging output is sent to the file set by LPATH in
 * config.h Here we just open that file and make sure it is opened to
 * fd 2 so that any fprintf's to stderr also goto the logfile.  If the
 * debuglevel is not set from the command line by -x, use /dev/null as
 * the dummy logfile as long as DEBUGMODE has been defined, else dont
 * waste the fd.
 */
static void open_debugfile()
{
#ifdef	DEBUGMODE
    int         fd;
    aClient    *cptr;

    if (debuglevel >= 0) 
    {
	cptr = make_client(NULL, NULL);
	cptr->fd = 2;
	SetLog(cptr);
	cptr->port = debuglevel;
	cptr->flags = 0;
	cptr->acpt = cptr;
	local[2] = cptr;
	(void) strcpy(cptr->sockhost, me.sockhost);

	(void) printf("isatty = %d ttyname = %#x\n",
		      isatty(2), (u_int) ttyname(2));
	if (!(bootopt & BOOT_TTY)) 	/* leave debugging output on fd */ 
	{
	    (void) truncate(LOGFILE, 0);
	    if ((fd = open(LOGFILE, O_WRONLY | O_CREAT, 0600)) < 0)
		if ((fd = open("/dev/null", O_WRONLY)) < 0)
		    exit(-1);
	    if (fd != 2) 
	    {
		(void) dup2(fd, 2);
		(void) close(fd);
	    }
	    strncpyzt(cptr->name, LOGFILE, sizeof(cptr->name));
	}
	else if (isatty(2) && ttyname(2))
	    strncpyzt(cptr->name, ttyname(2), sizeof(cptr->name));
	else
	    (void) strcpy(cptr->name, "FD2-Pipe");
	Debug((DEBUG_FATAL, "Debug: File <%s> Level: %d at %s",
	       cptr->name, cptr->port, myctime(time(NULL))));
    }
    else
	local[2] = NULL;
#endif
    return;
}

static void setup_signals()
{
#ifdef	POSIX_SIGNALS
    struct sigaction act;

    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;
    (void) sigemptyset(&act.sa_mask);
    (void) sigaddset(&act.sa_mask, SIGPIPE);
    (void) sigaddset(&act.sa_mask, SIGALRM);
# ifdef	SIGWINCH
    (void) sigaddset(&act.sa_mask, SIGWINCH);
    (void) sigaction(SIGWINCH, &act, NULL);
# endif
    (void) sigaction(SIGPIPE, &act, NULL);
    act.sa_handler = dummy;
    (void) sigaction(SIGALRM, &act, NULL);
    act.sa_handler = s_rehash;
    (void) sigemptyset(&act.sa_mask);
    (void) sigaddset(&act.sa_mask, SIGHUP);
    (void) sigaction(SIGHUP, &act, NULL);
    act.sa_handler = s_restart;
    (void) sigaddset(&act.sa_mask, SIGINT);
    (void) sigaction(SIGINT, &act, NULL);
    act.sa_handler = s_die;
    (void) sigaddset(&act.sa_mask, SIGTERM);
    (void) sigaction(SIGTERM, &act, NULL);

#else
# ifndef	HAVE_RELIABLE_SIGNALS
    (void) signal(SIGPIPE, dummy);
#  ifdef	SIGWINCH
    (void) signal(SIGWINCH, dummy);
#  endif
# else
#  ifdef	SIGWINCH
    (void) signal(SIGWINCH, SIG_IGN);
#  endif
    (void) signal(SIGPIPE, SIG_IGN);
# endif
    (void) signal(SIGALRM, dummy);
    (void) signal(SIGHUP, s_rehash);
    (void) signal(SIGTERM, s_die);
    (void) signal(SIGINT, s_restart);
#endif 

#ifdef RESTARTING_SYSTEMCALLS
    /*
     * * At least on Apollo sr10.1 it seems continuing system calls 
     * after signal is the default. The following 'siginterrupt' 
     * should change that default to interrupting calls.
     */
    (void) siginterrupt(SIGALRM, 1);
#endif
}

#ifndef NO_PRIORITY
/*
 * This is a pretty expensive routine -- it loops through all the fd's,
 * and finds the active clients (and servers and opers) and places them
 * on the "busy client" list
 */
void check_fdlists()
{
#ifdef CLIENT_SERVER
#define BUSY_CLIENT(x)	(((x)->priority < 55) || \
                         (!lifesux && ((x)->priority < 75)))
#else
#define BUSY_CLIENT(x)	(((x)->priority < 40) || \
                         (!lifesux && ((x)->priority < 60)))
#endif
#define FDLISTCHKFREQ  2

    aClient *cptr;
    int i, j;

    j = 0;
    for (i = highest_fd; i >= 0; i--) 
    {
	if (!(cptr = local[i]))
	    continue;
	if (IsServer(cptr) || IsListening(cptr) || IsOper(cptr)) 
	{
	    busycli_fdlist.entry[++j] = i;
	    continue;
	}
	if (cptr->receiveM == cptr->lastrecvM) 
	{
	    cptr->priority += 2;	/* lower a bit */
	    if (cptr->priority > 90)
		cptr->priority = 90;
	    else if (BUSY_CLIENT(cptr))
		busycli_fdlist.entry[++j] = i;
	    continue;
	}
	else 
	{
	    cptr->lastrecvM = cptr->receiveM;
	    cptr->priority -= 30;	/* active client */
	    if (cptr->priority < 0) 
	    {
		cptr->priority = 0;
		busycli_fdlist.entry[++j] = i;
	    }
	    else if (BUSY_CLIENT(cptr))
		busycli_fdlist.entry[++j] = i;
	}
    }
    busycli_fdlist.last_entry = j;	/* rest of the fdlist is garbage */
/*   return (now + FDLISTCHKFREQ + (lifesux + 1)); */
}
#endif

void build_version(void) 
{
    char *s=PATCHES;
    ircsprintf(version, "%s(%s)-%.1d.%.1d(%.2d)%s", BASENAME, BRANCH, /*AZZURRA*/
	       MAJOR, MINOR, PATCH, (*s != 0 ? PATCHES : ""));	
}


#ifdef USE_ACTIVITY_LOG
/* Open activity file. Return 0 on success, 1 on error. */
int activity_open()
{
#ifdef ACTIVITY_LOG_ROTATE
    char filename[1024];
    time_t timenow;
    struct tm *t;

    timenow = time(NULL);
    t=localtime(&timenow);
    sprintf(filename,"%s.%04d%02d%02d-%02d%02d", ACTIVITY_LOG_FILE, 
		     t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min);
    if ((activity_fd = open(filename,
#else
    if ((activity_fd = open(ACTIVITY_LOG_FILE,
#endif
                            (O_CREAT|O_APPEND|O_NONBLOCK|O_RDWR),
		            (S_IRUSR|S_IWUSR))) >= 0)
	activity_log("(STARTING ACTIVITY LOG)");
    
    return (activity_fd >= 0) ? 0 : 1;
}

/* Close activity file */
void activity_close()
{
    if (activity_fd>=0)
    {
	activity_log("(STOPPING ACTIVITY LOG)");
	close(activity_fd);
    }
}

/* Log message to activity file */
void activity_log(char *pattern, ...)
{
    static char buf[1024];
    va_list vl;
    int len;
    char *s;
#ifdef ACTIVITY_LOG_ROTATE
    static time_t nextrotate = 0;

    if (nextrotate == 0)
        nextrotate = 60 * ACTIVITY_LOG_ROTATE + time(NULL);

    if (time(NULL)>nextrotate)
    {
	nextrotate = 60 * ACTIVITY_LOG_ROTATE + time(NULL);
	
	/* NOTE: these two functions call this one!
	 * Anyway recursive calls are safe because we have
	 * incremented nextrotate.
	 */
	activity_close();
	activity_open();
    }

#endif
       
    if (activity_fd>=0)
    {
	va_start(vl, pattern);
	s = myctime(time(NULL));
	write(activity_fd, s, strlen(s));
	write(activity_fd, " ", 1);
	len = ircvsprintf(buf, pattern, vl);
	strcat(buf, "\n");
	write(activity_fd, buf, len+1);
	va_end(vl);
    }
    
}
#endif

