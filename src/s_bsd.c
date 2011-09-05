
/************************************************************************
 *   IRC - Internet Relay Chat, src/s_bsd.c
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
#include "res.h"
#include "numeric.h"
#include "patchlevel.h"
#include "zlink.h"
#include "throttle.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#if defined(SOL20)
#include <sys/filio.h>
#include <sys/select.h>
#include <unistd.h>
#endif
#include "inet.h"
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <utmp.h>
#include <sys/resource.h>

/* Stuff for poll() */

#ifdef USE_POLL
#include <poll.h>
#endif /* USE_POLL */

#ifdef	AIX
#include <time.h>
#include <arpa/nameser.h>
#else
#include "nameser.h"
#endif
#include "resolv.h"

#ifdef USE_SSL
#include "ssl.h"
#endif

/* If FD_ZERO isn't define up to this point,
 * define it (BSD4.2 needs this) */

#include "h.h"
#include "fdlist.h"
extern fdlist serv_fdlist;

#ifndef NO_PRIORITY
extern fdlist busycli_fdlist;
#endif

extern fdlist default_fdlist;

#ifndef IN_LOOPBACKNET
#define IN_LOOPBACKNET	0x7f
#endif

#if defined(MAXBUFFERS)
int rcvbufmax = 0, sndbufmax = 0;
#endif

#ifdef MAXBUFFERS
void reset_sock_opts(int, int);
#endif

aClient *local[MAXCONNECTIONS];
int highest_fd = 0, resfd = -1;
time_t timeofday;
static struct SOCKADDR_IN mysk;

static struct SOCKADDR *connect_inet(aConfItem *, aClient *, int *);
static int completed_connection(aClient *);
static int check_init(aClient *, char *);
static void do_dns_async(void), set_sock_opts(int, aClient *);
struct SOCKADDR_IN vserv;
char specific_virtual_host;

#if defined(MAXBUFFERS)
static char *readbuf;
#else
static char readbuf[8192];
#endif

/* Silly macro to ignore certain report error statements */
#define silent_report_error(x,y)

#ifdef INET6
static unsigned char minus_one[] =
   { 255, 255, 255, 255, 255, 255, 255, 255, 255,
   255, 255, 255, 255, 255, 255, 255, 0
};

void ip6_expand(char *host, size_t len) {
    if(*host == ':') {
        char *b;
        DupString(b, host);
        *host = '0';
        strncpyzt((host + 1), b, len - 1);
        MyFree(b);
    }
}
#endif


/*
 * Try and find the correct name to use with getrlimit() for setting
 * the max. number of files allowed to be open by this process.
 */

#ifdef RLIMIT_FDMAX
#define RLIMIT_FD_MAX   RLIMIT_FDMAX
#else
#ifdef RLIMIT_NOFILE
#define RLIMIT_FD_MAX RLIMIT_NOFILE
#else
#ifdef RLIMIT_OPEN_MAX
#define RLIMIT_FD_MAX RLIMIT_OPEN_MAX
#else
#undef RLIMIT_FD_MAX
#endif
#endif
#endif


/*
 * add_local_domain() 
 * Add the domain to hostname, if it is missing
 * (as suggested by eps@TOASTER.SFSU.EDU)
 */

void add_local_domain(char *hname, int size)
{
#ifdef RES_INIT
    /* try to fix up unqualified name */
    if (!strchr(hname, '.')) 
    {
	if (!(_res.options & RES_INIT))
	{
	    Debug((DEBUG_DNS, "res_init()"));
	    res_init();
	}
	if (_res.defdname[0])
	{
	    (void) strncat(hname, ".", size - 1);
	    (void) strncat(hname, _res.defdname, size - 2);
	}
    }
#endif
    return;
}

/*
 * Cannot use perror() within daemon. stderr is closed in 
 * ircd and cannot be used. And, worse yet, it might have 
 * been reassigned to a normal connection...
 */

/*
 * report_error 
 * This a replacement for perror(). Record error to log and 
 * also send a copy to all *LOCAL* opers online. 
 * text    is a *format* string for outputting error. It must
 * contain only two '%s', the first will be replaced by the
 * sockhost from the cptr, and the latter will be taken from 
 * sys_errlist[errno].
 * 
 * cptr, if not NULL, is the *LOCAL* client associated with
 * the error.
 */

void report_error(char *text, aClient * cptr)
{
    int errtmp = errno;		/* debug may change 'errno' */
    char *host;
    int err;
    socklen_t len = sizeof(err);
    extern char *strerror();

    host =
	(cptr) ? get_client_name(cptr,
				 (IsServer(cptr) ? HIDEME : FALSE)) : "";

    Debug((DEBUG_ERROR, text, host, strerror(errtmp)));
    /* 
     * Get the *real* error from the socket (well try to anyway..). This
     * may only work when SO_DEBUG is enabled but its worth the gamble
     * anyway.
     */

#ifdef	SO_ERROR
    if (!IsMe(cptr) && cptr->fd >= 0)
	if (!getsockopt(cptr->fd, SOL_SOCKET, SO_ERROR, (char *) &err, &len))
	    if (err)
		errtmp = err;
#endif
    sendto_realops_lev(DEBUG_LEV, text, host, strerror(errtmp));
#ifdef USE_SYSLOG
    syslog(LOG_WARNING, text, host, strerror(errtmp));
    if (bootopt & BOOT_STDERR)
    {
	fprintf(stderr, text, host, strerror(errtmp));
	fprintf(stderr, "\n");
    }
#endif
    return;
}

/* inetport
 *
 * Create a socket in the AFINET domain, bind it to the port given in
 * 'port' and listen to it.  Connections are accepted to this socket
 * depending on the IP# mask given by 'name'.  Returns the fd of the
 * socket created or -1 on error.
 */
#ifndef INET6
int inetport(aClient * cptr, char *name, int port, u_long bind_addr)
#else
int inetport(aClient *cptr, char *name, int port, char *bind_addr)
#endif
{
    static struct SOCKADDR_IN server;
    int ad[4];
    socklen_t len = sizeof(server);
    char ipname[20];

    ad[0] = ad[1] = ad[2] = ad[3] = 0;
    /* 
     * do it this way because building ip# from separate values for each
     * byte requires endian knowledge or some nasty messing. Also means
     * easy conversion of "*" 0.0.0.0 or 134.* to 134.0.0.0 :-)
     */
#ifndef INET6
    (void) sscanf(name, "%d.%d.%d.%d", &ad[0], &ad[1], &ad[2], &ad[3]);
    (void) ircsprintf(ipname, "%d.%d.%d.%d", ad[0], ad[1], ad[2], ad[3]);
#else
   if (*name == '*')
      ircsprintf(ipname, INADDRANY_STR);
   else
      ircsprintf(ipname, "%s", name);
#endif

    if (cptr != &me)
    {
	(void) ircsprintf(cptr->sockhost, "%-.42s.%.u",
			  name, (unsigned int) port);
	(void) strcpy(cptr->name, me.name);
    }
    
    /* At first, open a new socket */
    
    if (cptr->fd == -1)
    {
	cptr->fd = socket(AFINET, SOCK_STREAM, 0);
	if (cptr->fd < 0 && errno == EAGAIN)
	{
	    sendto_realops("opening stream socket %s: No more sockets",
			   get_client_name(cptr, HIDEME));
	    return -1;
	}
    }
    if (cptr->fd < 0)
    {
	report_error("opening stream socket %s:%s", cptr);
	return -1;
    } else if (cptr->fd >= (HARD_FDLIMIT - 10)) {
	sendto_realops("No more connections allowed (%s)", cptr->name);
	(void) close(cptr->fd);
	return -1;
    }
    set_sock_opts(cptr->fd, cptr);

    /* 
     * Bind a port to listen for new connections if port is non-null,
     * else assume it is already open and try get something from it.
     */
    if (port)
    {
	memset((char *) &server, '\0', sizeof(server));
	server.SIN_FAMILY = AFINET;

	if (bind_addr)
#ifndef INET6
	    server.SIN_ADDR.S_ADDR = bind_addr;
	else
	    server.SIN_ADDR.S_ADDR = INADDR_ANY;
#else
	    memcpy(server.SIN_ADDR.S_ADDR, bind_addr, sizeof(struct IN_ADDR));
	else
	    memset(server.SIN_ADDR.S_ADDR, 0x0, sizeof(struct IN_ADDR));
#endif
	server.SIN_PORT = htons((short) port);
	/* 
	 * Try 10 times to bind the socket with an interval of 20
	 * seconds. Do this so we dont have to keepp trying manually to
	 * bind. Why ? Because a port that has closed often lingers
	 * around for a short time. This used to be the case.  Now it no
	 * longer is. Could cause the server to hang for too long -
	 * avalon
	 */
	if (bind(cptr->fd, (struct SOCKADDR *) &server,
		 sizeof(server)) == -1)
	{
	    report_error("binding stream socket %s:%s", cptr);
	    (void) close(cptr->fd);
	    return -1;
	}
    }
    if (getsockname(cptr->fd, (struct SOCKADDR *) &server, &len))
    {
	report_error("getsockname failed for %s:%s", cptr);
	(void) close(cptr->fd);
	return -1;
    }

    if (cptr == &me)
    {
	int rv;
	/* KLUDGE to get it work... */
	char buf[1024];

	(void) ircsprintf(buf, rpl_str(RPL_MYPORTIS), me.name, "*",
			  ntohs(server.SIN_PORT));
	rv = write(0, buf, strlen(buf));
    }
    if (cptr->fd > highest_fd)
	highest_fd = cptr->fd;
#ifndef INET6
    inet_pton(AFINET, ipname, (struct IN_ADDR *)&cptr->ip.S_ADDR);
#else
    inet_pton(AFINET, ipname, cptr->ip.S_ADDR);
#endif
    cptr->port = (int) ntohs(server.SIN_PORT);
    /* 
     * If the operating system has a define for SOMAXCONN, use it,
     * otherwise use HYBRID_SOMAXCONN -Dianora
     */

#ifdef SOMAXCONN
    (void) listen(cptr->fd, SOMAXCONN);
#else
    (void) listen(cptr->fd, HYBRID_SOMAXCONN);
#endif
    local[cptr->fd] = cptr;

    return 0;
}

/*
 * add_listener
 *
 * Create a new client which is essentially the stub like 'me' to be used
 * for a socket that is passive (listen'ing for connections to be
 * accepted).
 */
int add_listener(aConfItem * aconf)
{
    aClient *cptr;
#ifndef INET6
    u_long vaddr;
#else
    char   vaddr[sizeof(struct IN_ADDR)];
#endif

#ifdef USE_SSL
    extern int ssl_capable;
#endif

    cptr = make_client(NULL, NULL);
    cptr->flags = FLAGS_LISTEN;
    cptr->acpt = cptr;
    cptr->from = cptr;
    SetMe(cptr);
    strncpyzt(cptr->name, aconf->host, sizeof(cptr->name));

    if ((aconf->passwd[0] != '\0') && (aconf->passwd[0] != '*'))
#ifndef INET6
      inet_pton(AFINET, aconf->passwd, &vaddr);
   else
      memset(&vaddr, 0x0, sizeof(struct IN_ADDR));
#else
      inet_pton(AFINET, aconf->passwd, vaddr);
   else
      memset(vaddr, 0x0, sizeof(struct IN_ADDR));
#endif
      

    if (inetport(cptr, aconf->host, aconf->port, vaddr))
	cptr->fd = -2;

    if (cptr->fd >= 0)
    {
	char *ptr;
	cptr->confs = make_link();
	cptr->confs->next = NULL;
	cptr->confs->value.aconf = aconf;
	set_non_blocking(cptr->fd, cptr);
	ptr = aconf->name;
	while (*ptr)
	{
	    switch (*ptr)
	    {
		case 'S':
#ifdef USE_SSL /*AZZURRA*/
		    if (ssl_capable)
		    {
			cptr->ssl = NULL;
			cptr->client_cert = NULL;
		    }
#endif
		    SetSSL(cptr);
		    break;
		case 'H':
		    SetHAProxy(cptr);
		    break;
		default:
		    break;
	    }
	    ptr++;
	}

	if (IsHAProxy(cptr) && IsSSL(cptr))
	{
	    /* SSL/TLS will be performed by stud, mark this client as secure */
	    ClearSSL(cptr);
	    SetStud(cptr);
	}
	else if (IsSSL(cptr)
#ifdef USE_SSL
		 && !ssl_capable
#endif
		)
	    ClearSSL(cptr);
    } else
	free_client(cptr);
    return 0;
}

/*
 * close_listeners
 *
 * Close and free all clients which are marked as having their socket open
 * and in a state where they can accept connections.  Unix sockets have
 * the path to the socket unlinked for cleanliness.
 */
void close_listeners()
{
    aClient *cptr;
    int i;
    aConfItem *aconf;

    /* 
     * close all 'extra' listening ports we have and unlink the file
     * name if it was a unix socket.
     */
    for (i = highest_fd; i >= 0; i--)
    {
	if (!(cptr = local[i]))
	    continue;
	if (cptr == &me || !IsListening(cptr))
	    continue;
	aconf = cptr->confs->value.aconf;

	if (IsIllegal(aconf) && aconf->clients == 0)
	{
	    close_connection(cptr);
	}
    }
}

#ifdef HAVE_FD_ALLOC
fd_set *write_set, *read_set;

#endif

/* init_sys */
void init_sys()
{
    int fd;

#ifdef RLIMIT_FD_MAX
    struct rlimit limit;

    if (!getrlimit(RLIMIT_FD_MAX, &limit))
    {
	if (limit.rlim_max < MAXCONNECTIONS)
	{
	    (void) fprintf(stderr, "ircd fd table too big\n");
	    (void) fprintf(stderr, "Hard Limit: %ld IRC max: %d\n",
			   (long) limit.rlim_max, MAXCONNECTIONS);
	    (void) fprintf(stderr, "Fix MAXCONNECTIONS\n");
	    exit(-1);
	}
	limit.rlim_cur = limit.rlim_max;	/* make soft limit the max */
	if (setrlimit(RLIMIT_FD_MAX, &limit) == -1)
	{
	    (void) fprintf(stderr, "error setting max fd's to %ld\n",
			   (long) limit.rlim_cur);
	    exit(-1);
	}
#ifndef USE_POLL
	if (MAXCONNECTIONS > FD_SETSIZE)
	{
	    (void) fprintf(stderr,
			   "FD_SETSIZE = %d MAXCONNECTIONS = %d\n",
			   FD_SETSIZE, MAXCONNECTIONS);
	    (void) fprintf(stderr,
			   "Make sure your kernel supports a larger "
			   "FD_SETSIZE then recompile with -DFD_SETSIZE=%d\n",
			   MAXCONNECTIONS);
	    exit(-1);
	}
#endif

#ifndef HAVE_FD_ALLOC
	printf("Value of FD_SETSIZE is %d\n", FD_SETSIZE);
#else
	read_set = FD_ALLOC(MAXCONNECTIONS);
	write_set = FD_ALLOC(MAXCONNECTIONS);
	printf("Value of read_set is %lX\n", read_set);
	printf("Value of write_set is %lX\n", write_set);
#endif
	printf("Value of NOFILE is %d\n", NOFILE);
    }
#endif

    printf("Ircd is now becoming a daemon.\n");

#if !defined(SOL20)
    (void) setlinebuf(stderr);
#endif

    for (fd = 3; fd < MAXCONNECTIONS; fd++)
    {
	(void) close(fd);
	local[fd] = NULL;
    }
    local[1] = NULL;

    if (bootopt & BOOT_TTY)
    {
	/* debugging is going to a tty */
	resfd = init_resolver(0x1f);
	return;
    }
    (void) close(1);
    if (!(bootopt & BOOT_DEBUG) && !(bootopt & BOOT_STDERR))
	(void) close(2);

    if (((bootopt & BOOT_CONSOLE) || isatty(0)) &&
	!(bootopt & BOOT_STDERR))
    {
	int pid;

	if ((pid = fork()) < 0)
	{
	    int rv;
	    if ((fd = open("/dev/tty", O_RDWR)) >= 0)
		rv = write(fd, "Couldn't fork!\n", 15);  /* crude, but effective */
	    exit(0);
	} else if (pid > 0)
	    exit(0);
#ifdef TIOCNOTTY
	if ((fd = open("/dev/tty", O_RDWR)) >= 0)
	{
	    (void) ioctl(fd, TIOCNOTTY, (char *) NULL);
	    (void) close(fd);
	}
#endif
#if defined(SOL20) || defined(DYNIXPTX) || \
    defined(_POSIX_SOURCE) || defined(SVR4)
	(void) setsid();
#else
	(void) setpgrp(0, (int) getpid());
#endif
	(void) close(0);		/* fd 0 opened by inetd */
	local[0] = NULL;
    }

    resfd = init_resolver(0x1f);
    return;
}

void write_pidfile()
{
#ifdef IRCD_PIDFILE
    int fd;
    char buff[20];

    if ((fd = open(IRCD_PIDFILE, O_CREAT | O_WRONLY, 0600)) >= 0)
    {
	(void) ircsprintf(buff, "%5d\n", (int) getpid());
	if (write(fd, buff, strlen(buff)) == -1)
	    Debug((DEBUG_NOTICE, "Error writing to pid file %s",
		   IRCD_PIDFILE));
	(void) close(fd);
	return;
    }
#ifdef	DEBUGMODE
    else
	Debug((DEBUG_NOTICE, "Error opening pid file %s", IRCD_PIDFILE));
#endif
#endif
}

#ifdef INET6
/*
 * #undef IN6_IS_ADDR_LOOPBACK
 */
int
in6_is_addr_loopback(uint32_t * f)
{
    /* ipv6 loopback */ 
    if(((*f == 0) && (*(f + 1) == 0) &&
	(*(f + 2) == 0) && (*(f + 3) == htonl(1))) || 
	/* ipv4 mapped 127.0.0.1 */ 
	((*(f + 2) == htonl(0x0000ffff)) && 
	(*(f + 3) == htonl(0x7f000001)))) 
		return 1; 
    return 0; 
}
#endif

/*
 * Initialize the various name strings used to store hostnames. This is
 * set from either the server's sockhost (if client fd is a tty or
 * localhost) or from the ip# converted into a string. 0 = success, -1
 * = fail.
 */
static int check_init(aClient * cptr, char *sockn)
{
    struct SOCKADDR_IN sk;
    socklen_t len = sizeof(struct SOCKADDR_IN);

    /* If descriptor is a tty, special checking... * IT can't EVER be a tty */

    if (getpeername(cptr->fd, (struct SOCKADDR *) &sk, &len) == -1)
    {
	/*
	 * This fills syslog, if on, and is just annoying.
	 * Nobody needs it. -lucas
	 *    report_error("connect failure: %s %s", cptr);
	 */
	return -1;
    }

    /* Damn bahamut... */
    if (!IsHAProxy(cptr->acpt))
    {
	inet_ntop(AFINET, (char *) &sk.SIN_ADDR, sockn, HOSTLEN);
#ifndef INET6
	if (inet_netof(sk.SIN_ADDR) == IN_LOOPBACKNET)
#else
	if (in6_is_addr_loopback((uint32_t *) & cptr->ip))
#endif
	{
	    cptr->hostp = NULL;
	    strncpyzt(sockn, me.sockhost, HOSTLEN);
	}
	memcpy((char *) &cptr->ip, (char *) &sk.SIN_ADDR, sizeof(struct IN_ADDR));
    }
    else
    {
	inet_ntop(AFINET, (char *)&cptr->ip, sockn, HOSTLEN);
    }
    
    cptr->port = (int) (ntohs(sk.SIN_PORT));

    return 0;
}

/*
 * Ordinary client access check. Look for conf lines which have the
 * same status as the flags passed. 0 = Success -1 = Access denied -2 =
 * Bad socket.
 */
int check_client(aClient * cptr)
{
    static char sockname[HOSTLEN + 1];
    struct hostent *hp = NULL;
    int i;

    ClearAccess(cptr); 
    Debug((DEBUG_DNS, "ch_cl: check access for %s[%s]",
	   cptr->name, inet_ntop(AFINET, (char *) &cptr->ip,
	   mydummy, sizeof (mydummy))));

    if (check_init(cptr, sockname))
	return -2;

    hp = cptr->hostp;
    /* 
     * Verify that the host to ip mapping is correct both ways and that
     * the ip#(s) for the socket is listed for the host.
     */
    if (hp)
    {
	for (i = 0; hp->h_addr_list[i]; i++)
	    if (!memcmp(hp->h_addr_list[i], (char *) &cptr->ip,
			sizeof(struct IN_ADDR))) break;

	if (!hp->h_addr_list[i])
	    hp = NULL;
    }

    if ((i = attach_Iline(cptr, hp, sockname)))
    {
	Debug((DEBUG_DNS, "ch_cl: access denied: %s[%s]",
	       cptr->name, sockname));
	return i;
    }

    Debug((DEBUG_DNS, "ch_cl: access ok: %s[%s]", cptr->name, sockname));
#ifndef INET6
    if (inet_netof(cptr->ip) == IN_LOOPBACKNET ||
	inet_netof(cptr->ip) == inet_netof(mysk.SIN_ADDR))
#else
   if (in6_is_addr_loopback((uint32_t *) & cptr->ip) ||
       (cptr->ip.s6_addr[0] == mysk.sin6_addr.s6_addr[0] &&
	cptr->ip.s6_addr[1] == mysk.sin6_addr.s6_addr[1]))
#endif
    {
	ircstp->is_loc++;
	cptr->flags |= FLAGS_LOCAL;
    }
    return 0;
}

#define	CFLAG	CONF_CONNECT_SERVER
#define	NFLAG	CONF_NOCONNECT_SERVER

/*
 * check_server_init(), check_server() check access for a server given
 * its name (passed in cptr struct). Must check for all C/N lines which
 * have a name which matches the name given and a host which matches. A
 * host alias which is the same as the server name is also acceptable
 * in the host field of a C/N line. 0 = Success -1 = Access denied -2 =
 * Bad socket.
 */
int check_server_init(aClient * cptr)
{
    char *name;
    aConfItem *c_conf = NULL, *n_conf = NULL;
    struct hostent *hp = NULL;
    Link *lp;

    name = cptr->name;
    Debug((DEBUG_DNS, "sv_cl: check access for %s[%s]",
	   name, cptr->sockhost));

    if (IsUnknown(cptr) && !attach_confs(cptr, name, CFLAG | NFLAG))
    {
	Debug((DEBUG_DNS, "No C/N lines for %s", name));
	return -1;
    }
    lp = cptr->confs;
    /* 
     * We initiated this connection so the client should have a C and N
     * line already attached after passing through the connect_server()
     * function earlier.
     */
    if (IsConnecting(cptr) || IsHandshake(cptr))
    {
	c_conf = find_conf(lp, name, CFLAG);
	n_conf = find_conf(lp, name, NFLAG);
	if (!c_conf || !n_conf)
	{
	    sendto_realops_lev(DEBUG_LEV, "Connecting Error: %s[%s]", name,
			       cptr->sockhost);
	    det_confs_butmask(cptr, 0);
	    return -1;
	}
    }
    /* 
     * * If the servername is a hostname, either an alias (CNAME) or *
     * real name, then check with it as the host. Use gethostbyname() *
     * to check for servername as hostname.
     */
    if (!cptr->hostp)
    {
	aConfItem *aconf;

	aconf = count_cnlines(lp);
	if (aconf)
	{
	    char *s;
	    Link lin;

	    /* 
	     * * Do a lookup for the CONF line *only* and not * the server
	     * connection else we get stuck in a * nasty state since it
	     * takes a SERVER message to * get us here and we cant
	     * interrupt that very * well.
	     */
	    ClearAccess(cptr);
	    lin.value.aconf = aconf;
	    lin.flags = ASYNC_CONF;
	    nextdnscheck = 1;
	    if ((s = strchr(aconf->host, '@')))
		s++;
	    else
		s = aconf->host;
	    Debug((DEBUG_DNS, "sv_ci:cache lookup (%s)", s));
	    hp = gethost_byname(s, &lin);
	}
    }
    return check_server(cptr, hp, c_conf, n_conf, 0);
}

int check_server(aClient * cptr, struct hostent *hp, aConfItem * c_conf,
		 aConfItem * n_conf, int estab)
{
    char *name;
    char abuff[HOSTLEN + USERLEN + 2];
    char sockname[HOSTLEN + 1], fullname[HOSTLEN + 1];
    Link *lp = cptr->confs;
    int i;

    ClearAccess(cptr);
    if (check_init(cptr, sockname))
	return -2;

    if (hp)
    {
	for (i = 0; hp->h_addr_list[i]; i++)
	    if (!memcmp(hp->h_addr_list[i], (char *) &cptr->ip,
			sizeof(struct IN_ADDR))) break;

	if (!hp->h_addr_list[i])
	{ 
	 sendto_realops_lev(DEBUG_LEV,
			    "Server IP# Mismatch: %s != %s[%08x]",
			    hp->h_name, inet_ntop(AFINET, (char *) &cptr->ip,
			    mydummy, sizeof (mydummy)),
			    *((unsigned long *) hp->h_addr));
	    hp = NULL;
	}
    }
    else if (cptr->hostp)
    {
	hp = cptr->hostp;
	for (i = 0; hp->h_addr_list[i]; i++)
	    if (!memcmp(hp->h_addr_list[i], (char *) &cptr->ip,
			sizeof(struct IN_ADDR))) break;
    }

    if (hp)
	/* 
	 * if we are missing a C or N line from above, search for it
	 * under all known hostnames we have for this ip#.
	 */
	for (i = 0, name = hp->h_name; name; name = hp->h_aliases[i++])
	{
	    strncpyzt(fullname, name, sizeof(fullname));
	    add_local_domain(fullname, HOSTLEN - strlen(fullname));
	    Debug((DEBUG_DNS, "sv_cl: gethostbyaddr: %s->%s",
		   sockname, fullname));
	    (void) ircsprintf(abuff, "%s@%s", cptr->username, fullname);
	    if (!c_conf)
		c_conf = find_conf_host(lp, abuff, CFLAG);
	    if (!n_conf)
		n_conf = find_conf_host(lp, abuff, NFLAG);
	    if (c_conf && n_conf) {
		get_sockhost(cptr, fullname);
		break;
	    }
	}

    name = cptr->name;
    /* 
     * Check for C and N lines with the hostname portion the ip number
     * of the host the server runs on. This also checks the case where
     * there is a server connecting from 'localhost'.
     */
    if (IsUnknown(cptr) && (!c_conf || !n_conf))
    {
	(void) ircsprintf(abuff, "%s@%s", cptr->username, sockname);
	if (!c_conf)
	    c_conf = find_conf_host(lp, abuff, CFLAG);
	if (!n_conf)
	    n_conf = find_conf_host(lp, abuff, NFLAG);
    }
    /* 
     * Attach by IP# only if all other checks have failed. It is quite
     * possible to get here with the strange things that can happen when
     * using DNS in the way the irc server does. -avalon
     */
    if (!hp)
    {
	if (!c_conf)
	    c_conf = find_conf_ip(lp, (char *) &cptr->ip,
				  cptr->username, CFLAG);
	if (!n_conf)
	    n_conf = find_conf_ip(lp, (char *) &cptr->ip,
				  cptr->username, NFLAG);
    } 
    else
	for (i = 0; hp->h_addr_list[i]; i++)
	{
	    if (!c_conf)
		c_conf = find_conf_ip(lp, hp->h_addr_list[i],
				      cptr->username, CFLAG);
	    if (!n_conf)
		n_conf = find_conf_ip(lp, hp->h_addr_list[i],
				      cptr->username, NFLAG);
	}
    /* detach all conf lines that got attached by attach_confs() */
    det_confs_butmask(cptr, 0);
    /* if no C or no N lines, then deny access */
    if (!c_conf || !n_conf)
    {
	get_sockhost(cptr, sockname);
	Debug((DEBUG_DNS, "sv_cl: access denied: %s[%s@%s] c %x n %x",
	       name, cptr->username, cptr->sockhost, c_conf, n_conf));
	return -1;
    }
    /* attach the C and N lines to the client structure for later use. */
    (void) attach_conf(cptr, n_conf);
    (void) attach_conf(cptr, c_conf);
    (void) attach_confs(cptr, name, CONF_HUB | CONF_ULINE);
    /* this may give cptr a new sendq length.. */
    cptr->sendqlen = get_sendq(cptr);
#ifndef INET6
    if ((c_conf->ipnum.S_ADDR == -1))
#else
   if (!memcmp(c_conf->ipnum.S_ADDR, minus_one, sizeof(struct IN_ADDR)))
#endif
	memcpy((char *) &c_conf->ipnum, (char *) &cptr->ip,

	       sizeof(struct IN_ADDR));

    get_sockhost(cptr, c_conf->host);
    
    Debug((DEBUG_DNS, "sv_cl: access ok: %s[%s]", name, cptr->sockhost));
    if (estab)
	return m_server_estab(cptr);
    return 0;
}

#undef	CFLAG
#undef	NFLAG

/*
 * completed_connection 
 * Complete non-blocking
 * connect()-sequence. Check access and *       terminate connection,
 * if trouble detected. *
 *
 *      Return  TRUE, if successfully completed *               FALSE,
 * if failed and ClientExit
 */
static int completed_connection(aClient * cptr)
{
    aConfItem *aconf;
    aConfItem *nconf;

    SetHandshake(cptr);

    aconf = find_conf(cptr->confs, cptr->name, CONF_CONNECT_SERVER);
    if (!aconf)
    {
	sendto_realops("Lost C-Line for %s", get_client_name(cptr, HIDEME));
	return -1;
    }
    nconf = find_conf(cptr->confs, cptr->name, CONF_NOCONNECT_SERVER);
    if (!nconf)
    {
	sendto_realops("Lost N-Line for %s", get_client_name(cptr, HIDEME));
	return -1;
    }
    if (!BadPtr(aconf->passwd))
	sendto_one(cptr, "PASS %s :TS", aconf->passwd);

    /* pass on our capabilities to the server we /connect'd */
#ifdef HAVE_ENCRYPTION_ON
    if(!(nconf->port & CAP_DODKEY))
	sendto_one(cptr, "CAPAB TS3 NOQUIT SSJOIN BURST UNCONNECT ZIP NICKIP TSMODE EBMODE");
    else
	sendto_one(cptr, "CAPAB TS3 NOQUIT SSJOIN BURST UNCONNECT DKEY ZIP NICKIP TSMODE EBMODE");
#else
    sendto_one(cptr, "CAPAB TS3 NOQUIT SSJOIN BURST UNCONNECT ZIP NICKIP TSMODE EBMODE");
#endif

    aconf = nconf;
    sendto_one(cptr, "SERVER %s 1 :%s",
	       my_name_for_link(me.name, aconf), me.info);
#if defined(DO_IDENTD) && !defined(NO_SERVER_IDENTD) /*AZZURRA*/
    /* Is this the right place to do this?  dunno... -Taner */
    if (!IsDead(cptr))
	start_auth(cptr);
#endif

    return (IsDead(cptr)) ? -1 : 0;
}

/*
 * close_connection *
 * Close the physical connection. This function must make 
 * MyConnect(cptr) == FALSE, and set cptr->from == NULL.
 */
void close_connection(aClient * cptr)
{
    aConfItem *aconf;
    int i, j;
    int empty = cptr->fd;

    if (IsServer(cptr))
    {
	ircstp->is_sv++;
	ircstp->is_sbs += cptr->sendB;
	ircstp->is_sbr += cptr->receiveB;
	ircstp->is_sks += cptr->sendK;
	ircstp->is_skr += cptr->receiveK;
	ircstp->is_sti += timeofday - cptr->firsttime;
	if (ircstp->is_sbs > 2047)
	{
	    ircstp->is_sks += (ircstp->is_sbs >> 10);
	    ircstp->is_sbs &= 0x3ff;
	}
	if (ircstp->is_sbr > 2047)
	{
	    ircstp->is_skr += (ircstp->is_sbr >> 10);
	    ircstp->is_sbr &= 0x3ff;
	}
    } 
    else if (IsClient(cptr))
    {
	ircstp->is_cl++;
	ircstp->is_cbs += cptr->sendB;
	ircstp->is_cbr += cptr->receiveB;
	ircstp->is_cks += cptr->sendK;
	ircstp->is_ckr += cptr->receiveK;
	ircstp->is_cti += timeofday - cptr->firsttime;
	if (ircstp->is_cbs > 2047)
	{
	    ircstp->is_cks += (ircstp->is_cbs >> 10);
	    ircstp->is_cbs &= 0x3ff;
	}
	if (ircstp->is_cbr > 2047)
	{
	    ircstp->is_ckr += (ircstp->is_cbr >> 10);
	    ircstp->is_cbr &= 0x3ff;
	}
    } 
    else
	ircstp->is_ni++;
    /* remove outstanding DNS queries. */
    del_queries((char *) cptr);
    /* 
     * If the connection has been up for a long amount of time, schedule
     * a 'quick' reconnect, else reset the next-connect cycle.
     */
    if ((aconf = find_conf_exact(cptr->name, cptr->username,
				 cptr->sockhost, CONF_CONNECT_SERVER)))
    {
	/* 
	 * Reschedule a faster reconnect, if this was a automaticly
	 * connected configuration entry. (Note that if we have had a
	 * rehash in between, the status has been changed to
	 * CONF_ILLEGAL). But only do this if it was a "good" link.
	 */
	aconf->hold = time(NULL);
	aconf->hold += (aconf->hold - cptr->since > HANGONGOODLINK) ?
	    HANGONRETRYDELAY : ConfConFreq(aconf);
	if (nextconnect > aconf->hold)
	    nextconnect = aconf->hold;
    }

    if (cptr->authfd >= 0)
	(void) close(cptr->authfd);

    if (cptr->fd >= 0)
    {
#ifdef USE_SSL
	if(!IsDead(cptr))
#endif
	    dump_connections(cptr->fd);
	local[cptr->fd] = NULL;
#ifdef USE_SSL
	if(IsSSL(cptr) && cptr->ssl) {
	    SSL_set_shutdown(cptr->ssl, SSL_RECEIVED_SHUTDOWN);
	    SSL_smart_shutdown(cptr->ssl);
	    SSL_free(cptr->ssl);
	    cptr->ssl = NULL;
	}
#endif
	(void) close(cptr->fd);
	cptr->fd = -2;
	DBufClear(&cptr->sendQ);
	DBufClear(&cptr->recvQ);
	memset(cptr->passwd, '\0', sizeof(cptr->passwd));
	/* clean up extra sockets from P-lines which have been discarded. */
	if (cptr->acpt != &me && cptr->acpt != cptr) 
	{
	    aconf = cptr->acpt->confs->value.aconf;
	    if (aconf->clients > 0)
		aconf->clients--;
	    if (!aconf->clients && IsIllegal(aconf))
		close_connection(cptr->acpt);
	}
    }
    for (; highest_fd > 0; highest_fd--)
	if (local[highest_fd])
	    break;

    det_confs_butmask(cptr, 0);
    cptr->from = NULL;		/* ...this should catch them! >:) --msa */
    /* fd remap to keep local[i] filled at the bottom. */
    if (empty > 0)
	/* We don't dup listening fds (IsMe())... - CS */
	if ((j = highest_fd) > (i = empty) &&
	    !IsLog(local[j]) && !IsMe(local[j])) 
	{
	    if (dup2(j, i) == -1)
		return;
	    local[i] = local[j];
	    local[i]->fd = i;
#ifdef USE_SSL
	    if(IsSSL(local[i])) {
		BIO_set_fd(SSL_get_rbio(local[i]->ssl), i, BIO_NOCLOSE);
		BIO_set_fd(SSL_get_wbio(local[i]->ssl), i, BIO_NOCLOSE);
	    }
#endif
	    local[j] = NULL;
	    /* update server list */
	    if (IsServer(local[i]))
	    {

#ifndef NO_PRIORITY
		delfrom_fdlist(j, &busycli_fdlist);
#endif
		delfrom_fdlist(j, &serv_fdlist);
#ifndef NO_PRIORITY
		addto_fdlist(i, &busycli_fdlist);
#endif
		addto_fdlist(i, &serv_fdlist);
	    }
	    /* update oper list */
	    if (IsAnOper(local[i]))
	    {
#ifndef NO_PRIORITY
		delfrom_fdlist(j, &busycli_fdlist);
#endif
		delfrom_fdlist(j, &oper_fdlist);
#ifndef NO_PRIORITY
		addto_fdlist(i, &busycli_fdlist);
#endif
		addto_fdlist(i, &oper_fdlist);
	    }
	    (void) close(j);
	    while (!local[highest_fd])
		highest_fd--;
	}
    return;
}

#ifdef MAXBUFFERS

/* reset_sock_opts type =  0 = client, 1 = server */
void reset_sock_opts(int fd, int type)
{
#define CLIENT_BUFFER_SIZE	4096
#define SEND_BUF_SIZE		2048
    int opt;

    opt = type ? rcvbufmax : CLIENT_BUFFER_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &opt, sizeof(opt)) < 0) 
	sendto_realops("REsetsockopt(SO_RCVBUF) for fd %d (%s) failed",
		       fd, type ? "server" : "client");
    opt = type ? sndbufmax : SEND_BUF_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &opt, sizeof(opt)) < 0) 
	sendto_realops("REsetsockopt(SO_SNDBUF) for fd %d (%s) failed",
		       fd, type ? "server" : "client");
}

#endif				/* MAXBUFFERS */

/* set_sock_opts */
static void set_sock_opts(int fd, aClient * cptr)
{
    int opt;

#if defined( INET6 ) && defined( IPV6_BIND_V6_ONLY ) && defined( IPPROTO_IPV6 ) && defined( IPV6_V6ONLY )
    opt = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &opt, sizeof(opt)) < 0)
	silent_report_error("setsockopt(IPV6_V6ONLY) %s:%s", cptr);
#endif

#ifdef SO_REUSEADDR
    opt = 1;
    if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt,
		    sizeof(opt)) < 0)
	silent_report_error("setsockopt(SO_REUSEADDR) %s:%s", cptr);
#endif
#if  defined(SO_DEBUG) && defined(DEBUGMODE) && 0
    /* Solaris with SO_DEBUG writes to syslog by default */
#if !defined(SOL20) || defined(USE_SYSLOG)
    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_DEBUG, (char *) &opt, sizeof(opt)) < 0)
	silent_report_error("setsockopt(SO_DEBUG) %s:%s", cptr);
#endif				/* SOL20 */
#endif
#ifdef	SO_USELOOPBACK
    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_USELOOPBACK, (char *) &opt,
		   sizeof(opt)) < 0)
	silent_report_error("setsockopt(SO_USELOOPBACK) %s:%s", cptr);
#endif
#ifdef	SO_RCVBUF
#if defined(MAXBUFFERS)
    if (rcvbufmax == 0)
    {
	socklen_t optlen;

	optlen = sizeof(rcvbufmax);
	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &rcvbufmax, &optlen);
	while ((rcvbufmax < 16385) &&
	       (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, 
			   (char *) (char *) &rcvbufmax,optlen) >= 0))
	    rcvbufmax += 1024;
	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &rcvbufmax, &optlen);
	readbuf = (char *) malloc(rcvbufmax * sizeof(char));
    }
    if (IsServer(cptr))
	opt = rcvbufmax;
    else
	opt = 4096;
#else
    opt = 8192;
#endif
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &opt, sizeof(opt)) < 0)
	silent_report_error("setsockopt(SO_RCVBUF) %s:%s", cptr);
#endif
#ifdef	SO_SNDBUF
#if defined(MAXBUFFERS)
    if (sndbufmax == 0)
    {
	socklen_t optlen;
	
	optlen = sizeof(sndbufmax);
	getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &sndbufmax, &optlen);
	while ((sndbufmax < 16385) && (setsockopt (fd, SOL_SOCKET, SO_SNDBUF,
						   (char *) &sndbufmax,
						   optlen) >= 0))
	    sndbufmax += 1024;
	getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &sndbufmax, &optlen);
    }
    if (IsServer(cptr))
	opt = sndbufmax;
    else
	opt = 4096;
#else
    opt = 8192;
#endif
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &opt, sizeof(opt)) < 0)
	silent_report_error("setsockopt(SO_SNDBUF) %s:%s", cptr);
#endif
#if defined(IP_OPTIONS) && defined(IPPROTO_IP) && !defined(INET6) /* controlla STRONZONE */
    {
        socklen_t optlen;
# if defined(MAXBUFFERS)
	char *s = readbuf, *t = readbuf + (rcvbufmax * sizeof(char)) / 2;
	optlen = (rcvbufmax * sizeof(char)) / 8;
# else
	char *s = readbuf, *t = readbuf + sizeof(readbuf) / 2;
	
	optlen = sizeof(readbuf) / 8;
# endif
	if (getsockopt(fd, IPPROTO_IP, IP_OPTIONS, t, &optlen) < 0)
	    silent_report_error("getsockopt(IP_OPTIONS) %s:%s", cptr);
	else if (optlen > 0)
	{
	    for (*readbuf = '\0'; optlen > 0; optlen--, s += 3)
		(void) ircsprintf(s, "%02.2x:", *t++);
	    *s = '\0';
	    sendto_realops("Connection %s using IP opts: (%s)",
			   get_client_name(cptr, HIDEME), readbuf);	}
	if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, (char *) NULL, 0) < 0)
	    silent_report_error("setsockopt(IP_OPTIONS) %s:%s", cptr);
    }
#endif
}

int get_sockerr(aClient * cptr)
{
    int errtmp = errno, err = 0;
    socklen_t len = sizeof(err);
    
#ifdef	SO_ERROR
    if (cptr->fd >= 0)
	if (!getsockopt(cptr->fd, SOL_SOCKET, SO_ERROR, (char *) &err, &len))
	    if (err)
		errtmp = err;
#endif
    return errtmp;
}

char *irc_get_sockerr(aClient *cptr)
{
    if(cptr->sockerr == 0)
	return "No error";
    
    if(cptr->sockerr > 0)
	return strerror(cptr->sockerr);
    
    switch(cptr->sockerr)
    { 
    case -1: /* this is the default */
	return "Unset error message [this is a bug!]";
    case IRCERR_BUFALLOC:
	return "dbuf allocation error";
    case IRCERR_ZIP:
	return "compression general failure";
#ifdef USE_SSL
    case IRCERR_SSL:
	return "SSL error";
#endif
    default:
	return "Unknown error!";
    }
    
    /* unreachable code, but the compiler is complaining.. */
    return NULL;
}

/*
 * * set_non_blocking *       Set the client connection into non-blocking
 * mode. If your *      system doesn't support this, you can make this
 * a dummy *    function (and get all the old problems that plagued the *
 * blocking version of IRC--not a problem if you are a *        lightly
 * loaded node...)
 */
void set_non_blocking(int fd, aClient * cptr)
{
    int res, nonb = 0;

    /* 
     * * NOTE: consult ALL your relevant manual pages *BEFORE* changing *
     * hese ioctl's.  There are quite a few variations on them, *
     * s can be seen by the PCS one.  They are *NOT* all the same. *
     * eed this well. - Avalon.
     */
#ifdef	NBLOCK_POSIX
    nonb |= O_NONBLOCK;
#endif
#ifdef	NBLOCK_BSD
    nonb |= O_NDELAY;
#endif
#ifdef	NBLOCK_SYSV
    /* 
     * This portion of code might also apply to NeXT.  -LynX
     */
    res = 1;

    if (ioctl(fd, FIONBIO, &res) < 0)
	silent_report_error("ioctl(fd,FIONBIO) failed for %s:%s", cptr);
#else
    if ((res = fcntl(fd, F_GETFL, 0)) == -1)
	silent_report_error("fcntl(fd, F_GETFL) failed for %s:%s", cptr);
    else if (fcntl(fd, F_SETFL, res | nonb) == -1)
	silent_report_error("fcntl(fd, F_SETL, nonb) failed for %s:%s", cptr);
#endif
    return;
}

#ifdef INET6
/* Detect 6to4 and/or Teredo tunnels */
void set_tunnel_host(aClient *cptr)
{
    size_t off = 0;

    memset(cptr->tunnel_host, '\0', HOSTIPLEN + 1);
    if (cptr->ip.s6_addr[0] == 0x20 && cptr->ip.s6_addr[1] == 0x02)
    {
        Set6to4(cptr);
        off = 2;
    }
    else if (cptr->ip.s6_addr[0] == 0x20 && cptr->ip.s6_addr[1] == 0x01 && cptr->ip.s6_addr[2] == 0 && cptr->ip.s6_addr[3] == 0)
    {
        SetTeredo(cptr);
        off = 12;
    }
    if (IsTunnel(cptr))
    {
        struct in_addr endpoint_addr;
        memcpy(&endpoint_addr.s_addr, cptr->ip.s6_addr + off, sizeof(endpoint_addr.s_addr));
        /* Flip all bits if this is a Teredo tunnel */
        if (IsTeredo(acptr))
            endpoint_addr.s_addr ^= 0xFFFFFFFFU;
        if (inet_ntop(AF_INET, &endpoint_addr, cptr->tunnel_host, HOSTIPLEN + 1) == NULL)
        {
            /* Clear flags and log error */
            ClearTunnel(cptr);
            sendto_realops_lev(DEBUG_LEV, "inet_ntop failed while resolving tunnel endpoint for %s", get_client_name(cptr, TRUE));
        }
    }
}
#endif

/*
 * Creates a client which has just connected to us on the given fd. The
 * sockhost field is initialized with the ip# of the host. The client
 * is added to the linked list of clients but isnt added to any hash
 * tables yuet since it doesnt have a name.
 */
aClient *add_connection(aClient * cptr, int fd)
{
    Link lin;
    aClient *acptr;
    aConfItem *aconf = NULL;
    char *s, *t;
    struct SOCKADDR_IN addr;
    socklen_t len;
#if defined(DO_IDENTD) && defined(NO_SERVER_IDENTD) /*AZZURRA*/
    aConfItem *tmpconf;
#endif   
    int doident = YES;
#ifdef INET6
    size_t off = 0;
#endif /* INET6 */
   
    acptr = make_client(NULL, &me);
    
    if (cptr != &me)
	aconf = cptr->confs->value.aconf;

    len = sizeof(struct SOCKADDR_IN);
    
    if (getpeername(fd, (struct SOCKADDR *) &addr, &len) == -1)
    { 
	ircstp->is_ref++;
	acptr->fd = -2;
	free_client(acptr);
	close(fd);
	return NULL;
    }
    
    /* don't want to add "Failed in connecting to" here.. */
    if (aconf && IsIllegal(aconf))
    {
	ircstp->is_ref++;
	acptr->fd = -2;
	free_client(acptr);
	close(fd);
	return NULL;
    }
    /* 
     * Copy ascii address to 'sockhost' just in case. Then we have
     * something valid to put into error messages...
     */
    inet_ntop(AFINET, (char *) &addr.SIN_ADDR, mydummy, sizeof (mydummy));
#ifdef INET6
    ip6_expand(mydummy, sizeof(mydummy));
#endif
    get_sockhost(acptr, mydummy);
    memcpy((char *) &acptr->ip, (char *) &addr.SIN_ADDR,
	    sizeof(struct IN_ADDR));
	
    acptr->port = ntohs(addr.SIN_PORT);
    /* 
     * Check that this socket (client) is allowed to accept
     * connections from this IP#.
     */
    for (s = (char *) &cptr->ip, t = (char *) &acptr->ip, len = 4;
	     len > 0; len--, s++, t++)
    {
	if (!*s)
	    continue;
	if (*s != *t)
	    break;
    }
	
    if (len)
    {
	ircstp->is_ref++;
	acptr->fd = -2;
	free_client(acptr);
	close(fd);
	return NULL;
    }

    acptr->lport = cptr->port;

#ifdef USE_SSL /*AZZURRA*/
    if (IsSSL(cptr))
    {
	extern SSL_CTX *ircdssl_ctx;

	acptr->ssl = NULL;
	    
	/* SSL client init.
	 */
	if((acptr->ssl = SSL_new(ircdssl_ctx)) == NULL)
	{
	    sendto_realops_lev(DEBUG_LEV, "SSL creation of "
		    "new SSL object failed [client %s]",
		    acptr->sockhost);
	    ircstp->is_ref++;
	    acptr->fd = -2;
	    free_client(acptr);
	    close(fd);
	    return NULL ;
	}

	SetSSL(acptr);
	set_non_blocking(fd, acptr);
	set_sock_opts(fd, acptr);
	SSL_set_fd(acptr->ssl, fd);
	if (!safe_SSL_accept(acptr, fd))
	{
	    SSL_set_shutdown(acptr->ssl, SSL_RECEIVED_SHUTDOWN);
	    SSL_smart_shutdown(acptr->ssl);
	    SSL_free(acptr->ssl);
	    ircstp->is_ref++;
	    acptr->fd = -2;
	    free_client(acptr);
	    close(fd);
	    return NULL;
	}
    }
#endif

    if (IsHAProxy(cptr))
    {
	/* Delay hostname resolution until we get the real IP from upstream */
	SetHAProxy(acptr);
    }
    else
    {
	/* Start normal hostname resolution */
	lin.flags = ASYNC_CLIENT;
	lin.value.cptr = acptr;
	Debug((DEBUG_DNS, "lookup %s", inet_ntop(AFINET, (char *)
		&addr.SIN_ADDR, mydummy, sizeof (mydummy))));

	acptr->hostp = gethost_byaddr((char *) &acptr->ip, &lin);
	if (!acptr->hostp)
	    SetDNS(acptr);

	nextdnscheck = 1;
    }

    if (aconf)
	aconf->clients++;

    acptr->fd = fd;

    if (fd > highest_fd)
	highest_fd = fd;

    local[fd] = acptr;
    acptr->acpt = cptr;
    add_client_to_list(acptr);

#ifdef USE_SSL
    if(!IsSSL(acptr))
    {
#endif
	set_non_blocking(acptr->fd, acptr);
	set_sock_opts(acptr->fd, acptr);
#ifdef USE_SSL
    }
#endif

    if (IsStud(cptr))
	SetStud(acptr);

#if defined(DO_IDENTD) && defined(NO_SERVER_IDENTD) /*AZZURRA*/
    /* We do NOT want to start auth if the unknown connection
     * matches a N-line that has * as username. 
     * NOTE: this works ONLY with IP addresses!
     * -INT
     */
    for (tmpconf = conf; tmpconf; tmpconf = tmpconf->next)
    {
        /* Check only N-lines */
        if (!(tmpconf->status & CONF_NOCONNECT_SERVER) || !tmpconf->host)
	   continue;
       
        s = index(tmpconf->host, '@');
       
        /* Sanity check. It should not be possibile to have tmpconf->host
	 * without '@'! */
        if (!s)
	   continue;
        
        /* Username '*' and host check */
        if ((*(tmpconf->host) == '*') && (s == tmpconf->host + 1) &&
	    !strcmp(s+1, acptr->sockhost))
        {
	    doident = NO; /* finally stop ident */
	    break;
        }
    }

#ifdef NO_LOCAL_IDENTD
    /* Stop auth if this connection is coming from M-lined IP */
    if (doident && (specific_virtual_host == 1))
       if (!memcmp((char *) &acptr->ip, 
		   (char *) &vserv.SIN_ADDR,  sizeof(struct IN_ADDR)))
           doident = NO;
#endif

#endif
    /* Disable identd lookup if we're behind HAProxy */
    if (doident && IsHAProxy(acptr))
	doident = NO;

#ifdef WEBIRC
    /* ident lookup on W:lined IPs is pointless */
    if (doident && find_webirc_host(acptr->sockhost) != NULL)
        doident = NO;
#endif

    if (doident)
       start_auth(acptr); 
   
#ifdef INET6
    SetIPv6(acptr);

    /* If we're not behind HAProxy check for a 6to4/Teredo tunnel */
    if (!IsHAProxy(acptr))
	set_tunnel_host(acptr);
#endif

    return acptr;
}

/* handle taking care of the client's recvq here */
static int do_client_queue(aClient *cptr)
{
    int dolen = 0, done;
    
    while (DBufLength(&cptr->recvQ) && !NoNewLine(cptr) &&
	   ((cptr->status < STAT_UNKNOWN) || (cptr->since - timeofday < 10) ||
	    IsNegoServer(cptr))) 
    {
	/* If it's become registered as a server, just parse the whole block */
	if (IsServer(cptr) || IsNegoServer(cptr)) 
	{
#if defined(MAXBUFFERS)
	    dolen = dbuf_get(&cptr->recvQ, readbuf, rcvbufmax * sizeof(char));
#else
	    dolen = dbuf_get(&cptr->recvQ, readbuf, sizeof(readbuf));
#endif
	    if (dolen <= 0)
		break;
	    if ((done = dopacket(cptr, readbuf, dolen)))
		return done;
	    break;
	}
	
#if defined(MAXBUFFERS)
	dolen = dbuf_getmsg(&cptr->recvQ, readbuf, rcvbufmax * sizeof(char));
#else
	dolen = dbuf_getmsg(&cptr->recvQ, readbuf, sizeof(readbuf));
#endif
	
	if (dolen <= 0) 
	{
	    if (dolen < 0)
		return exit_client(cptr, cptr, cptr, "dbuf_getmsg fail");
	    
	    if (DBufLength(&cptr->recvQ) < 510) 
	    {
		cptr->flags |= FLAGS_NONL;
		break;
	    }
	    /* The buffer is full (more than 512 bytes) and it has no \n
	     * Some user is trying to trick us. Kill their recvq. */
	    DBufClear(&cptr->recvQ);
	    break;
	}
	else if(client_dopacket(cptr, readbuf, dolen) == FLUSH_BUFFER)
	    return FLUSH_BUFFER;
    }
    return 1;
}

/*
 * read_packet
 *
 * Read a 'packet' of data from a connection and process it.  Read in 8k 
 * chunks to give a better performance rating (for server connections). 
 * Do some tricky stuff for client connections to make sure they don't
 * do any flooding >:-) -avalon
 */

#define MAX_CLIENT_RECVQ 8192	/* 4 dbufs */
#ifdef USE_SSL
#define RECV2(from, buf, len)	IsSSL(cptr) ? \
				safe_SSL_read(from, buf, len) : \
				RECV(from->fd, buf, len)
#else
#define RECV2(from, buf, len)	RECV(from->fd, buf, len)
#endif


static int read_packet(aClient * cptr)
{
    int length = 0, done;

    /* If data is ready, and the user is either not a person or
     * is a person and has a recvq of less than MAX_CLIENT_RECVQ,
     * read from this client
     */ 
    if (!(IsPerson(cptr) && DBufLength(&cptr->recvQ) > MAX_CLIENT_RECVQ)) 
    {
	errno = 0;

#if defined ( MAXBUFFERS )
        if (IsPerson(cptr))
	    length = RECV2(cptr, readbuf, 8192 * sizeof(char));
	else
	    length = RECV2(cptr, readbuf, rcvbufmax * sizeof(char));
#else
	    length = RECV2(cptr, readbuf, sizeof(readbuf));
#endif /*MAXBUFFERS*/

#ifdef USE_REJECT_HOLD
	/* 
	 * If client has been marked as rejected i.e. it is a client that
	 * is trying to connect again after a k-line, pretend to read it
	 * but don't actually. -Dianora
	 */

	if (cptr->flags & FLAGS_REJECT_HOLD) {
	    if ((cptr->firsttime + REJECT_HOLD_TIME) > timeofday)
		exit_client(cptr, cptr, cptr, "reject held client");
	    else
		return 1;
	}
#endif

	cptr->lasttime = timeofday;
	if (cptr->lasttime > cptr->since)
	    cptr->since = cptr->lasttime;
	cptr->flags &= ~(FLAGS_PINGSENT | FLAGS_NONL);
	/* If not ready, fake it so it isnt closed */
	if (length == -1 && ((errno == EWOULDBLOCK) || (errno == EAGAIN)))
	    return 1;
	if (length <= 0)
	{
	    cptr->sockerr = length ? errno : 0;
	    return length;
	}
    }

    /* 
     * For server connections, we process as many as we can without
     * worrying about the time of day or anything :)
     */
    if (IsServer(cptr) || IsConnecting(cptr) || IsHandshake(cptr) ||
	IsNegoServer(cptr)) 
    {
	if (length > 0)
	    if ((done = dopacket(cptr, readbuf, length)))
		return done;
    } 
    else 
    {
	/* 
	 * Before we even think of parsing what we just read, stick 
	 * it on the end of the receive queue and do it when its turn
	 * comes around. */
	if (dbuf_put(&cptr->recvQ, readbuf, length) < 0)
	    return exit_client(cptr, cptr, cptr, "dbuf_put fail");
	
	if (IsPerson(cptr) &&
#ifdef NO_OPER_FLOOD
	    !IsAnOper(cptr) &&
#endif
	    !IsUmodez(cptr) && DBufLength(&cptr->recvQ) > CLIENT_FLOOD)
	{
	    sendto_realops_lev(FLOOD_LEV,
			       "Flood -- %s!%s@%s (%d) Exceeds %d RecvQ",
			       cptr->name[0] ? cptr->name : "*",
			       cptr->user ? cptr->user->username : "*",
			       cptr->user ? cptr->user->host : "*",
			       DBufLength(&cptr->recvQ), CLIENT_FLOOD);
	    return exit_client(cptr, cptr, cptr, "Excess Flood");
	}
	return do_client_queue(cptr);
    }
    return 1;
}

static void read_error_exit(aClient *cptr, int length, int err)
{
    char fbuf[512];
    char errmsg[512];
    
    if (IsServer(cptr) || IsHandshake(cptr) || IsConnecting(cptr)) 
    {
	if (length == 0) 
	{
	    char *errtxt = "Server %s closed the connection";
	    
	    ircsprintf(fbuf, "from %s: %s", me.name, errtxt);
	    sendto_gnotice(fbuf, get_client_name(cptr, HIDEME));
	    ircsprintf(fbuf, ":%s GNOTICE :%s", me.name, errtxt);
	    sendto_serv_butone(cptr, fbuf, get_client_name(cptr, HIDEME));
	}
	else 
	{
	    char *errtxt = "Read error from %s, closing link (%s)";

	    ircsprintf(fbuf, "from %s: %s", me.name, errtxt);
	    sendto_gnotice(fbuf, get_client_name(cptr, HIDEME), strerror(err));
	    ircsprintf(fbuf, ":%s GNOTICE :%s", me.name, errtxt);
	    sendto_serv_butone(cptr, fbuf, 
			       get_client_name(cptr, HIDEME), strerror(err));
	}
    }
    
    if (err)
	ircsprintf(errmsg, "Read error: %s", strerror(err));
    else
	ircsprintf(errmsg, "Client closed connection");
    
    exit_client(cptr, cptr, &me, errmsg);
}

void accept_connection(aClient *cptr)
{
    aConfItem *tmp;
    char dumpstring[491];
    static struct SOCKADDR_IN addr;
    socklen_t addrlen = sizeof(struct SOCKADDR_IN);
    char host[HOSTLEN + 2];
    int newfd;
    
    cptr->lasttime = timeofday;
    if ((newfd = accept(cptr->fd, (struct SOCKADDR *) &addr, &addrlen)) < 0) 
    {
	switch(errno)
	{
#ifdef EMFILE
	   case EMFILE:
	      report_error("Cannot accept connections %s:%s", cptr);
	      break;
#endif
#ifdef ENFILE
	   case ENFILE:
	      report_error("Cannot accept connections %s:%s", cptr);
	      break;
	    report_error("Cannot accept connections %s:%s", cptr);
	}
	return;
#endif
    }

    inet_ntop(AFINET, (char *) &addr.SIN_ADDR, host, sizeof(host));
#ifdef INET6
    ip6_expand(host, sizeof(host));
#endif

    if ((tmp=find_is_zlined(host))!=NULL) 
    {
	int rv;
	ircstp->is_ref++;
	ircsprintf(dumpstring, "ERROR :Closing Link: %s (Host zlined: %s)\r\n",
		INADDRANY_STR, tmp->passwd);
	rv = write(newfd, dumpstring, strlen(dumpstring));
	close(newfd);
	return;
    }

    /* if they are throttled, drop them silently. */
    if (throttle_check(host, newfd, NOW) == 0) {
       ircstp->is_ref++;
       close(newfd);
       return;
    }

    if (newfd >= HARD_FDLIMIT - 10) 
    {
	ircstp->is_ref++;
	sendto_realops_lev(CCONN_LEV,"All connections in use. fd: %d (%s)",
		   newfd, get_client_name(cptr, HIDEME));
	SEND(newfd, "ERROR :All connections in use\r\n", 32);
	close(newfd);
	return;
    }
    ircstp->is_ac++;
    
    add_connection(cptr, newfd);
#ifdef PINGNAZI
    nextping = timeofday;
#endif
    if (!cptr->acpt)
	cptr->acpt = &me;
}

/*
 * USE_FAST_FD_ISSET
 *
 * The idea with this, is to save the compute over and over again of
 * nearly the same thing.
 *
 * In SUNOS and BSD the following is done for a FD_ISSET
 *
 * (p)->fd_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
 *
 *
 * Thats one divide, one left shift, and one AND for every case of
 * FD_ISSET used. What I have done here, is saved the last value of
 * offset, and mask and increment them for use on the next fd.
 * hopefully adding up to some CPU savings.
 *
 * The caveats are the following:
 *
 * 1) sizeof(NFDBITS) != sizeof(int)
 *
 * 2) structure element fd_bits might not be, i.e. its linux or some
 * variant.
 *
 * i.e. basically, we now have carnal knowledge of the internals of what
 * happens in an FD_ISSET()
 *
 * 3) the fd list has to be scanned in a linear order, not as it was using
 * the fdlist.
 *
 * -Dianora
 */

#ifdef FAST_FD_ISSET
#define MYFD_ISSET_READ (read_set->fds_bits[fd_read_offset] & fd_read_mask)
#define MYFD_ISSET_WRITE (write_set->fds_bits[fd_write_offset] & \
                           fd_write_mask)
#define MYFD_CLR_READ read_set->fds_bits[fd_read_offset] &= ~fd_read_mask;
#define FAST_FD_INC fd_read_mask <<= 1; if (!fd_read_mask) {\
                     fd_read_offset++; fd_read_mask = 1; }\
                     fd_write_mask <<= 1; if (!fd_write_mask) {\
		     fd_write_offset++;	fd_write_mask = 1; }
#else
#define MYFD_ISSET_READ (FD_ISSET(i, read_set))
#define MYFD_ISSET_WRITE (FD_ISSET(i, write_set))
#define MYFD_CLR_READ FD_CLR(i, read_set);
#define FAST_FD_INC
#endif

/*
 * Check all connections for new connections and input data that is to
 * be processed. Also check for connections with data queued and
 * whether we can write it out.
 */
#ifndef USE_POLL
int read_message(time_t delay, fdlist * listp)
{                        
    aClient *cptr;
    int nfds;
    struct timeval wait;

#ifndef HAVE_FD_ALLOC
    fd_set readset, writeset;
    fd_set *read_set, *write_set;
#endif
    time_t delay2 = delay, now;
    int res, length;
    int auth = 0;
    int i, j;
    char errmsg[256];

#ifdef USE_FAST_FD_ISSET
    int fd_read_mask;
    int fd_read_offset;
    int fd_write_mask;
    int fd_write_offset;
#endif

#ifndef HAVE_FD_ALLOC
    read_set = &readset;
    write_set = &writeset;
#endif

    /* if it is called with NULL we check all active fd's */
    if (!listp) 
    {
	listp = &default_fdlist;
	listp->last_entry = highest_fd + 1;
    }

    now = timeofday;

    for (res = 0;;) 
    {
	FD_ZERO(read_set);
	FD_ZERO(write_set);
	for (i = listp->entry[j = 1]; j <= listp->last_entry;
	     i = listp->entry[++j]) 
	{
	    if (!(cptr = local[i]))
		continue;
	    if (IsLog(cptr))
		continue;
#ifdef USE_SSL
	    if (cptr->ssl != NULL && IsSSL(cptr) &&
		    !SSL_is_init_finished(cptr->ssl))
	    {
		if(IsDead(cptr) || (!safe_SSL_accept(cptr, cptr->fd)))
		    close_connection(cptr);
		continue;
	    }
#endif
	    if (DoingAuth(cptr)) 
	    {
		auth++;
		Debug((DEBUG_NOTICE, "auth on %x %d", cptr, i));
		FD_SET(cptr->authfd, read_set);
		if (cptr->flags & FLAGS_WRAUTH)
		    FD_SET(cptr->authfd, write_set);
	    }
	    if (DoingDNS(cptr) || DoingAuth(cptr))
		continue;
	    if ((IsMe(cptr) && IsListening(cptr)) || IsConnecting(cptr))
	    {
		FD_SET(i, read_set);
	    } 
	    else if (!IsMe(cptr)) 
	    {
		if (DBufLength(&cptr->recvQ) && delay2 > 2)
		    delay2 = 1;
		FD_SET(i, read_set);
	    }

	    length = DBufLength(&cptr->sendQ);

	    if (DoList(cptr) && IsSendable(cptr)) 
	    {
		send_list(cptr, 64);
		length = DBufLength(&cptr->sendQ);
	    }

	    if (length || IsConnecting(cptr) ||
		(ZipOut(cptr) && zip_is_data_out(cptr->serv->zip_out)) ) 
		FD_SET(i, write_set);
	}

	if (resfd >= 0) {
	    FD_SET(resfd, read_set);
	}
	wait.tv_sec = MIN(delay2, delay);
	wait.tv_usec = 0;
	nfds = select(MAXCONNECTIONS, read_set, write_set, 0, &wait);
	if ((timeofday = time(NULL)) == -1)
	{
#ifdef USE_SYSLOG
	    syslog(LOG_WARNING, "Clock Failure (%d), TS can be corrupted", errno);
#endif
	    sendto_ops("Clock Failure (%d), TS can be corrupted", errno);
	}

	if (nfds == -1 && errno == EINTR)
	{
	    return -1;
	} 
	else if (nfds >= 0)
	    break;
	report_error("select %s:%s", &me);
	res++;
	if (res > 5)
	    restart("too many select errors");
	sleep(10);
    }
    
    if (resfd >= 0 && FD_ISSET(resfd, read_set)) 
    {
	do_dns_async();
	nfds--;
	FD_CLR(resfd, read_set);
    }

#ifdef USE_FAST_FD_ISSET
    fd_read_mask = 1;
    fd_read_offset = 0;
    fd_write_mask = 1;
    fd_write_offset = 0;

    for (i = 0; i <= highest_fd; i++)
#else
    for (i = listp->entry[j = 1]; j <= listp->last_entry; 
	 i = listp->entry[++j])
#endif
    { 
	if (!(cptr = local[i])) 
	{
	    FAST_FD_INC
		continue;
	}
	
	/* Check the auth fd's first... */
	if ((auth > 0) && (cptr->authfd >= 0))        
	{
	    auth--;
	    if ((nfds > 0) && FD_ISSET(cptr->authfd, write_set)) 
	    {
		nfds--;
		send_authports(cptr);
	    }
	    else if ((nfds > 0) && FD_ISSET(cptr->authfd, read_set)) 
	    {
		nfds--;
		read_authports(cptr);
	    }
	}
	
	/* Now see if there's a connection pending... */
	if (IsListening(cptr) && MYFD_ISSET_READ)
	{
	    MYFD_CLR_READ
		
	    nfds--;
	    accept_connection(cptr);
	    
	    FAST_FD_INC

		continue;
	}

	if (IsMe(cptr))
	{
	    FAST_FD_INC
	    continue;
	}
	
	/* See if we can write... */
	if(MYFD_ISSET_WRITE)
	{
	    int write_err = 0;
	    
	    nfds--;
	    
	    if (IsConnecting(cptr))
		write_err = completed_connection(cptr);
	    if (!write_err)
		send_queued(cptr);
	    
	    if (IsDead(cptr) || write_err) 
	    {
		if(MYFD_ISSET_READ)
		{
		    MYFD_CLR_READ
		}
		ircsprintf(errmsg, "Write Error: %s", 
			  (cptr->flags & FLAGS_SENDQEX) ?
			  "SendQ Exceeded" : irc_get_sockerr(cptr));
		exit_client(cptr, cptr, &me, errmsg);
		FAST_FD_INC
		continue;
	    }
	}
	
	length = 1;                /* for fall through case */
	
	if(MYFD_ISSET_READ)
	    length = read_packet(cptr);
	else if(DBufLength(&cptr->recvQ) && IsPerson(cptr) && !NoNewLine(cptr))
	    length = do_client_queue(cptr);
	
#ifdef DEBUGMODE
	readcalls++;
#endif
	
	if ((length != FLUSH_BUFFER) && IsDead(cptr)) 
	{
	    if(MYFD_ISSET_READ)
	    {
		MYFD_CLR_READ
	    }
	    ircsprintf(errmsg, "Read/Dead Error: %s",
		       (cptr->flags & FLAGS_SENDQEX) ?
		       "SendQ Exceeded" : irc_get_sockerr(cptr));
	    exit_client(cptr, cptr, &me, errmsg);
	    FAST_FD_INC
	    continue;
	}
	
	if(length > 0)
	{
	    if(MYFD_ISSET_READ)
		nfds--;
	    FAST_FD_INC
	    continue;
	}
	
	if(length != FLUSH_BUFFER)
	{
	    Debug((DEBUG_ERROR, "READ ERROR: fd = %d %d %d", i, errno,
		   length));
	    read_error_exit(cptr, length, cptr->sockerr);
	}
	FAST_FD_INC
    }
    return 0;
}

#else   /* USE_POLL */

#ifdef AIX
#define POLLREADFLAGS (POLLIN|POLLMSG)
#endif
#if defined(POLLMSG) && defined(POLLIN) && defined(POLLRDNORM)
#define POLLREADFLAGS (POLLMSG|POLLIN|POLLRDNORM)
#endif
#if defined(POLLIN) && defined(POLLRDNORM) && !defined(POLLMSG)
#define POLLREADFLAGS (POLLIN|POLLRDNORM)
#endif
#if defined(POLLIN) && !defined(POLLRDNORM) && !defined(POLLMSG)
#define POLLREADFLAGS POLLIN
#endif
#if defined(POLLRDNORM) && !defined(POLLIN) && !defined(POLLMSG)
#define POLLREADFLAGS POLLRDNORM
#endif

#if defined(POLLOUT) && defined(POLLWRNORM)
#define POLLWRITEFLAGS (POLLOUT|POLLWRNORM)
#else
#if defined(POLLOUT)
#define POLLWRITEFLAGS POLLOUT
#else
#if defined(POLLWRNORM)
#define POLLWRITEFLAGS POLLWRNORM
#endif
#endif
#endif

#if defined(POLLERR) && defined(POLLHUP)
#define POLLERRORS (POLLERR|POLLHUP)
#else
#define POLLERRORS POLLERR
#endif

#define PFD_SETR(thisfd) { CHECK_PFD(thisfd); pfd->events |= POLLREADFLAGS; }
#define PFD_SETW(thisfd) { CHECK_PFD(thisfd); pfd->events |= POLLWRITEFLAGS; }
#define CHECK_PFD( thisfd ) if ( pfd->fd != thisfd ) { \
                            pfd = &poll_fdarray[nbr_pfds++];\
                            pfd->fd     = thisfd;\
                            pfd->events = 0;\
                            }

int read_message(time_t delay, fdlist * listp)
{
    aClient *cptr;
    int nfds;
    static struct pollfd poll_fdarray[MAXCONNECTIONS];
    struct pollfd *pfd = poll_fdarray;
    struct pollfd *res_pfd = NULL;
    int nbr_pfds = 0;
    u_long waittime;
    time_t delay2 = delay;
    int res, length, fd;
    int auth, rr, rw;
    int i, j;
    static char errmsg[512];
    static aClient *authclnts[MAXCONNECTIONS];
    
    /* if it is called with NULL we check all active fd's */
    if (!listp) 
    {
	listp = &default_fdlist;
	listp->last_entry = highest_fd + 1;
    }
    
    for (res = 0;;) 
    {
	nbr_pfds = 0;
	pfd = poll_fdarray;
	pfd->fd = -1;
	res_pfd = NULL;
	auth = 0;
	
	for (i = listp->entry[j = 1]; j <= listp->last_entry;
	     i = listp->entry[++j]) 
	{
	    if (!(cptr = local[i]))
		continue;
	    if (IsLog(cptr))
		continue;
#ifdef USE_SSL
	    if (cptr->ssl != NULL && IsSSL(cptr) &&
		    !SSL_is_init_finished(cptr->ssl))
	    {
		if(IsDead(cptr) || (!safe_SSL_accept(cptr, cptr->fd)))
		    close_connection(cptr);
		continue;
	    }
#endif
	    if (DoingAuth(cptr)) 
	    {
		if (auth == 0)
		    memset((char *) &authclnts, '\0', sizeof(authclnts));
		auth++;
		Debug((DEBUG_NOTICE, "auth on %x %d", cptr, i));
		PFD_SETR(cptr->authfd);
		if (cptr->flags & FLAGS_WRAUTH)
		    PFD_SETW(cptr->authfd);
		authclnts[cptr->authfd] = cptr;
		continue;
	    }
	    if (DoingDNS(cptr) || DoingAuth(cptr))
		continue;
	    if (IsMe(cptr) && IsListening(cptr)) 
	    {
# if defined(SOL20) || defined(AIX)
#  define CONNECTFAST
# endif
		
# ifdef CONNECTFAST
		/* 
		 * This is VERY bad if someone tries to send a lot of
		 * clones to the server though, as mbuf's can't be
		 * allocated quickly enough... - Comstud
		 */
		PFD_SETR(i);
# else
		if (timeofday > (cptr->lasttime + 2))
		{
		    PFD_SETR(i);
		} 
		else if (delay2 > 2)
		    delay2 = 2;
# endif
	    } 
	    else if (!IsMe(cptr)) 
	    {
		if (DBufLength(&cptr->recvQ) && delay2 > 2)
		    delay2 = 1;
		PFD_SETR(i);
	    }
	    
	    length = DBufLength(&cptr->sendQ);
	    if (DoList(cptr) && IsSendable(cptr)) 
	    {
		send_list(cptr, 64);
		length = DBufLength(&cptr->sendQ);
	    }
	    
	    if (length || IsConnecting(cptr) ||
		(ZipOut(cptr) && zip_is_data_out(cptr->serv->zip_out))) 
		PFD_SETW(i);
	}
	
	if (resfd >= 0) 
	{
	    PFD_SETR(resfd);
	    res_pfd = pfd;
	}

	waittime = MIN(delay2, delay) * 1000;
	nfds = poll(poll_fdarray, nbr_pfds, waittime);
	if (nfds == -1 && ((errno == EINTR) || (errno == EAGAIN)))
	    return -1;
	else if (nfds >= 0)
	    break;
	report_error("poll %s:%s", &me);
	res++;
	if (res > 5)
	    restart("too many poll errors");
	sleep(10);
    }
    
    if (res_pfd && (res_pfd->revents & (POLLREADFLAGS | POLLERRORS))) 
    {
	do_dns_async();
	nfds--;
    }
    
    for (pfd = poll_fdarray, i = 0; i < nbr_pfds; i++, pfd++) 
    {
        fd = pfd->fd;

        if (pfd == res_pfd)
           continue;

        if (nfds && pfd->revents)
        {
           nfds--;
           rr = pfd->revents & (POLLREADFLAGS | POLLERRORS);
           rw = pfd->revents & POLLWRITEFLAGS;

           if ((auth > 0) && ((cptr = authclnts[fd]) != NULL) && (cptr->authfd == fd)) 
           {
               auth--;
               if (rr)
                  read_authports(cptr);
               if (rw && cptr->authfd >= 0)
                  send_authports(cptr);
               continue;
           }

           if (!(cptr = local[fd]))
              continue;

           if (rr && IsListening(cptr)) 
           {
              accept_connection(cptr);
              continue;
           }

           if (IsMe(cptr))
              continue;

           if (rw) /* socket is marked for writing.. */
           {
              int write_err = 0;
              if (IsConnecting(cptr))
                 write_err = completed_connection(cptr);
              if (!write_err)
                 send_queued(cptr);

              if (IsDead(cptr) || write_err) 
              {
		 ircsprintf(errmsg, "Write Error: %s",
                            (cptr->flags & FLAGS_SENDQEX) ?
                            "SendQ Exceeded" : irc_get_sockerr(cptr));
                 exit_client(cptr, cptr, &me, errmsg);
                 continue;
              }

           }
	
           length = 1; /* for fall through case */
	
           if (rr)
              length = read_packet(cptr);
           else if(DBufLength(&cptr->recvQ) && IsPerson(cptr) && !NoNewLine(cptr))
              length = do_client_queue(cptr);
        }
        else /* nfds == 0 or there are no events for this socket */
        {
           if(!(cptr = local[fd]))
              continue;

           if(DBufLength(&cptr->recvQ) && IsPerson(cptr) && !NoNewLine(cptr))
              length = do_client_queue(cptr);
           else
              continue;
        }   
	    
# ifdef DEBUGMODE
	readcalls++;
# endif
	if (length == FLUSH_BUFFER)
	    continue;
	
	if (IsDead(cptr)) 
	{
	    ircsprintf(errmsg, "Read/Dead Error: %s", 
		       (cptr->flags & FLAGS_SENDQEX) ?
		       "SendQ Exceeded" : irc_get_sockerr(cptr));
	    exit_client(cptr, cptr, &me, errmsg);
	    continue;
	}
	
	if (length > 0)
	    continue;

#if 0
	if (length == 0 && cptr->sockerr == 0)
	{
	    continue;
	}
#endif

	/* An error has occured reading from cptr, drop it. */
	read_error_exit(cptr, length, cptr->sockerr);
    }
    return 0;
}

#endif /* USE_POLL */

/* connect_server */
int connect_server(aConfItem * aconf, aClient * by, struct hostent *hp)
{
    struct SOCKADDR *svp;
    aClient *cptr, *c2ptr;
    char *s;
    int errtmp, len;
 
    Debug((DEBUG_NOTICE, "Connect to %s[%s] @%s", aconf->name,
	  aconf->host, inet_ntop(AFINET, &aconf->ipnum, mydummy,
	  sizeof(mydummy))));
    
    if ((c2ptr = find_server(aconf->name, NULL)))
    {
	sendto_ops("Server %s already present from %s",
		   aconf->name, get_client_name(c2ptr, HIDEME));
	if (by && IsPerson(by) && !MyClient(by))
	    sendto_one(by,
		       ":%s NOTICE %s :Server %s already present from %s",
		       me.name, by->name, aconf->name,
		       get_client_name(c2ptr, HIDEME));
	return -1;
    }
    /* 
     * If we dont know the IP# for this host and itis a hostname and not
     * a ip# string, then try and find the appropriate host record.
     */
#ifndef INET6
    if ((!aconf->ipnum.S_ADDR))
#else
    if (!memcmp(aconf->ipnum.S_ADDR, minus_one, sizeof(struct IN_ADDR)))
#endif
    {
	Link lin;

	lin.flags = ASYNC_CONNECT;
	lin.value.aconf = aconf;
	nextdnscheck = 1;
	s = (char *) strchr(aconf->host, '@');
	s++;			/* should NEVER be NULL */
#ifndef INET6
	if (inet_pton(AFINET, s, &aconf->ipnum.S_ADDR) < 0)
	{
	    aconf->ipnum.S_ADDR = 0;
#else
	if (inet_pton(AFINET, s, aconf->ipnum.S_ADDR) < 0)
	{
	    memcpy(aconf->ipnum.S_ADDR, minus_one, sizeof(struct IN_ADDR));
#endif
	    hp = gethost_byname(s, &lin);
	    Debug((DEBUG_NOTICE, "co_sv: hp %x ac %x na %s ho %s",
		   hp, aconf, aconf->name, s));
	    if (!hp)
		return 0;
	    memcpy((char *) &aconf->ipnum, hp->h_addr,
		   
		   sizeof(struct IN_ADDR));
	}
    }
    cptr = make_client(NULL, &me);
    cptr->hostp = hp;
    /* Copy these in so we have something for error detection. */
    strncpyzt(cptr->name, aconf->name, sizeof(cptr->name));
    strncpyzt(cptr->sockhost, aconf->host, HOSTLEN + 1);
    svp = connect_inet(aconf, cptr, &len);

    if (!svp)
    {
	if (cptr->fd != -1)
	    (void) close(cptr->fd);
	cptr->fd = -2;
	free_client(cptr);
	return -1;
    }
    
    set_non_blocking(cptr->fd, cptr);
    set_sock_opts(cptr->fd, cptr);
    (void) signal(SIGALRM, dummy);
    if (connect(cptr->fd, svp, len) < 0 && errno != EINPROGRESS) 
    {
	errtmp = errno;		/* other system calls may eat errno */
	report_error("Connect to host %s failed: %s", cptr);
	if (by && IsPerson(by) && !MyClient(by))
	    sendto_one(by, ":%s NOTICE %s :Connect to server %s failed.",
		       me.name, by->name, cptr->name);
	(void) close(cptr->fd);
	cptr->fd = -2;
	free_client(cptr);
	errno = errtmp;
	if (errno == EINTR)
	    errno = ETIMEDOUT;
	return -1;
    }
    /* 
     * Attach config entries to client here rather than in
     * completed_connection. This to avoid null pointer references when
     * name returned by gethostbyaddr matches no C lines (could happen
     * in 2.6.1a when host and servername differ). No need to check
     * access and do gethostbyaddr calls. There must at least be one as
     * we got here C line...  meLazy
     */
    (void) attach_confs_host(cptr, aconf->host,
			     CONF_NOCONNECT_SERVER | CONF_CONNECT_SERVER);
    
    if (!find_conf_host(cptr->confs, aconf->host, CONF_NOCONNECT_SERVER) ||
	!find_conf_host(cptr->confs, aconf->host, CONF_CONNECT_SERVER))
    {
	sendto_ops("Server %s is not enabled for connecting:no C/N-line",
		   aconf->name);
	if (by && IsPerson(by) && !MyClient(by))
	    sendto_one(by, ":%s NOTICE %s :Connect to server %s failed.",
		       me.name, by->name, cptr->name);
	det_confs_butmask(cptr, 0);
	(void) close(cptr->fd);
	cptr->fd = -2;
	free_client(cptr);
	return (-1);
    }
    /* The socket has been connected or connect is in progress. */
    (void) make_server(cptr);
    if (by && IsPerson(by))
    {
	strcpy(cptr->serv->bynick, by->name);
	strcpy(cptr->serv->byuser, by->user->username);
	strcpy(cptr->serv->byhost, by->user->host);
    }
    else
    {
	strcpy(cptr->serv->bynick, "AutoConn.");
	*cptr->serv->byuser = '\0';
	*cptr->serv->byhost = '\0';
    }
    cptr->serv->up = me.name;
    if (cptr->fd > highest_fd)
	highest_fd = cptr->fd;
    local[cptr->fd] = cptr;
    cptr->acpt = &me;
    SetConnecting(cptr);

    /* sendq probably changed.. */
    cptr->sendqlen = get_sendq(cptr);

    get_sockhost(cptr, aconf->host);
    add_client_to_list(cptr);
#ifdef PINGNAZI
    nextping = timeofday;
#endif

    return 0;
}

static struct SOCKADDR *connect_inet(aConfItem * aconf,
				     aClient * cptr, int *lenp)
{
    static struct SOCKADDR_IN server;
    struct hostent *hp;
    char *s;
    struct SOCKADDR_IN sin;
    
    /* 
     * Might as well get sockhost from here, the connection is attempted
     * with it so if it fails its useless.
     */
    cptr->fd = socket(AFINET, SOCK_STREAM, 0);
    if (cptr->fd >= (HARD_FDLIMIT - 10))
    {
	sendto_realops("No more connections allowed (%s)", cptr->name);
	return NULL;
    }

    memset((char *) &server, '\0', sizeof(server));
    memset((char *) &sin, '\0', sizeof(server));
    server.SIN_FAMILY = sin.SIN_FAMILY = AFINET;
    get_sockhost(cptr, aconf->host);

    if (aconf->localhost)
#ifndef INET6
	inet_pton(AFINET, (void*)aconf->localhost, (void*)&sin.SIN_ADDR.S_ADDR);
#else
        inet_pton(AFINET, (void*)aconf->localhost, (void*)sin.SIN_ADDR.S_ADDR);
#endif
    if (specific_virtual_host == 1)
	memcpy(&sin.SIN_ADDR, &vserv.SIN_ADDR, sizeof(sin.SIN_ADDR));

    if (cptr->fd == -1)
    {
	report_error("opening stream socket to server %s:%s", cptr);
	return NULL;
    }
    /* 
     * Bind to a local IP# (with unknown port - let unix decide) so *
     * we have some chance of knowing the IP# that gets used for a host *
     * with more than one IP#.
     */
    /* 
     * No we don't bind it, not all OS's can handle connecting with an
     * already bound socket, different ip# might occur anyway leading to
     * a freezing select() on this side for some time.
     */
    if (specific_virtual_host || aconf->localhost)
    {
	/* 
	 * * No, we do bind it if we have virtual host support. If we
	 * don't explicitly bind it, it will default to IN_ADDR_ANY and
	 * we lose due to the other server not allowing our base IP
	 * --smg
	 */
	if (bind(cptr->fd, (struct SOCKADDR *) &sin, sizeof(sin)) == -1)
	{
	    report_error("error binding to local port for %s:%s", cptr);
	    return NULL;
	}
    }
    /* 
     * By this point we should know the IP# of the host listed in the
     * conf line, whether as a result of the hostname lookup or the ip#
     * being present instead. If we dont know it, then the connect
     * fails.
     */
    s = strchr(aconf->host, '@');
    s == NULL ? s = aconf->host : ++s;
#ifndef INET6
    if (inet_pton(AFINET, s, &aconf->ipnum.S_ADDR) < 0)
    {
	aconf->ipnum.S_ADDR = -1;
#else
    if (inet_pton(AFINET, s, aconf->ipnum.S_ADDR) < 0)
    {
	memcpy(aconf->ipnum.S_ADDR, minus_one, sizeof(struct IN_ADDR));
#endif
	hp = cptr->hostp;
	if (!hp)
	{
	    Debug((DEBUG_FATAL, "%s: unknown host", aconf->host));
	    return NULL;
	}
	memcpy((char *) &aconf->ipnum, hp->h_addr, sizeof(struct IN_ADDR));
    }
    memcpy((char *) &server.SIN_ADDR, (char *) &aconf->ipnum,
	   sizeof(struct IN_ADDR));
    
    memcpy((char *) &cptr->ip, (char *) &aconf->ipnum,
	   sizeof(struct IN_ADDR));

    server.SIN_PORT = htons((aconf->port > 0) ? aconf->port : portnum);
    *lenp = sizeof(server);
    return (struct SOCKADDR *) &server;
}

/*
 * find the real hostname for the host running the server (or one
 * which matches the server's name) and its primary IP#.  Hostname is
 * stored in the client structure passed as a pointer.
 */
void get_my_name(aClient * cptr, char *name, int len)
{
    static char tmp[HOSTLEN + 1];
    struct hostent *hp;

    /* 
     * The following conflicts with both AIX and linux prototypes oh
     * well, we can put up with the errors from other systems -Dianora
     */

    char *cname = cptr->name;
    
    /* Setup local socket structure to use for binding to. */
    memset((char *) &mysk, '\0', sizeof(mysk));
    mysk.SIN_FAMILY = AFINET;

    if (gethostname(name, len) == -1)
	return;
    name[len] = '\0';
    
    /* assume that a name containing '.' is a FQDN */
    if (!strchr(name, '.'))
	add_local_domain(name, len - strlen(name));
    /* 
     * If hostname gives another name than cname, then check if there
     * is a CNAME record for cname pointing to hostname. If so accept
     * cname as our name.   meLazy
     */
    if (BadPtr(cname))
	return;
    if ((hp = gethostbyname(cname)) || (hp = gethostbyname(name)))
    {
	char *hname;
	int i = 0;
	
	for (hname = hp->h_name; hname; hname = hp->h_aliases[i++])
	{
	    strncpyzt(tmp, hname, sizeof(tmp));
	    add_local_domain(tmp, sizeof(tmp) - strlen(tmp));
	    /* 
	     * Copy the matching name over and store the 'primary' IP#
	     * as 'myip' which is used later for making the right one is
	     * used for connecting to other hosts.
	     */
	    if (!mycmp(me.name, tmp))
		break;
	}
	if (mycmp(me.name, tmp))
	    strncpyzt(name, hp->h_name, len);
	else
	    strncpyzt(name, tmp, len);
	memcpy((char *) &mysk.SIN_ADDR, hp->h_addr, sizeof(struct IN_ADDR));

	Debug((DEBUG_DEBUG, "local name is %s", get_client_name(&me, TRUE)));
    }
    return;
}

/*
 * do_dns_async
 *
 * Called when the fd returned from init_resolver() has been selected for
 * reading.
 */
static void do_dns_async()
{
    static Link ln;
    aClient *cptr;
    aConfItem *aconf;
    struct hostent *hp;
    int bytes, packets = 0;

    do
    {
	ln.flags = -1;
	hp = get_res((char *) &ln);
	Debug((DEBUG_DNS, "%#x = get_res(%d,%#x)",
	       hp, ln.flags, ln.value.cptr));

	switch (ln.flags)
	{
	case ASYNC_NONE:
	    /* 
	     * no reply was processed that was outstanding or had
	     * a client still waiting.
	     */
	    break;
	case ASYNC_CLIENT:
	    if ((cptr = ln.value.cptr))
	    {
		del_queries((char *) cptr);

		ClearDNS(cptr);
		cptr->hostp = hp;
		if (!DoingAuth(cptr))
		    SetAccess(cptr);
	    }
	    break;
	case ASYNC_CONNECT:
	    aconf = ln.value.aconf;
	    if (hp && aconf)
	    {
		memcpy((char *) &aconf->ipnum, hp->h_addr,
	       
		       sizeof(struct IN_ADDR));
		
		(void) connect_server(aconf, NULL, hp);
	    } 
	    else
		sendto_ops("Connect to %s failed: host lookup",
			   (aconf) ? aconf->host : "unknown");
	    break;
	case ASYNC_CONF:
	    aconf = ln.value.aconf;
	    if (hp && aconf)
		memcpy((char *) &aconf->ipnum, hp->h_addr,
		       sizeof(struct IN_ADDR));

	    break;
	default:
	    break;
	}
	if (ioctl(resfd, FIONREAD, &bytes) == -1)
	    bytes = 0;
	packets++;
    }
    while ((bytes > 0) && (packets < 10));
}
