/*
 * src/res.c (C)opyright 1992 Darren Reed. All rights reserved. This
 * file may not be distributed without the author's permission in any
 * shape or form. The author takes no responsibility for any damage or
 * loss of property which results from the use of this software.
 */

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "res.h"
#include "numeric.h"
#include "h.h"

#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include "nameser.h"
#include "resolv.h"
#include "inet.h"

/* ALLOW_CACHE_NAMES
 *
 * If enabled, this allows our resolver code to keep a hash table
 * of names, for which we find in gethost_byname calls.
 * This presents a few problems with anti-spoofing code.
 *
 * Since the majority of our host lookups are reverse, having
 * a cached record for reverse records (addresses) seems useful.
 * If, for some reason, you want this on, you may define it.
 */
#undef ALLOW_CACHE_NAMES

/* SEARCH_CACHE_ADDRESSES
 *
 * All of our records will probably only have one valid IP address.
 * If you want to search for multiple addresses, define this.
 * (In the current implementation, it should not really be possible
 * to get multiple addresses.)
 *
 * If not, it saves CPU as a cache miss does not traverse the
 * entire cache tree for a result.
 */
#undef SEARCH_CACHE_ADDRESSES

#define PROCANSWER_STRANGE   -2 /* invalid answer or query, try again */
#define PROCANSWER_MALICIOUS -3 /* obviously malicious reply, 
				 * don't do DNS on this ip. */

#undef	DEBUG			/* because theres alot of debug code in here */
#ifndef INET6
#define RESHOSTLEN HOSTLEN
#else
#define RESHOSTLEN 128
#endif

extern int  dn_expand(char *, char *, char *, char *, int);
extern int  dn_skipname(char *, char *);
extern int
res_mkquery(int, char *, int, int, char *, int,
	    struct rrec *, char *, int);

extern int  errno, h_errno;
extern int  highest_fd;
extern aClient *local[];

static char hostbuf[RESHOSTLEN + 1];
static int  incache = 0;
static CacheTable hashtable[ARES_CACSIZE];
static aCache *cachetop = NULL;
static ResRQ *last, *first;

static void rem_cache(aCache *);
static void rem_request(ResRQ *);
static int  do_query_name(Link *, char *, ResRQ *, int);
static int  do_query_number(Link *, struct IN_ADDR *, ResRQ *);
static void resend_query(ResRQ *);
static int  proc_answer(ResRQ *, HEADER *, char *, char *);
static int  query_name(char *, int, int, ResRQ *);
static aCache *make_cache(ResRQ *);
static aCache *find_cache_name(char *);
static aCache *find_cache_number(ResRQ *, char *);
static int  add_request(ResRQ *);
static ResRQ *make_request(Link *);
static int  send_res_msg(char *, int, int);
static ResRQ *find_id(int);
static int  hash_number(unsigned char *);
static void update_list(ResRQ *, aCache *);
#ifdef ALLOW_CACHE_NAMES
static int  hash_name(char *);
#endif
static struct hostent *getres_err(ResRQ *, char *);

static struct cacheinfo
{
    int         ca_adds;
    int         ca_dels;
    int         ca_expires;
    int         ca_lookups;
    int         ca_na_hits;
    int         ca_nu_hits;
    int         ca_updates;
} cainfo;

static struct resinfo
{
    int         re_errors;
    int         re_nu_look;
    int         re_na_look;
    int         re_replies;
    int         re_requests;
    int         re_resends;
    int         re_sent;
    int         re_timeouts;
    int         re_shortttl;
    int         re_unkrep;
} reinfo;

int init_resolver(int op)
{
    int         ret = 0;
    
#ifdef	LRAND48
    srand48(timeofday);
#endif
    if (op & RES_INITLIST)
    {
	memset((char *) &reinfo, '\0', sizeof(reinfo));
	first = last = NULL;
    }
    if (op & RES_CALLINIT)
    {
	ret = res_init();
	if (!_res.nscount)
	{
	    _res.nscount = 1;
	    _res.nsaddr_list[0].sin_addr.s_addr = inet_addr("127.0.0.1");
	}
    }
    
    if (op & RES_INITSOCK)
    {
	int         on = 0;
	
	ret = resfd = socket(AF_INET, SOCK_DGRAM, 0);
	(void) setsockopt(ret, SOL_SOCKET, SO_BROADCAST,
			  (char *) &on, sizeof(on));
    }
#ifdef DEBUG
    if (op & RES_INITDEBG);
    _res.options |= RES_DEBUG;
#endif
    if (op & RES_INITCACH)
    {
	memset((char *) &cainfo, '\0', sizeof(cainfo));
	memset((char *) hashtable, '\0', sizeof(hashtable));
    }
    if (op == 0)
	ret = resfd;
    return ret;
}

static int add_request(ResRQ * new)
{
    if (!new)
	return -1;
    if (!first)
	first = last = new;
    else {
	last->next = new;
	last = new;
    }
    new->next = NULL;
    reinfo.re_requests++;
    return 0;
}

/*
 * remove a request from the list. This must also free any memory that
 * has been allocated for temporary storage of DNS results.
 */
static void rem_request(ResRQ * old)
{
    ResRQ **rptr, *r2ptr = NULL;
    int     i;
    char   *s;
    
    if (!old)
	return;
    for (rptr = &first; *rptr; r2ptr = *rptr, rptr = &(*rptr)->next)
	if (*rptr == old)
	{
	    *rptr = old->next;
	    if (last == old)
		last = r2ptr;
	    break;
	}
#ifdef	DEBUG
    Debug((DEBUG_INFO, "rem_request:Remove %#x at %#x %#x",
	   old, *rptr, r2ptr));
#endif
    r2ptr = old;
    
    if (r2ptr->he.h_name)
	MyFree((char *) r2ptr->he.h_name);
    for (i = 0; i < IRC_MAXALIASES; i++)
	if ((s = r2ptr->he.h_aliases[i]))
	    MyFree(s);
    
    if (r2ptr->he_rev.h_name)
	MyFree((char *) r2ptr->he_rev.h_name);
    for (i = 0; i < IRC_MAXALIASES; i++)
	if ((s = r2ptr->he_rev.h_aliases[i]))
	    MyFree(s);
    
    if (r2ptr->name)
	MyFree(r2ptr->name);
    MyFree(r2ptr);

    return;
}

/* Create a DNS request record for the server. */
static ResRQ *make_request(Link *lp)
{
    ResRQ  *nreq;
    
    nreq = (ResRQ *) MyMalloc(sizeof(ResRQ));
    memset((char *) nreq, '\0', sizeof(ResRQ));
    nreq->next = NULL;		/*  where NULL is non-zero */
    nreq->sentat = timeofday;
    nreq->retries = 3;
    nreq->resend = 1;
    nreq->srch = -1;
    if (lp)
	memcpy((char *) &nreq->cinfo, (char *) lp, sizeof(Link));
    else
	memset((char *) &nreq->cinfo, '\0', sizeof(Link));
    
    nreq->timeout = 4;		/* start at 4 and exponential inc. */
    nreq->he.h_addrtype = AFINET;
    nreq->he.h_name = NULL;
    nreq->he.h_aliases[0] = NULL;
    (void) add_request(nreq);
    return nreq;
}

/*
 * Remove queries from the list which have been there too long without
 * being resolved.
 */
time_t timeout_query_list(time_t now)
{
    ResRQ  *rptr, *r2ptr;
    time_t  next = 0, tout;
    aClient    *cptr;

    Debug((DEBUG_DNS, "timeout_query_list at %s", myctime(now)));
    for (rptr = first; rptr; rptr = r2ptr)
    {
	r2ptr = rptr->next;
	tout = rptr->sentat + rptr->timeout;
	if (now >= tout)
	{
	    if (--rptr->retries <= 0)
	    {
#ifdef DEBUG
		Debug((DEBUG_ERROR, "timeout %x now %d cptr %x",
		       rptr, now, rptr->cinfo.value.cptr));
#endif
		reinfo.re_timeouts++;
		cptr = rptr->cinfo.value.cptr;
		switch (rptr->cinfo.flags)
		{
		    case ASYNC_CLIENT:
			ClearDNS(cptr);
			if (!DoingAuth(cptr))
			    SetAccess(cptr);
			break;

		    case ASYNC_CONNECT:
			sendto_ops("Host %s unknown", rptr->name);
			break;
		}
		
		rem_request(rptr);
		continue;
	    }
	    else
	    {
		rptr->sentat = now;
		rptr->timeout += rptr->timeout;
		resend_query(rptr);
#ifdef DEBUG
		Debug((DEBUG_INFO, "r %x now %d retry %d c %x",
		       rptr, now, rptr->retries,
		       rptr->cinfo.value.cptr));
#endif
	    }
	}
	if (!next || tout < next)
	    next = tout;
    }
    return (next > now) ? next : (now + AR_TTL);
}

/*
 * del_queries - called by the server to cleanup outstanding queries
 * for which there no longer exist clients or conf lines.
 */
void del_queries(char *cp)
{
    ResRQ  *rptr, *r2ptr;

    for (rptr = first; rptr; rptr = r2ptr)
    {
	r2ptr = rptr->next;
	if (cp == rptr->cinfo.value.cp)
	    rem_request(rptr);
    }
}

/*
 * sends msg to all nameservers found in the "_res" structure. This
 * should reflect /etc/resolv.conf. We will get responses which arent
 * needed but is easier than checking to see if nameserver isnt
 * present. Returns number of messages successfully sent to nameservers
 * or -1 if no successful sends.
 */
static int send_res_msg(char *msg, int len, int rcount)
{
    int     i;
    int         sent = 0, max;

    if (!msg)
	return -1;
    
    max = MIN(_res.nscount, rcount);
    if (_res.options & RES_PRIMARY)
	max = 1;
    if (!max)
	max = 1;

    for (i = 0; i < max; i++)
    {
	_res.nsaddr_list[i].sin_family = AF_INET;
	if (sendto(resfd, msg, len, 0,
		   (struct sockaddr *) &(_res.nsaddr_list[i]),
		   sizeof(struct sockaddr)) == len)
	{
	    reinfo.re_sent++;
	    sent++;
	}
	else
	    Debug((DEBUG_ERROR, "s_r_m:sendto: %d on %d",
		   errno, resfd));
    }
    
    return (sent) ? sent : -1;
}

/* find a dns request id (id is determined by dn_mkquery) */
static ResRQ *find_id(int id)
{
    ResRQ  *rptr;

    for (rptr = first; rptr; rptr = rptr->next)
	if (rptr->id == id)
	    return rptr;
    return ((ResRQ *) NULL);
}

struct hostent *gethost_byname_type(char *name, Link *lp, int type)
{
    aCache *cp;
    
    if (name == (char *) NULL)
	return ((struct hostent *) NULL);
    
    reinfo.re_na_look++;
    if ((cp = find_cache_name(name)))
	return (struct hostent *) &(cp->he);
    if (!lp)
	return NULL;
    (void) do_query_name(lp, name, NULL, type);
    return ((struct hostent *) NULL);
}

struct hostent *gethost_byname(char *name, Link *lp) {
#ifndef INET6
	return gethost_byname_type(name, lp, T_A);
#else
  	return gethost_byname_type(name, lp, T_AAAA);
#endif
}

struct hostent *gethost_byaddr(char *addr, Link *lp)
{
    aCache     *cp;

    if (addr == (char *) NULL)
	return ((struct hostent *) NULL);

    reinfo.re_nu_look++;
    if ((cp = find_cache_number(NULL, addr)))
	return (struct hostent *) &(cp->he);
    if (!lp)
	return NULL;
    (void) do_query_number(lp, (struct IN_ADDR *) addr, NULL);
    return ((struct hostent *) NULL);
}

static int do_query_name(Link *lp, char *name, ResRQ * rptr, int type)
{
    char        hname[RESHOSTLEN + 1];
    int         len;
    
    strncpyzt(hname, name, RESHOSTLEN);
    len = strlen(hname);
    
    if (rptr && !strchr(hname, '.') && _res.options & RES_DEFNAMES)
    {
	if ((sizeof(hname) - len - 1) >= 2)
	{
	    (void) strncat(hname, ".", sizeof(hname) - len - 1);
	    len++;
	    if ((sizeof(hname) - len - 1) >= 1)
		(void) strncat(hname, _res.defdname, sizeof(hname) - len - 1);
	}
    }
    /*
     * Store the name passed as the one to lookup and generate other
     * host names to pass onto the nameserver(s) for lookups.
     */
    if (!rptr)
    {
	size_t l = strlen(name) + 1;
	rptr = make_request(lp);
	rptr->type = type;
	rptr->name = (char *) MyMalloc(l);
	(void) strncpy(rptr->name, name, l);
    }
#ifndef INET6
    return (query_name(hname, C_IN, T_A, rptr));
#else
    return (query_name(hname, C_IN, type, rptr));
#endif
}

/* Use this to do reverse IP# lookups. */
static int do_query_number(Link *lp, struct IN_ADDR *numb, ResRQ * rptr)
{
#ifndef INET6
    char        ipbuf[32];
#else
    char	ipbuf[128];
#endif
    u_char *cp;

    cp = (u_char *) &numb->S_ADDR;
#ifndef INET6
    (void) ircsprintf(ipbuf, "%u.%u.%u.%u.in-addr.arpa.",
		      (u_int) (cp[3]), (u_int) (cp[2]),
		      (u_int) (cp[1]), (u_int) (cp[0]));

#else
   if (cp[0] == 0 && cp[1] == 0 && cp[2] == 0 && cp[3] == 0
	   && cp[4] == 0 && cp[5] == 0 && cp[6] == 0 && cp[7] == 0
	   && cp[8] == 0 && cp[9] == 0 && cp[10] == 0xff && cp[11] == 0xff) {
	   (void) ircsprintf(ipbuf, "%u.%u.%u.%u.in-addr.arpa.",
		   (u_int) (cp[15]), (u_int) (cp[14]),
		   (u_int) (cp[13]), (u_int) (cp[12]));
   } else {
	   (void) sprintf(ipbuf,
		   "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.arpa.",
		   (u_int) (cp[15] & 0xf), (u_int) (cp[15] >> 4),
		   (u_int) (cp[14] & 0xf), (u_int) (cp[14] >> 4),
		   (u_int) (cp[13] & 0xf), (u_int) (cp[13] >> 4),
		   (u_int) (cp[12] & 0xf), (u_int) (cp[12] >> 4),
		   (u_int) (cp[11] & 0xf), (u_int) (cp[11] >> 4),
		   (u_int) (cp[10] & 0xf), (u_int) (cp[10] >> 4),
		   (u_int) (cp[9] & 0xf), (u_int) (cp[9] >> 4),
		   (u_int) (cp[8] & 0xf), (u_int) (cp[8] >> 4),
		   (u_int) (cp[7] & 0xf), (u_int) (cp[7] >> 4),
		   (u_int) (cp[6] & 0xf), (u_int) (cp[6] >> 4),
		   (u_int) (cp[5] & 0xf), (u_int) (cp[5] >> 4),
		   (u_int) (cp[4] & 0xf), (u_int) (cp[4] >> 4),
		   (u_int) (cp[3] & 0xf), (u_int) (cp[3] >> 4),
		   (u_int) (cp[2] & 0xf), (u_int) (cp[2] >> 4),
		   (u_int) (cp[1] & 0xf), (u_int) (cp[1] >> 4),
		   (u_int) (cp[0] & 0xf), (u_int) (cp[0] >> 4));
   }
#endif

    if (!rptr)
    {
	rptr = make_request(lp);
	rptr->type = T_PTR;
#ifndef INET6
	rptr->addr.S_ADDR = numb->S_ADDR;
#else
	memcpy(&rptr->addr.S_ADDR, &numb->S_ADDR, sizeof(struct IN_ADDR));
#endif
	memcpy((char *) &rptr->he.h_addr,
	       (char *) &numb->S_ADDR, sizeof(struct IN_ADDR));
	rptr->he.h_length = sizeof(struct IN_ADDR);
    }
    return (query_name(ipbuf, C_IN, T_PTR, rptr));
}

/* generate a query based on class, type and name. */
static int query_name(char *name, int class, int type, ResRQ * rptr)
{
    struct timeval tv;
    char        buf[MAXPACKET];
    int         r, s, k = 0;
    HEADER     *hptr;

    memset(buf, '\0', sizeof(buf));
    r = res_mkquery(QUERY, name, class, type, NULL, 0, NULL,
		    buf, sizeof(buf));
    if (r <= 0)
    {
	h_errno = NO_RECOVERY;
	return r;
    }
    hptr = (HEADER *) buf;
#ifdef LRAND48
    do
    {
	hptr->id = htons(ntohs(hptr->id) + k + lrand48() & 0xffff);
#else
	(void) gettimeofday(&tv, NULL);
    do
    {
#if 0 /* emacs kludge */
    }
#endif
        hptr->id = htons(ntohs(hptr->id) + k +
			 (u_short) (tv.tv_usec & 0xffff));
#endif /* LRAND48 */
	k++;
    } while (find_id(ntohs(hptr->id)));
    rptr->id = ntohs(hptr->id);
    rptr->sends++;
    s = send_res_msg(buf, r, rptr->sends);
    if (s == -1)
    {
	h_errno = TRY_AGAIN;
	return -1;
    }
    else
	rptr->sent += s;
    return 0;
}
    
static void resend_query(ResRQ * rptr)
{
    if (rptr->resend == 0)
	return;
    reinfo.re_resends++;
    switch (rptr->type)
    {
    case T_PTR:
	(void) do_query_number(NULL, &rptr->addr, rptr);
	break;
    case T_A:
	(void) do_query_name(NULL, rptr->name, rptr, T_A);
#ifdef INET6
    case T_AAAA:
	(void) do_query_name(NULL, rptr->name, rptr, T_AAAA);
#endif
	break;
    default:
	break;
    }
    return;
}

/* returns 0 on failure, nonzero on success */
#ifndef INET6
int arpa_to_ip(char *arpastring, unsigned int *saddr)
{
    int idx = 0, onum = 0;
    char ipbuf[RESHOSTLEN + 1];
    char *fragptr[4];
    u_char *ipptr;
         
    memset((void *)ipbuf, 0x0, sizeof(ipbuf));
    strncpy(ipbuf, arpastring, RESHOSTLEN + 1);

    /* ipbuf should contain a string in the format of 4.3.2.1.in-addr.arpa */
    
    fragptr[onum++] = ipbuf;

    while(ipbuf[idx])
    {
	if(ipbuf[idx] == '.')
	{
	    ipbuf[idx++] = '\0';
	    if(onum == 4)
		break;
	    fragptr[onum++] = ipbuf + idx;
	}
	else
	    idx++;
    }

    if(onum != 4)
	return 0;

    if(mycmp(ipbuf + idx, "in-addr.arpa"))
	return 0;

    ipptr = (u_char *) saddr;

    ipptr[0] = (u_char) atoi(fragptr[3]);
    ipptr[1] = (u_char) atoi(fragptr[2]);
    ipptr[2] = (u_char) atoi(fragptr[1]);
    ipptr[3] = (u_char) atoi(fragptr[0]);
    return 1;
}
#else
int arpa_to_ip(const char *arpastring, u_char *sa, size_t size)
{
   unsigned short int idx = 0;
   struct IN_ADDR in;
   char ipbuf[RESHOSTLEN+1];
   u_char *ipptr =in.S_ADDR;
   char *fragptr[4];

   char *ip6 ="ip6.arpa", *ip4 ="in-addr.arpa", *str = NULL;
   unsigned short int dots = 0, n = 0;

   Debug(("arpatoip received arpastring: %s", arpastring));
   
   memset(ipbuf, 0x0, RESHOSTLEN+1);
   memcpy(ipbuf, arpastring, RESHOSTLEN);

   if(strstr(arpastring, ip6)) {
      /* ipbuf should contain a string like f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.ip6.arpa */
      str = ip6;
      dots = 64;

      while(ipbuf[idx])
      {
         if(ipbuf[idx] == '.')
         {
            ipbuf[idx++] = '\0';
   	 if(idx >=dots)
   		 break;
         }
         else
            idx++;
      }
      n = idx;
   } else if(strstr(arpastring, ip4)) {
      /* ipbuf should contain a string in the format of 4.3.2.1.in-addr.arpa */
      unsigned short int onum = 0;

      str = ip4;
      dots = 4;
      fragptr[onum++] = ipbuf;
  
      while(ipbuf[idx])
      {
  	if(ipbuf[idx] == '.')
  	{
  	    ipbuf[idx++] = '\0';
  	    if(onum == dots)
  		break;
  	    fragptr[onum++] = ipbuf + idx;
  	}
  	else
  	    idx++;
      }
      n = onum;
   } else
      return 0;

   if(n != dots)
      return 0;

   if(mycmp(ipbuf + idx, str))
      return 0;

   if(str == ip6) {
      unsigned short int i, j = 15;
      unsigned char bf[2];

      bf[2] = '\0';
      for(i = 0; i < 31; i++) {
    	 bf[1] =ipbuf[i*2];
    	 bf[0] =ipbuf[++i*2];
	 ipptr[j--] = (u_char) strtoul((char* )bf, NULL, 16);
      }
   } else if(str == ip4) {
      memset(ipptr, 0x0, 10);
      memset(ipptr + 10, 0xff, 2);
      ipptr[12] = (u_char) strtoul(fragptr[3], NULL, 10);
      ipptr[13] = (u_char) strtoul(fragptr[2], NULL, 10);
      ipptr[14] = (u_char) strtoul(fragptr[1], NULL, 10);
      ipptr[15] = (u_char) strtoul(fragptr[0], NULL, 10);
   }

   memcpy((void*)sa, (void*)ipptr, (size_t)size);
   return 1;
}
#endif

#undef DNS_ANS_DEBUG_MAX
#undef DNS_ANS_DEBUG

#define MAX_ACCEPTABLE_ANS 10

static char acceptable_answers[MAX_ACCEPTABLE_ANS][RESHOSTLEN + 1];
static int num_acc_answers = 0;

#define add_acceptable_answer(x) do { \
           if(num_acc_answers < MAX_ACCEPTABLE_ANS) { \
	       memset(acceptable_answers[num_acc_answers], 0x0, RESHOSTLEN + 1); \
	       strncpy(acceptable_answers[num_acc_answers++], x, RESHOSTLEN + 1); \
	   } \
} while (0);
	   
static inline char *is_acceptable_answer(char *h)
{
    int i;

    for (i = 0; i < num_acc_answers; i++) 
    {
	if(mycmp(acceptable_answers[i], h) == 0)
	    return acceptable_answers[i];
    }
    return 0;
}

#ifdef DNS_ANS_DEBUG_MAX
static char dhostbuf[RESHOSTLEN + 1];
#endif

/* process name server reply. */
static int proc_answer(ResRQ * rptr, HEADER *hptr, char *buf, char *eob)
{
    char   *cp, **alias, *acc;
    struct hent *hp;
    int class, type, dlen, len, ans = 0, n, origtype = rptr->type;
    int adr = 0;
    struct IN_ADDR ptrrep, dr;

    num_acc_answers = 0;
    
    cp = buf + sizeof(HEADER);
    hp = (struct hent *) &(rptr->he);

    while ((WHOSTENTP(hp->h_addr_list[adr].S_ADDR)) && (adr < IRC_MAXADDRS))
	adr++;

    alias = hp->h_aliases;
    while (*alias)
	alias++;

    if(hptr->qdcount != 1)
    {
	sendto_realops_lev(DEBUG_LEV,
			   "DNS packet with question count of %d (?)",
			   hptr->qdcount);
	return -1;
    }

    /*
     * ensure the question we're getting a reply for
     * is a the right question.
     */

    if((n = dn_expand(buf, eob, cp, hostbuf, sizeof(hostbuf))) <= 0)
    {
	/* broken dns packet, toss it out */
	return -1;
    }
    else
    {
	int strangeness = 0;
	char tmphost[RESHOSTLEN + 1];

	hostbuf[RESHOSTLEN] = '\0';
	cp += n;
	type = (int) _getshort(cp);
	cp += sizeof(short);
	class = (int) _getshort(cp);
	cp += sizeof(short);
	if(class != C_IN)
	{
	    sendto_realops_lev(DEBUG_LEV,
			       "Expected DNS packet class C_IN, got %d (?)",
			       class);
	    strangeness++;
	}

	if(type != rptr->type)
	{
	    sendto_realops_lev(DEBUG_LEV,
			       "Expected DNS packet type %d, got %d (?)",
			       rptr->type, type);
	    strangeness++;
	}

#ifndef INET6
	if(rptr->type == T_A && rptr->name)
#else
	if((rptr->type == T_AAAA || rptr->type == T_A) && rptr->name)
#endif
	{
	    memset(tmphost, 0x0, RESHOSTLEN + 1);
	    strncpy(tmphost, rptr->name, RESHOSTLEN + 1);
	}
	else if(rptr->type == T_PTR)
	{
	    u_char *ipp;
	    ipp = (u_char *) &rptr->addr.S_ADDR;
#ifndef INET6
	    ircsprintf(tmphost, "%u.%u.%u.%u.in-addr.arpa",
		       (u_int) (ipp[3]), (u_int) (ipp[2]),
		       (u_int) (ipp[1]), (u_int) (ipp[0]));  
#else
	    if (ipp[0] == 0 && ipp[1] == 0 && ipp[2] == 0 && ipp[3] == 0
		       && ipp[4] == 0 && ipp[5] == 0 && ipp[6] == 0 && ipp[7] == 0
		       && ipp[8] == 0 && ipp[9] == 0 && ipp[10] == 0xff && ipp[11] == 0xff) {
		    ircsprintf(tmphost, "%u.%u.%u.%u.in-addr.arpa",
				    (u_int) ipp[15], (u_int) ipp[14],
				    (u_int) ipp[13], (u_int) ipp[12]);
	    } else {
		    (void) sprintf(tmphost,
		       "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
		       "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
		       "%x.%x.%x.%x.%x.%x.ip6.arpa",
			 (u_int) (ipp[15] & 0xf), (u_int) (ipp[15] >> 4),
			 (u_int) (ipp[14] & 0xf), (u_int) (ipp[14] >> 4),
			 (u_int) (ipp[13] & 0xf), (u_int) (ipp[13] >> 4),
			 (u_int) (ipp[12] & 0xf), (u_int) (ipp[12] >> 4),
			 (u_int) (ipp[11] & 0xf), (u_int) (ipp[11] >> 4),
			 (u_int) (ipp[10] & 0xf), (u_int) (ipp[10] >> 4),
			 (u_int) (ipp[9] & 0xf), (u_int) (ipp[9] >> 4),
			 (u_int) (ipp[8] & 0xf), (u_int) (ipp[8] >> 4),
			 (u_int) (ipp[7] & 0xf), (u_int) (ipp[7] >> 4),
			 (u_int) (ipp[6] & 0xf), (u_int) (ipp[6] >> 4),
			 (u_int) (ipp[5] & 0xf), (u_int) (ipp[5] >> 4),
			 (u_int) (ipp[4] & 0xf), (u_int) (ipp[4] >> 4),
			 (u_int) (ipp[3] & 0xf), (u_int) (ipp[3] >> 4),
			 (u_int) (ipp[2] & 0xf), (u_int) (ipp[2] >> 4),
			 (u_int) (ipp[1] & 0xf), (u_int) (ipp[1] >> 4),
			 (u_int) (ipp[0] & 0xf), (u_int) (ipp[0] >> 4));
	    }
#endif
	}
	else
	{
	    sendto_realops_lev(DEBUG_LEV,
			       "rptr->type is unknown type %d! "
			       "(rptr->name == %x)", 
			       rptr->type, rptr->name);
	    return -1;
	}    

	if(mycmp(tmphost, hostbuf) != 0)
	{
	    sendto_realops_lev(DEBUG_LEV, "Asked question for %s, but got "
			       "reply about question %s (!!!)",
			       tmphost, hostbuf);
	    strangeness++;
	}
	
	if(strangeness)
	    return PROCANSWER_STRANGE;
    }

    /* proccess each answer sent to us blech. */
    while (hptr->ancount-- > 0 && cp && cp < eob) 
    {
	n = dn_expand(buf, eob, cp, hostbuf, sizeof(hostbuf));
	hostbuf[RESHOSTLEN] = '\0';
	
	if (n <= 0)
	    break;
	cp += n;
	type = (int) _getshort(cp);
	cp += sizeof(short);
	
	class = (int) _getshort(cp);
	cp += sizeof(short);
	
	rptr->ttl = _getlong(cp);
	cp += sizeof(rptr->ttl);
	dlen = (int) _getshort(cp);
	cp += sizeof(short);
	
	/* Wait to set rptr->type until we verify this structure */

	len = strlen(hostbuf);
	/* name server never returns with trailing '.' */
	if (!strchr(hostbuf, '.') && (_res.options & RES_DEFNAMES))
	{
	    (void) strcat(hostbuf, ".");
	    len++;
	    if ((len + 2) < sizeof(hostbuf))
	    {
		strncpyzt(hostbuf, _res.defdname,
			sizeof(hostbuf) - 1 - len);
		hostbuf[RESHOSTLEN] = '\0';
		len = MIN(len + strlen(_res.defdname),
			  sizeof(hostbuf)) - 1;
	    }
	}
	
#ifdef DNS_ANS_DEBUG_MAX
	memset(dhostbuf, 0x0, RESHOSTLEN + 1);
	strncpy(dhostbuf, hostbuf, RESHOSTLEN + 1);
#endif
	
	switch (type)
	{
#ifdef INET6
	case T_AAAA:
#endif
	case T_A:
	    if(rptr->name == NULL)
	    {
		sendto_realops_lev(DEBUG_LEV,"Received DNS_A answer, but null "
				   "rptr->name!");
		return PROCANSWER_STRANGE;
	    }
	    if(mycmp(rptr->name, hostbuf) != 0)
	    {
		if(!num_acc_answers || !(acc = is_acceptable_answer(hostbuf)))
		{
#ifdef DNS_ANS_DEBUG
		    sendto_realops_lev(DEBUG_LEV,
				       "Received DNS_A answer for %s, but "
				       "asked question for %s", hostbuf,
				       rptr->name);
#endif
		    return PROCANSWER_STRANGE;
		}
#ifdef DNS_ANS_DEBUG
		sendto_realops_lev(DEBUG_LEV,
				   "DNS_A answer from an acceptable (%s)",
				   acc);
#endif
	    }
	    hp->h_length = dlen;
	    if (ans == 1)
		hp->h_addrtype = (class == C_IN) ? AFINET : AF_UNSPEC;
	    /* from Christophe Kalt <kalt@stealth.net> */
	    if (dlen != (type == T_AAAA ? sizeof(dr) : sizeof(struct in_addr)))
	    {
		sendto_realops("Bad IP length (%d) returned for %s",
			       dlen, hostbuf);
		Debug((DEBUG_DNS, "Bad IP length (%d) returned for %s",
		       dlen, hostbuf));
		return PROCANSWER_MALICIOUS;
	    }

	    if(adr < IRC_MAXADDRS)
	    {
		/* ensure we never go over the bounds of our adr array */
		memcpy((char *)&dr, cp, sizeof(dr));
#ifndef INET6
		hp->h_addr_list[adr].S_ADDR = dr.S_ADDR;
#else
		if (type == T_AAAA)
			memcpy(hp->h_addr_list[adr].S_ADDR, dr.S_ADDR, sizeof(struct IN_ADDR));
		else {
			memset((char*)hp->h_addr_list[adr].S_ADDR, 0x0, 10);
			hp->h_addr_list[adr].S_ADDR[10] = hp->h_addr_list[adr].S_ADDR[11] = 0xff;
			memcpy(((char*)hp->h_addr_list[adr].S_ADDR) + 12, dr.S_ADDR, 4);
		}
#endif
		Debug((DEBUG_INFO, "got ip # %s for %s", inet_ntop(AFINET,
				&hp->h_addr_list[adr], mydummy, sizeof(mydummy)),
				hostbuf));
		
#ifdef DNS_ANS_DEBUG_MAX
                sendto_realops_lev(DEBUG_LEV, "%s A %s", dhostbuf, inet_ntop(AFINET,
				&hp->h_addr_list[adr], mydummy, sizeof(mydummy)));
#endif
		adr++;
	    }
	    
	    if (!hp->h_name) 
	    {
		hp->h_name = (char *) MyMalloc(len + 1);
		strncpy(hp->h_name, hostbuf, len + 1);
	    }
	    ans++;
	    cp += dlen;
	    rptr->type = type;
	    break;
	    
	case T_PTR:
	    acc = NULL;
	    if(!num_acc_answers || !(acc = is_acceptable_answer(hostbuf)))
	    {
#ifndef INET6
		if(!(arpa_to_ip(hostbuf, &ptrrep.S_ADDR)))
#else
	        if(!(arpa_to_ip(hostbuf, ptrrep.S_ADDR, sizeof(ptrrep.S_ADDR))))
#endif
		
		{
#ifdef DNS_ANS_DEBUG
		    inet_ntop(AFINET, &ptrrep.S_ADDR, mydummy, sizeof(mydummy));
		    inet_ntop(AFINET, &rptr->addr, mydummy2, sizeof(mydummy2));
                    sendto_realops_lev(DEBUG_LEV,
				       "Received strangely formed PTR answer for %s (asked for %s) [hostbuf: %s] -- ignoring",
				       mydummy, mydummy2, hostbuf);
				       
#endif
		    return PROCANSWER_STRANGE;
		}
		
#ifndef INET6
		if(ptrrep.S_ADDR != rptr->addr.S_ADDR)
#else
		if(memcmp(ptrrep.S_ADDR, rptr->addr.S_ADDR, sizeof(struct IN_ADDR)))
#endif
		{
#ifdef DNS_ANS_DEBUG
		    inet_ntop(AFINET, (char *)&ptrrep.S_ADDR, mydummy, sizeof(mydummy));
		    inet_ntop(AFINET, (char *)&rptr->addr, mydummy2, sizeof(mydummy2));
		    sendto_realops_lev(DEBUG_LEV,
				       "Received DNS_PTR answer for %s, "
				       "but asked question for %s", 
				       mydummy, mydummy2);

#endif
		    return PROCANSWER_STRANGE;
		}
	    }
	    
#ifdef DNS_ANS_DEBUG
	    if(acc)
		sendto_realops_lev(DEBUG_LEV, 
				   "DNS_PTR from an acceptable (%s)", acc);
#endif
	    
	    if ((n = dn_expand(buf, eob, cp, hostbuf, HOSTLEN - 1)) < 0) 
	    {
		cp = NULL;
		break;
	    }
	    
	    /*
	     * This comment is based on analysis by Shadowfax,
	     * Jolo and johan, not me. (Dianora) I am only
	     * commenting it.
	     * 
	     * dn_expand is guaranteed to not return more than
	     * sizeof(hostbuf) but do all implementations of
	     * dn_expand also guarantee buffer is terminated with
	     * null byte? Lets not take chances. -Dianora
	     */
	    hostbuf[HOSTLEN] = '\0';
	    cp += n;
	    len = strlen(hostbuf);
	    
#ifdef DNS_ANS_DEBUG_MAX
	    sendto_realops_lev(DEBUG_LEV, "%s PTR %s", dhostbuf, hostbuf);
#endif
	    
	    Debug((DEBUG_INFO, "got host %s", hostbuf));
	    /*
	     * copy the returned hostname into the host name or
	     * alias field if there is a known hostname already.
	     */
	    if (hp->h_name) 
	    {
		/*
		 * This is really fishy. In fact, so fishy,
		 * that I say we just don't do this in this case.
		 *
		 * seems to happen with a whole host of .my addresses.
		 * interesting. - lucas
		 */
		
		if (alias >= &(hp->h_aliases[IRC_MAXALIASES - 1]))
		    break;
		*alias = (char *) MyMalloc(len + 1);
		strncpy(*alias++, hostbuf, len + 1);
		*alias = NULL;
	    }
	    else 
	    {
		hp->h_name = (char *) MyMalloc(len + 1);
		strncpy(hp->h_name, hostbuf, len + 1);
	    }
	    ans++;
	    rptr->type = type;
	    break;
	    
	case T_CNAME:
	    acc = NULL;
	    
	    if(origtype == T_PTR)
	    {
		if(!num_acc_answers || !(acc = is_acceptable_answer(hostbuf)))
		{
#ifndef INET6
                    if(!(arpa_to_ip(hostbuf, &ptrrep.S_ADDR)))
#else
		    if(!(arpa_to_ip(hostbuf, ptrrep.S_ADDR, sizeof(ptrrep.S_ADDR))))
#endif
		    {
#ifdef DNS_ANS_DEBUG
			
			sendto_realops_lev(DEBUG_LEV,
					   "Received strangely formed "
					   "CNAME(PTR) answer for %s (asked "
					   "for %s) -- ignoring", 
					   hostbuf, inet_ntop(AFINET, (char *)&rptr->addr,
					   mydummy, sizeof(mydummy)));
#endif
			return PROCANSWER_STRANGE;
		    }

#ifndef INET6
		    if(ptrrep.S_ADDR != rptr->addr.S_ADDR)
#else
		    if(memcmp(ptrrep.S_ADDR, rptr->addr.S_ADDR, sizeof(struct IN_ADDR)))
#endif
		    {
#ifdef DNS_ANS_DEBUG
			inet_ntop(AFINET, &ptrrep.S_ADDR, mydummy, sizeof(mydummy));
			inet_ntop(AFINET, (char*)&rptr->addr, mydummy2, sizeof(mydummy2));
			sendto_realops_lev(DEBUG_LEV, "Received "
					   "DNS_CNAME(PTR) answer for %s, "
					   "but asked question for %s", 
					   mydummy, mydummy2);
#endif
			return PROCANSWER_STRANGE;
		    }
		}
#ifdef DNS_ANS_DEBUG
		if(acc)
		    sendto_realops_lev(DEBUG_LEV, "DNS_CNAME (PTR) answer "
				       "from an acceptable (%s)", acc);
#endif
	    }
#ifndef INET6
	    else if(origtype == T_A)
#else
	    else if(origtype == T_AAAA || origtype == T_A)
#endif
	    {
		if(mycmp(rptr->name, hostbuf) != 0)
		{
		    if(!num_acc_answers || !(acc = is_acceptable_answer(hostbuf)))
		    {
#ifdef DNS_ANS_DEBUG
			sendto_realops_lev(DEBUG_LEV, "Received DNS_CNAME(A) "
					   "answer for %s, but asked "
					   "question for %s", 
					   hostbuf, rptr->name);
#endif
			return PROCANSWER_STRANGE;
		    }
#ifdef DNS_ANS_DEBUG
		    sendto_realops_lev(DEBUG_LEV, "DNS_CNAME (A) answer from "
				       "an acceptable (%s)", acc);
#endif
		}
	    }
	    
	    Debug((DEBUG_INFO, "got cname %s", hostbuf));
	    
	    if (alias >= &(hp->h_aliases[IRC_MAXALIASES - 1]))
		break;
	    *alias = (char *) MyMalloc(len + 1);
	    strncpy(*alias++, hostbuf, len + 1);
	    *alias = NULL;
	    ans++;
	    rptr->type = type;
	    
	    if ((n = dn_expand(buf, eob, cp, hostbuf, HOSTLEN - 1)) < 0)
	    {
		cp = NULL;
		break;
	    }
	    
	    hostbuf[HOSTLEN] = '\0';
	    cp += n;
	    
	    add_acceptable_answer(hostbuf);
	    
#ifdef DNS_ANS_DEBUG_MAX
	    sendto_realops_lev(DEBUG_LEV, "%s CNAME %s", dhostbuf, hostbuf);
#endif
	    
	    break;
	    
	default:
#ifdef DEBUG
	    Debug((DEBUG_INFO, "proc_answer: type:%d for:%s",
		   type, hostbuf));
#endif
	    break;
	}
    }
    return ans;
}

/*
 * read a dns reply from the nameserver and process it.
 */
struct hostent *get_res(char *lp)
{
    static char buf[sizeof(HEADER) + MAXPACKET];
    HEADER *hptr;
    ResRQ  *rptr = NULL;
    aCache     *cp = (aCache *) NULL;
    struct sockaddr_in sin;
    int         rc, a, max;
    socklen_t len = sizeof(sin);
    
    rc = recvfrom(resfd, buf, sizeof(buf), 0, (struct sockaddr *) &sin, &len);
    if (rc <= sizeof(HEADER))
	return getres_err(rptr, lp);
    
    /*
     * convert DNS reply reader from Network byte order to CPU byte
     * order.
     */
    hptr = (HEADER *) buf;
    hptr->id = ntohs(hptr->id);
    hptr->ancount = ntohs(hptr->ancount);
    hptr->qdcount = ntohs(hptr->qdcount);
    hptr->nscount = ntohs(hptr->nscount);
    hptr->arcount = ntohs(hptr->arcount);
#ifdef	DEBUG
    Debug((DEBUG_NOTICE, "get_res:id = %d rcode = %d ancount = %d",
	   hptr->id, hptr->rcode, hptr->ancount));
#endif
    reinfo.re_replies++;
    /*
     * response for an id which we have already received an answer for
     * just ignore this response.
     */
    rptr = find_id(hptr->id);
    if (!rptr)
	return getres_err(rptr, lp);
    /*
     * check against possibly fake replies
     */
    max = MIN(_res.nscount, rptr->sends);
    if (!max)
	max = 1;

    for (a = 0; a < max; a++)
	if (!_res.nsaddr_list[a].sin_addr.s_addr ||
	    !memcmp((char *) &sin.sin_addr,
		    (char *) &_res.nsaddr_list[a].sin_addr,
		    sizeof(struct in_addr)))
	    break;

    if (a == max) 
    {
	reinfo.re_unkrep++;
	return getres_err(rptr, lp);
    }

    if ((hptr->rcode != NOERROR) || (hptr->ancount == 0))
    {
	switch (hptr->rcode)
	{
	case NXDOMAIN:
	    h_errno = TRY_AGAIN;
	    break;
	case SERVFAIL:
	    h_errno = TRY_AGAIN;
	    break;
	case NOERROR:
	    h_errno = NO_DATA;
	    break;
	case FORMERR:
	case NOTIMP:
	case REFUSED:
	default:
	    h_errno = NO_RECOVERY;
	    break;
	}
	reinfo.re_errors++;
	/*
	 * If a bad error was returned, we stop here and dont send
	 * send any more (no retries granted).
	 */
	if (h_errno != TRY_AGAIN)
	{
	    Debug((DEBUG_DNS, "Fatal DNS error %d for %d",
		   h_errno, hptr->rcode));
	    rptr->resend = 0;
	    rptr->retries = 0;
	}
	return getres_err(rptr, lp);
    }
    a = proc_answer(rptr, hptr, buf, buf + rc);
    
#ifdef DEBUG
    Debug((DEBUG_INFO, "get_res:Proc answer = %d", a));
#endif

    switch(a)
    {
    case PROCANSWER_STRANGE:
	rptr->resend = 1;
	rptr->retries--;
	if(rptr->retries <= 0)
	{
	    h_errno = TRY_AGAIN; /* fail this lookup.. */
	    return getres_err(rptr, lp);
	}
	else 
	    resend_query(rptr);
	return NULL;
	
    case PROCANSWER_MALICIOUS:
	if (lp)
	    memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));
	rem_request(rptr);
	return NULL;
	
    default:
	break;
    }
    
    if (a > 0 && rptr->type == T_PTR) 
    {
	int type;
	struct hostent *hp2 = NULL;

        Debug((DEBUG_DNS, "relookup %s <-> %s",
	     rptr->he.h_name, inet_ntop(AFINET, &rptr->he.h_addr, mydummy, sizeof(mydummy))));
	/*
	 * Lookup the 'authoritative' name that we were given for the ip#.
	 * By using this call rather than regenerating the type we
	 * automatically gain the use of the cache with no extra kludges.
	 */
#ifndef INET6
	type = T_A;
#else
	if(IN6_IS_ADDR_V4MAPPED(&rptr->he.h_addr))
		type = T_A;
	else
		type = T_AAAA;
#endif
	if ((hp2 = gethost_byname_type(rptr->he.h_name, &rptr->cinfo, type)))
	    if (lp)
		memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));
	
	if(!hp2)
	{
	    memcpy(&last->he_rev, &rptr->he, sizeof(struct hent));
	    memset(&rptr->he, 0, sizeof(struct hent));
	    last->has_rev = 1;
	}

	rem_request(rptr);
	return hp2;
    }

#ifndef INET6
    if(a > 0 && rptr->type == T_A)
#else
    if(a > 0 && (rptr->type == T_AAAA || rptr->type == T_A))
#endif
    {
	if(rptr->has_rev == 0)
	{ 
	    sendto_ops_lev(DEBUG_LEV, "Blindly accepting dns result for %s", 
			   rptr->he.h_name ? rptr->he.h_name : inet_ntop(AFINET,
			   (char *)&rptr->addr, mydummy, sizeof(mydummy)));
	}
	else
	{
	    int invalid_parms_name = 0;
	    int invalid_parms_ip = 0;
	    int found_match_ip = 0;
	    int nidx, tidx;
	    int numaddr, numnewaddr;
	    struct IN_ADDR new_addr_list[IRC_MAXADDRS];

	    if(!(rptr->he.h_name && rptr->he_rev.h_name))
		invalid_parms_name++;
	    
	    if(!(WHOSTENTP(rptr->he.h_addr_list[0].S_ADDR) && 
		 WHOSTENTP(rptr->he_rev.h_addr_list[0].S_ADDR)))
		invalid_parms_ip++;

	    if(invalid_parms_name || invalid_parms_ip)
	    {	
		sendto_ops_lev(DEBUG_LEV, 
			       "DNS query missing things! name: %s ip: %s",
			       invalid_parms_name ? "MISSING" :
			       rptr->he.h_name,
			       invalid_parms_ip ? "MISSING" : inet_ntop(AFINET,
			       (char *)&rptr->he.h_addr_list[0], mydummy,
			       sizeof(mydummy)));
		if (lp)
		    memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));
		rem_request(rptr);
		return NULL;
	    }

	    /* 
	     * This must ensure that all IPs in the forward query (he)
	     * are also in the reverse query (he_rev).
	     * Those not in the reverse query must be zeroed out!
	     */
	    
	    for(numaddr = numnewaddr = nidx = 0; nidx < IRC_MAXADDRS; nidx++)
	    {
		int does_match;
		
		if(!WHOSTENTP(rptr->he.h_addr_list[nidx].S_ADDR))
		    break;
		
		numaddr++;
		
		for(tidx = does_match = 0; tidx < IRC_MAXADDRS; tidx++)
		{
		    if(!WHOSTENTP(rptr->he_rev.h_addr_list[tidx].S_ADDR))
			break;
		    
#ifndef INET6
		    if(rptr->he_rev.h_addr_list[tidx].S_ADDR == 
				    rptr->he.h_addr_list[nidx].S_ADDR) /* MATCH */
#else
		    if(!memcmp(rptr->he_rev.h_addr_list[tidx].S_ADDR,
		       rptr->he.h_addr_list[nidx].S_ADDR, sizeof(struct IN_ADDR))) /* MATCH */
#endif
		    {
			found_match_ip++;
			does_match = 1;
			break;
		    }
		}
            
		if(does_match)
		{
#ifndef INET6
		    new_addr_list[numnewaddr++].S_ADDR = rptr->he.h_addr_list[nidx].S_ADDR;
		    new_addr_list[numnewaddr].S_ADDR = 0;
#else
		    memcpy(new_addr_list[numnewaddr++].S_ADDR,
			rptr->he.h_addr_list[nidx].S_ADDR, sizeof(struct IN_ADDR));
		    memset(new_addr_list[numnewaddr].S_ADDR, 0x0, sizeof(struct IN_ADDR));
#endif
		}
	    }
         
	    if(!found_match_ip)
	    {
		char ntoatmp_r[64];
		char ntoatmp_f[64];

		inet_ntop(AFINET, &rptr->he.h_addr_list[0], ntoatmp_f, sizeof(ntoatmp_f));
		inet_ntop(AFINET, &rptr->he_rev.h_addr_list[0], ntoatmp_r, sizeof(ntoatmp_r));
#ifdef DNS_ANS_DEBUG
		sendto_ops_lev(DEBUG_LEV, "Forward and Reverse queries do "
			       "not have matching IP! %s<>%s %s<>%s",
			       rptr->he.h_name, rptr->he_rev.h_name,
			       ntoatmp_f, ntoatmp_r);
#endif
		
		if (lp)
		    memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));
		
		rem_request(rptr);
		return NULL;
	    }
	    
	    if(numnewaddr != numaddr)
	    {
		memcpy(rptr->he.h_addr_list, new_addr_list,
		       sizeof(struct IN_ADDR) * IRC_MAXADDRS);
#ifdef DNS_ANS_DEBUG
		sendto_ops_lev(DEBUG_LEV, "numaddr = %d, numnewaddr = %d",
			       numaddr, numnewaddr);
#endif
	    }
	    
	    /*
	     * Our DNS query was made based on the hostname, so the hostname
	     * part should be fine.
	     */
	}
    }
    
    if (a > 0)
    {
	if (lp)
	    memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));

	cp = make_cache(rptr);
#ifdef	DEBUG
	Debug((DEBUG_INFO, "get_res:cp=%#x rptr=%#x (made)", cp, rptr));
#endif
	
	rem_request(rptr);
    }
    else if (!rptr->sent)
	rem_request(rptr);
    return cp ? (struct hostent *) &cp->he : NULL;
}

static struct hostent *getres_err(ResRQ * rptr, char *lp)
{
    /*
     * Reprocess an error if the nameserver didnt tell us to
     * "TRY_AGAIN".
     */
    if (rptr)
    {
	if (h_errno != TRY_AGAIN)
	{
	    /*
	     * If we havent tried with the default domain and its set,
	     * then give it a try next.
	     */
	    if (_res.options & RES_DEFNAMES && ++rptr->srch == 0)
	    {
		rptr->retries = _res.retry;
		rptr->sends = 0;
		rptr->resend = 1;
		resend_query(rptr);
	    }
	    else
		resend_query(rptr);
	}
	else if (lp)
	    memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));
    }
    return (struct hostent *) NULL;
}

static int hash_number(unsigned char *ip)
{
    u_int   hashv = 0;

    hashv += (int) *ip++;
    /* could use loop but slower */
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
#ifdef INET6
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
    hashv += hashv + (int) *ip++;
#endif
    hashv %= ARES_CACSIZE;
    return (hashv);
}

#if defined(ALLOW_CACHE_NAMES) || defined(DEBUG)
static int hash_name(char *name)
{
    u_int   hashv = 0;
    
    for (; *name && *name != '.'; name++)
	hashv += *name;
    hashv %= ARES_CACSIZE;
    return (hashv);
}
#endif

/* Add a new cache item to the queue and hash table. */
static aCache *add_to_cache(aCache * ocp)
{
    aCache *cp = NULL;
    int     hashv;
    
#ifdef DEBUG
    Debug((DEBUG_INFO,
	   "add_to_cache:ocp %#x he %#x name %#x addrl %#x 0 %#x",
	   ocp, &ocp->he, ocp->he.h_name, ocp->he.h_addr_list,
	   ocp->he.h_addr_list[0]));
#endif
    ocp->list_next = cachetop;
    cachetop = ocp;
    /* Make sure non-bind resolvers don't blow up (Thanks to Yves) */
    if (!ocp)
	return NULL;
    if (!(ocp->he.h_name))
	return NULL;
    if (!(ocp->he.h_addr))
	return NULL;
    
#ifdef ALLOW_CACHE_NAMES
    hashv = hash_name(ocp->he.h_name);
    
    ocp->hname_next = hashtable[hashv].name_list;
    hashtable[hashv].name_list = ocp;
#endif
    
    hashv = hash_number((u_char *) ocp->he.h_addr);
    
    ocp->hnum_next = hashtable[hashv].num_list;
    hashtable[hashv].num_list = ocp;
    
#ifdef	DEBUG
    Debug((DEBUG_INFO, "add_to_cache:added %s[%08x] cache %#x.",
	   ocp->he.h_name, ocp->he.h_addr_list[0], ocp));
    Debug((DEBUG_INFO,
	   "add_to_cache:h1 %d h2 %x lnext %#x namnext %#x numnext %#x",
	   hash_name(ocp->he.h_name), hashv, ocp->list_next,
	   ocp->hname_next, ocp->hnum_next));
#endif
    /* LRU deletion of excessive cache entries. */
    if (++incache > IRC_MAXCACHED)
    {
	for (cp = cachetop; cp->list_next; cp = cp->list_next);
	rem_cache(cp);
    }
    cainfo.ca_adds++;

    return ocp;
}

/*
 * update_list does not alter the cache structure passed. It is
 * assumed that * it already contains the correct expire time, if it is
 * a new entry. Old * entries have the expirey time updated.
 */
static void update_list(ResRQ * rptr, aCache * cachep)
{
    aCache **cpp, *cp = cachep;
    char   *s, *t, **base;
    int     i, j;
    int     addrcount;

    /*
     * search for the new cache item in the cache list by hostname. *
     * If found, move the entry to the top of the list and return.
     */
    cainfo.ca_updates++;

    for (cpp = &cachetop; *cpp; cpp = &((*cpp)->list_next))
	if (cp == *cpp)
	    break;
    if (!*cpp)
	return;
    *cpp = cp->list_next;
    cp->list_next = cachetop;
    cachetop = cp;
    if (!rptr)
	return;
    
#ifdef	DEBUG
    Debug((DEBUG_DEBUG, "u_l:cp %#x na %#x al %#x ad %#x",
	   cp, cp->he.h_name, cp->he.h_aliases, cp->he.h_addr));
    Debug((DEBUG_DEBUG, "u_l:rptr %#x h_n %#x", rptr, rptr->he.h_name));
#endif
    /*
     * Compare the cache entry against the new record.  Add any
     * previously missing names for this entry.
     */
    for (i = 0; cp->he.h_aliases[i]; i++);
    addrcount = i;
    for (i = 0, s = rptr->he.h_name; s && i < IRC_MAXALIASES;
	 s = rptr->he.h_aliases[i++])
    {
	for (j = 0, t = cp->he.h_name; t && j < IRC_MAXALIASES;
	     t = cp->he.h_aliases[j++])
	    if (!mycmp(t, s))
		break;
	if (!t && j < IRC_MAXALIASES - 1)
	{
	    base = cp->he.h_aliases;
	    
	    addrcount++;
	    base = (char **) MyRealloc((char *) base,
				       sizeof(char *) * (addrcount + 1));
	    
	    cp->he.h_aliases = base;
#ifdef	DEBUG
	    Debug((DEBUG_DNS, "u_l:add name %s hal %x ac %d",
		   s, cp->he.h_aliases, addrcount));
#endif
	    base[addrcount - 1] = s;
	    base[addrcount] = NULL;
	    if (i)
		rptr->he.h_aliases[i - 1] = NULL;
	    else
		rptr->he.h_name = NULL;
	}
    }
    for (i = 0; cp->he.h_addr_list[i]; i++);
    addrcount = i;
    /* Do the same again for IP#'s. */
    for (s = (char *) &rptr->he.h_addr.S_ADDR;
	 WHOSTENTP(((struct IN_ADDR *) s)->S_ADDR); s += sizeof(struct IN_ADDR)) {
	for (i = 0; (t = cp->he.h_addr_list[i]); i++)
	    if (!memcmp(s, t, sizeof(struct IN_ADDR)))
		break;

	if (i >= IRC_MAXADDRS || addrcount >= IRC_MAXADDRS)
	    break;
	/*
	 * Oh man this is bad...I *HATE* it. -avalon
	 * 
	 * Whats it do ?  Reallocate two arrays, one of pointers to "char *"
	 * and the other of IP addresses.  Contents of the IP array *MUST*
	 * be preserved and the pointers into it recalculated.
	 */
	if (!t)
	{
	    base = cp->he.h_addr_list;
	    addrcount++;
	    t = (char *) MyRealloc(*base,
				   addrcount * sizeof(struct IN_ADDR));
	    
	    base = (char **) MyRealloc((char *) base,
				       (addrcount + 1) * sizeof(char *));
	    
	    cp->he.h_addr_list = base;
#ifdef	DEBUG
#ifndef INET6
	 Debug((DEBUG_DNS, "u_l:add IP %x hal %x ac %d",
		ntohl(((struct IN_ADDR *) s)->S_ADDR),
		cp->he.h_addr_list,
		addrcount));
#else
	 
	 Debug((DEBUG_DNS, "u_l:add IP %x hal %x ac %d",
		inet_ntop(AFINET, (((struct IN_ADDR *) s)->S_ADDR),
		mydummy, sizeof(mydummy)), cp->he.h_addr_list, 
		addrcount));
#endif
#endif
	    for (; addrcount; addrcount--)
	    {
		*base++ = t;
		t += sizeof(struct IN_ADDR);
	    }
	    *base = NULL;
	    memcpy(*--base, s, sizeof(struct IN_ADDR));
	}
    }
    return;
}

static aCache *find_cache_name(char *name)
{
#ifdef ALLOW_CACHE_NAMES
    aCache *cp;
    char   *s;
    int     hashv, i;
    
    if (name == (char *) NULL)
	return (aCache *) NULL;
    hashv = hash_name(name);
    
    cp = hashtable[hashv].name_list;
#ifdef	DEBUG
    Debug((DEBUG_DNS, "find_cache_name:find %s : hashv = %d", name, hashv));
#endif
    
    for (; cp; cp = cp->hname_next)
	for (i = 0, s = cp->he.h_name; s; s = cp->he.h_aliases[i++])
	    if (mycmp(s, name) == 0)
	    {
		cainfo.ca_na_hits++;
		update_list(NULL, cp);
		return cp;
	    }
    
    for (cp = cachetop; cp; cp = cp->list_next)
    {
	/*
	 * if no aliases or the hash value matches, we've already done
	 * this entry and all possiblilities concerning it.
	 */
	if (!*cp->he.h_aliases)
	    continue;
	if (cp->he.h_name == (char *) NULL)	/*
						 * don't trust anything
						 * -Dianora 
						 */
	    continue;
	if (hashv == hash_name(cp->he.h_name))
	    continue;
	for (i = 0, s = cp->he.h_aliases[i]; s && i < IRC_MAXALIASES; i++)
	    if (!mycmp(name, s))
	    {
		cainfo.ca_na_hits++;
		update_list(NULL, cp);
		return cp;
	    }
    }
#endif
    return NULL;
}

/* find a cache entry by ip# and update its expire time */
static aCache *
find_cache_number(ResRQ * rptr, char *numb)
{
    aCache *cp;
    int     hashv, i;
    struct IN_ADDR *ip = (struct IN_ADDR *) numb;

    if ((u_char *) numb == (u_char *) NULL)
	return ((aCache *) NULL);
    hashv = hash_number((u_char *) numb);
    cp = hashtable[hashv].num_list;
    
#ifndef INET6
    Debug((DEBUG_DNS, "find_cache_number:find %s[%08x]: hashv = %d",
	   inet_ntop(AFINET, numb, mydummy, sizeof(mydummy)),
	   ntohl(ip->S_ADDR), hashv));
#else
    Debug((DEBUG_DNS, "find_cache_number:find %s: hashv = %d",
	   inet_ntop(AFINET, numb, mydummy, sizeof(mydummy)), hashv));
#endif

    for (; cp; cp = cp->hnum_next)
    {
	for (i = 0; cp->he.h_addr_list[i]; i++)
	{
	    /* 
	     * A 32 bit integer compare should be faster than this...
	     *  if (!memcmp(cp->he.h_addr_list[i], numb,
	     *	   sizeof(struct in_addr))) 
	     */
#ifndef INET6
	    if(((struct IN_ADDR *)cp->he.h_addr_list[i])->S_ADDR ==
			    ((struct IN_ADDR *)ip)->S_ADDR)
#else
	    if(!memcmp(((struct IN_ADDR *)cp->he.h_addr_list[i])->S_ADDR,
				    ((struct IN_ADDR *)ip)->S_ADDR,
				    sizeof(struct IN_ADDR)));
#endif
	    {
		cainfo.ca_nu_hits++;
		update_list(NULL, cp);
		return cp;
	    }
	}
    }
    
#ifdef SEARCH_CACHE_ADDRESSES
    for (cp = cachetop; cp; cp = cp->list_next)
    {
	/*
	 * single address entry...would have been done by hashed search 
	 * above...
	 */
	if (!cp->he.h_addr_list[1])
	    continue;
	/*
	 * if the first IP# has the same hashnumber as the IP# we are
	 * looking for, its been done already.
	 */
	if (hashv == hash_number((u_char *) cp->he.h_addr_list[0]))
	    continue;
	for (i = 1; cp->he.h_addr_list[i]; i++)
	    if (!memcmp(cp->he.h_addr_list[i], numb,
			sizeof(struct IN_ADDR)))
	    {
		cainfo.ca_nu_hits++;
		update_list(NULL, cp);
		return cp;
	    }
    }
#endif
    return NULL;
}

static aCache *make_cache(ResRQ * rptr)
{
    aCache *cp;
    int     i, n;
    struct hostent *hp;
    char   *s, **t;

    /* shouldn't happen but it just might... */
    if (!rptr->he.h_name || !WHOSTENTP(rptr->he.h_addr.S_ADDR))
	return NULL;
    /*
     * Make cache entry.  First check to see if the cache already
     * exists and if so, return a pointer to it.
     */
    if ((cp = find_cache_number(rptr, (char *) &rptr->he.h_addr.S_ADDR)))
	return cp;
    for (i = 1; WHOSTENTP(rptr->he.h_addr_list[i].S_ADDR) && i < IRC_MAXADDRS; i++)
	if ((cp = 
	     find_cache_number(rptr,
			       (char *) &(rptr->he.h_addr_list[i].S_ADDR))))
	    return cp;
    /* a matching entry wasnt found in the cache so go and make one up. */
    cp = (aCache *) MyMalloc(sizeof(aCache));
    memset((char *) cp, '\0', sizeof(aCache));
    hp = &cp->he;
    for (i = 0; i < IRC_MAXADDRS; i++)
	if (!WHOSTENTP(rptr->he.h_addr_list[i].S_ADDR))
	    break;
    /* build two arrays, one for IP#'s, another of pointers to them. */
    t = hp->h_addr_list = (char **) MyMalloc(sizeof(char *) * (i + 1));
    memset((char *) t, '\0', sizeof(char *) * (i + 1));
    
    s = (char *) MyMalloc(sizeof(struct IN_ADDR) * i);
    memset(s, '\0', sizeof(struct IN_ADDR) * i);
    
    for (n = 0; n < i; n++, s += sizeof(struct IN_ADDR))
    {
	*t++ = s;
	memcpy(s, (char *) &(rptr->he.h_addr_list[n].S_ADDR),
	       sizeof(struct IN_ADDR));
    }
    *t = (char *) NULL;
    /* an array of pointers to CNAMEs. */
    for (i = 0; i < IRC_MAXALIASES; i++)
	if (!rptr->he.h_aliases[i])
	    break;
    i++;
    t = hp->h_aliases = (char **) MyMalloc(sizeof(char *) * i);
    
    for (n = 0; n < i; n++, t++)
    {
	*t = rptr->he.h_aliases[n];
	rptr->he.h_aliases[n] = NULL;
    }
    
    hp->h_addrtype = rptr->he.h_addrtype;
    hp->h_length = rptr->he.h_length;
    hp->h_name = rptr->he.h_name;
    if (rptr->ttl < 600)
    {
	reinfo.re_shortttl++;
	cp->ttl = 600;
    }
    else
	cp->ttl = rptr->ttl;
    cp->expireat = timeofday + cp->ttl;
    rptr->he.h_name = NULL;
#ifdef DEBUG
    Debug((DEBUG_INFO, "make_cache:made cache %#x", cp));
#endif
    return add_to_cache(cp);
}

/*
 * rem_cache delete a cache entry from the cache structures and lists
 * and return all memory used for the cache back to the memory pool.
 */
static void rem_cache(aCache * ocp)
{
    aCache **cp;
    struct hostent *hp = &ocp->he;
    int     hashv;
    aClient *cptr;
    
#ifdef	DEBUG
    Debug((DEBUG_DNS, "rem_cache: ocp %#x hp %#x l_n %#x aliases %#x",
	   ocp, hp, ocp->list_next, hp->h_aliases));
#endif
    /*
     * * Cleanup any references to this structure by destroying the *
     * pointer.
     */
    for (hashv = highest_fd; hashv >= 0; hashv--)
	if ((cptr = local[hashv]) && (cptr->hostp == hp))
	    cptr->hostp = NULL;
    /*
     * remove cache entry from linked list
     */
    for (cp = &cachetop; *cp; cp = &((*cp)->list_next))
	if (*cp == ocp)
	{
	    *cp = ocp->list_next;
	    break;
	}
    /* remove cache entry from hashed name lists */
    if (hp->h_name == (char *) NULL)
	return;
#ifdef ALLOW_CACHE_NAMES
    hashv = hash_name(hp->h_name);
    
# ifdef	DEBUG
    Debug((DEBUG_DEBUG, "rem_cache: h_name %s hashv %d next %#x first %#x",
	   hp->h_name, hashv, ocp->hname_next,
	   hashtable[hashv].name_list));
# endif
    for (cp = &hashtable[hashv].name_list; *cp; cp = &((*cp)->hname_next))
	if (*cp == ocp)
	{
	    *cp = ocp->hname_next;
	    break;
	}
#endif
    /* remove cache entry from hashed number list */
    hashv = hash_number((u_char *) hp->h_addr);
    if (hashv < 0)
	return;
#ifdef	DEBUG 
    Debug((DEBUG_DEBUG, "rem_cache: h_addr %s hashv %d next %#x first %#x",
	   inet_ntop(AFINET, hp->h_addr, mydummy, sizeof(mydummy)), hashv,
	   ocp->hnum_next, hashtable[hashv].num_list));
#endif
    for (cp = &hashtable[hashv].num_list; *cp; cp = &((*cp)->hnum_next))
	if (*cp == ocp)
	{
	    *cp = ocp->hnum_next;
	    break;
	}
    /*
     * free memory used to hold the various host names and the array of
     * alias pointers.
     */
    if (hp->h_name)
	MyFree(hp->h_name);
    if (hp->h_aliases)
    {
	for (hashv = 0; hp->h_aliases[hashv]; hashv++)
	    MyFree(hp->h_aliases[hashv]);
	MyFree((char *) hp->h_aliases);
    }
    /* free memory used to hold ip numbers and the array of them. */
    if (hp->h_addr_list)
    {
	if (*hp->h_addr_list)
	    MyFree((char *) *hp->h_addr_list);
	MyFree((char *) hp->h_addr_list);
    }
    
    MyFree((char *) ocp);
    
    incache--;
    cainfo.ca_dels++;
    
    return;
}

/*
 * removes entries from the cache which are older than their expirey
 * times. returns the time at which the server should next poll the
 * cache.
 */
time_t expire_cache(time_t now)
{
    aCache *cp, *cp2;
    time_t  next = 0;
    time_t  mmax = now + AR_TTL;

    for (cp = cachetop; cp; cp = cp2)
    {
	cp2 = cp->list_next;
	
	if (now >= cp->expireat)
	{
	    cainfo.ca_expires++;
	    rem_cache(cp);
	}
	else if (!next || next > cp->expireat)
	    next = cp->expireat;
    }
    /*
     * don't let one DNS record that happens to be first
     * stop others from expiring.
     */
    return (next > now) ? (next < mmax ? next : mmax) : mmax;
}

/* remove all dns cache entries. */
void flush_cache()
{
    aCache *cp;
    
    while ((cp = cachetop))
	rem_cache(cp);
}

int m_dns(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aCache *cp;
    int     i;

    if(!IsAnOper(cptr))
    {
	sendto_one(cptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
	return 0;
    }

    if (parv[1] && *parv[1] == 'l')
    {
        if (!MyClient(sptr) || !IsAdmin(sptr))
        {
          sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
          return 0;
        }
	for (cp = cachetop; cp; cp = cp->list_next)
	{ 
	    sendto_one(sptr, "NOTICE %s :Ex %d ttl %d host %s(%s)",
		       parv[0], cp->expireat - timeofday, cp->ttl,
		       cp->he.h_name, inet_ntop(AFINET, cp->he.h_addr,
		       mydummy, sizeof(mydummy)));
	    for (i = 0; cp->he.h_aliases[i]; i++)
		sendto_one(sptr, "NOTICE %s : %s = %s (CN)",
			parv[0], cp->he.h_name,
			cp->he.h_aliases[i]);
	    for (i = 1; cp->he.h_addr_list[i]; i++)	
		sendto_one(sptr, "NOTICE %s : %s = %s (IP)",
			parv[0], cp->he.h_name, inet_ntop(AFINET,
			cp->he.h_addr_list[i], mydummy, sizeof(mydummy)));
	}
	return 0;
    }
    sendto_one(sptr, "NOTICE %s :Ca %d Cd %d Ce %d Cl %d Ch %d:%d Cu %d",
	       sptr->name,
	       cainfo.ca_adds, cainfo.ca_dels, cainfo.ca_expires,
	       cainfo.ca_lookups,
	       cainfo.ca_na_hits, cainfo.ca_nu_hits, cainfo.ca_updates);
    
    sendto_one(sptr, "NOTICE %s :Re %d Rl %d/%d Rp %d Rq %d",
	       sptr->name, reinfo.re_errors, reinfo.re_nu_look,
	       reinfo.re_na_look, reinfo.re_replies, reinfo.re_requests);
    sendto_one(sptr, "NOTICE %s :Ru %d Rsh %d Rs %d(%d) Rt %d", sptr->name,
	       reinfo.re_unkrep, reinfo.re_shortttl, reinfo.re_sent,
	       reinfo.re_resends, reinfo.re_timeouts);
    return 0;
}

u_long cres_mem(aClient *sptr)
{
    aCache *c = cachetop;
    struct hostent *h;
    int i;
    u_long      nm = 0, im = 0, sm = 0, ts = 0;

    for (; c; c = c->list_next)
    {
	sm += sizeof(*c);
	h = &c->he;
	for (i = 0; h->h_addr_list[i]; i++)
	{
	    im += sizeof(char *);
	    im += sizeof(struct IN_ADDR);
	}
	im += sizeof(char *);
	
	for (i = 0; h->h_aliases[i]; i++)
	{
	    nm += sizeof(char *);
	    
	    nm += strlen(h->h_aliases[i]);
	}
	nm += i - 1;
	nm += sizeof(char *);
	
	if (h->h_name)
	    nm += strlen(h->h_name);
    }
    ts = ARES_CACSIZE * sizeof(CacheTable);
    sendto_one(sptr, ":%s %d %s :RES table sz %d",
	       me.name, RPL_STATSDEBUG, sptr->name, ts);
    sendto_one(sptr, ":%s %d %s :RES Structs sz %d IP storage sz %d "
	       "Name storage sz %d", me.name, RPL_STATSDEBUG, sptr->name, sm,
	       im, nm);
    return ts + sm + im + nm;
}
