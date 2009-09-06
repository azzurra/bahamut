/************************************************************************
 *   IRC - Internet Relay Chat, src/s_user.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
 *
 *   This program is free softwmare; you can redistribute it and/or modify
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
#include "channel.h"
#include "throttle.h"
#include "inet.h"
#include <sys/stat.h>
#include <utmp.h>
#include <fcntl.h>
#include <sys/socket.h>
#include "h.h"
#ifdef FLUD
#include "blalloc.h"
#endif /* FLUD */
#include "inet.h" /*AZZURRA*/

#if defined( HAVE_STRING_H)
#include <string.h>
#else
#include <strings.h>
#endif

int         do_user(char *, aClient *, aClient *, char *, char *, char *,
		    unsigned long, char *, char *);

extern char motd_last_changed_date[];
extern int  send_motd(aClient *, aClient *, int, char **);
extern void send_topic_burst(aClient *);
int check_oper_can_mask(aClient *, char *, char *, char **, int *);
extern void outofmemory(void);	/*
				 * defined in list.c 
				 */
				 
#ifdef USE_ACTIVITY_LOG
extern void activity_log(char *, ...);
#endif 

#ifdef AZZURRA
int check_helper_can_mask(aClient *, char *, char *, char **);
__inline__ int check_for_spam(aClient *, char *, char *, char *);
#endif

#ifdef MAXBUFFERS
extern void reset_sock_opts();
extern int send_lusers(aClient *,aClient *,int, char **);
#endif

extern int  lifesux;

#ifdef WINGATE_NOTICE
extern char ProxyMonURL[TOPICLEN + 1];
extern char ProxyMonHost[HOSTLEN + 1];
#endif

#ifdef INET6
extern void ip6_expand(char *, size_t);
#endif

#ifdef RESTRICT_USERS
extern int restriction_enabled;
#endif

static char buf[BUFSIZE], buf2[BUFSIZE];
int  user_modes[] =
{
    UMODE_o, 'o',
    UMODE_O, 'O',
    UMODE_i, 'i',
    UMODE_w, 'w',
    UMODE_s, 's',
    UMODE_c, 'c',
    UMODE_r, 'r',
    UMODE_R, 'R',
    UMODE_k, 'k',
    UMODE_y, 'y',
    UMODE_d, 'd',
    UMODE_e, 'e',
    UMODE_g, 'g',
    UMODE_b, 'b',
    UMODE_a, 'a',
    UMODE_A, 'A',
    UMODE_f, 'f',
    UMODE_n, 'n',
    UMODE_m, 'm',
    UMODE_h, 'h',
    UMODE_S, 'S',
#ifdef NO_OPER_FLOOD
    UMODE_F, 'F',
#endif
    UMODE_K, 'K',
#ifdef AZZURRA
    UMODE_x, 'x',
    UMODE_z, 'z',
    UMODE_I, 'I',
#endif
    0, 0
};

#ifdef AZZURRA
extern Spam *spam_list;
extern int CONF_SERVER_LANGUAGE;	/* In s_serv.c */
#endif

/* internally defined functions */
unsigned long my_rand(void);	/* provided by orabidoo */
int add_dccallow(aClient *sptr, aClient *optr);
/* externally defined functions */
extern int  find_fline(aClient *);	/* defined in s_conf.c */
extern Link *find_channel_link(Link *, aChannel *);	/* defined in list.c */
#ifdef FLUD
int         flud_num = FLUD_NUM;
int         flud_time = FLUD_TIME;
int         flud_block = FLUD_BLOCK;
extern BlockHeap *free_fludbots;
extern BlockHeap *free_Links;

void        announce_fluder(aClient *, aClient *, aChannel *, int);
struct fludbot *remove_fluder_reference(struct fludbot **, aClient *);
Link       *remove_fludee_reference(Link **, void *);
int         check_for_fludblock(aClient *, aClient *, aChannel *, int);
int         check_for_flud(aClient *, aClient *, aChannel *, int);
void        free_fluders(aClient *, aChannel *);
void        free_fludees(aClient *);
#endif
int      check_for_ctcp(char *, char **);
int      allow_dcc(aClient *, aClient *);
static int      is_silenced(aClient *, aClient *);

#ifdef AZZURRA
int         spam_detect = YES;
#endif

#ifdef ANTI_SPAMBOT
int         spam_time = MIN_JOIN_LEAVE_TIME;
int         spam_num = MAX_JOIN_LEAVE_COUNT;
#endif

/* defines for check_ctcp results */
#define CTCP_NONE 	0
#define CTCP_YES	1
#define CTCP_DCC	2
#define CTCP_DCCSEND 	3

/* defines for the CTCP_BOGUS code */
#ifdef AZZURRA
#define CTCP_BOGUS        4
#endif

/*
 * cptr:
 ** always NON-NULL, pointing to a *LOCAL* client
 ** structure (with an open socket connected!). This
 ** is the physical socket where the message originated (or
 ** which caused the m_function to be executed--some
 ** m_functions may call others...).
 *
 * sptr:
 ** the source of the message, defined by the
 ** prefix part of the message if present. If not or
 ** prefix not found, then sptr==cptr.
 *
 *      *Always* true (if 'parse' and others are working correct):
 *
 *      1      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *      2      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 * cannot be a local connection, unless it's actually cptr!).
 *
 * MyConnect(x) should probably  be defined as (x == x->from) --msa
 *
 * parc:
 ** number of variable parameter strings (if zero,
 ** parv is allowed to be NULL)
 *
 * parv:
 ** a NULL terminated list of parameter pointers,
 *** parv[0], sender (prefix string), if not present his points to
 *** an empty string.
 *
 ** [parc-1]:
 *** pointers to additional parameters
 *** parv[parc] == NULL, *always*
 *
 * note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *         non-NULL pointers.
 */
/*
 * * next_client *    Local function to find the next matching
 * client. The search * can be continued from the specified client
 * entry. Normal *      usage loop is: *
 * 
 *      for (x = client; x = next_client(x,mask); x = x->next) *
 * andleMatchingClient; *
 * 
 */
aClient *next_client(aClient *next, char *ch)
{				
    /* search string (may include wilds) */
    aClient *tmp = next;
    
    next = find_client(ch, tmp);
    if (tmp && tmp->prev == next)
	return ((aClient *) NULL);

    if (next != tmp)
	return next;
    for (; next; next = next->next) 
    {
	if (!match(ch, next->name))
	    break;
    }
    return next;
}

/* this slow version needs to be used for hostmasks *sigh * */

aClient *next_client_double(aClient *next, char *ch)
{				
    /* search string (may include wilds) */
    aClient *tmp = next;

    next = find_client(ch, tmp);
    if (tmp && tmp->prev == next)
	return NULL;
    if (next != tmp)
	return next;
    for (; next; next = next->next) {
	if (!match(ch, next->name) || !match(next->name, ch))
	    break;
    }
    return next;
}

/*
 * hunt_server
 * 
 *      Do the basic thing in delivering the message (command)
 * across the relays to the specific server (server) for
 * actions.
 * 
 *      Note:   The command is a format string and *MUST* be
 * of prefixed style (e.g. ":%s COMMAND %s ...").
 * Command can have only max 8 parameters.
 * 
 * server  parv[server] is the parameter identifying the target server.
 * 
 *      *WARNING* 
 * parv[server] is replaced with the pointer to the 
 * real servername from the matched client
 * I'm lazy now --msa
 * 
 *      returns: (see #defines)
 */
int hunt_server(aClient *cptr, aClient *sptr, char *command, int server,
		int parc, char *parv[])
{
    aClient    *acptr;
    int         wilds;

    /* Assume it's me, if no server */
    if (parc <= server || BadPtr(parv[server]) ||
	match(me.name, parv[server]) == 0 ||
	match(parv[server], me.name) == 0)
	return (HUNTED_ISME);
    /*
     * These are to pickup matches that would cause the following
     * message to go in the wrong direction while doing quick fast
     * non-matching lookups.
     */
    if ((acptr = find_client(parv[server], NULL)))
	if (acptr->from == sptr->from && !MyConnect(acptr))
	    acptr = NULL;
    if (!acptr && (acptr = find_server(parv[server], NULL)))
	if (acptr->from == sptr->from && !MyConnect(acptr))
	    acptr = NULL;

    (void) collapse(parv[server]);
    wilds = (strchr(parv[server], '?') || strchr(parv[server], '*'));
    /*
     * Again, if there are no wild cards involved in the server name,
     * use the hash lookup - Dianora
     */

    if (!acptr) 
    {
	if (!wilds) 
	{
	    acptr = find_name(parv[server], (aClient *) NULL);
	    if (!acptr || !IsRegistered(acptr) || !IsServer(acptr)) 
	    {
		sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name,
			   parv[0], parv[server]);
		return (HUNTED_NOSUCH);
	    }
	}
	else 
	{
	    for (acptr = client;
		 (acptr = next_client(acptr, parv[server]));
		 acptr = acptr->next) 
	    {
		if (acptr->from == sptr->from && !MyConnect(acptr))
		    continue;
		/*
		 * Fix to prevent looping in case the parameter for some
		 * reason happens to match someone from the from link --jto
		 */
		if (IsRegistered(acptr) && (acptr != cptr))
		    break;
	    }
	}
    }

    if (acptr) 
    {
	if (IsMe(acptr) || MyClient(acptr))
	    return HUNTED_ISME;
	if (match(acptr->name, parv[server]))
	    parv[server] = acptr->name;
	sendto_one(acptr, command, parv[0],
		   parv[1], parv[2], parv[3], parv[4],
		   parv[5], parv[6], parv[7], parv[8]);
	return (HUNTED_PASS);
    }
    sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name,
	       parv[0], parv[server]);
    return (HUNTED_NOSUCH);
}

/*
 * canonize
 * 
 * reduce a string of duplicate list entries to contain only the unique *
 * items.  Unavoidably O(n^2).
 */
char *canonize(char *buffer)
{
    static char cbuf[BUFSIZ];
    char *s, *t, *cp = cbuf;
    int l = 0;
    char *p = NULL, *p2;

    *cp = '\0';
    
    for (s = strtoken(&p, buffer, ","); s; s = strtoken(&p, NULL, ",")) 
    {
	if (l) 
	{
	    for (p2 = NULL, t = strtoken(&p2, cbuf, ","); t;
		 t = strtoken(&p2, NULL, ","))
		if (!mycmp(s, t))
		    break;
		else if (p2)
		    p2[-1] = ',';
	}
	else
	    t = NULL;

	if (!t) 
	{
	    if (l)
		*(cp - 1) = ',';
	    else
		l = 1;
	    (void) strcpy(cp, s);
	    if (p)
		cp += (p - s);
	}
	else if (p2)
	    p2[-1] = ',';
    }
    return cbuf;
}

/*
 * * register_user 
 *  This function is called when both NICK and USER messages 
 *  have been accepted for the client, in whatever order.  Only 
 *  after this, is the USER message propagated.
 * 
 *      NICK's must be propagated at once when received, although
 * it would be better to delay them too until full info is
 * available. Doing it is not so simple though, would have to
 * implement the following:
 * 
 *      (actually it has been implemented already for a while)
 * -orabidoo
 * 
 * 1 user telnets in and gives only "NICK foobar" and waits
 * 2 another user far away logs in normally with the nick
 * "foobar" quite legal, as this server didnt propagate it.
 * 3 now this server gets nick "foobar" from outside, but has
 * already the same defined locally. Current server would just
 * issue "KILL foobar" to clean out dups. But, this is not
 * fair. It should actually request another nick from local user
 * or kill him/her...
 */

int register_user(aClient *cptr, aClient *sptr, char *nick, char *username)
{
    aClient *nsptr;
    aConfItem *aconf = NULL, *pwaconf = NULL;
    char       *parv[3];
    static char ubuf[12];
    char       *p;
    anUser     *user = sptr->user;
#ifdef SHORT_MOTD
    aMotd      *smotd;
#endif
    int         i, dots;
    int         bad_dns;		/* flag a bad dns name */
#ifdef FASTWEB /* AZZURRA */
	int			is_fastweb = 0;
#endif
#ifdef WEBIRC
    int webirc_spoof = 0;
#endif
    char        tmpstr2[512];

    //syslog(LOG_INFO, "CGI:IRC Is Installed"); /* CGIDEBUG */

    user->last = timeofday;
    parv[0] = sptr->name;
    parv[1] = parv[2] = NULL;

    /* hostip is already set by do_user if the client is remote */
    if (MyConnect(sptr))
    {
    	inet_ntop(AFINET, &sptr->ip, sptr->hostip, HOSTIPLEN + 1);
#ifdef INET6
    	ip6_expand(sptr->hostip, HOSTIPLEN);
#endif
    }
    
    p = sptr->hostip;
    if (MyConnect(sptr)) 
    {
#ifdef WEBIRC
        if (IsWEBIRC(sptr))
        {
            /* Kill throttles on real host */
            throttle_remove(sptr->hostip);
            
            /* Sanity check: kill FLAGS_GOTID (shouldn't be there, but hey...) */
            if (sptr->flags & FLAGS_GOTID)
            {
                sendto_realops_lev(DEBUG_LEV, "WebIRC client %s[%s/%s] has FLAGS_GOTID set (?!)", nick, sptr->sockhost, sptr->webirc_host);
                sptr->flags &= ~FLAGS_GOTID;
            }
            
            /* Restore correct iphash mapping */
            strncpyzt(sptr->hostip, sptr->webirc_ip, HOSTIPLEN + 1);
#ifndef INET6
            i = inet_pton(AFINET, sptr->hostip, (struct IN_ADDR *)&sptr->ip.S_ADDR);
#else
            i = inet_pton(AFINET, sptr->hostip, sptr->ip.S_ADDR);
#endif
            if (i == 0)
                return exit_client(cptr, sptr, &me, "Invalid IP address");
            
            strncpyzt(sptr->sockhost, sptr->webirc_host, HOSTLEN + 1);
            
            /* Kill real hostent */
            sptr->hostp = NULL;
            
            /* Try to attach an I:line to this client */
            i = attach_Iline(sptr, NULL, sptr->sockhost);
            
            webirc_spoof = 1;
        }
        else
#endif /* WEBIRC */
            i = check_client(sptr);
        
	if (i) 
	{
	    /* -2 is a socket error, already reported.*/
	    if (i != -2) 
	    {
		if (i == -4) 
		{
		    ircstp->is_ref++;
		    return exit_client(cptr, sptr, &me,
				       "Too many connections from your "
				       "hostname");
		}
		else if (i == -3)
		    sendto_realops_lev(CCONN_LEV, "%s for %s [%s] ",
				       "I-line is full (server is full)",
				       get_client_host(sptr), p);
		else
		    sendto_realops_lev(CCONN_LEV, "%s from %s [%s]",
				       "Unauthorized client connection",
				       get_client_host(sptr),p);
		ircstp->is_ref++;
		return exit_client(cptr, sptr, &me, i == -3 ?
				   "No more connections allowed in your "
				   "connection class (the server is full)" :
				   "You are not authorized to use this "
				   "server"
#ifdef AZZURRA
#ifndef FASTWEB
				   ", visit www.azzurra.org/access.html "
#else
				   ", visit www.azzurra.org/fastweb.html "
#endif
				   "for more info"
#endif				   
				   );
	    }
	    else
		return exit_client(cptr, sptr, &me, "Socket Error");
	}

	strncpyzt(user->host, sptr->sockhost, HOSTLEN);
		
	dots = 0;
	p = user->host;
	bad_dns = NO;
	while (*p) 
	{
	    if (!isalnum(*p)) 
	    {
#ifdef RFC1035_ANAL
		if ((*p != '-') && (*p != '.')
#ifdef INET6
				&& (*p != ':')
#endif
				)
#else
		    if ((*p != '-') && (*p != '.') && (*p != '_') &&
			(*p != '/')
#ifdef INET6
			&& (*p != ':')
#endif
			)
#endif /* RFC1035_ANAL */
			bad_dns = YES;
	    }
#ifndef INET6
	    if (*p == '.')
#else
	    if (*p == '.' || *p == ':')
#endif
		dots++;
	    p++;
	}
	/*
	 * Check that the hostname has AT LEAST ONE dot (.) in it. If
	 * not, drop the client (spoofed host) -ThemBones
	 */
	if (!dots) 
	{
	    sendto_realops("Invalid hostname for %s, dumping user %s",
			   sptr->hostip, sptr->name);
	    return exit_client(cptr, sptr, &me, "Invalid hostname");
	}
	
	if (bad_dns) 
	{
	    sendto_one(sptr, ":%s NOTICE %s :*** Notice -- You have a bad "
		       "character in your hostname", me.name, cptr->name);
	    strcpy(user->host, sptr->hostip);
	    strcpy(sptr->sockhost, sptr->hostip);
	}
	
	pwaconf = sptr->confs->value.aconf;

	if (sptr->flags & FLAGS_DOID && !(sptr->flags & FLAGS_GOTID)) 
	{
	    /* because username may point to user->username */
	    char        temp[USERLEN + 1];
	    
	    strncpyzt(temp, username, USERLEN + 1);
	    *user->username = '~';
	    (void) strncpy(&user->username[1], temp, USERLEN);
	    user->username[USERLEN] = '\0';
#ifdef IDENTD_COMPLAIN
	    /* tell them to install identd -Taner */
	    sendto_one(sptr, ":%s NOTICE %s :*** Notice -- It seems that you "
		       "don't have identd installed on your host.",
		       me.name, cptr->name);
	    sendto_one(sptr, ":%s NOTICE %s :*** Notice -- If you wish to "
		       "have your username show up without the ~ (tilde),",
		       me.name, cptr->name);
	    sendto_one(sptr, ":%s NOTICE %s :*** Notice -- then install "
		       "identd.", me.name, cptr->name);
	    /* end identd hack */
#endif
	}
#ifndef FOLLOW_IDENT_RFC
	else if (sptr->flags & FLAGS_GOTID && *sptr->username != '-')
	    strncpyzt(user->username, sptr->username, USERLEN + 1);
#endif
	else if(username != user->username) /* don't overlap */
	    strncpyzt(user->username, username, USERLEN + 1);


	if (!BadPtr(pwaconf->passwd))
	{
	    char *tmpptr = strchr(sptr->passwd, ':');
	    char tmppwd[PASSWDLEN + 1];

	    /*
	     * If there's a : in the password, fix it so after this function,
	     * sptr->passwd changes from:
	     * moo:cow:test:asdf
	     * to
	     * cow:test:asdf
	     */

	    if(tmpptr)
	    {
		*tmpptr++ = '\0';
		strcpy(tmppwd, tmpptr);
	    }

	   if(!StrEq(sptr->passwd, pwaconf->passwd)) 
	    {
		ircstp->is_ref++;
		sendto_one(sptr, err_str(ERR_PASSWDMISMATCH),
			   me.name, parv[0]);
		return exit_client(cptr, sptr, &me, "Bad Password");
	    }
	    if(tmpptr)
		strcpy(sptr->passwd, tmppwd);
	    else
		sptr->passwd[0] = '\0';
	} else {
          //syslog(LOG_INFO, "CGI:IRC PASSWORD non presente"); /* CGIDEBUG */
	}

	/* Limit clients */
	/*
	 * We want to be able to have servers and F-line clients connect,
	 * so save room for "buffer" connections. Smaller servers may
	 * want to decrease this, and it should probably be just a
	 * percentage of the MAXCLIENTS... -Taner
	 */
	/* Except "F:" clients */
	if ((Count.local >= (MAXCLIENTS - 10)) && !(find_fline(sptr))) 
	{ 
	    sendto_realops_lev(SPY_LEV, "Too many clients, rejecting %s[%s].",
			       nick, sptr->sockhost);
	    ircstp->is_ref++;
	    return exit_client(cptr, sptr, &me,
			       "Sorry, server is full - try later");
	}
	
	/* hostile username checks begin here */
	
	{
	    char *tmpstr;
	    u_char      c, cc;
	    int lower, upper, special;
	    
	    lower = upper = special = cc = 0;
			  
	    /* check for "@" in identd reply -Taner */
	    if ((strchr(user->username, '@') != NULL) ||
		(strchr(username, '@') != NULL)) 
	    {
		sendto_realops_lev(REJ_LEV,
				   "Illegal \"@\" in username: %s (%s)",
				   get_client_name(sptr, FALSE), username);
		ircstp->is_ref++;
		(void) ircsprintf(tmpstr2,
				  "Invalid username [%s] - '@' is not allowed",
				  username);
		return exit_client(cptr, sptr, sptr, tmpstr2);
	    }
	    /* First check user->username... */
#ifdef IGNORE_FIRST_CHAR
	    tmpstr = (user->username[0] == '~' ? &user->username[2] :
		      &user->username[1]);
	    /*
	     * Ok, we don't want to TOTALLY ignore the first character. We
	     * should at least check it for control characters, etc -
	     * ThemBones
	     */
	    cc = (user->username[0] == '~' ? user->username[1] :
		  user->username[0]);
	    if ((!isalnum(cc) && !strchr(" -_.", cc)) || (cc > 127))
#ifndef AZZURRA	     
		special++;
#else
	    {	
	       /* We do not want to disconnect users if they provide
		* bad usernames. Let's replace bad characters with "_" 
		* -INT */
	        special++;
	        if (user->username[0] == '~')
	             user->username[1] = '_';
	        else
	             user->username[0] = '_';
	    }	   
#endif /* AZZURRA */	   
#else
	    tmpstr = (user->username[0] == '~' ? &user->username[1] :
		      user->username);
#endif /* IGNORE_FIRST_CHAR */
	    
	    while (*tmpstr) 
	    {
		c = *(tmpstr++);
		if (islower(c)) 
		{
		    lower++;
		    continue;
		}
		if (isupper(c)) 
		{
		    upper++;
		    continue;
		}
		if ((!isalnum(c) && !strchr(" -_.", c)) || (c > 127) || (c<32))
#ifndef AZZURRA		 
		    special++;
#else
		{
		    
	            /* tmpstr points to user->username[0 or 1] */
	            *(tmpstr - 1) = '_';
		    special++;
		}
	       
#endif
	    }
#ifdef NO_MIXED_CASE
	    if (lower && upper) 
	    {
		sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
				   nick, user->username, user->host);
		ircstp->is_ref++;
		(void) ircsprintf(tmpstr2, "Invalid username [%s]",
				  user->username);
		return exit_client(cptr, sptr, &me, tmpstr2);
	    }
#endif /* NO_MIXED_CASE */
	    if (special) 
	    {
		sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
				   nick, user->username, user->host);
		ircstp->is_ref++;
#ifndef AZZURRA 	       
		(void) ircsprintf(tmpstr2, "Invalid username [%s]",
				  user->username);
		return exit_client(cptr, sptr, &me, tmpstr2);
#else
	        sendto_one(sptr,
		           ":%s NOTICE %s :*** Your username contains bad "
			   "characters. They will be replaced.",
			   me.name, sptr->name);
		       
#endif
	    }
	    /* Ok, now check the username they provided, if different */
	    lower = upper = special = cc = 0;
			  
	    if (strcmp(user->username, username)) 
	    {
				  
#ifdef IGNORE_FIRST_CHAR
		tmpstr = (username[0] == '~' ? &username[2] : &username[1]);
		/*
		 * Ok, we don't want to TOTALLY ignore the first character.
		 * We should at least check it for control charcters, etc
		 * -ThemBones
		 */
		cc = (username[0] == '~' ? username[1] : username[0]);
				  
		if ((!isalnum(cc) && !strchr(" -_.", cc)) || (cc > 127))
#ifndef AZZURRA		 
		    special++;
#else
		{
		    
		   if (user->username[0] == '~')
	               user->username[1] = '_';
		   else
	               user->username[0] = '_';
		}	   
#endif
#else
		tmpstr = (username[0] == '~' ? &username[1] : username);
#endif /* IGNORE_FIRST_CHAR */
		while (*tmpstr) 
		{
		    c = *(tmpstr++);
		    if (islower(c)) 
		    {
			lower++;
			continue;
		    }
		    if (isupper(c)) 
		    {
			upper++;
			continue;
		    }
		    if ((!isalnum(c) && !strchr(" -_.", c)) || (c > 127))
#ifndef AZZURRA		     
			special++;
#else
		        /* tmpstr points to user->username[0 or 1] */
		        *(tmpstr - 1) = '_';
#endif
		}
#ifdef NO_MIXED_CASE
		if (lower && upper) 
		{
		    sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
				       nick, username, user->host);
		    ircstp->is_ref++;
		    (void) ircsprintf(tmpstr2, "Invalid username [%s]",
				      username);
		    return exit_client(cptr, sptr, &me, tmpstr2);
		}
#endif /* NO_MIXED_CASE */
		if (special) 
		{
		    sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
				       nick, username, user->host);
		    ircstp->is_ref++;
#ifndef AZZURRA
		    (void) ircsprintf(tmpstr2, "Invalid username [%s]",
				      username);
		    return exit_client(cptr, sptr, &me, tmpstr2);
#else
		    sendto_one(sptr,
		           ":%s NOTICE %s :*** Your username contains bad "
			   "characters. They will be replaced.",
			   me.name, sptr->name);
		       
#endif		   
		}
	    }			/* usernames different  */
	}

	/*
	 * reject single character usernames which aren't alphabetic i.e.
	 * reject jokers who have '?@somehost' or '.@somehost'
	 * 
	 * -Dianora
	 */
		
	if ((user->username[1] == '\0') && !isalpha(user->username[0])) 
	{
	    sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
			       nick, user->username, user->host);
	    ircstp->is_ref++;
#ifndef AZZURRA	   
	    (void) ircsprintf(tmpstr2, "Invalid username [%s]",
			      user->username);
	    return exit_client(cptr, sptr, &me, tmpstr2);
#else
	    user->username[0] = '_';
	    sendto_one(sptr,
		       ":%s NOTICE %s :*** Your username contains bad "
		       "characters. They will be replaced.",
		       me.name, sptr->name);	   
#endif	   
	}

#ifdef FASTWEB
	if(pwaconf->flags & CONF_FLAGS_I_FASTWEBPORT)
	{ 
	    /* workaround for fastweb`s MAN`s lame addressing :D */
	    int ip[4];
	    char isdns =0, *p;
   		
	    for (p =user->host, i = 0; *p; p++) /* sanity check to avoid mistakes. */
	    {
		if(isalpha(*p))
		{
		    isdns = 1;
		    break;
		}
	    }

	    if(!isdns)
	    {
		sscanf(sptr->user->host, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
		ircsprintf(sptr->user->host, "%d-%d.%d-%d.%s", ip[3], ip[2], ip[1], ip[0], FAST_RES);
		strcpy(sptr->sockhost, sptr->user->host);
		is_fastweb = 1;
	    }
	}
#endif

	/* following block for the benefit of time-dependent K:-lines */
	if ((aconf = find_kill(sptr))) 
	{
	    char *reason;
	    char *ktype;
	    int kline;
			
	    kline = (aconf->status == CONF_KILL) ? 1 : 0;
	    ktype = kline ? "K-lined" : "Autokilled";
	    reason = aconf->passwd ? aconf->passwd : ktype;
			
#ifdef RK_NOTICES
	    sendto_realops("%s %s@%s. for %s", ktype, sptr->user->username,
			   sptr->sockhost, reason);
#endif
	    sendto_one(sptr, err_str(ERR_YOUREBANNEDCREEP),
		       me.name, sptr->name, ktype);
	    sendto_one(sptr,
		       ":%s NOTICE %s :*** You are not welcome on this %s.",
		       me.name, sptr->name,
		       kline ? "server" : "network");
	    sendto_one(sptr, ":%s NOTICE %s :*** %s for %s",
		       me.name, sptr->name, ktype, reason);
	    sendto_one(sptr, ":%s NOTICE %s :*** Your hostmask is %s!%s@%s",
		       me.name, sptr->name, sptr->name, sptr->user->username,
		       sptr->sockhost);
	    sendto_one(sptr, ":%s NOTICE %s :*** For more information, please "
		       "mail %s and include everything shown here.",
		       me.name, sptr->name,
		       kline ? SERVER_KLINE_ADDRESS : NETWORK_KLINE_ADDRESS);
	    
#ifdef USE_REJECT_HOLD
	    cptr->flags |= FLAGS_REJECT_HOLD;
#endif
	    ircstp->is_ref++;
	    
#ifndef USE_REJECT_HOLD			
	    return exit_client(cptr, sptr, &me, reason);
#endif
	}
		
	if ((++Count.local) > Count.max_loc) 
	{
	    Count.max_loc = Count.local;
	    if (!(Count.max_loc % 10))
		sendto_ops("New Max Local Clients: %d",
			   Count.max_loc);
	}
	if ((NOW - Count.day) > 86400) 
	{
	    Count.today = 0;
	    Count.day = NOW;
	}
	if ((NOW - Count.week) > 604800) 
	{
	    Count.weekly = 0;
	    Count.week = NOW;
	}
	if ((NOW - Count.month) > 2592000) 
	{
	    Count.monthly = 0;
	    Count.month = NOW;
	}
	if ((NOW - Count.year) > 31536000) 
	{
	    Count.yearly = 0;
	    Count.year = NOW;
	}
	Count.today++;
	Count.weekly++;
	Count.monthly++;
	Count.yearly++;
	if(sptr->flags & FLAGS_BAD_DNS) 
            sendto_realops_lev(SPY_LEV, "DNS lookup: %s (%s@%s) is a possible "
			       "cache polluter", 
			       sptr->name, sptr->user->username,
			       sptr->user->host); 
    }
    else
	strncpyzt(user->username, username, USERLEN + 1);
#ifdef AZZURRA
    if(IsIPv6(sptr))
	strncpyzt(user->virthost, user->host, HOSTLEN);
    else if(!cloakhost(user->host, user->virthost))
	strncpyzt(user->virthost, user->host, HOSTLEN);
#endif
 
    SetClient(sptr);
    /* Increment our total user count here */
    if (++Count.total > Count.max_tot)
	Count.max_tot = Count.total;

    if(IsInvisible(sptr)) Count.invisi++;
	
    if (MyConnect(sptr))
    {
	sptr->pingval = get_client_ping(sptr);
	sptr->sendqlen = get_sendq(sptr);
#ifdef MAXBUFFERS
	/* Let's try changing the socket options for the client here... */
	reset_sock_opts(sptr->fd, 0);
	/* End sock_opt hack */
#endif

#ifdef AZZURRA
        if (IsJava(sptr))
	{
	    sendto_one(sptr,
		    ":%s 001 %s :Welcome to the Internet "
		    "Relay Chat network, %s!%s@%s",
		    me.name, nick, nick, user->username, user->host);
	    sendto_one(sptr,
		    ":%s 002 %s :Your host is %s, "
		    "running version 1.8.4-SEC",
		    me.name, nick, me.name);
	    sendto_one(sptr, rpl_str(RPL_CREATED), me.name, nick, creation);
	    sendto_one(sptr,
		    ":%s 004 %s %s CR1.8.4-SEC oiwsabjgrchytxkmnpeAEGFSLMRTX abcdeijklmnoprstuvzAMNLO",
		    me.name, nick, me.name);
	    sendto_one(sptr,
		    ":%s 005 %s WATCH=128 SAFELIST TUNL FLG=s,5 "
		    ":ConferenceRoom by WebMaster",
		    me.name, nick);
	} else {
#endif

#ifdef FASTWEB
		sendto_one(sptr, rpl_str(RPL_WELCOME), me.name, nick, nick, 
			sptr->user->username, is_fastweb ? sptr->hostip : sptr->user->host);
#else
		sendto_one(sptr, rpl_str(RPL_WELCOME), me.name, nick, nick, 
			sptr->user->username, sptr->user->host);
#endif

	    /*
	     * This is a duplicate of the NOTICE but see below...
	     * um, why were we hiding it? they did make it on to the
	     * server and all.. -wd
	     */
	    sendto_one(sptr, rpl_str(RPL_YOURHOST), me.name, nick,
	    	   get_client_name(&me, TRUE), version);
#ifdef	IRCII_KLUDGE
	    /* Don't mess with this one - IRCII needs it! -Avalon */
	    sendto_one(sptr, "NOTICE %s :*** Your host is %s, running version %s",
	    	   nick, get_client_name(&me, TRUE), version);
#endif
	    sendto_one(sptr, rpl_str(RPL_CREATED), me.name, nick, creation);
	    sendto_one(sptr, rpl_str(RPL_MYINFO), me.name, parv[0],
	    	   me.name, version);
	    sendto_one(sptr, rpl_str(RPL_PROTOCTL), me.name, parv[0], MAXWATCH,
	    	   MAXMODEPARAMSUSER, MAXCHANNELSPERUSER, MAXBANS, NICKLEN,
	    	   TOPICLEN, TOPICLEN, MAXSILES);
#ifdef AZZURRA
	}
#endif

#if (RIDICULOUS_PARANOIA_LEVEL>=1)
	if(!BadPtr(sptr->passwd) && (pwaconf->flags & CONF_FLAGS_I_OPERPORT))
	    do 
	    {
		char *onptr = sptr->passwd;
		char *opptr;
		char *onick;
		char *tmpptr;
		char tmppwd[PASSWDLEN + 1];
		int global;
		
		if(!(opptr = strchr(onptr, ':')))
		    break;
		
		*opptr++ = '\0';
		if((tmpptr = strchr(opptr, ':')))
		    *tmpptr++ = '\0';

		if(check_oper_can_mask(sptr, onptr, opptr, &onick, &global) != 0)
		{
		    sendto_one(sptr, ":%s NOTICE %s :*** Your hostname has "
			       "been masked.",
			       me.name, sptr->name);

		    throttle_remove(sptr->hostip);		    	    
		    sptr->user->real_oper_host = 
			MyMalloc(strlen(sptr->user->host) + 1);
		    sptr->user->real_oper_username = 
			MyMalloc(strlen(sptr->username) + 1);
		    sptr->user->real_oper_ip = 
			MyMalloc(strlen(sptr->hostip) + 1);
		    strcpy(sptr->user->real_oper_host, sptr->user->host);
		    strcpy(sptr->user->real_oper_username, sptr->user->username);
		    strcpy(sptr->user->real_oper_ip, sptr->hostip);
		    strncpyzt(sptr->user->host, global ? STAFF_ADDRESS :
			    LOCALOP_ADDRESS, HOSTLEN + 1);
#ifdef AZZURRA
		    strncpyzt(sptr->user->virthost, global ? STAFF_ADDRESS :
			    LOCALOP_ADDRESS, HOSTLEN + 1);
		    sptr->umode &= ~UMODE_x;
#endif
		    strncpyzt(sptr->user->username, onick, USERLEN + 1);
		    strncpyzt(sptr->username, onick, USERLEN + 1);
		    sptr->flags |= FLAGS_GOTID; /* fake ident */
		    if(sptr->flags & FLAGS_IPHASH)
		    {
			remove_one_ip(sptr->ip.S_ADDR);
			sptr->flags &= ~FLAGS_IPHASH;
		    }
#ifndef INET6
		    sptr->ip.S_ADDR = INADDR_ANY;
#else
	            memset(sptr->ip.S_ADDR, 0x0, sizeof(struct IN_ADDR));
#endif
		    strcpy(sptr->hostip, INADDRANY_STR);
		    strncpy(sptr->sockhost, STAFF_ADDRESS, HOSTLEN + 1);
		}

		if(tmpptr)
		{
		    strcpy(tmppwd, tmpptr);
		    strcpy(sptr->passwd, tmppwd);
		}
		else
		    sptr->passwd[0] = '\0';
	    } while(0);
#ifdef AZZURRA
	if(!BadPtr(sptr->passwd) && (pwaconf->flags & CONF_FLAGS_I_HELPERPORT))
	    do 
	    {
		char *onptr = sptr->passwd;
		char *opptr;
		char *onick;
		char *tmpptr;
		char tmppwd[PASSWDLEN + 1];
		
		if(!(opptr = strchr(onptr, ':')))
		    break;
		
		*opptr++ = '\0';
		if((tmpptr = strchr(opptr, ':')))
		    *tmpptr++ = '\0';

		if(check_helper_can_mask(sptr, onptr, opptr, &onick) != 0)
		{
		    sendto_one(sptr, ":%s NOTICE %s :*** Your hostname has "
			       "been masked.",
			       me.name, sptr->name);

		    throttle_remove(sptr->hostip);		    	    
		    sptr->user->real_helper_host = 
			MyMalloc(strlen(sptr->user->host) + 1);
		    sptr->user->real_helper_username = 
			MyMalloc(strlen(sptr->username) + 1);
		    sptr->user->real_helper_ip = 
			MyMalloc(strlen(sptr->hostip) + 1);
		    strcpy(sptr->user->real_helper_host, sptr->user->host);
		    strcpy(sptr->user->real_helper_username, sptr->user->username);
		    strcpy(sptr->user->real_helper_ip, sptr->hostip);
		    strncpyzt(sptr->user->host, HELPER_ADDRESS, HOSTLEN + 1);
		    strncpyzt(sptr->user->virthost, HELPER_ADDRESS, HOSTLEN + 1);
		    sptr->umode &= ~UMODE_x;
		    strncpyzt(sptr->user->username, onick, USERLEN + 1);
		    strncpyzt(sptr->username, onick, USERLEN + 1);
		    sptr->flags |= FLAGS_GOTID; /* fake ident */
		    if(sptr->flags & FLAGS_IPHASH)
		    {
			remove_one_ip(sptr->ip.S_ADDR);
			sptr->flags &= ~FLAGS_IPHASH;
		    }
#ifndef INET6
		    sptr->ip.S_ADDR = INADDR_ANY;
#else
	            memset(sptr->ip.S_ADDR, 0x0, sizeof(struct IN_ADDR));
#endif
		    strcpy(sptr->hostip, INADDRANY_STR);
		    strncpy(sptr->sockhost, HELPER_ADDRESS, HOSTLEN + 1);
		}

		if(tmpptr)
		{
		    strcpy(tmppwd, tmpptr);
		    strcpy(sptr->passwd, tmppwd);
		}
		else
		    sptr->passwd[0] = '\0';
	    } while(0);
#endif /* AZZURRA */

#endif /* RIDICOLOUS_PARANOIA_LEVEL >= 1 */


	sendto_realops_lev(CCONN_LEV, "Client connecting: %s (%s@%s) [%s] {%d} [%s] (%d)%s%s",
		nick, user->username, user->host, sptr->hostip, get_client_class(sptr),
		sptr->info,
#ifdef WEBIRC
		webirc_spoof ? 80 :
#endif
		sptr->lport,
		IsSSL(sptr) ? " SSL" : "",
#ifdef WEBIRC
		webirc_spoof ? " (Spoofed WEBIRC Host)" : 
#endif
		"");

#ifdef USE_ACTIVITY_LOG
	activity_log("(CONNECT): %s (%s@%s) [%s] {%d} %s",
		     nick,
		     user->username,
		     user->host,
		     sptr->hostip,
		     get_client_class(sptr),
		     IsSSL(sptr) ? "SSL" : "");
#endif

	(void) send_lusers(sptr, sptr, 1, parv);
		
	sendto_one(sptr,
		   ":%s NOTICE %s :*** Notice -- motd was last changed at %s",
		   me.name, nick, motd_last_changed_date);
#ifdef SHORT_MOTD
	sendto_one(sptr, ":%s NOTICE %s :*** Notice -- Please read the motd "
		   "if you haven't read it", me.name, nick);
	
	sendto_one(sptr, rpl_str(RPL_MOTDSTART),
		   me.name, parv[0], me.name);
	if((smotd = shortmotd) == NULL)
	{
	    sendto_one(sptr,
		       rpl_str(RPL_MOTD),
		       me.name, parv[0],
		       "*** This is the short motd ***"
		);
	}
	else 
	{
	    while (smotd) 
	    {
		sendto_one(sptr, rpl_str(RPL_MOTD), me.name, parv[0],
			   smotd->line);
		smotd = smotd->next;
	    }
	}
	
	sendto_one(sptr, rpl_str(RPL_ENDOFMOTD),
		   me.name, parv[0]);
#else
	(void) send_motd(sptr, sptr, 1, parv);
#endif
#ifdef WINGATE_NOTICE
	sendto_one(sptr, ":%s NOTICE %s :*** Notice -- This server runs an "
		   "open proxy monitor to prevent abuse.", me.name, nick);
	sendto_one(sptr, ":%s NOTICE %s :*** Notice -- If you see various "
		   "connections from %s", me.name, nick,
		   ProxyMonHost);
	sendto_one(sptr, ":%s NOTICE %s :*** Notice -- please disregard them, "
		   "as they are the detector in action.",
		   me.name, nick);
	sendto_one(sptr, ":%s NOTICE %s :*** Notice -- For more information "
		   "please visit %s", me.name, nick, ProxyMonURL);
#endif
#ifdef RESTRICT_USERS
	if (restriction_enabled && (sptr->confs->value.aconf->flags & CONF_FLAGS_I_RESTRICTED))
		sendto_one(sptr, ":%s NOTICE %s :*** Notice -- Your connection is restricted! For more information "
				 "please visit "RESTRICT_USERS_URL, me.name, nick);
#endif
    }
    else if (IsServer(cptr)) 
    {
	aClient    *acptr;
	
	if ((acptr = find_server(user->server, NULL)) &&
	    acptr->from != sptr->from)
	{
	    sendto_realops_lev(DEBUG_LEV,
			       "Bad User [%s] :%s USER %s@%s %s, != %s[%s]",
			       cptr->name, nick, user->username,
			       user->host, user->server,
			       acptr->name, acptr->from->name);
	    sendto_one(cptr,
		       ":%s KILL %s :%s (%s != %s[%s] USER from wrong "
		       "direction)", me.name, sptr->name, me.name,
		       user->server,
		       acptr->from->name, acptr->from->sockhost);
	    sptr->flags |= FLAGS_KILLED;
	    return exit_client(sptr, sptr, &me,
			       "USER server wrong direction");
			
	}
	/*
	 * Super GhostDetect: If we can't find the server the user is
	 * supposed to be on, then simply blow the user away.     -Taner
	 */
	if (!acptr)
	{
	    sendto_one(cptr,
		       ":%s KILL %s :%s GHOST (no server %s on the net)",
		       me.name, sptr->name, me.name, user->server);
	    sendto_realops("No server %s for user %s[%s@%s] from %s",
			   user->server, sptr->name, user->username,
			   user->host, sptr->from->name);
	    sptr->flags |= FLAGS_KILLED;
	    return exit_client(sptr, sptr, &me, "Ghosted Client");
	}
    }
    send_umode(NULL, sptr, 0, SEND_UMODES, ubuf);
    if (!*ubuf)
    {
	ubuf[0] = '+';
	ubuf[1] = '\0';
    }
    hash_check_watch(sptr, RPL_LOGON);

#ifndef INET6
    if (sptr->ip.s_addr > 0)
	sendto_nickip_servs_butone(1, cptr, 
			       "NICK %s %d %ld %s %s %s %s %lu %lu :%s",
			       nick, sptr->hopcount + 1, sptr->tsinfo, ubuf,
			       user->username, user->host, user->server, 
			       sptr->user->servicestamp, htonl(sptr->ip.s_addr),
			       sptr->info);
    else   
#endif
    sendto_nickip_servs_butone(1, cptr, 
			       "NICK %s %d %ld %s %s %s %s %lu %s :%s",
			       nick, sptr->hopcount + 1, sptr->tsinfo, ubuf,
			       user->username, user->host, user->server, 
			       sptr->user->servicestamp,
			       sptr->hostip ? sptr->hostip : "0.0.0.0",
			       sptr->info);
    sendto_nickip_servs_butone(0, cptr, 
			       "NICK %s %d %ld %s %s %s %s %lu :%s",
			       nick, sptr->hopcount + 1, sptr->tsinfo, ubuf,
			       user->username, user->host, user->server, 
			       sptr->user->servicestamp, sptr->info);
   
    if(MyClient(sptr))
    {
	/* if the I:line doesn't have a password and the user does
	 * send it over to NickServ
	 */
	if(sptr->passwd[0] && (nsptr=find_person(NICKSERV,NULL))!=NULL)
	{
	    sendto_one(nsptr,":%s PRIVMSG %s@%s :SIDENTIFY %s", sptr->name,
		       NICKSERV, SERVICES_NAME, sptr->passwd);
	}
	
	memset(sptr->passwd, '\0', PASSWDLEN);
	
	if (ubuf[1]) send_umode(cptr, sptr, 0, ALL_UMODES, ubuf);
    }
    
    return 0;
}

/* Code provided by orabidoo */
/*
 * a random number generator loosely based on RC5; assumes ints are at
 * least 32 bit
 */

unsigned long my_rand()
{
    static unsigned long s = 0, t = 0, k = 12345678;
    int         i;

    if (s == 0 && t == 0)
    {
	s = (unsigned long) getpid();
	t = (unsigned long) time(NULL);
    }
    for (i = 0; i < 12; i++)
    {
	s = (((s ^ t) << (t & 31)) | ((s ^ t) >> (31 - (t & 31)))) + k;
	k += s + t;
	t = (((t ^ s) << (s & 31)) | ((t ^ s) >> (31 - (s & 31)))) + k;
	k += s + t;
    }
    return s;
}

char *exploits_2char[] =
{
    "js",
    "pl",
    NULL
};
char *exploits_3char[] = 
{
    "exe",
    "com",
    "bat",
    "dll",
    "ini",
    "vbs",
    "pif",
    "mrc",
    "scr",
    "doc",
    "xls",
    "lnk",
    "shs",
    "htm",
    "zip",
    "rar",
    "ace",
    "php",
    "asp",
	"hta",
	NULL
};

char *exploits_4char[] =
{
    "html",
    NULL
};

int check_dccsend(aClient *from, aClient *to, char *msg)
{
    /*
     * we already know that msg will consist of "DCC SEND" so we can skip
     * to the end
     */
    char *filename = msg + 8;
    char *ext;
    char **farray = NULL;
    int arraysz;
    int len = 0, extlen = 0, i;
#ifdef AZZURRA
    char *endfile, *s;
    unsigned long port, pasvdccid;
#endif

    /* people can send themselves stuff all the like..
     * opers need to be able to send cleaner files 
     * sanity checks..
     */

#ifndef AZZURRA
    if (from == to || !IsPerson(from) || IsAnOper(from) || !MyClient(to)) 
#else
    if (from == to || !IsPerson(from) || IsAnOper(from)) 
#endif
		return 0;

    while (*filename == ' ')
		++filename;

	if (!(*filename))
		return 0;

#ifndef AZZURRA
    while (*(filename + len) != ' ')
    {
		if (!(*(filename + len)))
			break;

		len++;
    }
#else

	if (*filename == '\"') {

		/* Skip the leading " */
		++filename;

		/* Filename ends at the next " */
		endfile = strchr(filename, '\"');

		/* If there isn't one, it's malformed. */
		if (!endfile)
			return 0;

		/* Skip any trailing spaces. */
		while ((endfile > filename) && *(endfile - 1) == ' ')
			--endfile;
	}
	else {

		/* Filename ends at the next space. */
		endfile = strchr(filename, ' ');

		/* If there isn't one, it's malformed. */
		if (!endfile)
			return 0;
	}

	if (endfile <= filename)
		return 0;

	/* get port number, if port == 0 dcc is passive */
	for (s = endfile+1; *s && *s != ' '; s++);
	if (*s)
		port = atol(s);
	else
		return 0; /* malformed */
	
	/* get dcc id number */
	for (s = rindex(endfile, ' '); (s > endfile) && (*s == ' '); s--);
	while (*s != ' ' && s > endfile)
		s--;
	pasvdccid = atol(s);
	
	len = endfile - filename;

	/* Block files coming from windows directories. They're almost certainly a worm. */
	if (MyClient(from) && (!myncmp(filename + 1, ":\\WINDOWS\\", 10) || 
				!myncmp(filename + 1, ":\\WINNT\\", 8))) {

		char buffer[BUFSIZE];

		if (len > 127)
			len = 127;

		strncpy(buffer, filename, len);
		buffer[len] = '\0';

		if (CONF_SERVER_LANGUAGE == LANG_IT)
			sendto_one(from, ":%s NOTICE %s :Non e' consentito inviare files direttamente da dentro "
				"la directory di Windows. Sposta il file in un'altra directory e riprova. L'invio "
				"del seguente file all'utente %s e' stato rifiutato dal server: %s",
				me.name, from->name, to->name, buffer);
		else
			sendto_one(from, ":%s NOTICE %s :Files may not be sent directly from the Windows directory. "
				"Please move the file to another directory and try again. DCC SEND of the following "
				"file to user %s has been rejected: %s",
				me.name, from->name, to->name, buffer);

		return 1;
	}
	
	/* if dcc is passive remember the dcc number in client structure */
	if (port == 0)
		from->pasvdccid = pasvdccid;
		
#endif	/* AZZURRA */

	/* STOP here is destination client is not my client */
	if (!MyClient(to))
		return 0;

	for (ext = filename + len; ; ext--) {

		if (ext == filename)
			return 0;

		if (*ext == '.') {

			ext++;
			extlen--;
			break;
		}

		extlen++;
	}

    switch (extlen) {

		case 0:
			arraysz = 0;
			break;

		case 2:
			farray = exploits_2char;
			arraysz = 2;
			break;

		case 3:
			farray = exploits_3char;
			arraysz = 3;
			break;

		case 4:
			farray = exploits_4char;
			arraysz = 4;
			break;

		default:
			/* no executable file here.. */
			return 0;
	}

    if (arraysz != 0) {

		for (i = 0; farray[i]; i++) {

			if (myncmp(farray[i], ext, arraysz) == 0)
				break;
		}

		if (farray[i] == NULL)
			return 0;
    }

    /* check pasvdccid and dccallow list. to IS MyClient!! */
    if (to->pasvdccid == pasvdccid && pasvdccid != 0) {
		to->pasvdccid = 0;
    } else if (!allow_dcc(to, from)) {

		char tmpext[8];
		char tmpfn[128];

		Link *tlp, *flp;
		aChannel *chptr = NULL;

		strncpy(tmpext, ext, extlen);
		tmpext[extlen] = '\0';

		if (len > 127) 
			len = 127;

		strncpy(tmpfn, filename, len);
		tmpfn[len] = '\0';

		/* use notices! 
		*   server notices are hard to script around.
		*   server notices are not ignored by clients.
		*/ 

#ifndef AZZURRA
		sendto_one(from, ":%s NOTICE %s :The user %s is not accepting DCC "
			"sends of filetype *.%s from you.  Your file %s was not "
			"sent.", me.name, from->name, to->name, tmpext, tmpfn);

		sendto_one(to, ":%s NOTICE %s :%s (%s@%s) has attempted to send you a "
			"file named %s, which was blocked.", me.name, to->name,
			from->name, from->user->username,
			from->user->host, tmpfn);

		if (!SeenDCCNotice(to)) {

			SetDCCNotice(to);
 
			sendto_one(to, ":%s NOTICE %s :The majority of files sent of this "
				"type are malicious virii and trojan horses."
				" In order to prevent the spread of this problem, we "
				"are blocking DCC sends of these types of"
				" files by default.", me.name, to->name);

			sendto_one(to, ":%s NOTICE %s :If you trust %s, and want him/her "
				"to send you this file, you may obtain"
				" more information on using the dccallow system by "
				"typing /dccallow help",
				me.name, to->name, from->name, to->name);
		}
#else
		if (CONF_SERVER_LANGUAGE == LANG_IT) {

			sendto_one(from, ":%s NOTICE %s :Per l'invio di files *.%s e' richiesta l'autorizzazione del ricevente. "
				"Fai sapere a %s che deve digitare \2/DCCALLOW +%s\2 per poter ricevere questo file.", 
				me.name, from->name, tmpext, to->name, from->name);

			sendto_one(to, ":%s NOTICE %s :L'utente %s (%s@%s) ha provato ad inviarti un file chiamato \2%s\2. "
				"Per la ricezione di questo file e' necessaria la tua autorizzazione. "
				"Se hai la certezza che non si tratti di un file infetto, digita \2/DCCALLOW +%s\2 per riceverlo.",
				me.name, to->name, from->name, from->user->username, IsUmodex(from) ? from->user->virthost : from->user->host,
				tmpfn, from->name);
		}
		else {
			sendto_one(from, ":%s NOTICE %s :The receiver's authorization is required for DCC sends of filetype *.%s. "
				"Let %s know they need to type \2/DCCALLOW +%s\2 in order to receive this file.", 
				me.name, from->name, tmpext, to->name, from->name);

			sendto_one(to, ":%s NOTICE %s :User %s (%s@%s) tried to send you a file named \2%s\2, which was blocked. "
				"Your authorization is required for DCC sends of this filetype. "
				"If you're absolutely sure this file is not infected with a trojan, type \2/DCCALLOW +%s\2 to receive it.",
				me.name, to->name, from->name, from->user->username, IsUmodex(from) ? from->user->virthost : from->user->host,
				tmpfn, from->name);
		}
#endif

		for (tlp = to->user->channel; tlp && !chptr; tlp = tlp->next) {

			for (flp = from->user->channel; flp && !chptr; flp = flp->next) {

				if (tlp->value.chptr == flp->value.chptr)
					chptr = tlp->value.chptr;
			}
		}
	
		if (chptr)
			sendto_realops_lev(DCCSEND_LEV, "%s (%s@%s) sending forbidden filetyped file %s to %s (channel %s)",
				from->name, from->user->username, from->user->host, tmpfn, to->name, chptr->chname); 
		else
			sendto_realops_lev(DCCSEND_LEV, "%s (%s@%s) sending forbidden filetyped file %s to %s",
				from->name, from->user->username, from->user->host, tmpfn, to->name); 

		return 1;
	}

	return 0;
}

/* check to see if the message has any color chars in it. */
int msg_has_colors(char *msg)
{

    char *c;
    if (msg==NULL) return 0;
    c=msg;

    while(*c)
    {
	if(*c == '\003' || *c == '\033')
	    break;
	else
	    c++;
    }

    if(*c)
	return 1;

    return 0;
}

/*
 * check target limit: message target rate limiting
 * anti spam control!
 * should only be called for local PERSONS!
 * sptr: client sending message
 * acptr: client receiving message
 *
 * return value:
 * 1: block
 * 0: do nothing
 */

#ifdef MSG_TARGET_LIMIT

#ifdef AZZURRA
unsigned short int tlim_target_min = MSG_TARGET_MIN,
    tlim_target_max = MSG_TARGET_MAX, 	/* MUST BE >= tlim_target_min !!! */
    tlim_target_mintomaxtime = MSG_TARGET_MINTOMAXTIME,
    tlim_target_time = MSG_TARGET_TIME,
    tlim_enabled = 1;
#else
#define tlim_target_min MSG_TARGET_MIN
#define tlim_target_max MSG_TARGET_MAX
#define tlim_target_mintomaxtime MSG_TARGET_MINTOMAXTIME
#define tlim_target_time MSG_TARGET_TIME
#endif

int check_target_limit(aClient *sptr, aClient *acptr)
{
   int ti;
   int max_targets;
   time_t tmin = tlim_target_time; /* minimum time to wait before another message can be sent */

#ifdef DYNAMIC_TARGET_LIMIT
   if(tlim_enabled == 0)
       return 0;
#endif

   /* don't limit opers, people talking to themselves, or people talking to services */
   if(IsOper(sptr) || sptr == acptr || IsULine(acptr)
#ifdef AZZURRA
      || IsUmodez(sptr)
#endif		   
     )
      return 0;

   max_targets = ((NOW - sptr->firsttime) > tlim_target_mintomaxtime) ? tlim_target_max : tlim_target_min;

   for(ti = 0; ti < max_targets; ti++)
   {
      if (
          sptr->targets[ti].cli == NULL ||  /* no client */
          sptr->targets[ti].cli == acptr || /* already have this client */
          sptr->targets[ti].sent < (NOW - tlim_target_time) /* haven't talked to this client in > tlim_target_time secs */
         )
      {
         sptr->targets[ti].cli = acptr;
         sptr->targets[ti].sent = NOW;
         break;
      }
      else if((NOW - sptr->targets[ti].sent) < tmin)
         tmin = NOW - sptr->targets[ti].sent;
   }

   if(ti == max_targets)
   {
      sendto_one(sptr, err_str(ERR_TARGETTOFAST), me.name, sptr->name, acptr->name, tlim_target_time - tmin);
      sptr->since += 2; /* penalize them 2 seconds for this! */
      sptr->num_target_errors++;

      if(sptr->last_target_complain + 60 <= NOW)
      {
         sendto_realops_lev(SPAM_LEV, "Target limited: %s (%s@%s) [%d failed targets]", sptr->name,
                        sptr->user->username, sptr->user->host, sptr->num_target_errors);
         sptr->num_target_errors = 0;
         sptr->last_target_complain = NOW;
      }
      return 1;
   }

   return 0;
}

#endif


/*
 * m_message (used in m_private() and m_notice()) the general
 * function to deliver MSG's between users/channels
 * 
 * parv[0] = sender prefix
 * parv[1] = receiver list
 * parv[2] = message text
 * 
 * massive cleanup * rev argv 6/91
 * 
 */

static inline int m_message(aClient *cptr, aClient *sptr, int parc,
			    char *parv[], int notice)
{
    aClient *acptr;
    char *s;
#ifdef SERVICESHUB
    char *myparv[2];
#endif
    int i, ret, typedest;
    aChannel *chptr;
    char *nick, *chan, *server, *p, *cmd, *dccmsg;

    cmd = notice ? MSG_NOTICE : MSG_PRIVATE;

    if (parc < 2 || *parv[1] == '\0') 
    {
       sendto_one(sptr, err_str(ERR_NORECIPIENT), me.name, parv[0], cmd);
       return -1;
    }

    if (parc < 3 || *parv[2] == '\0') 
    {
       sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
       return -1;
    }

    if (MyConnect(sptr)) 
    {
        
#if defined( ANTI_SPAMBOT ) && !defined( ANTI_SPAMBOT_WARN_ONLY )
       /* if its a spambot, just ignore it */
       if (sptr->join_leave_count >= MAX_JOIN_LEAVE_COUNT)
	 return 0;
#endif

       parv[1] = canonize(parv[1]);
    }

    for (p = NULL, nick = strtoken(&p, parv[1], ","), i = 0; nick && i < 20; nick = strtoken(&p, NULL, ",")) 
    {
       /*
	* If someone is spamming via "/msg nick1,nick2,nick3,nick4 SPAM"
	* (or even to channels) then subject them to flood control!
	* -Taner
	*/
       if (i++ > 10)
#ifdef NO_OPER_FLOOD
	 if (!IsAnOper(sptr) && !IsULine(sptr)
#ifdef AZZURRA
	     && !IsUmodez(sptr)
#endif
	     )
#endif
	   sptr->since += 8;

       chptr = NULL;
       acptr = NULL;
       chan = NULL;
       typedest = 0;
       
       /* Recognize destination */
       if (IsChannelName(nick)) /* normal channel */
       { 
	  typedest |= TO_CHAN;
	  chan = nick;
       }
       else if ((acptr = find_person(nick, NULL))) /* normal nick */
	  typedest |= TO_NICK;
       else { /* privmsg @%+#channel */
	  chan = nick;
	  while(*chan) 
	  {

	     switch(*chan) {
		case '@' : 	typedest |= TO_OPS; 
				chan++; 
				continue;
#ifdef AZZURRA
		case '%' : 	typedest |= TO_HALFOP; 
				chan++; 
				continue;
#endif
		case '+' : 	typedest |= TO_VOICE; 
				chan++; 
				continue;
		default : 	break;
	     }
	     
	     /* another check to make sure that this messages is sent to a channel */
	     if (IsChannelName(chan))
		typedest |= TO_CHAN;

	     break;
	  }
       }

       if (chan && (!(chptr=find_channel(chan,NullChn))))
	  typedest = 0;
       
       /* Channel addressed? */
       if (typedest & TO_CHAN) 
       {
#ifdef SHUN
	  if (MyClient(sptr) && IsShunned(sptr))
	    continue;
#endif
	  if (!notice)
	    switch (check_for_ctcp(parv[2], NULL))
	    {
	     case CTCP_NONE:
	       break;

#ifdef AZZURRA
	     case CTCP_BOGUS:
#endif

	     case CTCP_DCCSEND:
	     case CTCP_DCC:
	       sendto_one(sptr, ":%s NOTICE %s :You may not send a DCC "
			  "command to a channel (%s)", me.name, parv[0], chan);
	       continue;

#ifdef AZZURRA
	     case CTCP_YES:
	       if(chptr->mode.mode & MODE_NOCTCP)
	       {
		  sendto_one(sptr, err_str(ERR_NOCTCPSTOCHAN), me.name, parv[0], chan, parv[2]);
		  continue;
	       }
#endif

	     default:
#ifdef FLUD
	       if (check_for_flud(sptr, NULL, chptr, 1))
		 return 0;
#endif
	       break;
	    }

#ifndef AZZURRA	  
	  ret = IsULine(sptr) ? 0 : can_send(sptr, chptr, parv[2]);
#else
	  ret = (IsULine(sptr) || IsUmodez(sptr)) ? 0 : can_send(sptr, chptr, parv[2]);
#endif	  
	  
	  if (MyClient(sptr) && ret == ERR_NOCOLORSONCHAN)
	  {
	     sendto_one(sptr, err_str(ERR_NOCOLORSONCHAN), me.name, parv[0], chan, parv[2]);
	     continue;
	  }

	  if (MyClient(sptr) && ret == ERR_NEEDREGGEDNICK)
	  {
	     sendto_one(sptr, err_str(ERR_NEEDREGGEDNICK), me.name, parv[0], chan, "speak in");		
	     continue;
	  }

	  if (ret)
	  {
	     if(!notice)
	       sendto_one(sptr, err_str(ERR_CANNOTSENDTOCHAN), me.name, parv[0], chan);
	     continue;
	  }

#ifdef AZZURRA
	  if (check_for_spam(sptr, parv[2], chan, notice ? "NOTICE" : "PRIVMSG"))
	    continue;
#endif

	  if (!((typedest & TO_OPS) || 
#ifdef AZZURRA
	        (typedest & TO_HALFOP) || 
#endif
                (typedest & TO_VOICE)))
	  {
	      sendto_channel_butone(cptr, sptr, chptr, ":%s %s %s :%s",
					parv[0], cmd, chan, parv[2]);
	  } else 
	  {

#ifdef AZZURRA
	      sendto_channelflag_butone(cptr, sptr, typedest, chptr, ":%s %s %s%s%s%s :%s",
				    parv[0], cmd, 
				    typedest & TO_OPS ? "@" : "",
				    typedest & TO_HALFOP ? "%" : "",
				    typedest & TO_VOICE ? "+" : "",
				    chan, parv[2]);
#else
	      sendto_channelflag_butone(cptr, sptr, typedest, chptr, ":%s %s %s%s%s :%s",
				    parv[0], cmd, 
				    typedest & TO_OPS ? "@" : "",
				    typedest & TO_VOICE ? "+" : "",
				    chan, parv[2]);
#endif
	  }

	  continue;
       }
	
       /* nickname addressed? */
       if (typedest & TO_NICK) 
       {
#ifdef SHUN
	  if (MyClient(sptr) && IsShunned(sptr) && !(sptr == acptr) && !IsULine(acptr))
	    continue;
#endif

#ifdef RESTRICT_USERS
	  if (MyClient(sptr) && !IsKnownNick(sptr) && !IsULine(acptr) && !IsAnOper(acptr))
	  {
	  	/* check if destination user is on a +U channel. If test is
		 * successful, allow message -int */
		Link *ptr = acptr->user->channel;
		int umodeu = 0;
		
		while (ptr) {
			if (ptr->value.chptr->mode.mode & MODE_UNRESTRICT) {
				umodeu = 1;
				break;
			}
			ptr = ptr->next;
		}
	  
	  	if (!umodeu && check_restricted_user(sptr))
	  		continue;
	  }
#endif

/*	  if (IsNoNonReg(acptr) && !IsRegNick(sptr) && !IsULine(sptr) && AZZURRA */
	  if (IsNoNonReg(acptr) && !IsRegNick(sptr) && !IsULine(sptr) && !IsServer(sptr) && !IsOper(sptr))
	  {
	     sendto_one(sptr, rpl_str(ERR_NONONREG), me.name, parv[0], acptr->name);
	     continue;
	  }

#ifdef MSG_TARGET_LIMIT
	  /* Only check target limits for my clients */
	  if (MyClient(sptr) && check_target_limit(sptr, acptr))
	    continue;
#endif

#ifdef FLUD
	  if (!notice && MyFludConnect(acptr))
#else
	  if (!notice && MyConnect(acptr))
#endif
	  {
	     
	     switch (check_for_ctcp(parv[2], &dccmsg))
	     {

	      case CTCP_NONE:
		break;

#ifdef AZZURRA
	      case CTCP_BOGUS:
		sendto_snotice("from %s: User %s (%s@%s) is trying to send a bogus DCC to %s (length: %d)",
			       me.name, parv[0], sptr->user->username, sptr->user->host, nick, strlen(parv[2]));

		sendto_serv_butone(NULL, ":%s SNOTICE :User %s (%s@%s) is trying to send a bogus DCC to %s (length: %d)",
				   me.name, parv[0], sptr->user->username, sptr->user->host, nick, strlen(parv[2]));

		continue;
#endif

	      case CTCP_DCCSEND:
#ifdef FLUD
		if (check_for_flud(sptr, acptr, NULL, 1))
		  return 0;
#endif
		
		if (check_dccsend(sptr, acptr, dccmsg))
		  continue;

		break;

	      default:
#ifdef FLUD
		if (check_for_flud(sptr, acptr, NULL, 1))
		  return 0;
#endif
		break;
	     }
	  }

#ifdef DENY_SERVICES_MSGS
	  if(MyClient(acptr) && !strcasecmp(NICKSERV,nick))
				sendto_one(sptr, rpl_str(ERR_MSGSERVICES), me.name, parv[0], NICKSERV, NICKSERV, NICKSERV);
	  else if(MyClient(acptr) && !strcasecmp(CHANSERV,nick))
				sendto_one(sptr, rpl_str(ERR_MSGSERVICES), me.name, parv[0], CHANSERV, CHANSERV, CHANSERV);
	  else if(MyClient(acptr) && !strcasecmp(MEMOSERV,nick))
				sendto_one(sptr, rpl_str(ERR_MSGSERVICES), me.name, parv[0], MEMOSERV, MEMOSERV, MEMOSERV);
	  else if(MyClient(acptr) && !strcasecmp(ROOTSERV,nick))
				sendto_one(sptr, rpl_str(ERR_MSGSERVICES), me.name, parv[0], ROOTSERV, ROOTSERV, ROOTSERV);
	  else
#endif
	    if (is_silenced(sptr, acptr))
	      continue;

#ifdef AZZURRA
	    if (!IsULine(acptr) && check_for_spam(sptr, parv[2], nick, notice ? "NOTICE" : "PRIVMSG"))
	    continue;
#endif
	    
	  if (!notice && MyClient(acptr) && acptr->user && acptr->user->away)
	  {
	     sendto_one(sptr, rpl_str(RPL_AWAY), me.name, parv[0], acptr->name, acptr->user->away);
	  }

	  sendto_prefix_one(acptr, sptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);
	  continue;
       }
		
#ifndef AZZURRA
       if(IsAnOper(sptr))
#else 
       if(IsSAdmin(sptr) || (IsAdmin(sptr) && *nick == '$' &&
			     !strcasecmp(nick + 1, me.name)))
#endif	 
       {

	  /*
	   * the following two cases allow masks in NOTICEs
	   * (for OPERs only) 
	   * 
	   * Armin, 8Jun90 (gruner@informatik.tu-muenchen.de)
	   */

	  if ((*nick == '$' || *nick == '#')) 
	  {

	     if (!(s = (char *) strrchr(nick, '.'))) 
	     {
		sendto_one(sptr, err_str(ERR_NOTOPLEVEL), me.name, parv[0], nick);
		continue;
	     }

	     while (*++s)
	       if (*s == '.' || *s == '*' || *s == '?')
		 break;

	     if (*s == '*' || *s == '?') 
	     {
		sendto_one(sptr, err_str(ERR_WILDTOPLEVEL), me.name, parv[0], nick);
		continue;
	     }

	     sendto_match_butone(IsServer(cptr) ? cptr : NULL, sptr, nick + 1,
				 (*nick == '#') ? MATCH_HOST : MATCH_SERVER, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);

	     continue;
	  }
       }

       /* user@server addressed? */
       if (!IsChannelName(nick) && (server = (char *) strchr(nick, '@')) && 
	   (acptr = find_server(server + 1, NULL))) 
       {

	  int count = 0;

	  /* Not destined for a user on me :-( */
	  if (!IsMe(acptr)) 
	  {
#ifdef SERVICESHUB
	     if(strcasecmp(server+1,SERVICES_NAME)!=0)
	       sendto_one(acptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);

	     else 
	     {

		if (!strcasecmp(nick,NICKSERVATSERVICES)) 
		{
		   
		   myparv[0]=parv[0];
		   myparv[1]=parv[2];
		   m_ns(cptr, sptr, parc-1, myparv);
		}
		else if (!strcasecmp(nick,CHANSERVATSERVICES)) 
		{
		   myparv[0]=parv[0];
		   myparv[1]=parv[2];
		   m_cs(cptr, sptr, parc-1, myparv);
		}
		else if(!strcasecmp(nick,MEMOSERVATSERVICES)) 
		{
		   myparv[0]=parv[0];
		   myparv[1]=parv[2];
		   m_ms(cptr, sptr, parc-1, myparv);
		}
		else if(!strcasecmp(nick,ROOTSERVATSERVICES)) {

		   myparv[0]=parv[0];
		   myparv[1]=parv[2];
		   m_rs(cptr, sptr, parc-1, myparv);
		}
		else
		  sendto_one(acptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);
	     }
#else
#ifdef SHUN
	     if (MyClient(sptr) && IsShunned(sptr) && !IsULine(acptr))
	       continue;
#endif
#ifdef AZZURRA
	     if (!IsULine(acptr) && check_for_spam(sptr, parv[2], nick, notice ? "NOTICE" : "PRIVMSG"))
	       continue;
#endif
	     sendto_one(acptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);
#endif
	     continue;
	  }

	  *server = '\0';

#ifdef SHUN
	  if (MyClient(sptr) && IsShunned(sptr) && !(sptr == acptr))
	    continue;
#endif
#ifdef AZZURRA
	  if (check_for_spam(sptr, parv[2], nick, notice ? "NOTICE" : "PRIVMSG"))
	    continue;
#endif

	  /*
	   * Look for users which match the destination host 
	   * (no host == wildcard) and if one and one only is found
	   * connected to me, deliver message!
	   */
	  
	  acptr = find_person(nick, NULL);
	  
	  if (server)
	    *server = '@';
	  
	  if (acptr) 
	  {
	     if (count == 1)
	       sendto_prefix_one(acptr, sptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);
	     
	     else if (!notice)
	       sendto_one(sptr, err_str(ERR_TOOMANYTARGETS), me.name, parv[0], nick);
	  }

	  if (acptr)
	    continue;
       }

       sendto_one_services(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], nick);
    }

    if ((i > 20) && sptr->user)
       sendto_realops_lev(SPY_LEV, "User %s (%s@%s) tried to msg %d users",
			  sptr->name, sptr->user->username, sptr->user->host, i);
   
    return 0;
}

/*
 * m_private 
 * parv[0] = sender prefix 
 * parv[1] = receiver list 
 * parv[2] = message text
 */

int m_private(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    return m_message(cptr, sptr, parc, parv, 0);
}

/*
 * m_notice *
 * parv[0] = sender prefix 
 * parv[1] = receiver list
 * parv[2] = notice text
 */

int m_notice(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    return m_message(cptr, sptr, parc, parv, 1);
}

#ifdef AZZURRA
static inline char * get_umode_str(aClient *acptr)
{
    register char *m;
    int f, *s;

    m = buf;
    *m++ = '+';
    for(s = user_modes; (f = *s) && (m - buf < BUFSIZE - 4) ; s += 2)
	if(acptr->umode & f)
	    *m++ = (char) (*(s + 1));
    *m = '\0';
    return buf;
}
#endif

/*
 * m_whois 
 * parv[0] = sender prefix 
 * parv[1] = nickname masklist
 */
int m_whois(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    static anUser UnknownUser =
    {
	NULL,			/* channel */
	NULL,			/* invited */
	NULL,			/* away */
	0,			/* last */
	0,			/* joined */
	"<Unknown>",		/* user */
	"<Unknown>",		/* host */
#ifdef AZZURRA
	"<Unknown>",		/* virthost */
#endif
	"<Unknown>",		/* server */
	0,  /* servicestamp */
	NULL /* silenced */
    };
    
    Link   *lp;
    anUser *user;
    aClient    *acptr, *a2cptr;
    aChannel   *chptr;
    char       *nick, *tmp, *name;
    char       *p = NULL;
    int         found, len, mlen;

    if (parc < 2)
    {
	sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN),
		   me.name, parv[0]);
	return 0;
    }

    if (parc > 2)
    {
	if (hunt_server(cptr, sptr, ":%s WHOIS %s :%s", 1, parc, parv) !=
	    HUNTED_ISME)
	    return 0;
	parv[1] = parv[2];    
    }
	
    for (tmp = parv[1]; (nick = strtoken(&p, tmp, ",")); tmp = NULL)
    {
	int         invis, member, showchan;
		
	found = 0;
	(void) collapse(nick);
	acptr = hash_find_client(nick, (aClient *) NULL);
	if (!acptr || !IsPerson(acptr))
	{
	    sendto_one(sptr, err_str(ERR_NOSUCHNICK),
		       me.name, parv[0], nick);
	    continue;
	}
#ifdef AZZURRA
	if (IsUmodey(acptr) && acptr != sptr)
	    sendto_one(acptr,
		    ":%s NOTICE %s :%s!%s@%s is doing a WHOIS on you",
		    me.name, acptr->name, parv[0], sptr->user->username,
		    sptr->user->host);
#endif

	user = acptr->user ? acptr->user : &UnknownUser;
	name = (!*acptr->name) ? "?" : acptr->name;
	invis = IsInvisible(acptr);
	member = (user->channel) ? 1 : 0;
		
	a2cptr = find_server(user->server, NULL);
		
	sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
		   parv[0], name, user->username, 
#ifdef AZZURRA
		   IsUmodex(acptr) ? user->virthost :
#endif
		   user->host, acptr->info);
#ifdef SHUN
	if (IsAnOper(sptr) && IsShunned(acptr))
	    sendto_one(sptr, rpl_str(RPL_SHUNNED),
		    me.name, parv[0], acptr->name);
#endif

#if (RIDICULOUS_PARANOIA_LEVEL>=1)
#if (RIDICULOUS_PARANOIA_LEVEL==1)
	if(MyConnect(acptr) && user->real_oper_host && (IsAdmin(sptr) || (sptr == acptr) || IsSAdmin(sptr)))
	{
	    sendto_one(sptr, rpl_str(RPL_WHOISACTUALLY),
		       me.name, sptr->name, name, 
#ifndef AZZURRA
		       user->real_oper_username,
#endif
		       user->real_oper_host, 
		       user->real_oper_ip);
	}
#ifdef AZZURRA
	else if(MyConnect(acptr) && user->real_helper_host && (IsAnOper(sptr) || (sptr == acptr)))
	{
	    sendto_one(sptr, rpl_str(RPL_WHOISACTUALLY),
		       me.name, sptr->name, name, 
		       user->real_helper_host, 
		       user->real_helper_ip);
	}
#endif
#endif 

#if (RIDICULOUS_PARANOIA_LEVEL==2)
	if(MyConnect(acptr) && user->real_oper_host && (IsAdmin(sptr) || (sptr == acptr) || IsSAdmin(sptr)) &&
	    MyConnect(sptr))
        {
            sendto_one(sptr, rpl_str(RPL_WHOISACTUALLY),
                       me.name, sptr->name, name,
#ifndef AZZURRA
                       user->real_oper_username,
#endif
		       user->real_oper_host,
                       user->real_oper_ip);
        }
#ifdef AZZURRA
	else if(MyConnect(acptr) && user->real_helper_host && (IsAnOper(sptr) || (sptr == acptr)) &&
	    MyConnect(sptr))
        {
            sendto_one(sptr, rpl_str(RPL_WHOISACTUALLY),
                       me.name, sptr->name, name,
		       user->real_helper_host,
                       user->real_helper_ip);
        }
#endif
#endif 
	else
#endif		

#ifdef AZZURRA
	if (CanShowIP(sptr, acptr) && IsAnOper(sptr))
	    sendto_one(sptr, rpl_str(RPL_WHOISACTUALLY),
		    me.name, parv[0], name,
		    user->host, acptr->hostip);

	if (IsAnOper(sptr))
	    sendto_one(sptr, rpl_str(RPL_WHOISMODES),
		    me.name, parv[0], name, get_umode_str(acptr));
#endif

	mlen = strlen(me.name) + strlen(parv[0]) + 6 +
	    strlen(name);
	for (len = 0, *buf = '\0', lp = user->channel; lp;
	     lp = lp->next)
	{
#ifdef AZZURRA
	    if(IsUmodez(acptr) && !IsAnOper(sptr))
		break;
#endif
	    chptr = lp->value.chptr;
	    showchan = ShowChannel(sptr,chptr);
	    if (showchan || IsAdmin(sptr) || IsSAdmin(sptr))
	    {
		if (len + strlen(chptr->chname)
		    > (size_t) BUFSIZE - 4 - mlen)
		{
		    sendto_one(sptr,
			       ":%s %d %s %s :%s",
			       me.name,
			       RPL_WHOISCHANNELS,
			       parv[0], name, buf);
		    *buf = '\0';
		    len = 0;
		}
		if(!showchan) /* if we're not really supposed to show the chan
			       * but do it anyways, mark it as such! */
#ifndef AZZURRA
		    *(buf + len++) = '%';
#else
		    *(buf + len++) = '-';
#endif
		if (is_chan_op(acptr, chptr))
		    *(buf + len++) = '@';
#ifdef AZZURRA
		else if (is_half_op(acptr, chptr))
		    *(buf + len++) = '%';
#endif
		else if (has_voice(acptr, chptr))
		    *(buf + len++) = '+';
		if (len)
		    *(buf + len) = '\0';
		(void) strcpy(buf + len, chptr->chname);
		len += strlen(chptr->chname);
		(void) strcat(buf + len, " ");
		len++;
	    }
	}
	if (buf[0] != '\0')
	    sendto_one(sptr, rpl_str(RPL_WHOISCHANNELS),
		       me.name, parv[0], name, buf);
	
	sendto_one(sptr, rpl_str(RPL_WHOISSERVER),
		   me.name, parv[0], name, user->server,
		   a2cptr ? a2cptr->info : "*Not On This Net*");
	if(IsRegNick(acptr))
	    sendto_one(sptr, rpl_str(RPL_WHOISREGNICK),
		       me.name, parv[0], name);
	if (user->away)
	    sendto_one(sptr, rpl_str(RPL_AWAY), me.name,
		       parv[0], name, user->away);
	if (IsUmodeS(acptr))
	    sendto_one(sptr, rpl_str(RPL_USINGSSL), me.name,
		       parv[0], name);
	
	buf[0]='\0';
	if (IsAnOper(acptr))
	{
	    strcat(buf, "an IRC Operator");

	    if (IsAdmin(acptr))
	    {
		strcat(buf, " - Server Administrator");
	    }
	    else if (IsSAdmin(acptr))
	    {
		strcat(buf, " - Services Administrator");
	    }

	    sendto_one(sptr, rpl_str(RPL_WHOISOPERATOR),
		       me.name, parv[0], name, buf);
	}
#ifdef AZZURRA
	else if (IsSAdmin(acptr))
	{
	    sendto_one(sptr, rpl_str(RPL_WHOISOPERATOR),
			me.name, parv[0], name, "a Services Administrator");
	}
#endif

#ifdef AZZURRA
	if (IsUmodez(acptr))
	    sendto_one(sptr, rpl_str(RPL_WHOISAGENT),
		    me.name, parv[0], name);

	if (IsUmodeh(acptr))
	    sendto_one(sptr, rpl_str(RPL_WHOISHELPER),
		    me.name, parv[0], name);
#endif

	if (acptr->user && MyConnect(acptr)
#ifdef AZZURRA
		&& (IsAnOper(sptr) || !IsHiddenIdle(acptr) || acptr == sptr)
#endif
		)
	    sendto_one(sptr, rpl_str(RPL_WHOISIDLE),
		       me.name, parv[0], name,
		       timeofday - user->last,
		       acptr->firsttime);
	
	continue;
	if (!found)
	    sendto_one(sptr, err_str(ERR_NOSUCHNICK),
		       me.name, parv[0], nick);
	if (p)
	    p[-1] = ',';
    }
    sendto_one(sptr, rpl_str(RPL_ENDOFWHOIS), me.name, parv[0], parv[1]);
    
    return 0;
}

/*
 * m_user 
 * parv[0] = sender prefix
 * parv[1] = username (login name, account) 
 * parv[2] = client host name (used only from other servers) 
 * parv[3] = server host name (used only from other servers)
 * parv[4] = users real name info
 */
int m_user(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
#define	UFLAGS	(UMODE_i|UMODE_w|UMODE_s)
    char       *username, *host, *server, *realname;
    aConfItem *aconf;
    
    if (parc > 2 && (username = (char *) strchr(parv[1], '@')))
	*username = '\0';
    if (parc < 5 || *parv[1] == '\0' || *parv[2] == '\0' ||
	*parv[3] == '\0' || *parv[4] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		   me.name, parv[0], "USER");
	if (IsServer(cptr))
	    sendto_realops("bad USER param count for %s from %s",
			   parv[0], get_client_name(cptr, FALSE));
	else
	    return 0;
    }
    /* Copy parameters into better documenting variables */   
    username = (parc < 2 || BadPtr(parv[1])) ? "<bad-boy>" : parv[1];
    host = (parc < 3 || BadPtr(parv[2])) ? "<nohost>" : parv[2];
    server = (parc < 4 || BadPtr(parv[3])) ? "<noserver>" : parv[3];
    realname = (parc < 5 || BadPtr(parv[4])) ? "<bad-realname>" : parv[4];
    if ((aconf = find_conf_name(realname, CONF_GCOS))) {
	return exit_client(cptr, sptr, sptr, BadPtr(aconf->passwd) ?
			   "Bad GCOS: Reason unspecified" : aconf->passwd);
    }
    return do_user(parv[0], cptr, sptr, username, host, server, 0, "0.0.0.0", realname);
}

/* do_user */
int do_user(char *nick, aClient *cptr, aClient *sptr, char *username,
	    char *host, char *server, unsigned long serviceid, char *ip,
	    char *realname)
{
    anUser     *user;
    
    long        oflags;
    int nothrottle = 0; /* this will be set to 1 if we don't have a valid ip */
        
    user = make_user(sptr);
    oflags = sptr->umode;

    
    /*
     * changed the goto into if-else...   -Taner 
     * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ GOOD FOR YOU Taner!!! - Dianora 
     */
    
    if (!MyConnect(sptr))
    {
	user->server = find_or_add(server);
	strncpyzt(user->host, host, sizeof(user->host));
    } 
    else
    {
	if (!IsUnknown(sptr))
	{
	    sendto_one(sptr, err_str(ERR_ALREADYREGISTRED),
		       me.name, nick);
	    return 0;
	}
#ifndef	NO_DEFAULT_INVISIBLE
	sptr->umode |= UMODE_i;
#endif

#ifndef INET6
#if defined(AZZURRA) && !defined(NO_DEFAULT_UMODEX)
	if(!(sptr->user->real_oper_host) && !(IsIPv6(sptr)))
	    SetCloak(sptr);
#endif
#endif
#ifdef USE_SSL
	if(IsSSL(sptr))
	    SetSSLUmode(sptr);
#endif
	
	sptr->umode |= (UFLAGS & atoi(host));
	strncpyzt(user->host, host, sizeof(user->host));
	user->server = me.name;
    }
    strncpyzt(sptr->info, realname, sizeof(sptr->info));
    
    sptr->user->servicestamp = serviceid;
    if (!MyConnect(sptr))
    {
    	strncpyzt(sptr->hostip, ip, HOSTIPLEN+1);
#ifndef INET6
	if (!((index(ip, '.') && inet_aton(ip, &sptr->ip))))
	{
		nothrottle = 1;
		sptr->ip.S_ADDR = INADDR_ANY;
	}
#else
	if (!(index(ip, ':') && inet_pton(AF_INET6, ip, (void *)sptr->ip.S_ADDR)))
	{
		nothrottle = 1;
        	memset(sptr->ip.S_ADDR, 0x0, sizeof(struct IN_ADDR));
	}
#endif
	/* add non-local clients to the throttle checker.  obviously, we only
	 * do this for REMOTE clients!@$$@!  throttle_check() is called
	 * elsewhere for the locals! -wd */
#ifdef THROTTLE_ENABLE
	if (nothrottle == 0) 
	   throttle_check(inet_ntop(AFINET, (char *)&sptr->ip, mydummy,
		       sizeof(mydummy)), -1, sptr->tsinfo);
#endif
    }

    if(MyConnect(sptr))
	sptr->oflag=0;
    if (sptr->name[0])		/* NICK already received, now I have USER... */
	return register_user(cptr, sptr, sptr->name, username);
    else
	strncpyzt(sptr->user->username, username, USERLEN + 1);
    return 0;
}

/*
 * m_quit 
 * parv[0] = sender prefix 
 * parv[1] = comment
 */
int m_quit(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *reason = (parc > 1 && parv[1]) ? parv[1] : cptr->name;
    char        comment[TOPICLEN + 1];
    
    sptr->flags |= FLAGS_NORMALEX;
    if (!IsServer(cptr))
    {
	strcpy(comment, "Quit: ");
#if defined( AZZURRA )
	if(!IsShunned(cptr) && !check_for_spam(sptr, reason, "*", "QUIT"))
#elif defined( SHUN )
	if(!IsShunned(cptr))
#endif
	    strncpy(comment + 6, reason, TOPICLEN - 6);
	comment[TOPICLEN] = 0;
	return exit_client(cptr, sptr, sptr, comment);
    }
    else
	return exit_client(cptr, sptr, sptr, reason);
}

/*
 * m_kill 
 * parv[0] = sender prefix 
 * parv[1] = kill victim 
 * parv[2] = kill path
 */
int m_kill(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient    *acptr;
    char       *user, *path, *killer, *p, *nick;
    char mypath[KILLLEN + 1];
    char       *unknownfmt = "<Unknown>";	/*
						 * AFAIK this shouldnt happen
						 * but -Raist 
						 */
    int         chasing = 0, kcount = 0;
    
    if (parc < 2 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		   me.name, parv[0], "KILL");
	return 0;
    }
    
    user = parv[1];
    path = parv[2];		/* Either defined or NULL (parc >= 2!!) */
    if(path==NULL)
	path=")";
    
    if (!IsPrivileged(cptr))
    {
	sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
	return 0;
    }
    if (!BadPtr(path))
	if (strlen(path) > (size_t) KILLLEN)
	    path[KILLLEN] = '\0';
    if (MyClient(sptr))
	user = canonize(user);
    for (p = NULL, nick = strtoken(&p, user, ","); nick;
	 nick = strtoken(&p, NULL, ","))
    {
	chasing = 0;
	if (!(acptr = find_client(nick, NULL)))
	{
	    /*
	     * If the user has recently changed nick, we automaticly
	     * rewrite the KILL for this new nickname--this keeps
	     * servers in synch when nick change and kill collide
	     */
	    if (!(acptr = get_history(nick, (long) KILLCHASETIMELIMIT)))
	    {
		sendto_one(sptr, err_str(ERR_NOSUCHNICK),
			   me.name, parv[0], nick);
		continue; /* XXX AZZURRA CHANGED (return 0) */
	    }
	    sendto_one(sptr, ":%s NOTICE %s :KILL changed from %s to %s",
		       me.name, parv[0], nick, acptr->name);
	    chasing = 1;
	}
#ifdef AZZURRA
	if (IsUmodez(acptr))
	{
	    if(MyConnect(sptr))
		sendto_one(sptr, err_str(ERR_CANNOTKILLMODEZ), me.name,
			parv[0]);
	    continue;
	}
#endif
	if ((!MyConnect(acptr) && MyClient(cptr) && !OPCanGKill(cptr)) ||
	    (MyConnect(acptr) && MyClient(cptr) && 
	     !OPCanLKill(cptr)))
	{
	    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
	    continue;
	}
	if (IsServer(acptr) || IsMe(acptr) ||	 
		(MyClient(sptr) && IsULine(acptr)))
	{
	    sendto_one(sptr, err_str(ERR_CANTKILLSERVER),
		       me.name, parv[0]);
	    continue;
	}
	kcount++;
	if (!IsServer(sptr) && (kcount > MAXKILLS))
	{
	    sendto_one(sptr,":%s NOTICE %s :Too many targets, kill list was "
		       "truncated. Maximum is %d.", me.name, sptr->name,
		       MAXKILLS);
	    break;
	}
		
	if(MyClient(sptr)) 
	{
	    char myname[HOSTLEN+1], *s;
	    int slen;

	    strncpy(myname, me.name, HOSTLEN + 1);
	    if((s = index(myname, '.')))
		*s=0;
	    
	    /* "<myname>!<sptr->user->host>!<sptr->name> (path)" */
#ifndef AZZURRA
	    slen = KILLLEN - (strlen(sptr->name) + strlen(sptr->user->host) + strlen(myname) + 8);
#else
	    slen = KILLLEN - (strlen(sptr->name) + strlen((IsUmodex(sptr) ?
			    sptr->user->virthost : sptr->user->host)) + strlen(myname) + 8);
#endif
	    if(slen < 0)
		slen = 0;
	    
	    if(strlen(path) > slen) 
		path[slen] = '\0'; 
	    
#ifndef AZZURRA
	    ircsnprintf(mypath, KILLLEN, "%s!%s!%s (%s)", myname, sptr->user->host, sptr->name, path); 
#else
	    ircsnprintf(mypath, KILLLEN, "%s!%s!%s (%s)", myname, IsUmodex(sptr) ?
		    sptr->user->virthost : sptr->user->host, sptr->name, path);
#endif

	    mypath[KILLLEN]='\0';  
	}
	else
	    strncpy(mypath, path, KILLLEN + 1);
	/*
	 * Notify all *local* opers about the KILL, this includes the
	 * one originating the kill, if from this server--the special
	 * numeric reply message is not generated anymore.
	 * 
	 * Note: "acptr->name" is used instead of "user" because we may
	 * have changed the target because of the nickname change.
	 */
	if (IsLocOp(sptr) && !MyConnect(acptr)) 
	{
	    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
	    return 0;
	}
#ifndef AZZURRA
	if (IsAnOper(sptr))
	    sendto_ops_lev(0, "Received KILL message for %s!%s@%s. From %s "
			   "Path: %s", acptr->name, 
			   acptr->user ? acptr->user->username : unknownfmt,
			   acptr->user ? acptr->user->host : unknownfmt,
			   parv[0], mypath);
	else
#endif
	if(IsULine(sptr))
	{
	    sendto_ops_lev(USKILL_LEV, "Received KILL message for %s!%s@%s. "
			   "From %s Path: %s", acptr->name,
			   acptr->user ? acptr->user->username : unknownfmt,
			   acptr->user ? acptr->user->host : unknownfmt,
			   parv[0], mypath);
	}
	else
	{
	    sendto_ops_lev(SKILL_LEV, "Received KILL message for %s!%s@%s. "
			   "From %s Path: %s", acptr->name,
			   acptr->user ? acptr->user->username : unknownfmt,
			   acptr->user ? acptr->user->host : unknownfmt,
			   parv[0], mypath);
	}
	    
		
#if defined(USE_SYSLOG) && defined(SYSLOG_KILL)
	if (IsOper(sptr))
	    syslog(LOG_INFO, "KILL From %s!%s@%s For %s!%s@%s Path %s",
		   sptr->name, sptr->user->username, sptr->user
		   ->host, acptr->name, acptr->user ? acptr->user
		   ->username : unknownfmt, acptr->user ? acptr->user
		   ->host : unknownfmt, mypath);
#endif
	/*
	 * And pass on the message to other servers. Note, that if KILL
	 * was changed, the message has to be sent to all links, also
	 * back. Suicide kills are NOT passed on --SRB
	 */
	if (!MyConnect(acptr) || !MyConnect(sptr) || !IsAnOper(sptr))
	{
	    sendto_serv_butone(cptr, ":%s KILL %s :%s",
			       parv[0], acptr->name, mypath);
	    if (chasing && IsServer(cptr))
		sendto_one(cptr, ":%s KILL %s :%s",
			   me.name, acptr->name, mypath);
	    acptr->flags |= FLAGS_KILLED;
	}
	/*
	 * Tell the victim she/he has been zapped, but *only* if the
	 * victim is on current server--no sense in sending the
	 * notification chasing the above kill, it won't get far anyway
	 * as this user don't exist there any more either
	 */
	if (MyConnect(acptr))
	    sendto_prefix_one(acptr, sptr, ":%s KILL %s :%s",
			      parv[0], acptr->name, mypath);
	/*
	 * Set FLAGS_KILLED. This prevents exit_one_client from sending
	 * the unnecessary QUIT for this. ,This flag should never be
	 * set in any other place...
	 */
	if (MyConnect(acptr) && MyConnect(sptr) && IsAnOper(sptr))
	    (void) ircsprintf(buf2, "Local kill by %s (%s)", sptr->name,
			      BadPtr(parv[2]) ? sptr->name : parv[2]);
	else 
	{
	    killer = strchr(mypath, '(');
	    if(killer==NULL)
		killer="()";
	    (void)ircsprintf(buf2, "Killed (%s %s)", sptr->name, killer);
	}
	if (exit_client(cptr, acptr, sptr, buf2) == FLUSH_BUFFER)
	    return FLUSH_BUFFER;
    }
    return 0;
}

/***********************************************************************
 * m_away() - Added 14 Dec 1988 by jto.
 *            Not currently really working, I don't like this
 *            call at all...
 *
 *            ...trying to make it work. I don't like it either,
 *	      but perhaps it's worth the load it causes to net.
 *	      This requires flooding of the whole net like NICK,
 *	      USER, MODE, etc messages...  --msa
 *
 * 	      Added FLUD-style limiting for those lame scripts out there.
 ***********************************************************************/
/*
 * m_away 
 * parv[0] = sender prefix 
 * parv[1] = away message
 */
int m_away(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char   *away, *awy2 = parv[1];
    /* make sure the user exists */
    if (!(sptr->user)) 
    {
	sendto_realops_lev(DEBUG_LEV, "Got AWAY from nil user, from %s (%s)\n",
			   cptr->name, sptr->name);
	return 0;
    }
    
    away = sptr->user->away;
    
#ifdef NO_AWAY_FLUD
    if(MyClient(sptr))
    {
	if ((sptr->alas + MAX_AWAY_TIME) < NOW)
	    sptr->acount = 0;
	sptr->alas = NOW;
	sptr->acount++;
    }
#endif 
    
    if (parc < 2 || !*awy2)
    {
	/* Marking as not away */

	if (away) 
	{
	    MyFree(away);
	    sptr->user->away = NULL;
	    /* Don't spam unaway unless they were away - lucas */
	    sendto_serv_butone_services(cptr, ":%s AWAY", parv[0]);
	}
	
	if (MyConnect(sptr))
	    sendto_one(sptr, rpl_str(RPL_UNAWAY),
		       me.name, parv[0]);
	return 0;
    }

    /* Marking as away */
#ifdef NO_AWAY_FLUD
    /* we dont care if they are just unsetting away, hence this is here */
    /* only care about local non-opers */
    if (MyClient(sptr) && (sptr->acount > MAX_AWAY_COUNT) && !IsAnOper(sptr))
    {
	sendto_one(sptr, err_str(ERR_TOOMANYAWAY), me.name, parv[0]);
	return 0;
    }
#endif
    if (strlen(awy2) > (size_t) TOPICLEN)
	awy2[TOPICLEN] = '\0';
    /*
     * some lamers scripts continually do a /away, hence making a lot of
     * unnecessary traffic. *sigh* so... as comstud has done, I've
     * commented out this sendto_serv_butone() call -Dianora
     * readded because of anti-flud stuffs -epi
     */
    
    sendto_serv_butone_services(cptr, ":%s AWAY :%s", parv[0], parv[1]);

    if (away)
	MyFree(away);
    
    away = (char *) MyMalloc(strlen(awy2) + 1);
    strcpy(away, awy2);

    sptr->user->away = away;

    if (MyConnect(sptr))
	sendto_one(sptr, rpl_str(RPL_NOWAWAY), me.name, parv[0]);
    return 0;
}

/*
 * m_ping 
 * parv[0] = sender prefix 
 * parv[1] = origin
 * parv[2] = destination
 */
int m_ping(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient    *acptr;
    char       *origin, *destination;
    
    if (parc < 2 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NOORIGIN), me.name, parv[0]);
	return 0;
    }
    origin = parv[1];
    destination = parv[2];	/* Will get NULL or pointer (parc >= 2!!) */
    
    acptr = find_client(origin, NULL);
    if (!acptr)
	acptr = find_server(origin, NULL);
    if (acptr && acptr != sptr)
	origin = cptr->name;
    if (!BadPtr(destination) && mycmp(destination, me.name) != 0)
    {
	if ((acptr = find_server(destination, NULL)))
	    sendto_one(acptr, ":%s PING %s :%s", parv[0],
		       origin, destination);
	else
	{
	    sendto_one(sptr, err_str(ERR_NOSUCHSERVER),
		       me.name, parv[0], destination);
	    return 0;
	}
    }
    else
	sendto_one(sptr, ":%s PONG %s :%s", me.name,
		   (destination) ? destination : me.name, origin);
    return 0;
}

/*
 * m_pong 
 * parv[0] = sender prefix 
 * parv[1] = origin
 * parv[2] = destination
 */
int m_pong(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient    *acptr;
    char       *origin, *destination;

    if (parc < 2 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NOORIGIN), me.name, parv[0]);
	return 0;
    }

    origin = parv[1];
    destination = parv[2];
    cptr->flags &= ~FLAGS_PINGSENT;
    sptr->flags &= ~FLAGS_PINGSENT;

    /* if it's my client and it's a server.. */
    if(sptr == cptr && IsServer(cptr))
    {
	if(sptr->flags & FLAGS_USERBURST)
	{
	    sptr->flags &= ~FLAGS_USERBURST;
	    sendto_gnotice("from %s: %s has processed user/channel burst, "
			   "sending topic burst.", me.name, sptr->name);
#ifdef SERVICESHUB 
            /* services doesn't care about TOPICs during a sync or AWAY messages */
            if(strcasecmp(cptr->name,SERVICES_NAME)!=0 && strcasecmp(cptr->name,STATS_NAME)!=0)
#endif
		send_topic_burst(sptr);

	    sptr->flags |= FLAGS_PINGSENT|FLAGS_SOBSENT;
	    sendto_one(sptr, "PING :%s", me.name);
	}
	else if(sptr->flags & FLAGS_TOPICBURST)
	{
	    sptr->flags &= ~FLAGS_TOPICBURST;
	    sendto_gnotice("from %s: %s has processed topic burst (synched "
			   "to network data).", me.name, sptr->name);
#ifdef HUB
	    sendto_serv_butone(sptr, ":%s GNOTICE :%s has synched to network "
			       "data.", me.name, sptr->name);
#endif
	    /* Kludge: Get the "sync" message on small networks immediately */ 
	    sendto_one(sptr, "PING :%s", me.name);
	}
    }

    /*
     * Now attempt to route the PONG, comstud pointed out routable PING
     * is used for SPING.  routable PING should also probably be left in
     * -Dianora That being the case, we will route, but only for
     * registered clients (a case can be made to allow them only from
     * servers). -Shadowfax
     */
    if (!BadPtr(destination) && mycmp(destination, me.name) != 0
	&& IsRegistered(sptr))
    {
	if ((acptr = find_client(destination, NULL)) ||
	    (acptr = find_server(destination, NULL)))
	    sendto_one(acptr, ":%s PONG %s %s",
		       parv[0], origin, destination);
	else
	{
	    sendto_one(sptr, err_str(ERR_NOSUCHSERVER),
		       me.name, parv[0], destination);
	    return 0;
	}
    }
    
#ifdef	DEBUGMODE
    else
	Debug((DEBUG_NOTICE, "PONG: %s %s", origin,
	       destination ? destination : "*"));
#endif
    return 0;
}

#if (RIDICULOUS_PARANOIA_LEVEL>=1)
int check_oper_can_mask(aClient *sptr, char *name, char *password,
			char **onick, int *global)
{
    aConfItem *aconf;
    char *encr;

#ifdef CRYPT_OPER_PASSWORD
    extern char *crypt();
#endif

    if (!(aconf = find_conf_exact(name, sptr->username, sptr->sockhost,
				  CONF_OPS)) &&
	!(aconf = find_conf_exact(name, sptr->username, sptr->hostip,
				  CONF_OPS))) 
    {
	sendto_realops("Failed OPERMASK attempt by %s (%s@%s) [No Entry for "
		       "%s]", sptr->name, sptr->user->username,
		       sptr->user->host, name);
	return 0;
    }
    
#ifdef CRYPT_OPER_PASSWORD
    /* use first two chars of the password they send in as salt */
    /* passwd may be NULL pointer. Head it off at the pass... */
    if (password && *aconf->passwd)
	encr = crypt(password, aconf->passwd);
    else
	encr = "";
#else
    encr = password;
#endif /* CRYPT_OPER_PASSWORD */
    
    if(StrEq(encr, aconf->passwd))
    {
#ifdef USE_SYSLOG
	syslog(LOG_INFO, "OPERMASK: %s (%s!%s@%s)", aconf->name, sptr->name,
	       sptr->user->username, sptr->user->host);
#endif
	*onick = aconf->name;
	*global = (aconf->port & OFLAG_ISGLOBAL);
	sendto_realops("%s oper %s [%s] (%s@<hidden>) has masked their hostname.",
		       *global ? "Global" : "Local", sptr->name, aconf->name,
		       sptr->user->username);
	return 1;
    }

    sendto_realops("Failed OPERMASK attempt by %s (%s@%s) [Bad Password]",
		   sptr->name, sptr->user->username, sptr->user->host);

    return 0;
}
#ifdef AZZURRA
int check_helper_can_mask(aClient *sptr, char *name, char *password,
			char **onick)
{
    aConfItem *aconf;
    char *encr;

#ifdef CRYPT_OPER_PASSWORD
    extern char *crypt();
#endif

    if (!(aconf = find_conf_exact(name, sptr->username, sptr->sockhost,
				  CONF_HELPER)) &&
	!(aconf = find_conf_exact(name, sptr->username, sptr->hostip,
				  CONF_HELPER))) 
    {
	sendto_realops("Failed HELPERMASK attempt by %s (%s@%s) [No Entry for "
		       "%s]", sptr->name, sptr->user->username,
		       sptr->user->host, name);
	return 0;
    }
    
#ifdef CRYPT_OPER_PASSWORD
    /* use first two chars of the password they send in as salt */
    /* passwd may be NULL pointer. Head it off at the pass... */
    if (password && *aconf->passwd)
	encr = crypt(password, aconf->passwd);
    else
	encr = "";
#else
    encr = password;
#endif /* CRYPT_OPER_PASSWORD */
    
    if(StrEq(encr, aconf->passwd))
    {
#ifdef USE_SYSLOG
	syslog(LOG_INFO, "HELPERMASK: %s (%s!%s@%s)", aconf->name, sptr->name,
	       sptr->user->username, sptr->user->host);
#endif
	*onick = aconf->name;
	sendto_realops("%s [%s] (%s@<hidden>) has masked their hostname.",
		       sptr->name, aconf->name, sptr->user->username);
	return 1;
    }

    sendto_realops("Failed HELPERMASK attempt by %s (%s@%s) [Bad Password]",
		   sptr->name, sptr->user->username, sptr->user->host);

    return 0;
}
#endif
#endif

/*
 * m_oper 
 * parv[0] = sender prefix 
 * parv[1] = oper name 
 * parv[2] = oper password
 */
int m_oper(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aConfItem  *aconf;
    char       *name, *password, *encr, *oper_ip;

#ifdef CRYPT_OPER_PASSWORD
    extern char *crypt();

#endif /* CRYPT_OPER_PASSWORD */

    name = parc > 1 ? parv[1] : (char *) NULL;
    password = parc > 2 ? parv[2] : (char *) NULL;

    if (!IsServer(cptr) && (BadPtr(name) || BadPtr(password)))
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		   me.name, parv[0], "OPER");
	return 0;
    }

    /* if message arrived from server, trust it, and set to oper */

    if ((IsServer(cptr) || IsMe(cptr)) && !IsOper(sptr))
    {
#ifdef DEFAULT_HELP_MODE
	sptr->umode |= UMODE_o;
	sptr->umode |= UMODE_h;
	sendto_serv_butone(cptr, ":%s MODE %s :+oh", parv[0], parv[0]);
#else
	sptr->umode |= UMODE_o;
	sendto_serv_butone(cptr, ":%s MODE %s :+o", parv[0], parv[0]);
#endif
	Count.oper++;
	if (IsMe(cptr))
	    sendto_one(sptr, rpl_str(RPL_YOUREOPER),
		       me.name, parv[0]);
	return 0;
    }
    else if (IsAnOper(sptr))
    {
	if (MyConnect(sptr))
	    sendto_one(sptr, rpl_str(RPL_YOUREOPER),
		       me.name, parv[0]);
	return 0;
    }

#if (RIDICULOUS_PARANOIA_LEVEL>=1)
	if(!(sptr->user && sptr->user->real_oper_host)) {
#endif

		if (!(aconf = find_conf_exact(name, sptr->username, sptr->sockhost, CONF_OPS)) && 
			!(aconf = find_conf_exact(name, sptr->username, cptr->hostip, CONF_OPS))) {

			sendto_one(sptr, err_str(ERR_NOOPERHOST), me.name, parv[0]);
			sendto_realops("Failed OPER attempt by %s (%s@%s)", parv[0],
				sptr->user->username, sptr->user->host);
#ifdef AZZURRA
			sendto_security(NULL, "Failed OPER attempt by %s (%s@%s) [%s %s]",
				parv[0], sptr->user->username, sptr->user->host, name,
#ifdef FAILEDOPER_SHOWPASS			    
			    password);
#else
				"HIDDEN");
#endif
#endif


			return 0;
		}

		oper_ip = sptr->hostip;
#if (RIDICULOUS_PARANOIA_LEVEL>=1)
	}
	else {

		if (!(aconf = find_conf_exact(name, sptr->user->real_oper_username, sptr->user->real_oper_host, CONF_OPS)) &&
			!(aconf = find_conf_exact(name, sptr->user->real_oper_username, sptr->user->real_oper_ip, CONF_OPS))) {

				sendto_one(sptr, err_str(ERR_NOOPERHOST), me.name, parv[0]);
				sendto_realops("Failed OPER attempt by %s (%s@%s)", parv[0],
					sptr->user->username, sptr->user->host);

#ifdef AZZURRA	  
				sendto_security(NULL, "Failed OPER attempt by %s (%s@%s) [%s %s]",
					parv[0], sptr->user->username, sptr->user->host, name,
#ifdef FAILEDOPER_SHOWPASS			    
					password);
#else
					"HIDDEN");
#endif
#endif

			return 0;
		}

		oper_ip = sptr->user->real_oper_ip;
	}
#endif
#ifdef CRYPT_OPER_PASSWORD
    /* use first two chars of the password they send in as salt */
    /* passwd may be NULL pointer. Head it off at the pass... */
    if (password && *aconf->passwd)
		encr = crypt(password, aconf->passwd);
    else
		encr = "";
#else
    encr = password;
#endif /* CRYPT_OPER_PASSWORD */

	if ((aconf->status & CONF_OPS) && StrEq(encr, aconf->passwd) && !attach_conf(sptr, aconf)) {

		int         old = (sptr->umode & ALL_UMODES);
		char       *s;
	
		s = strchr(aconf->host, '@');

		if (s == (char *) NULL) {

			sendto_one(sptr, err_str(ERR_NOOPERHOST), me.name, parv[0]);
			sendto_realops("corrupt aconf->host = [%s]", aconf->host);
			return 0;
		}

		*s++ = '\0';

		if (!(aconf->port & OFLAG_ISGLOBAL))
			SetLocOp(sptr);
		else
			SetOper(sptr);

#ifdef DEFAULT_HELP_MODE			
		sptr->umode|=(UMODE_s|UMODE_g|UMODE_w|UMODE_n|UMODE_h);
#else			
		sptr->umode|=(UMODE_s|UMODE_g|UMODE_w|UMODE_n);
#endif

		sptr->oflag = aconf->port;
		Count.oper++;
		*--s = '@';
		addto_fdlist(sptr->fd, &oper_fdlist);
		throttle_remove(oper_ip);
		sendto_ops("%s (%s@%s) is now operator (%c)", parv[0],
			sptr->user->username, sptr->sockhost, IsOper(sptr) ? 'O' : 'o');

#ifdef AZZURRA
		sendto_security(NULL, "%s (%s@%s) is now operator (%c)",
			parv[0], sptr->user->username, sptr->user->host, IsOper(sptr) ? 'O' : 'o');
#endif

		send_umode_out(cptr, sptr, old);
		sendto_one(sptr, rpl_str(RPL_YOUREOPER), me.name, parv[0]);
		sptr->pingval = get_client_ping(sptr);
		sptr->sendqlen = get_sendq(sptr);
#if !defined(CRYPT_OPER_PASSWORD) && (defined(FNAME_OPERLOG) || (defined(USE_SYSLOG) && defined(SYSLOG_OPER)))
		encr = "";
#endif
#if defined(USE_SYSLOG) && defined(SYSLOG_OPER)
		syslog(LOG_INFO, "OPER (%s) (%s) by (%s!%s@%s)", name, encr, parv[0], sptr->user->username, sptr->sockhost);
#endif
#if defined(FNAME_OPERLOG)
		{
			int         logfile;
			
			/*
			* This conditional makes the logfile active only after it's
			* been created - thus logging can be turned off by removing
			* the file.
			* 
			* stop NFS hangs...most systems should be able to open a file in
			* 3 seconds. -avalon (curtesy of wumpus)
			*/

			(void) alarm(3);
			if (IsPerson(sptr) && (logfile = open(FNAME_OPERLOG, O_WRONLY | O_APPEND)) != -1) {

				(void) alarm(0);
				(void) ircsprintf(buf, "%s OPER (%s) (%s) by (%s!%s@%s)\n",
					myctime(timeofday), name, encr, parv[0], sptr->user->username, sptr->sockhost);

				(void) alarm(3);
				(void) write(logfile, buf, strlen(buf));
				(void) alarm(0);
				(void) close(logfile);
			}

			(void) alarm(0);
			/* Modification by pjg */
		}
#endif
	}
    else {

		(void) detach_conf(sptr, aconf);
		sendto_one(sptr, err_str(ERR_PASSWDMISMATCH), me.name, parv[0]);
#ifdef FAILED_OPER_NOTICE
		sendto_realops("Failed OPER attempt by %s (%s@%s)",
			parv[0], sptr->user->username, sptr->sockhost);
#endif
#ifdef AZZURRA
		sendto_security(NULL, "Failed OPER attempt by %s (%s@%s) (Password mismatch)",
			parv[0], sptr->user->username, sptr->user->host);
#endif
	}

    return 0;
}

/***************************************************************************
 * m_pass() - Added Sat, 4 March 1989
 ***************************************************************************/
/*
 * m_pass 
 * parv[0] = sender prefix 
 * parv[1] = password
 * parv[2] = optional extra version information
 */
int m_pass(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *password = parc > 1 ? parv[1] : NULL;
    
    if (BadPtr(password))
    {
	sendto_one(cptr, err_str(ERR_NEEDMOREPARAMS),
		   me.name, parv[0], "PASS");
	return 0;
    }
#ifndef AZZURRA
    if (!MyConnect(sptr) || (!IsUnknown(cptr) && !IsHandshake(cptr)))
    {
	sendto_one(cptr, err_str(ERR_ALREADYREGISTRED),
		   me.name, parv[0]);
	return 0;
    }
#else
    if (!MyConnect(sptr))
    {
	sendto_one(cptr, err_str(ERR_ALREADYREGISTRED),
		me.name, parv[0]);
	return 0;
    }
    else if (!IsUnknown(cptr) && !IsHandshake(cptr))
    {
	static char passbuf[NICKLEN + 32 + 2]; /* PASSMAX in services == 32,
						* plus space plus NULL */
	static char *myparv[3];
	
	myparv[0] = parv[0];
	
	if(parc > 2)
	{
	    if(strlen(parv[2]) < 5)
		return 0;
	    snprintf(passbuf, sizeof(passbuf), "%s %s", parv[1], parv[2]);
	}
	else
	{
	    if(strlen(parv[1]) < 5)
		return 0;
	    strncpyzt(passbuf, parv[1], sizeof(passbuf));
	}
	myparv[1] = passbuf;
	myparv[2] = NULL;
	
	return m_identify(cptr, sptr, 2, myparv);
    }
#endif
    
    strncpyzt(cptr->passwd, password, sizeof(cptr->passwd));
    if (parc > 2)
    {
	int         l = strlen(parv[2]);
	
	if (l < 2)
	    return 0;

	if (parv[2][0] == 'T' && parv[2][1] == 'S')
	    cptr->tsinfo = (ts_val) TS_DOESTS;
    }
    return 0;
}

/*
 * m_userhost added by Darren Reed 13/8/91 to aid clients and reduce
 * the need for complicated requests like WHOIS. It returns user/host
 * information only (no spurious AWAY labels or channels).
 */
int m_userhost(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *p = NULL;
    aClient    *acptr;
    char   *s;
    int     i, len, res = 0;
    
    ircsprintf(buf, rpl_str(RPL_USERHOST), me.name, parv[0]);
    len = strlen(buf);

    for (i = 5, s = strtoken(&p, parv[1], " "); i && s;
	 s = strtoken(&p, (char *) NULL, " "), i--)
	if ((acptr = find_person(s, NULL)))
	{
	    if (++res > 1)
               buf[len++] = ' ';

	    len += ircsnprintf(buf + len, sizeof(buf) - (len + 1), "%s%s=%c%s@%s",
			      acptr->name,
			      IsAnOper(acptr) ? "*" : "",
			      (acptr->user->away) ? '-' : '+',
			      acptr->user->username,
#if defined( AZZURRA )
			      (acptr == sptr) ?
				  ((acptr->confs->value.aconf->flags & CONF_FLAGS_I_FASTWEBPORT) ? // thanks 2: G
				  acptr->hostip : acptr->user->host) :
			      (IsUmodex(acptr) ? acptr->user->virthost :
			      acptr->user->host)
#else
			      acptr->user->host
#endif
			      );
	    
	}
    sendto_one(sptr, "%s", buf);
    return 0;
}

/*
 * m_ison added by Darren Reed 13/8/91 to act as an efficent user
 * indicator with respect to cpu/bandwidth used. Implemented for NOTIFY
 * feature in clients. Designed to reduce number of whois requests. Can
 * process nicknames in batches as long as the maximum buffer length.
 * 
 * format: ISON :nicklist
 */
/* Take care of potential nasty buffer overflow problem -Dianora */

int m_ison(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *acptr;
    char   *s, **pav = parv;
    char       *p = (char *) NULL;
    int     len;
    int     len2;

    if (parc < 2) 
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		   me.name, parv[0], "ISON");
	return 0;
    }

    (void) ircsprintf(buf, rpl_str(RPL_ISON), me.name, *parv);
    len = strlen(buf);
    if (!IsOper(cptr))
	cptr->priority += 20;	/* this keeps it from moving to 'busy' list  */
    for (s = strtoken(&p, *++pav, " "); s;
	 s = strtoken(&p, (char *) NULL, " "))
	if ((acptr = find_person(s, NULL))) 
	{
	    len2 = strlen(acptr->name);
	    if ((len + len2 + 5) < sizeof(buf)) /* make sure can never */
	    {                                   /* overflow */
		(void) strcat(buf, acptr->name);
		len += len2;
		(void) strcat(buf, " ");
		len++;
	    }
	    else
		break;
	}
    sendto_one(sptr, "%s", buf);
    return 0;
}

/*
 * m_umode2() --vjt
 * UMODE +x == MODE parv[0] +x
 */

int
m_umode2(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    static char *myparv[4];

    myparv[0] = myparv[1] = parv[0];
    myparv[2] = parv[1];
    myparv[3] = NULL;

    return m_umode(cptr, sptr, parc + 1, myparv);
}

/*
 * m_umode() added 15/10/91 By Darren Reed.
 * parv[0] - sender
 * parv[1] - username to change mode for
 * parv[2] - modes to change
 */
int m_umode(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int     flag;
    int    *s;
    char  **p, *m;
    aClient    *acptr;
    int         what, setflags;
    int         badflag = NO;	/* Only send one bad flag notice -Dianora */
    what = MODE_ADD;
    
    if (parc < 2) {

		sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "MODE");
		return 0;
	}

	if (!(acptr = find_person(parv[1], NULL))) {

		if (MyConnect(sptr))
			sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], parv[1]);

		return 0;
	}

	if ((IsServer(sptr) || (sptr != acptr) || (acptr->from != sptr->from))) {

		if (!IsServer(cptr))
			sendto_one(sptr, err_str(ERR_USERSDONTMATCH), me.name, parv[0]);

		return 0;
	}

    if (parc < 3) {

		m = buf;
		*m++ = '+';

		for (s = user_modes; (flag = *s) && (m - buf < BUFSIZE - 4); s += 2) {

			if (sptr->umode & (flag & ALL_UMODES))
				*m++ = (char) (*(s + 1));
		}

		*m = '\0';

		sendto_one(sptr, rpl_str(RPL_UMODEIS), me.name, parv[0], buf);
		return 0;
	}

	/* find flags already set for user */
	setflags = 0;

	for (s = user_modes; (flag = *s); s += 2) {

		if (sptr->umode & flag)
			setflags |= flag;
	}

	/* parse mode change string(s) */
	for (p = &parv[2]; p && *p; p++) {

		for (m = *p; *m; m++) {

			switch (*m) {

				case '+':
					what = MODE_ADD;
					break;

				case '-':
					what = MODE_DEL;
					break;

					/* we may not get these, but they shouldnt be in default */
				case ' ':
				case '\r':
				case '\n':
				case '\t':
					break;

#ifdef AZZURRA /* UMODE_H_SERVICES_RESTRICTED */
				case 'h':

					if (IsUmodeh(sptr) && what == MODE_DEL)
						sptr->umode &= ~UMODE_h;

					break;
#endif

#ifdef INET6

				case 'x': /* IPv6 users cannot set themselves +x! */

					if (!MyConnect(sptr)) {

						if (what == MODE_ADD)
							sptr->umode |= UMODE_x;
						else
							sptr->umode &= ~UMODE_x;
					}
					break;
#endif
#ifdef AZZURRA
				case 'z': /* users can`t set themselves +z ! */
				case 'j': /* users can`t set themselves +j ! */
				case 'a': /* users can`t set themselves +a ! */
#endif
				case 'S': /* users can`t set themselves +S ! */
				case 'r': /* users can't set themselves +r! */
					break;

				case 'A':

#ifndef AZZURRA
					/* set auto +a if user is setting +A */
					if (MyClient(sptr) && (what == MODE_ADD))
						sptr->umode |= UMODE_a;
#endif
					// fall...
				case 'g': /* users shouldn`t set themselves +g ! */
					if (!IsPrivileged(cptr))
						break;

				default:

					for (s = user_modes; (flag = *s); s += 2) {

						if (*m == (char) (*(s + 1))) {

							if (what == MODE_ADD)
								sptr->umode |= flag;
							else
								sptr->umode &= ~flag;

							break;
						}
					}

					if (flag == 0 && MyConnect(sptr))
						badflag = YES;

					break;
			}
		}
	}

	if (badflag)
		sendto_one(sptr, err_str(ERR_UMODEUNKNOWNFLAG), me.name, parv[0]);

	/* stop users making themselves operators too easily */
	if (!(setflags & UMODE_o) && IsOper(sptr) && !IsServer(cptr))
		ClearOper(sptr);
	
	if (!(setflags & UMODE_O) && IsLocOp(sptr) && !IsServer(cptr))
		sptr->umode &= ~UMODE_O;
	
	if ((setflags & (UMODE_o | UMODE_O)) && !IsAnOper(sptr) && MyConnect(sptr)) {

		det_confs_butmask(sptr, CONF_CLIENT & ~CONF_OPS);
		sptr->sendqlen = get_sendq(sptr);
		sptr->pingval = get_client_ping(sptr);
		sptr->oflag = 0;
	}

	if (!(setflags & (UMODE_o | UMODE_O)) && IsAnOper(sptr))
		Count.oper++;

	if ((setflags & (UMODE_o | UMODE_O)) && !IsAnOper(sptr)) {

		Count.oper--;

		if (MyConnect(sptr))
			delfrom_fdlist(sptr->fd, &oper_fdlist);

        /*
         * Now that the user is no longer opered, let's return
         * them back to the appropriate Y:class -srd
         */

		/* sptr->pingval = get_client_ping(sptr); */
		/* sptr->sendqlen = get_sendq(sptr); */
    }

	if (!(setflags & UMODE_i) && IsInvisible(sptr))
		Count.invisi++;

	if ((setflags & UMODE_i) && !IsInvisible(sptr))
		Count.invisi--;

    /*
     * compare new flags with old flags and send string which will cause
     * servers to update correctly.
     */
	if (!IsAnOper(sptr) && !IsServer(sptr)) {

		if (IsAdmin(sptr)) ClearAdmin(sptr);
#ifndef AZZURRA
		if (IsSAdmin(sptr)) ClearSAdmin(sptr);
#endif
		if (IsUmodef(sptr)) ClearUmodef(sptr);
		if (IsUmodec(sptr)) ClearUmodec(sptr);
		if (IsUmodey(sptr)) ClearUmodey(sptr);
		if (IsUmoded(sptr)) ClearUmoded(sptr);
		if (IsUmodeb(sptr)) ClearUmodeb(sptr);
		if (IsUmoden(sptr)) ClearUmoden(sptr);
		if (IsUmodem(sptr)) ClearUmodem(sptr);
		if (IsUmodee(sptr)) ClearUmodee(sptr);
		if (IsUmodeK(sptr)) ClearUmodeK(sptr);

#ifdef AZZURRA
		if (SendSkillNotice(sptr)) ClearSkillNotice(sptr);
		if (IsHiddenIdle(sptr)) ClearHiddenIdle(sptr);
		if (SendGlobops(sptr)) ClearGlobops(sptr);
#endif
		if (NoMsgThrottle(sptr)) ClearNoMsgThrottle(sptr);
	}

	if (MyClient(sptr)) {

		if (IsAdmin(sptr) && !OPIsAdmin(sptr)) ClearAdmin(sptr);

#ifndef AZZURRA
		if (IsSAdmin(sptr) && !OPIsSAdmin(sptr)) ClearSAdmin(sptr);

		/* Allow +F for any opers. */
		if (NoMsgThrottle(sptr) && !OPCanUModeF(sptr)) ClearNoMsgThrottle(sptr);
#endif

		if (IsUmodef(sptr) && !OPCanUModef(sptr)) ClearUmodef(sptr);
		if (IsUmodec(sptr) && !OPCanUModec(sptr)) ClearUmodec(sptr);
		if (IsUmodey(sptr) && !OPCanUModey(sptr)) ClearUmodey(sptr);
		if (IsUmoded(sptr) && !OPCanUModed(sptr)) ClearUmoded(sptr);
		if (IsUmodeb(sptr) && !OPCanUModeb(sptr)) ClearUmodeb(sptr);

#ifdef AZZURRA
		/* Don't allow local opers to set themselves +m */
		if (IsUmodem(sptr) && !OPCanSpam(sptr)) ClearUmodem(sptr);

		/* Don't allow local opers to set themselves +I */
		if (IsHiddenIdle(sptr) && !IsOper(sptr)) ClearHiddenIdle(sptr);
#endif
	}

	send_umode_out(cptr, sptr, setflags);
    return 0;
}

/* send the MODE string for user (user) to connection cptr -avalon */
void send_umode(aClient *cptr, aClient *sptr, int old, int sendmask,
		char *umode_buf)
{
    int    *s, flag;
    char   *m;
    int         what = MODE_NULL;

    /*
     * build a string in umode_buf to represent the change in the user's
     * mode between the new (sptr->flag) and 'old'.
     */
    m = umode_buf;
    *m = '\0';
    for (s = user_modes; (flag = *s); s += 2)
    {
	if (MyClient(sptr) && !(flag & sendmask))
	    continue;
	if ((flag & old) && !(sptr->umode & flag))
	{
	    if (what == MODE_DEL)
		*m++ = *(s + 1);
	    else
	    {
		what = MODE_DEL;
		*m++ = '-';
		*m++ = *(s + 1);
	    }
	}
	else if (!(flag & old) && (sptr->umode & flag))
	{
	    if (what == MODE_ADD)
		*m++ = *(s + 1);
	    else
	    {
		what = MODE_ADD;
		*m++ = '+';
		*m++ = *(s + 1);
	    }
	}
    }
    *m = '\0';
    if (*umode_buf && cptr)
	sendto_one(cptr, ":%s MODE %s :%s",
		   sptr->name, sptr->name, umode_buf);
}

/* added Sat Jul 25 07:30:42 EST 1992 */
/*
 * extra argument evenTS added to send to TS servers or not -orabidoo
 * 
 * extra argument evenTS no longer needed with TS only th+hybrid server
 * -Dianora
 */
void send_umode_out(aClient *cptr, aClient *sptr, int old)
{
    int     i, j;
    aClient *acptr;
    fdlist      fdl = serv_fdlist;

    send_umode(NULL, sptr, old, SEND_UMODES, buf);
    /*
     * Cycling through serv_fdlist here should be MUCH faster than
     * looping through every client looking for servers. -ThemBones
     */

    for (i = fdl.entry[j = 1]; j <= fdl.last_entry; i = fdl.entry[++j])
	if ((acptr = local[i]) && (acptr != cptr) &&
	    (acptr != sptr) && (*buf))
	    sendto_one(acptr, ":%s MODE %s :%s",
		       sptr->name, sptr->name, buf);
    
    if (cptr && MyClient(cptr))
	send_umode(cptr, sptr, old, ALL_UMODES, buf);
}

/*
 * This function checks to see if a CTCP message (other than ACTION) is
 * contained in the passed string.  This might seem easier than I am
 * doing it, but a CTCP message can be changed together, even after a
 * normal message.
 * 
 * If the message is found, and it's a DCC message, pass it back in
 * *dccptr.
 *
 * Unfortunately, this makes for a bit of extra processing in the
 * server.
 */
int check_for_ctcp(char *str, char **dccptr)
{
    char       *p = str;

	while ((p = strchr(p, 1)) != NULL) {

		++p;

		if (myncmp(p, "DCC", 3) == 0) {

#ifdef AZZURRA
			char *s, *t;
			int ret = CTCP_DCC;
			int checkbogus = NO;
			int spaces = 0;
			size_t len = 0;
#endif
			if (dccptr)
				*dccptr = p;

			if (myncmp(p + 3, " SEND", 5) == 0) {       

				ret = CTCP_DCCSEND;
#ifndef AZZURRA

			}	  
#else

				p += 8;
				checkbogus = YES;	     
			}	  
			else if (myncmp(p + 3, " RESUME", 7) == 0)
			{     
				p += 10;
				checkbogus = YES;
			}
	  
			/* Check for bogus dcc send and resume that can crash 
			* some IRC client.
			* This check will assure that there requirements are met:
			* 1) file name is at most MAXDCCFILELEN characters long.
			* 2) file name containts at most MAXDCCFILESPACES spaces.
			*/

			if (checkbogus) {
	       
				/* Skip any leading white space. */
				while (*p == ' ')
					++p;

				/* Point s to the first space in the string. */
				if (!(s = strchr(p + 1, ' ')))
					return ((strlen(p) >= MAXDCCFILELEN) ? CTCP_BOGUS : ret);

				/* Check if there's a '"' in the first param. */
				for (t = p; t < s; ++t) {

					++len;

					if (*t == '"') {
		   
						/* Filename begins at the '"' make sure there is at least another one. */
						if (!(p = strchr(t + 1, '"')))
							return CTCP_BOGUS;

						/* Filename longer than MAXDCCFILELEN chars. */
						if ((p - (t + 1)) >= MAXDCCFILELEN)
							return CTCP_BOGUS;

						/* Loop through the filename and count spaces. */
						for (s = t + 1; s < p; ++s) {

							if (*s == ' ') {

								/* More than MAXDCCFILESPACES spaces found. Bogus DCC. */
								if (++spaces > MAXDCCFILESPACES)
									return CTCP_BOGUS;
							}
						}

						return ret;
					}
				}

				/* Filename longer than MAXDCCFILELEN characters. */
				if (len >= MAXDCCFILELEN)
					return CTCP_BOGUS;
			}
#endif       
			return ret;
		}

		if (myncmp(p, "ACTION ", 7) != 0)
			return CTCP_YES;

		if ((p = strchr(p, 1)) == NULL)
			return CTCP_NONE;

		if(!(*(++p)))
			break;
	}

	return CTCP_NONE;
}


/* Shadowfax's FLUD code */
#ifdef FLUD
void announce_fluder(aClient *fluder, aClient *cptr, aChannel *chptr, int type)
{				
    char       *fludee;
    
    if (cptr)
	fludee = cptr->name;
    else
	fludee = chptr->chname;
    
    sendto_ops_lev(FLOOD_LEV, "Flooder %s [%s@%s] on %s target: %s",
		   fluder->name, fluder->user->username, fluder->user->host,
		   fluder->user->server, fludee);
}

/*
 * This is really just a "convenience" function.  I can only keep three
 * or * four levels of pointer dereferencing straight in my head.  This
 * remove * an entry in a fluders list.  Use this when working on a
 * fludees list :)
 */
struct fludbot *remove_fluder_reference(struct fludbot **fluders, 
					aClient *fluder)
{
    struct fludbot *current, *prev, *next;
    
    prev = NULL;
    current = *fluders;
    while (current)
    {
	next = current->next;
	if (current->fluder == fluder)
	{
	    if (prev)
		prev->next = next;
	    else
		*fluders = next;
	    
	    BlockHeapFree(free_fludbots, current);
	}
	else
	    prev = current;
	current = next;
    }

    return (*fluders);
}

/* Another function to unravel my mind. */
Link *remove_fludee_reference(Link **fludees, void *fludee)
{
    Link       *current, *prev, *next;

    prev = NULL;
    current = *fludees;
    while (current)
    {
	next = current->next;
	if (current->value.cptr == (aClient *) fludee)
	{
	    if (prev)
		prev->next = next;
	    else
		*fludees = next;

	    BlockHeapFree(free_Links, current);
	}
	else
	    prev = current;
	current = next;
    }

    return (*fludees);
}

int check_for_fludblock(aClient *fluder, aClient *cptr, aChannel *chptr, 
			int type)
{				
    time_t      now;
    int         blocking;

    /* If it's disabled, we don't need to process all of this */
    if (flud_block == 0)
	return 0;

#ifdef AZZURRA
    /* !@*#$%!!!!! */
    if (IsOper(fluder) || IsULine(fluder) || IsUmodez(fluder))
        return 0;
#endif

    /* It's either got to be a client or a channel being fluded */
    if ((cptr == NULL) && (chptr == NULL))
	return 0;

    if (cptr && !MyFludConnect(cptr))
    {
	sendto_ops("check_for_fludblock() called for non-local client");
	return 0;
    }

    /* Are we blocking fluds at this moment? */
    time(&now);
    if (cptr)
	blocking = (cptr->fludblock > (now - flud_block));
    else
	blocking = (chptr->fludblock > (now - flud_block));

    return (blocking);
}

int check_for_flud(aClient *fluder, aClient *cptr, aChannel *chptr, int type)
{				
    time_t      now;
    struct fludbot *current, *prev, *next;
    int         blocking, count, found;
    Link       *newfludee;
    
    /* If it's disabled, we don't need to process all of this */
    if (flud_block == 0)
	return 0;
	
#ifdef AZZURRA
    /* !@*#$%!!!!! */
    if (IsOper(fluder) || IsULine(fluder) || IsUmodez(fluder))
        return 0;
#endif
	
    /* It's either got to be a client or a channel being fluded */
    if ((cptr == NULL) && (chptr == NULL))
	return 0;
	
    if (cptr && !MyFludConnect(cptr)) 
    {
	sendto_ops("check_for_flud() called for non-local client");
	return 0;
    }
	
    /* Are we blocking fluds at this moment? */
    time(&now);
    if (cptr)
	blocking = (cptr->fludblock > (now - flud_block));
    else
	blocking = (chptr->fludblock > (now - flud_block));
	
    /* Collect the Garbage */
    if (!blocking) 
    {
	if (cptr)
	    current = cptr->fluders;
	else
	    current = chptr->fluders;
	prev = NULL;
	while (current) 
	{
	    next = current->next;
	    if (current->last_msg < (now - flud_time))
	    {
		if (cptr)
		    remove_fludee_reference(&current->fluder->fludees,
					    (void *) cptr);
		else
		    remove_fludee_reference(&current->fluder->fludees,
					    (void *) chptr);
				
		if (prev)
		    prev->next = current->next;
		else if (cptr)
		    cptr->fluders = current->next;
		else
		    chptr->fluders = current->next;
		BlockHeapFree(free_fludbots, current);
	    }
	    else
		prev = current;
	    current = next;
	}
    }
    /*
     * Find or create the structure for the fluder, and update the
     * counter * and last_msg members.  Also make a running total count
     */
    if (cptr)
	current = cptr->fluders;
    else
	current = chptr->fluders;
    count = found = 0;
    while (current) 
    {
	if (current->fluder == fluder)
	{
	    current->last_msg = now;
	    current->count++;
	    found = 1;
	}
	if (current->first_msg < (now - flud_time))
	    count++;
	else
	    count += current->count;
	current = current->next;
    }
    if (!found) 
    {
	if ((current = BlockHeapALLOC(free_fludbots, struct fludbot)) != NULL) 
	{
	    current->fluder = fluder;
	    current->count = 1;
	    current->first_msg = now;
	    current->last_msg = now;
	    if (cptr) 
	    {
		current->next = cptr->fluders;
		cptr->fluders = current;
	    }
	    else 
	    {
		current->next = chptr->fluders;
		chptr->fluders = current;
	    }
			
	    count++;
			
	    if ((newfludee = BlockHeapALLOC(free_Links, Link)) != NULL) 
	    {
		if (cptr) 
		{
		    newfludee->flags = 0;
		    newfludee->value.cptr = cptr;
		}
		else 
		{
		    newfludee->flags = 1;
		    newfludee->value.chptr = chptr;
		}
		newfludee->next = fluder->fludees;
		fluder->fludees = newfludee;
	    }
	    else
		outofmemory();
	    /*
	     * If we are already blocking now, we should go ahead * and
	     * announce the new arrival
	     */
	    if (blocking)
		announce_fluder(fluder, cptr, chptr, type);
	}
	else
	    outofmemory();
    }
    /*
     * Okay, if we are not blocking, we need to decide if it's time to *
     * begin doing so.  We already have a count of messages received in *
     * the last flud_time seconds
     */
    if (!blocking && (count > flud_num)) 
    {
	blocking = 1;
	ircstp->is_flud++;
	/*
	 * if we are going to say anything to the fludee, now is the *
	 * time to mention it to them.
	 */
	if (cptr)
	    sendto_one(cptr,
		       ":%s NOTICE %s :*** Notice -- Server flood protection "
		       "activated for %s", me.name, cptr->name, cptr->name);
	else
	    sendto_channel_butserv(chptr, &me,
				   ":%s NOTICE %s :*** Notice -- Server "
				   "flood protection activated for %s",
				   me.name, chptr->chname, chptr->chname);
	/*
	 * Here we should go back through the existing list of * fluders
	 * and announce that they were part of the game as * well.
	 */
	if (cptr)
	    current = cptr->fluders;
	else
	    current = chptr->fluders;
	while (current) {
	    announce_fluder(current->fluder, cptr, chptr, type);
	    current = current->next;
	}
    }
    /*
     * update blocking timestamp, since we received a/another CTCP
     * message
     */
    if (blocking) 
    {
	if (cptr)
	    cptr->fludblock = now;
	else
	    chptr->fludblock = now;
    }
	
    return (blocking);
}

void free_fluders(aClient *cptr, aChannel *chptr)
{
    struct fludbot *fluders, *next;

    if ((cptr == NULL) && (chptr == NULL)) 
    {
	sendto_ops("free_fluders(NULL, NULL)");
	return;
    }

    if (cptr && !MyFludConnect(cptr))
	return;

    if (cptr)
	fluders = cptr->fluders;
    else
	fluders = chptr->fluders;

    while (fluders) 
    {
	next = fluders->next;

	if (cptr)
	    remove_fludee_reference(&fluders->fluder->fludees, (void *) cptr);
	else
	    remove_fludee_reference(&fluders->fluder->fludees, (void *) chptr);

	BlockHeapFree(free_fludbots, fluders);
	fluders = next;
    }
}

void free_fludees(aClient *badguy)
{
    Link       *fludees, *next;

    if (badguy == NULL) 
    {
	sendto_ops("free_fludees(NULL)");
	return;
    }
    fludees = badguy->fludees;
    while (fludees) 
    {
	next = fludees->next;

	if (fludees->flags)
	    remove_fluder_reference(&fludees->value.chptr->fluders, badguy);
	else 
	{
	    if (!MyFludConnect(fludees->value.cptr))
		sendto_ops("free_fludees() encountered non-local client");
	    else
		remove_fluder_reference(&fludees->value.cptr->fluders, badguy);
	}

	BlockHeapFree(free_Links, fludees);
	fludees = next;
    }
}
#endif /* FLUD */


/* is_silenced - Returns 1 if a sptr is silenced by acptr */
static int is_silenced(aClient *sptr, aClient *acptr)
{
    Link *lp;
    anUser *user;
    char sender[HOSTLEN+NICKLEN+USERLEN+5];
#ifdef AZZURRA
    char vsender[HOSTLEN+NICKLEN+USERLEN+5];
#endif

    if (!(acptr->user) || !(lp=acptr->user->silence) || !(user=sptr->user))
	return 0;

    ircsprintf(sender,"%s!%s@%s",sptr->name,user->username,user->host);
#ifdef AZZURRA
    ircsprintf(vsender,"%s!%s@%s",sptr->name,user->username,user->virthost);
#endif

    for (;lp;lp=lp->next) 
    {
	if (!match(lp->value.cp, sender)
#ifdef AZZURRA
		|| !match(lp->value.cp, vsender)
#endif
		) 
	{
	    if (!MyConnect(sptr)) 
	    {
		sendto_one(sptr->from, ":%s SILENCE %s :%s",acptr->name,
			   sptr->name, lp->value.cp);
		lp->flags = 1; 
	    }
	    return 1;
	}
    }
    return 0;
}

int del_silence(aClient *sptr, char *mask) 
{
    Link **lp, *tmp;
    for (lp=&(sptr->user->silence);*lp;lp=&((*lp)->next))
	if (mycmp(mask, (*lp)->value.cp)==0) 
	{
	    tmp = *lp;
	    *lp = tmp->next;
	    MyFree(tmp->value.cp);
	    free_link(tmp);
	    return 0;
	}
    return 1;
}

static int add_silence(aClient *sptr,char *mask) 
{
    Link *lp;
    int cnt=0, len=0;
    for (lp=sptr->user->silence;lp;lp=lp->next) 
    {
	len += strlen(lp->value.cp);
	if (MyClient(sptr)) 
	{
	    if ((len > MAXSILELENGTH) || (++cnt >= MAXSILES)) 
	    {
		sendto_one(sptr, err_str(ERR_SILELISTFULL), me.name,
			   sptr->name, mask);
		return -1;
	    } 
	    else
	    {
		if (!match(lp->value.cp, mask))
		    return -1;
	    }
	}
	else if (!mycmp(lp->value.cp, mask))
	    return -1;
    }
    lp = make_link();
    lp->next = sptr->user->silence;
    lp->value.cp = (char *)MyMalloc(strlen(mask)+1);
    (void)strcpy(lp->value.cp, mask);
    sptr->user->silence = lp;
    return 0;
}

/* m_silence
 * parv[0] = sender prefix
 * From local client:
 * parv[1] = mask (NULL sends the list)
 * From remote client:
 * parv[1] = nick that must be silenced
 * parv[2] = mask
 */
int m_silence(aClient *cptr,aClient *sptr,int parc,char *parv[]) 
{
    Link *lp;
    aClient *acptr=NULL;
    char c, *cp;
    if (check_registered_user(sptr)) return 0;
    if (MyClient(sptr)) 
    {
	acptr = sptr;
	if (parc < 2 || *parv[1]=='\0' ||
	    (acptr = find_person(parv[1], NULL))) 
	{
	    if (!(acptr->user)) return 0;
	    for (lp = acptr->user->silence; lp; lp = lp->next)
		sendto_one(sptr, rpl_str(RPL_SILELIST), me.name,
			   sptr->name, acptr->name, lp->value.cp);
	    sendto_one(sptr, rpl_str(RPL_ENDOFSILELIST), me.name, acptr->name);
	    return 0;
	}
	cp = parv[1];
	c = *cp;
	if (c=='-' || c=='+') cp++;
	else if (!(strchr(cp, '@') || strchr(cp, '.') ||
		   strchr(cp, '!') || strchr(cp, '*'))) 
	{
	    sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0],
		       parv[1]);
	    return 0;
	}
	else c = '+';
	cp = pretty_mask(cp);
	if ((c=='-' && !del_silence(sptr,cp)) ||
	    (c!='-' && !add_silence(sptr,cp))) 
	{
	    sendto_prefix_one(sptr, sptr, ":%s SILENCE %c%s", parv[0], c, cp);
	    if (c=='-')
		sendto_serv_butone(NULL, ":%s SILENCE * -%s", sptr->name, cp);
	}
    }
    else if (parc < 3 || *parv[2]=='\0') 
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
		   "SILENCE");
	return -1;
    } 
    else if ((c = *parv[2])=='-' || (acptr = find_person(parv[1], NULL))) 
    {
	if (c=='-') 
	{
	    if (!del_silence(sptr,parv[2]+1))
		sendto_serv_butone(cptr, ":%s SILENCE %s :%s",
				   parv[0], parv[1], parv[2]);
	}
	else
	{
	    (void)add_silence(sptr,parv[2]);
	    if (!MyClient(acptr))
		sendto_one(acptr, ":%s SILENCE %s :%s",
			   parv[0], parv[1], parv[2]);
	} 
    } 
    else
    {
	sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], parv[1]);
	return 0;
    }
    return 0;
}

int add_dccallow(aClient *sptr, aClient *optr)
{
    Link *lp;
    int cnt = 0;

    for(lp = sptr->user->dccallow; lp; lp = lp->next)
    {
	if(lp->flags != DCC_LINK_ME)
	    continue;
	if(++cnt >= MAXDCCALLOW)
	{
	    sendto_one(sptr, err_str(ERR_TOOMANYDCC), me.name, sptr->name,
		       optr->name, MAXDCCALLOW);
	    return 0;
	}
	else if(lp->value.cptr == optr)
	{
	    /* silently return */
	    return 0;
	}
    }

    lp = make_link();
    lp->value.cptr = optr;
    lp->flags = DCC_LINK_ME;
    lp->next = sptr->user->dccallow;
    sptr->user->dccallow = lp;

    lp = make_link();
    lp->value.cptr = sptr;
    lp->flags = DCC_LINK_REMOTE;
    lp->next = optr->user->dccallow;
    optr->user->dccallow = lp;   

    sendto_one(sptr, rpl_str(RPL_DCCSTATUS), me.name, sptr->name, optr->name,
	       "added to");
    return 0;
}

int del_dccallow(aClient *sptr, aClient *optr) 
{
    Link **lpp, *lp;
    int found = 0;

    for (lpp = &(sptr->user->dccallow); *lpp; lpp=&((*lpp)->next))
    {
	if((*lpp)->flags != DCC_LINK_ME)
	    continue;

	if((*lpp)->value.cptr == optr)
	{
	    lp = *lpp;
	    *lpp = lp->next;
	    free_link(lp);
	    found++;
	    break;
	}
    }

    if(!found)
    {
	sendto_one(sptr, ":%s %d %s :%s is not in your DCC allow list",
		   me.name, RPL_DCCINFO, sptr->name, optr->name);
	return 0;
    }

    for (found = 0, lpp = &(optr->user->dccallow); *lpp; lpp=&((*lpp)->next))
    {
	if((*lpp)->flags != DCC_LINK_REMOTE)
	    continue;

	if((*lpp)->value.cptr == sptr)
	{
	    lp = *lpp;
	    *lpp = lp->next;
	    free_link(lp);
	    found++;
	    break;
	}
    }

    if(!found)
	sendto_realops_lev(DEBUG_LEV, "%s was in dccallowme list of %s but "
			   "not in dccallowrem list!", optr->name, sptr->name);

    sendto_one(sptr, rpl_str(RPL_DCCSTATUS), me.name, sptr->name, optr->name,
	       "removed from");
    
    return 0;
}

int allow_dcc(aClient *to, aClient *from)
{
    Link *lp;
    
    for(lp = to->user->dccallow; lp; lp = lp->next)
    {
	if(lp->flags == DCC_LINK_ME && lp->value.cptr == from)
	    return 1;
    }
    return 0;
}

int m_dccallow(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    Link *lp;
    char *p, *s;
    char *cn;
    aClient *acptr, *lastcptr = NULL;
    int didlist = 0, didhelp = 0, didanything = 0;
    char **ptr;
    static char *dcc_help[] = 
	{
	    "/DCCALLOW [<+|->nick[,<+|->nick, ...]] [list] [help]",
	    "You may allow DCCs of filetypes which are otherwise blocked by "
	    "the IRC server",
	    "by specifying a DCC allow for the user you want to recieve files "
	    "from.",
	    "For instance, to allow the user bob to send you file.exe, you "
	    "would type:",
	    "/dccallow +bob",
	    "and bob would then be able to send you files. bob will have to "
	    "resend the file",
	    "if the server gave him an error message before you added him to "
	    "your allow list.",
	    "/dccallow -bob",
	    "Will do the exact opposite, removing him from your dcc allow "
	    "list.",
	    "/dccallow list",
	    "Will list the users currently on your dcc allow list.",
	    NULL 
	};

    if(!MyClient(sptr)) return 0;
    /* don't accept dccallows from servers or clients that aren't mine.. */
    
    if(parc < 2)
    {
	sendto_one(sptr, ":%s NOTICE %s :No command specified for DCCALLOW. "
		   "Type /dccallow help for more information.", me.name,
		   sptr->name);
	return 0;
    }

    for (p = NULL, s = strtoken(&p, parv[1], ", "); s;
	 s = strtoken(&p, NULL, ", "))
    {
	if(*s == '+')
	{
	    didanything++;
	    cn = s + 1;
	    if(*cn == '\0')
		continue;

	    acptr = find_person(cn, NULL);
	    
	    if(acptr == sptr) continue;
	    
	    if(!acptr)
	    {
		sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name,
			   sptr->name, cn);
		continue;
	    }

	    if(lastcptr == acptr)
		sendto_realops_lev(SPY_LEV, "User %s (%s@%s) may be flooding "
				   "dccallow: add %s", sptr->name,
				   sptr->user->username, sptr->user->host,
				   acptr->name);
	    lastcptr = acptr;
	    add_dccallow(sptr, acptr);
	}
	else if(*s == '-')
	{
	    didanything++;
	    cn = s + 1;
	    if(*cn == '\0')
		continue;

	    acptr = find_person(cn, NULL);

	    if(acptr == sptr) continue;

	    if(!acptr)
	    {
		sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, 
			   sptr->name, cn);
		continue;
	    }

	    if(lastcptr == acptr)
		sendto_realops_lev(SPY_LEV, "User %s (%s@%s) may be flooding "
				   "dccallow: del %s", sptr->name,
				   sptr->user->username, sptr->user->host,
				   acptr->name);
	    
	    lastcptr = acptr;
	    del_dccallow(sptr, acptr);
	}
	else
	{
	    if(!didlist && myncmp(s, "list", 4) == 0)
	    {
		didanything++;
		didlist++;
		sendto_one(sptr, ":%s %d %s :The following users are on your "
			   "dcc allow list:", me.name, RPL_DCCINFO,
			   sptr->name);
		for(lp = sptr->user->dccallow; lp; lp = lp->next)
		{
		    if(lp->flags == DCC_LINK_REMOTE) 
			continue;
		    sendto_one(sptr, ":%s %d %s :%s (%s@%s)", me.name,
			       RPL_DCCLIST, sptr->name, lp->value.cptr->name,
			       lp->value.cptr->user->username,
#ifdef AZZURRA
			       IsUmodex(lp->value.cptr) ? 
			       lp->value.cptr->user->virthost :
#endif
			       lp->value.cptr->user->host);
		}
		sendto_one(sptr, rpl_str(RPL_ENDOFDCCLIST), me.name,
			   sptr->name, s);
	    }
	    else if(!didhelp && myncmp(s, "help", 4) == 0)
	    {
		didanything++;
		didhelp++;
		for(ptr = dcc_help; *ptr; ptr++)
		    sendto_one(sptr, ":%s %d %s :%s", me.name, RPL_DCCINFO,
			       sptr->name, *ptr);
		sendto_one(sptr, rpl_str(RPL_ENDOFDCCLIST), me.name,
			   sptr->name, s);
	    }
	}
    }

    if(!didanything)
    {
	sendto_one(sptr, ":%s NOTICE %s :Invalid syntax for DCCALLOW. Type "
		   "/dccallow help for more information.", me.name,
		   sptr->name);
	return 0;
    }
    
    return 0;
}

#ifdef WEBIRC
int m_webirc(aClient *cptr, aClient *sptr, int parc, char **parv)
{
    aConfItem *wptr;
    
    if (!MyConnect(sptr))
        return 0;

    if (!IsUnknown(sptr))
    {
        sendto_one(sptr, err_str(ERR_ALREADYREGISTRED), me.name, parv[0]);
        return 0;
    }
    
    if (parc < 5 || BadPtr(parv[1]) || BadPtr(parv[2]) || BadPtr(parv[3]) || BadPtr(parv[4]))
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "WEBIRC");
        return 0;
    }
    
    /* This is tricky, we need to find a valid WEBIRC conf matching this user's ip address */
    if ((wptr = find_webirc_host(sptr->sockhost)) == NULL)
    {
        sendto_realops("No matching W:line for %s", sptr->sockhost);
        return exit_client(cptr, sptr, &me, "No WEBIRC spoof block");
    }
    
    /* parv[2] SHOULD be "cgiirc", but at least one client (qwebirc) uses it to advertise itself */
    if (mycmp(parv[1], wptr->passwd) == 0)
    {
        /* Password matches, check hostname and ip lengths */
        if (strlen(parv[3]) > HOSTLEN || strlen(parv[4]) > HOSTIPLEN)
        {
            sendto_realops("Bad arguments for WEBIRC command from %s", sptr->sockhost);
            return exit_client(cptr, sptr, &me, "Invalid argument");
        }
        strncpyzt(sptr->webirc_host, parv[3], HOSTLEN + 1);
        strncpyzt(sptr->webirc_ip, parv[4], HOSTIPLEN + 1);
        SetWEBIRC(sptr);
    }
    else
    {
        sendto_realops("W:line password mismatch for %s", sptr->sockhost);
        return exit_client(cptr, sptr, &me, "Password mismatch");
    }
    
    return 0;
}
#endif

#ifdef AZZURRA
/* CR, i 0wn j00 */
int m_guest(aClient *cptr, aClient *sptr, int parc, char **parv)
{
    static char nick[24];
    static char *user = "JAVA", *realname = "JavaUser";
    static char *prv[5];

    if (!MyConnect(sptr))
    {
        return 0;
    }

    if (!IsUnknown(sptr))
    {
        sendto_one(sptr, err_str(ERR_ALREADYREGISTRED), me.name, parv[0]);
        return 0;
    }

    SetJava(sptr);

    srand(getpid() * time(NULL));

    do
    {
        ircsnprintf(nick, sizeof(nick), "Guest%d", (unsigned short) rand());
    }
    while ((find_client(nick, NULL)) != NULL);

    sendto_one(sptr, ":Guest%d NICK %s", (unsigned short) rand(), nick);

    prv[0] = parv[0];
    prv[1] = nick;
    prv[2] = NULL;

    m_nick(cptr, sptr, 2, prv);

    prv[0] = parv[0];
    prv[1] = user;
    prv[2] = "*";
    prv[3] = "*";
    prv[4] = realname;
    prv[5] = NULL;

    m_user(cptr, sptr, 5, prv);

    return 0;
}
#endif

#ifdef SHUN /*AZZURRA*/
int m_shun(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *acptr;
    char *user, *p, *nick, *reason;
    int chasing, scount = 0;

    if (!(IsAdmin(cptr) || IsSAdmin(cptr) || IsServer(cptr)))
    {
	sendto_one(sptr, err_str(ERR_UNKNOWNCOMMAND), me.name, parv[0], "SHUN");
	return 0;
    }

    if (parc < 2 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "SHUN");
	return 0;
    }

    user = parv[1];
    reason = parv[2] ? parv[2] : "No reason given";

    if (user[0] == '-' && user[1] == 'l')
    {
	sendto_one(sptr, ":%s NOTICE %s :List of shunned users",
		me.name, parv[0]);
	for(acptr = client; acptr; acptr = acptr->next)
	{
	    if(IsShunned(acptr))
	    {
		sendto_one(sptr, ":%s NOTICE %s :%s (%s@%s)",
			me.name, parv[0], acptr->name,
			acptr->user->username, acptr->user->host);
		scount++;
	    }
	}
	sendto_one(sptr, ":%s NOTICE %s :End of list (%d shunned user%s)",
		me.name, parv[0], scount, (scount == 1) ? "" : "s");

	return 0;
    }

    if (MyClient(sptr))
	user = canonize(user);
    for (p = NULL, nick = strtoken(&p, user, ","); nick;
	    nick = strtoken(&p, NULL, ","))
    {
	chasing = 0;
	if(!(acptr = find_client(nick, NULL)))
	{
	    if (!(acptr = get_history(nick, (long) KILLCHASETIMELIMIT)))
	    {
		sendto_one(sptr, err_str(ERR_NOSUCHNICK),
			me.name, parv[0], nick);
		continue;
	    }
	    sendto_one(sptr, ":%s NOTICE %S :SHUN changed from %s to %s",
		    me.name, parv[0], nick, acptr->name);
	    chasing = 1;
	}
#ifdef AZZURRA
	if(IsUmodez(acptr))
	{
	    sendto_one(sptr, ":%s NOTICE %s :Cannot SHUN Services agent",
		    me.name, parv[0]);
	    continue;
	}
#endif
	if(IsAnOper(acptr))
	{
	    sendto_one(sptr, ":%s NOTICE %s :Cannot SHUN Oper",
		    me.name, parv[0]);
	    continue;
	}
	if(IsServer(acptr) || IsMe(acptr))
	{
	    sendto_one(sptr, ":%s NOTICE %s :Cannot SHUN server",
		    me.name, parv[0]);
	    continue;
	}
	if(IsShunned(acptr))
	{
	    sendto_one(sptr, ":%s NOTICE %s :%s is already shunned",
		    me.name, parv[0], acptr->name);
	    continue;
	}

	scount++;
	if (!IsServer(sptr) && scount > MAXSHUNS)
	{
	    sendto_one(sptr, ":%s NOTICE %s :Too many targets, shun list "
		    "was truncated. Maximum is %d.", me.name, sptr->name,
		    MAXSHUNS);
	    break;
	}

	if (IsServer(sptr))
            sendto_realops_lev(SPAM_LEV,
		"Received SHUN message for %s!%s@%s. "
		"From %s (%s)", acptr->name, acptr->user->username,
		acptr->user->host, parv[0], reason);
	else 
	{
	    sendto_realops_lev(SPAM_LEV,
		"Received SHUN message for %s!%s@%s. "
		"From %s!%s@%s (%s)", acptr->name, acptr->user->username,
		acptr->user->host, parv[0], sptr->user->username,
		sptr->user->host, reason);
	    if (MyClient(sptr) && !SendSpamNotice(sptr)) {
		sendto_one(sptr, ":%s NOTICE %s :*** Notice -- "
				 "Received SHUN message for %s!%s@%s. "
				 "From %s!%s@%s (%s)", me.name, sptr->name,
				 acptr->name, acptr->user->username,
				 acptr->user->host, parv[0], sptr->user->username,
				 sptr->user->host, reason);
	    }
	}

#if defined(USE_SYSLOG) && defined(SYSLOG_SHUN)
        if (IsServer(sptr))
	   syslog(LOG_INFO, "SHUN for %s!%s@%s From %s",
		acptr->name, acptr->user->username, 
	        acptr->user->host, parv[0]);
        else
	   syslog(LOG_INFO, "SHUN for %s!%s@%s From %s!%s@%s",
		acptr->name, acptr->user->username,
		acptr->user->host, parv[0], sptr->user->username,
		sptr->user->host);       
#endif

	/* Pass the message. */
	sendto_serv_butone(cptr, ":%s SHUN %s :%s",
		parv[0], acptr->name, reason);
	if (chasing && IsServer(cptr))
	    sendto_one(cptr, ":%s SHUN %s :%s",
		    me.name, acptr->name, reason);
	/* shun the local client */
	SetShun(acptr);
    }
    return 0;
}

int m_unshun(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *acptr;
    char *user, *p, *nick;
    int chasing, scount = 0;

    if (!(IsAdmin(cptr) || IsSAdmin(cptr) || IsServer(cptr)))
    {
	sendto_one(sptr, err_str(ERR_UNKNOWNCOMMAND), me.name, parv[0], "UNSHUN");
	return 0;
    }

    if (parc < 2 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "UNSHUN");
	return 0;
    }

    user = parv[1];

    if (MyClient(sptr))
	user = canonize(user);
    for (p = NULL, nick = strtoken(&p, user, ","); nick;
	    nick = strtoken(&p, NULL, ","))
    {
	chasing = 0;
	if(!(acptr = find_client(nick, NULL)))
	{
	    if (!(acptr = get_history(nick, (long) KILLCHASETIMELIMIT)))
	    {
		sendto_one(sptr, err_str(ERR_NOSUCHNICK),
			me.name, parv[0], nick);
		continue;
	    }
	    sendto_one(sptr, ":%s NOTICE %S :UNSHUN changed from %s to %s",
		    me.name, parv[0], nick, acptr->name);
	    chasing = 1;
	}
	if(!IsShunned(acptr))
	{
	    if(MyConnect(sptr) && !IsServer(sptr))
		sendto_one(sptr, ":%s NOTICE %s :%s is not shunned",
			me.name, parv[0], acptr->name);
	    continue;
	}

	scount++;
	if (!IsServer(sptr) && scount > MAXSHUNS)
	{
	    sendto_one(sptr, ":%s NOTICE %s :Too many targets, unshun list "
		    "was truncated. Maximum is %d.", me.name, sptr->name,
		    MAXSHUNS);
	    break;
	}

        if (IsServer(sptr))
	   sendto_realops_lev(SPAM_LEV,
		"Received UNSHUN message for %s!%s@%s. "
		"From %s", acptr->name, acptr->user->username,
		acptr->user->host, parv[0]);
        else {
	    sendto_realops_lev(SPAM_LEV,
		"Received UNSHUN message for %s!%s@%s. "
		"From %s!%s@%s", acptr->name, acptr->user->username,
		acptr->user->host, parv[0], sptr->user->username,
		sptr->user->host);
	    if (MyClient(sptr) && !SendSpamNotice(sptr)) {
		sendto_one(sptr, ":%s NOTICE %s :*** Notice -- "
				 "Received UNSHUN message for %s!%s@%s. "
				 "From %s!%s@%s", me.name, sptr->name,
				 acptr->name, acptr->user->username,
				 acptr->user->host, parv[0], sptr->user->username,
				 sptr->user->host);
	    }
	}

#if defined(USE_SYSLOG) && defined(SYSLOG_SHUN)
        if (IsServer(sptr))
	   syslog(LOG_INFO, "UNSHUN for %s!%s@%s From %s",
		acptr->name, acptr->user->username,
		acptr->user->host, parv[0]);
       else
	   syslog(LOG_INFO, "UNSHUN for %s!%s@%s From %s!%s@%s",
		acptr->name, acptr->user->username,
		acptr->user->host, parv[0], sptr->user->username,
		sptr->user->host);
#endif

	/* Pass the message. */
	sendto_serv_butone(cptr, ":%s UNSHUN %s",
		parv[0], acptr->name);
	if (chasing && IsServer(cptr))
	    sendto_one(cptr, ":%s UNSHUN %s",
		    me.name, acptr->name);
	/* unshun the local client */
	UnShun(acptr);
    }
    return 0;
}
#endif

#ifdef AZZURRA
__inline__ int check_for_spam(aClient *sender, char *input, char *dest, char *messagetype)
{
    register Spam *sp;
    static char msg[BUFSIZE];
    char *s = msg;
    register char *in_msg = input;
    
    /* Actions that can be performed against spammers. Disabled by default  -INT */
    int block_message = NO;
    int spam_notice = NO;
    int security_channel = NO;
#ifdef SHUN
    int autoshun = NO;
#endif
    
    /* Check should not be performed if SPAM DETECT is disabled or the user has
     * server/oper/service agent privileges. -INT
     */
    if (!spam_detect || IsAnOper(sender) || IsULine(sender) || !MyClient(sender) || IsUmodez(sender))
		return 0;
    
    while (*in_msg) {

		if (*in_msg == '\3') {

			++in_msg;

			if (isdigit(*in_msg))
				++in_msg;

			if (*in_msg == ',') {

				++in_msg;

				if (isdigit(*in_msg)) {

					++in_msg;

					if (isdigit(*in_msg))
						++in_msg;
				}
			}

			continue;
		}

		if ((*in_msg < '\040') && (*in_msg != '\001')) {

			++in_msg;
			continue;
		}

		/* FIXME: what about non-ascii patterns? */
		if (isprint((int)*in_msg) || (*in_msg == '\001'))
			*s++ = *in_msg;

		++in_msg;
    }

	*s = '\0';

    sp = spam_list;
    while(sp)
    {
	if(sp->msg && !match(sp->msg, msg))
	{
	    aClient *acptr = NULL;

	    /* Check if destination is oper or the sender */
	    if ((dest[0] != '#') && (acptr = find_person(dest, NULL)))
	    {
		if ((sender == acptr) || IsAnOper(acptr))
		    return 0;
	    }

#ifdef NOSPAMCHECK_CHANNEL	   
	    /* Check if destination is NOSPAMCHECK_CHANNEL (#OperHelp) */
	    if (!strcasecmp(dest, NOSPAMCHECK_CHANNEL))
	        return 0;
#endif	   
 
	    sp->daycount++;
	    sp->weekcount++;
	    sp->monthcount++;
	    sp->count++;
	    
	    /* Check SPAM LINE type -INT */
	    switch(sp->type) {
		case SPAM_BLOCK_NOMESSAGE :
		    block_message = YES;
		    break;
		case SPAM_BLOCK_NOTICE :
		    block_message = YES;
		    spam_notice = YES;
		    break;
		case SPAM_BLOCK_SECURITY :
		    block_message = YES;
		    security_channel = YES;
		    break;
		case SPAM_BLOCK_NOTICE_SECURITY :
		    block_message = YES;
		    spam_notice = YES;
		    security_channel = YES;
		    break;
		case SPAM_NOBLOCK_SECURITY :
		    security_channel = YES;
		    break;
		case SPAM_AUTOSHUN :
		    block_message = YES;
		    spam_notice = YES;
		    security_channel = YES;
#ifdef SHUN
	            if (!strcmp(messagetype, "PRIVMSG") ||
			!strcmp(messagetype, "NOTICE"))
		        autoshun = YES;
#endif
		    break;
		default :
		/* never reached */
		    break;
	    }

	    if (spam_notice)
	    {
		sendto_snotice("from %s: %s (%s@%s) used %s to %s."
			" %s. Matched with: %s (%s)",
			me.name, sender->name, sender->user->username,
			sender->user->host, messagetype, dest, 
			block_message ? "Blocked" : "Allowed", 
			sp->msg, sp->reason);
		sendto_serv_butone(NULL, ":%s SNOTICE :%s (%s@%s) used %s "
			"to %s. %s. Matched with: %s (%s)",
			me.name, sender->name, sender->user->username, 
			sender->user->host, messagetype, dest, 
			block_message ? "Blocked" : "Allowed", 
			sp->msg, sp->reason);
	    }

	    if (security_channel)
	    {	
		sendto_security(SPAMREPORT_CHANNEL, 
			"%s SPAM %s from %s (%s@%s) to %s. Matched with: %s (%s)",
			block_message ? "Blocked" : "Allowed", messagetype, sender->name,
			sender->user->username, sender->user->host, dest, sp->msg, sp->reason);

		if ((dest[0] == '#') || !strcmp(messagetype, "QUIT"))
			sendto_security(SPAMREPORT_CHANNEL, "<%s> %s", sender->name, input);
	    }	   

#ifdef SHUN
	    if (autoshun && !IsShunned(sender))
	    {
		
		sendto_realops_lev(SPAM_LEV,
		    "Received SHUN message for %s!%s@%s. "
		    "From %s (SPAM %s to %s [Matched with %s])", 
		    sender->name, sender->user->username, sender->user->host, 
		    me.name, messagetype, dest, sp->msg);

#if defined(USE_SYSLOG) && defined(SYSLOG_SHUN)
		syslog(LOG_INFO, "SHUN for %s!%s@%s From %s (SPAM SHUN)",
		    sender->name, sender->user ? sender->user->username :
		    "<unknown>", sender->user ? sender->user->host :
		    "<unknown>", me.name);
#endif
		/* Pass the message. */
		sendto_serv_butone(NULL, ":%s SHUN %s :SPAM %s to %s [Matched with %s]",
		    me.name, sender->name, messagetype, dest, sp->msg);
		    
		if (security_channel)
		    sendto_security(NULL,
			"User %s (%s@%s) has been AUTO-SHUNNED for SPAM.",
			sender->name, sender->user->username,
			sender->user->host);
			
		/* shun the local client */
		SetShun(sender);
	    }
#endif
	         	    
	    if (block_message)
		return 1;
	}
	sp = sp->next;
    }

    return 0;
}
#endif
