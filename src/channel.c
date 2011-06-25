/*
 *   IRC - Internet Relay Chat, src/channel.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Co Center
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
#include "channel.h"
#include "h.h"

#ifdef NO_CHANOPS_WHEN_SPLIT
#include "fdlist.h"
extern fdlist serv_fdlist;

int         server_was_split = YES;
time_t      server_split_time = 0;
int         server_split_recovery_time = (MAX_SERVER_SPLIT_RECOVERY_TIME * 60);

#endif

aChannel   *channel = NullChn;

static void add_invite(aClient *, aChannel *);
static int  add_banid(aClient *, aChannel *, char *);
static int  add_restrictid(aClient *, aChannel *, char *);
static int  can_join(aClient *, aChannel *, char *);
static void channel_modes(aClient *, char *, char *, char *, aChannel *);
static int  del_banid(aChannel *, char *);
static int  del_restrictid(aChannel*, char *);
static aBan *is_banned(aClient *, aChannel *);
static aBan *is_restricted(aClient *, aChannel *);

/* SUX */
static int  set_mode(aClient *, aClient *, aChannel *, int,
		     int, char **, char *, char *, char *, char *, int *,
		     char *, char *, int *);

static void sub1_from_channel(aChannel *);

int         check_channelname(aClient *, unsigned char *);
void        clean_channelname(unsigned char *);
void        del_invite(aClient *, aChannel *);

#ifdef ORATIMING
struct timeval tsdnow, tsdthen;
unsigned long tsdms;
#endif

extern __inline__ int check_for_spam(aClient *, char *, char *, char *);
int hide_tunix = YES;
int unknown_list_allowed = UNKNOWN_LISTS; /* Defined in ./config -> options.h */
                
#ifdef ANTI_INVITE_FLOOD
int  invite_num = MAX_INVITES;
int  invite_time = MAX_INVITE_TIME;
int  invite_spam = YES;
#endif

#ifdef SHOW_RESTRICTED_JOINS
int  show_restricted_joins = YES;
#else
int  show_restricted_joins = NO;
#endif
int  restricted_joins_num = RESTRICTED_JOINS_NUM;
int  restricted_joins_time = RESTRICTED_JOINS_TIME;
extern int restriction_enabled;

/* number of seconds to add to all readings of time() when making TS's */

static char *PartFmt = ":%s PART %s";
static char *PartFmt2 = ":%s PART %s :%s";

/* old and new server SJOIN formats: old with dual TS */
static char *oldSJOINFmt = ":%s SJOIN %ld %ld %s %s %s :%s";
static char *newSJOINFmt = ":%s SJOIN %ld %s %s %s :%s";
/* NP means no paramaters, don't send the extra space there */
static char *oldSJOINFmtNP = ":%s SJOIN %ld %ld %s %s :%s";
static char *newSJOINFmtNP = ":%s SJOIN %ld %s %s :%s";
/* client sjoin.. old is the same as server, new is our new version */
static char *oldCliSJOINFmt = ":%s SJOIN %ld %ld %s + :%s";
static char *newCliSJOINFmt = ":%s SJOIN %ld %s";

/* some buffers for rebuilding channel/nick lists with ,'s */
static char nickbuf[BUFSIZE], buf[BUFSIZE];
static char modebuf[REALMODEBUFLEN], parabuf[REALMODEBUFLEN];
static char stripped_modebuf[REALMODEBUFLEN], stripped_parabuf[REALMODEBUFLEN];
/* mode buffers for non-EBMODE capable servers (cybcop and stats) */
static char noneb_modebuf[REALMODEBUFLEN], noneb_parabuf[REALMODEBUFLEN];

/* htm ... */
extern int lifesux;

/* externally defined function */
extern Link *find_channel_link(Link *, aChannel *);	/* defined in list.c */
#ifdef ANTI_SPAMBOT
extern int  spam_num;		/* defined in s_serv.c */
extern int  spam_time;		/* defined in s_serv.c */
#endif

/* return the length (>=0) of a chain of links. */
static int list_length(Link *lp)
{
    int     count = 0;
    
    for (; lp; lp = lp->next)
	count++;
    return count;
}

/*
 * find_chasing 
 *   Find the client structure for a nick name (user) using history 
 *   mechanism if necessary. If the client is not found, an error message 
 *   (NO SUCH NICK) is generated. If the client was found through the 
 *   history, chasing will be 1 and otherwise 0.
 */
aClient *find_chasing(aClient *sptr, char *user, int *chasing)
{
    aClient *who = find_client(user, (aClient *) NULL);
    
    if (chasing)
	*chasing = 0;
    if (who)
	return who;
    if (!(who = get_history(user, (long) KILLCHASETIMELIMIT)))
    {
	sendto_one(sptr, err_str(ERR_NOSUCHNICK),
		   me.name, sptr->name, user);
	return ((aClient *) NULL);
    }
    if (chasing)
	*chasing = 1;
    return who;
}

/*
 * Fixes a string so that the first white space found becomes an end of
 * string marker (`\-`).  returns the 'fixed' string or "*" if the
 * string was NULL length or a NULL pointer.
 */
static char * check_string(char *s)
{
    static char star[2] = "*";
    char       *str = s;
    
    if (BadPtr(s))
	return star;
    
    for (; *s; s++)
	if (isspace(*s))
	{
	    *s = '\0';
	    break;
	}
    
    return (BadPtr(str)) ? star : str;
}
/*
 * create a string of form "foo!bar@fubar" given foo, bar and fubar as
 * the parameters.  If NULL, they become "*".
 */
static char *make_nick_user_host(char *nick, char *name, char *host)
{
    static char namebuf[NICKLEN + USERLEN + HOSTLEN + 6];
    int         n;
    char   *ptr1, *ptr2;
    
    ptr1 = namebuf;
    for (ptr2 = check_string(nick), n = NICKLEN; *ptr2 && n--;)
	*ptr1++ = *ptr2++;
    *ptr1++ = '!';
    for (ptr2 = check_string(name), n = USERLEN; *ptr2 && n--;)
	*ptr1++ = *ptr2++;
    *ptr1++ = '@';
    for (ptr2 = check_string(host), n = HOSTLEN; *ptr2 && n--;)
	*ptr1++ = *ptr2++;
    *ptr1 = '\0';
    return (namebuf);
}

/* Restrict functions to work with mode +z */
/* add_restrictid - add an id to be restricted to the channel  (belongs to cptr) */

static int add_restrictid(aClient *cptr, aChannel *chptr, char *resid)
{
    aBan   	*res;
    int     	 cnt = 0;

    for (res = chptr->restrictlist; res; res = res->next)
    {
	if (MyClient(cptr) && (++cnt >= MAXBANS))
	{
	    sendto_one(cptr, getreply(ERR_RESTRICTLISTFULL), me.name, cptr->name,
		       chptr->chname, resid);
	    return -1;
	}
	/* yikes, we were doing all sorts of weird crap here before, now
	 * we ONLY want to know if current restrinctions cover this restriction, not if this
	 * restriction covers current ones, since it may cover other things too -wd */
	else if (!match(res->banstr, resid))
	    return -1;
    }

    res = (aBan *) MyMalloc(sizeof(aBan));
    res->banstr = (char *) MyMalloc(strlen(resid) + 1);
    (void) strcpy(res->banstr, resid);
    res->next = chptr->restrictlist;

    if (IsPerson(cptr))
    {
	res->who = (char *) MyMalloc(strlen(cptr->name) +
				     strlen(cptr->user->username) +
				     (IsUmodex(cptr) ?
				      strlen(cptr->user->virthost) :
				      strlen(cptr->user->host))
				     + 3);

	(void) ircsprintf(res->who, "%s!%s@%s",
			  cptr->name, cptr->user->username,
			  IsUmodex(cptr) ? cptr->user->virthost :
			  cptr->user->host);
    }
    else
    {
	res->who = (char *) MyMalloc(strlen(cptr->name) + 1);
	(void) strcpy(res->who, cptr->name);
    }

    /* determine what 'type' of mask this is, for less matching later */

    if(resid[0] == '*' && resid[1] == '!')
    {
	if(resid[2] == '*' && resid[3] == '@')
	    res->type = MTYP_HOST;
	else
	    res->type = MTYP_USERHOST;
    }
    else
	res->type = MTYP_FULL;

    res->when = timeofday;
    chptr->restrictlist = res;

    return 0;
}

/*
 * del_restrictid - delete an id belonging to cptr if resid is null,
 * deleteall resids belonging to cptr.
 */
static int del_restrictid(aChannel *chptr, char *resid)
{
   aBan        **res;
   aBan   	*tmp;

   if (!resid)
       return -1;
   for (res = &(chptr->restrictlist); *res; res = &((*res)->next))
       if (mycmp(resid, (*res)->banstr) == 0)
       {
	   tmp = *res;
	   *res = tmp->next;

	   MyFree(tmp->banstr);
	   MyFree(tmp->who);
	   MyFree(tmp);

	   break;
       }
   return 0;
}

/* Ban functions to work with mode +b */
/* add_banid - add an id to be banned to the channel  (belongs to cptr) */

static int add_banid(aClient *cptr, aChannel *chptr, char *banid)
{
    aBan   	*ban;
    int     	 cnt = 0;
    chanMember 	*cm;
    char 	*s, nickuhost[NICKLEN+USERLEN+HOSTLEN+6];
    char	nickuvirthost[NICKLEN+USERLEN+HOSTLEN+6];
    
    for (ban = chptr->banlist; ban; ban = ban->next)
    {
	if (MyClient(cptr) && (++cnt >= MAXBANS))
	{
	    sendto_one(cptr, getreply(ERR_BANLISTFULL), me.name, cptr->name,
		       chptr->chname, banid);
	    return -1;
	}
	/* yikes, we were doing all sorts of weird crap here before, now
	 * we ONLY want to know if current bans cover this ban, not if this
	 * ban covers current ones, since it may cover other things too -wd */
	else if (!match(ban->banstr, banid))
	    return -1;
    }

    ban = (aBan *) MyMalloc(sizeof(aBan));
    ban->banstr = (char *) MyMalloc(strlen(banid) + 1);
    (void) strcpy(ban->banstr, banid);
    ban->next = chptr->banlist;
    
    if (IsPerson(cptr))
    {
	ban->who = (char *) MyMalloc(strlen(cptr->name) +
				     strlen(cptr->user->username) +
				     (IsUmodex(cptr) ?
				      strlen(cptr->user->virthost) :
				      strlen(cptr->user->host))
				     + 3);
	(void) ircsprintf(ban->who, "%s!%s@%s",
			  cptr->name, cptr->user->username,
			  IsUmodex(cptr) ? cptr->user->virthost :
			  cptr->user->host);
    }
    else
    {
	ban->who = (char *) MyMalloc(strlen(cptr->name) + 1);
	(void) strcpy(ban->who, cptr->name);
    }
    
    /* determine what 'type' of mask this is, for less matching later */
    
    if(banid[0] == '*' && banid[1] == '!')
    {
	if(banid[2] == '*' && banid[3] == '@')
	    ban->type = MTYP_HOST;
	else
	    ban->type = MTYP_USERHOST;
    }
    else
	ban->type = MTYP_FULL;

    ban->when = timeofday;
    chptr->banlist = ban;
    
    for (cm = chptr->members; cm; cm = cm->next) 
    {
	if(!MyConnect(cm->cptr))
	    continue;
	strcpy(nickuvirthost, make_nick_user_host(cm->cptr->name,
		    cm->cptr->user->username, cm->cptr->user->virthost));
	strcpy(nickuhost, make_nick_user_host(cm->cptr->name,
					      cm->cptr->user->username,
					      cm->cptr->hostip));
	s = make_nick_user_host(cm->cptr->name, cm->cptr->user->username,
				cm->cptr->user->host);
	if (match(banid, nickuhost) == 0 || match(banid, s) == 0 
		|| (match(banid, nickuvirthost) == 0))
	    cm->bans++;
    }
    return 0;
}

/*
 * del_banid - delete an id belonging to cptr if banid is null,
 * deleteall banids belonging to cptr.
 */
static int del_banid(aChannel *chptr, char *banid)
{
   aBan        **ban;
   aBan   	*tmp;
   chanMember 	*cm;
   char 	*s, nickuhost[NICKLEN+USERLEN+HOSTLEN+6];
   char 	 nickuvirthost[NICKLEN+USERLEN+HOSTLEN+6];

   if (!banid)
       return -1;
   for (ban = &(chptr->banlist); *ban; ban = &((*ban)->next))
       if (mycmp(banid, (*ban)->banstr) == 0)
       {
	   tmp = *ban;
	   *ban = tmp->next;
	   
	   for (cm = chptr->members; cm; cm = cm->next) 
	   {
	       if(!MyConnect(cm->cptr) || cm->bans == 0) 
		   continue;

	       strcpy(nickuvirthost, make_nick_user_host(cm->cptr->name,
			       cm->cptr->user->username, cm->cptr->user->virthost));
	       
	       strcpy(nickuhost, make_nick_user_host(cm->cptr->name,
			   cm->cptr->user->username, cm->cptr->hostip));
	       s = make_nick_user_host(cm->cptr->name, 
				       cm->cptr->user->username,
				       cm->cptr->user->host);
	       if (match(banid, nickuhost) == 0 || match(banid, s) == 0
		       || (match(banid, nickuvirthost) == 0))
		   cm->bans--;
	   }
	   
	   MyFree(tmp->banstr);
	   MyFree(tmp->who);
	   MyFree(tmp);
	   
	   break;
       }
   return 0;
}

/*
 * is_restrictd - returns a pointer to the restrict structure if restricted else
 * NULL
 *
 * IP_BAN_ALL from comstud always on...
 */

static aBan *is_restricted(aClient *cptr, aChannel *chptr)
{
    aBan       *tmp;
    char        s[NICKLEN + USERLEN + HOSTLEN + 6];
    char       *s2;
    char	sv[NICKLEN + USERLEN + HOSTLEN + 6];

    if (!IsPerson(cptr))
	return NULL;
    strcpy(sv, make_nick_user_host(cptr->name, cptr->user->username,
		    cptr->user->virthost));
    
    strcpy(s, make_nick_user_host(cptr->name, cptr->user->username,
				  cptr->user->host));
    s2 = make_nick_user_host(cptr->name, cptr->user->username,
			     cptr->hostip);

    for (tmp = chptr->restrictlist; tmp; tmp = tmp->next)
	if ((match(tmp->banstr, s) == 0) ||
	    (match(tmp->banstr, s2) == 0)
	    || (match(tmp->banstr, sv) == 0)
	    )
	    break;
    return (tmp);
}

/*
 * is_banned - returns a pointer to the ban structure if banned else
 * NULL
 * 
 * IP_BAN_ALL from comstud always on...
 */

static aBan *is_banned(aClient *cptr, aChannel *chptr)
{
    aBan       *tmp;
    char        s[NICKLEN + USERLEN + HOSTLEN + 6];
    char       *s2;
    char	sv[NICKLEN + USERLEN + HOSTLEN + 6];
    
    if (!IsPerson(cptr))
	return NULL;

    strcpy(sv, make_nick_user_host(cptr->name, cptr->user->username,
		    cptr->user->virthost));
    
    strcpy(s, make_nick_user_host(cptr->name, cptr->user->username,
				  cptr->user->host));
    s2 = make_nick_user_host(cptr->name, cptr->user->username,
			     cptr->hostip);
    
    for (tmp = chptr->banlist; tmp; tmp = tmp->next)
	if ((match(tmp->banstr, s) == 0)  ||
	    (match(tmp->banstr, s2) == 0) ||
	    (match(tmp->banstr, sv) == 0))
	    break;
    return (tmp);
}

aBan *nick_is_banned(aChannel *chptr, char *nick, aClient *cptr)
{
    aBan *tmp;
    char *s, s2[NICKLEN+USERLEN+HOSTLEN+6];
    char sv[NICKLEN+USERLEN+HOSTLEN+6];
    
    if (!IsPerson(cptr)) return NULL;
    
    strcpy(s2, make_nick_user_host(nick, cptr->user->username,
				   cptr->user->host));

    strcpy(sv, make_nick_user_host(nick, cptr->user->username,
		    		   cptr->user->virthost));

    s = make_nick_user_host(nick, cptr->user->username, cptr->hostip);

    for (tmp = chptr->banlist; tmp; tmp = tmp->next)
	if (tmp->type == MTYP_FULL &&        /* only check applicable bans */
	    ((match(tmp->banstr, s2) == 0) ||    /* check host before IP */
	     (match(tmp->banstr, s) == 0)  ||
	     (match(tmp->banstr, sv) == 0)))
	    break;
    return (tmp);
}

void remove_matching_bans(aChannel *chptr, aClient *cptr, aClient *from) 
{
    aBan *ban, *bnext;
    char targhost[NICKLEN+USERLEN+HOSTLEN+6];
    char targip[NICKLEN+USERLEN+HOSTLEN+6];
    char *m;
    int count = 0, send = 0;
    char targvirthost[NICKLEN+USERLEN+HOSTLEN+6];
    
    if (!IsPerson(cptr)) return;
    
    strcpy(targhost, make_nick_user_host(cptr->name, cptr->user->username,
					 cptr->user->host));
    strcpy(targip, make_nick_user_host(cptr->name, cptr->user->username,
					 cptr->hostip));
    strcpy(targvirthost, make_nick_user_host(cptr->name,
		    cptr->user->username, cptr->user->virthost));
  
  m = modebuf;  
  *m++ = '-';
  *m = '\0'; 
  
  *parabuf = '\0';
  
  ban = chptr->banlist;
  
  while(ban)
  {
      bnext = ban->next;
      if((match(ban->banstr, targhost) == 0) ||
	 (match(ban->banstr, targip) == 0)   ||
	 (match(ban->banstr, targvirthost) == 0))
      {
	  if (strlen(parabuf) + strlen(ban->banstr) + 10 < (size_t) MODEBUFLEN)
	  {
	      if(*parabuf)
		  strcat(parabuf, " ");
	      strcat(parabuf, ban->banstr);
	      count++;
	      *m++ = 'b';
	      *m = '\0';
	  }
	  else 
	      if(*parabuf)
		  send = 1;
	  
	  if(count == MAXTSMODEPARAMS)
	      send = 1;
	  
	  if(send)
	  {
	      sendto_channel_butserv(chptr, from, ":%s MODE %s %s %s", 
				     from->name, chptr->chname, modebuf,
				     parabuf);
	      sendto_server(from, chptr, NOCAPS, CAP_TSMODE, ":%s MODE %s %s %s",
				  from->name, chptr->chname, modebuf, parabuf);
	      sendto_server(from, chptr, CAP_TSMODE, NOCAPS, ":%s MODE %s %ld %s %s",
				  from->name, chptr->chname, chptr->channelts, modebuf, parabuf);
	      send = 0;
	      *parabuf = '\0';
	      m = modebuf;
	      *m++ = '-';
	      if(count != MAXTSMODEPARAMS)
	      {
		  strcpy(parabuf, ban->banstr);
		  *m++ = 'b';
		  count = 1;
	      }
	      else
		  count = 0;
	      *m = '\0';
	  }
	  
	  del_banid(chptr, ban->banstr);
      }
      ban = bnext;
  }
  
  if(*parabuf)
  {
      sendto_channel_butserv(chptr, from, ":%s MODE %s %s %s", from->name,
			     chptr->chname, modebuf, parabuf);
      sendto_server(from, chptr, NOCAPS, CAP_TSMODE, ":%s MODE %s %s %s",
		    from->name, chptr->chname, modebuf, parabuf);
      sendto_server(from, chptr, CAP_TSMODE, NOCAPS, ":%s MODE %s %ld %s %s",
		    from->name, chptr->chname, chptr->channelts, modebuf, parabuf);
  }
  
  return;
}

/*
 * adds a user to a channel by adding another link to the channels
 * member chain.
 */
static void add_user_to_channel(aChannel *chptr, aClient *who, int flags)
{
    Link   *ptr;
    chanMember *cm;
    
#ifdef DUMP_DEBUG
    fprintf(dumpfp,"Add to channel %s: %p:%s\n",chptr->chname,who,who->name);
#endif
    
    if (who->user)
    {
	cm = make_chanmember();
	cm->flags = flags;
	cm->cptr = who;
	cm->next = chptr->members;
	cm->bans = 0;
	chptr->members = cm;
	chptr->users++;
	
	ptr = make_link();
	ptr->value.chptr = chptr;
	ptr->next = who->user->channel;
	who->user->channel = ptr;
	who->user->joined++;
    }
}

void remove_user_from_channel(aClient *sptr, aChannel *chptr)
{
    chanMember  **curr, *tmp;
    Link  	   **lcurr, *ltmp;
    
    for (curr = &chptr->members; (tmp = *curr); curr = &tmp->next)
	if (tmp->cptr == sptr)
	{
	    *curr = tmp->next;
	    free_chanmember(tmp);
	    break;
	}

    for (lcurr = &sptr->user->channel; (ltmp = *lcurr); lcurr = &ltmp->next)
	if (ltmp->value.chptr == chptr)
	{
	    *lcurr = ltmp->next;
	    free_link(ltmp);
	    break;
	}
    sptr->user->joined--;
    sub1_from_channel(chptr);
}

int is_chan_op(aClient *cptr, aChannel *chptr)
{
    chanMember   *cm;
    
    if (chptr)
	if ((cm = find_user_member(chptr->members, cptr)))
	    return (cm->flags & CHFL_CHANOP);
    
    return 0;
}

int is_half_op(aClient *cptr, aChannel *chptr)
{
    chanMember   *cm;
    
    if (chptr)
	if ((cm = find_user_member(chptr->members, cptr)))
	    return (cm->flags & CHFL_HALFOP);
    
    return 0;
}

int is_deopped(aClient *cptr, aChannel *chptr)
{
    chanMember   *cm;
    
    if (chptr)
	if ((cm = find_user_member(chptr->members, cptr)))
	    return (cm->flags & CHFL_DEOPPED);
    
    return 0;
}

int has_voice(aClient *cptr, aChannel *chptr)
{
    chanMember   *cm;
    
    if (chptr)
	if ((cm = find_user_member(chptr->members, cptr)))
	    return (cm->flags & CHFL_VOICE);
    
    return 0;
}

int can_send(aClient *cptr, aChannel *chptr, char *msg)
{
    chanMember   *cm;
    int     member;
    
    if (IsServer(cptr) || IsULine(cptr) || IsUmodez(cptr))
	return 0;
    
    member = (cm = find_user_member(chptr->members, cptr)) ? 1 : 0;
    
    if(!member)
    {
	if (chptr->mode.mode & MODE_MODERATED)
	    return (MODE_MODERATED);
	if(chptr->mode.mode & MODE_NOPRIVMSGS)
	    return (MODE_NOPRIVMSGS);
	if ((chptr->mode.mode & MODE_MODREG) && !IsRegNick(cptr))
	    return (ERR_NEEDREGGEDNICK);
	if ((chptr->mode.mode & MODE_NOCOLOR) && msg_has_colors(msg))
	    return (ERR_NOCOLORSONCHAN);
	if (MyClient(cptr) && is_banned(cptr, chptr))
	    return (MODE_BAN); /*
				* channel is -n and user is not there;
				* we need to bquiet them if we can
				*/
    }
    else
    {
	if (chptr->mode.mode & MODE_MODERATED &&
	    !(cm->flags & (CHFL_CHANOP | CHFL_VOICE | CHFL_HALFOP)))
	    return (MODE_MODERATED);
	if(cm->bans && !(cm->flags & (CHFL_CHANOP | CHFL_VOICE | CHFL_HALFOP)))
	    return (MODE_BAN);
	if ((chptr->mode.mode & MODE_MODREG) && !IsRegNick(cptr) &&
	    !(cm->flags & (CHFL_CHANOP | CHFL_VOICE | CHFL_HALFOP)))
	    return (ERR_NEEDREGGEDNICK);
	if ((chptr->mode.mode & MODE_NOCOLOR) && msg_has_colors(msg))
	    return (ERR_NOCOLORSONCHAN);
    }
    return 0;
}

__inline int can_change_nick (aChannel *chptr, aClient *cptr)
{
    chanMember *cm;
    
    if (IsServer(cptr) || IsULine(cptr) || IsUmodez(cptr))
	return 0;

    if((cm = find_user_member(chptr->members, cptr)) == NULL)
	return 0; /* should not happen . . */
    
    if (chptr->mode.mode & MODE_NONICKCHG &&
	    !(cm->flags & (CHFL_CHANOP | CHFL_VOICE | CHFL_HALFOP)))
	    return (MODE_NONICKCHG);
    return 0;
}

/*
 * write the "simple" list of channel modes for channel chptr onto
 * buffer mbuf with the parameters in pbuf.
 */
static void channel_modes(aClient *cptr, char *mbuf, char *pbuf,
			  char *noneb_mbuf, aChannel *chptr)
{
#define ADDMODE(x,c)                    \
	do {                            \
	    if (chptr->mode.mode & (x)) \
	    {                           \
		*mbuf++ = c;            \
		*noneb_mbuf++ = c;      \
	    }                           \
	}                               \
	while (0)

    *mbuf++ = '+';
    *noneb_mbuf++ = '+';
    ADDMODE(MODE_SECRET, 's');
    ADDMODE(MODE_PRIVATE, 'p');
    ADDMODE(MODE_MODERATED, 'm');
    ADDMODE(MODE_TOPICLIMIT, 't');
    ADDMODE(MODE_INVITEONLY, 'i');
    ADDMODE(MODE_NOPRIVMSGS, 'n');
    ADDMODE(MODE_REGISTERED, 'r');
    ADDMODE(MODE_REGONLY, 'R');
    ADDMODE(MODE_NOCOLOR, 'c');
    ADDMODE(MODE_OPERONLY, 'O');
    ADDMODE(MODE_MODREG, 'M');
    ADDMODE(MODE_NONICKCHG, 'd');
    ADDMODE(MODE_NOSPAM, 'u');
    ADDMODE(MODE_NOCTCP, 'C');
    ADDMODE(MODE_SSLONLY, 'S');
    ADDMODE(MODE_NOUNKNOWN, 'j');
    ADDMODE(MODE_UNRESTRICT, 'U');
    /* don't add to noneb_mbuf */
    if (chptr->mode.mode & MODE_HIDEBANS)
	*mbuf++ = 'B';
    if (chptr->mode.limit) {
	*mbuf++ = 'l';
	*noneb_mbuf++ = 'l';
	if (IsMember(cptr, chptr) || IsServer(cptr) || IsULine(cptr) || IsUmodez(cptr))
	{
	    if (*chptr->mode.key)
		ircsprintf(pbuf, "%d ", chptr->mode.limit);
	    else
		ircsprintf(pbuf, "%d", chptr->mode.limit);	    
	}
    }
    if (*chptr->mode.key)
    {
	*mbuf++ = 'k';
	*noneb_mbuf++ = 'k';
	if (IsMember(cptr, chptr) || IsServer(cptr) || IsULine(cptr) || IsUmodez(cptr))
	    strcat(pbuf, chptr->mode.key);
    }
    *mbuf++ = '\0';
    *noneb_mbuf++ = '\0';
    return;
#undef ADDMODE
}

static void send_restrict_list(aClient *cptr, aChannel *chptr)
{
    aBan   *bp;
    char   *cp;
    int         count = 0, send = 0;

    cp = modebuf + strlen(modebuf);

    if (*parabuf) /* mode +l or +k xx */
	count = 1;

    for (bp = chptr->restrictlist; bp; bp = bp->next) 
    {
	if (strlen(parabuf) + strlen(bp->banstr) + 20 < (size_t) MODEBUFLEN) 
	{
	    if(*parabuf)
		strcat(parabuf, " ");
	    strcat(parabuf, bp->banstr);
	    count++;
	    *cp++ = 'z';
	    *cp = '\0';
	}
	else if (*parabuf)
	    send = 1;

	if (count == MAXTSMODEPARAMS)
	    send = 1;

	if (send) {
	    if(IsCapable(cptr, CAP_TSMODE))
		sendto_one(cptr, ":%s MODE %s %ld %s %s", me.name, chptr->chname,
			   chptr->channelts, modebuf, parabuf);
	    else
		sendto_one(cptr, ":%s MODE %s %s %s", me.name, chptr->chname,
			   modebuf, parabuf);
	    send = 0;
	    *parabuf = '\0';
	    cp = modebuf;
	    *cp++ = '+';
	    if (count != MAXTSMODEPARAMS) {
		strcpy(parabuf, bp->banstr);
		*cp++ = 'z';
		count = 1;
	    }
	    else
		count = 0;
	    *cp = '\0';
	}
    }
}

static void send_ban_list(aClient *cptr, aChannel *chptr)
{
    aBan   *bp;
    char   *cp;
    int         count = 0, send = 0;

    cp = modebuf + strlen(modebuf);

    if (*parabuf) /* mode +l or +k xx */
	count = 1;

    for (bp = chptr->banlist; bp; bp = bp->next) 
    {
	if (strlen(parabuf) + strlen(bp->banstr) + 20 < (size_t) MODEBUFLEN) 
	{
	    if(*parabuf)
		strcat(parabuf, " ");
	    strcat(parabuf, bp->banstr);
	    count++;
	    *cp++ = 'b';
	    *cp = '\0';
	}
	else if (*parabuf)
	    send = 1;

	if (count == MAXTSMODEPARAMS)
	    send = 1;

	if (send) {
	    if(IsCapable(cptr, CAP_TSMODE))
		sendto_one(cptr, ":%s MODE %s %ld %s %s", me.name, chptr->chname,
			   chptr->channelts, modebuf, parabuf);
	    else
		sendto_one(cptr, ":%s MODE %s %s %s", me.name, chptr->chname,
			   modebuf, parabuf);
	    send = 0;
	    *parabuf = '\0';
	    cp = modebuf;
	    *cp++ = '+';
	    if (count != MAXTSMODEPARAMS) {
		strcpy(parabuf, bp->banstr);
		*cp++ = 'b';
		count = 1;
	    }
	    else
		count = 0;
	    *cp = '\0';
	}
    }
}

/* send "cptr" a full list of the modes for channel chptr. */
void send_channel_modes(aClient *cptr, aChannel *chptr)
{
    chanMember       *l, *anop = NULL, *skip = NULL;
    int         n = 0;
    char       *t;

    if (*chptr->chname != '#')
	return;

    *modebuf = *parabuf = *noneb_modebuf = '\0';
    channel_modes(cptr, modebuf, parabuf, noneb_modebuf, chptr);

    if(IsCapable(cptr, CAP_NSJOIN))
	ircsprintf(buf, ":%s SJOIN %ld %s %s %s :", me.name,
		   chptr->channelts, chptr->chname,
		   IsCapable(cptr, CAP_EBMODE) ? modebuf : noneb_modebuf, parabuf);
    else
	ircsprintf(buf, ":%s SJOIN %ld %ld %s %s %s :", me.name,
		   chptr->channelts, chptr->channelts, chptr->chname,
		   IsCapable(cptr, CAP_EBMODE) ? modebuf : noneb_modebuf,
		   parabuf);
    t = buf + strlen(buf);
    for (l = chptr->members; l; l = l->next)
	if (l->flags & MODE_CHANOP)
	{
	    anop = l;
	    break;
	}
    /*
     * follow the channel, but doing anop first if it's defined *
     * -orabidoo
     */
    l = NULL;
    for (;;)
    {
	if (anop)
	{
	    l = skip = anop;
	    anop = NULL;
	}
	else
	{
	    if (l == NULL || l == skip)
		l = chptr->members;
	    else
		l = l->next;
	    if (l && l == skip)
		l = l->next;
	    if (l == NULL)
		break;
	}

	if (l->flags & MODE_HALFOP)
	    *t++ = '%';

	if (l->flags & MODE_CHANOP)
	    *t++ = '@';

	if (l->flags & MODE_VOICE)
	    *t++ = '+';
	strcpy(t, l->cptr->name);
	t += strlen(t);
	*t++ = ' ';
	n++;
	if (t - buf > BUFSIZE - 80)
	{
	    *t++ = '\0';
	    if (t[-1] == ' ')
		t[-1] = '\0';
	    sendto_one(cptr, "%s", buf);
	    if(IsCapable(cptr, CAP_NSJOIN))
		sprintf(buf, ":%s SJOIN %ld %s 0 :", me.name,
			chptr->channelts, chptr->chname);
	    else
		sprintf(buf, ":%s SJOIN %ld %ld %s 0 :", me.name,
			chptr->channelts, chptr->channelts,
			chptr->chname);
	    t = buf + strlen(buf);
	    n = 0;
	}
    }

    if (n)
    {
	*t++ = '\0';
	if (t[-1] == ' ')
	    t[-1] = '\0';
	sendto_one(cptr, "%s", buf);
    }
    *parabuf = '\0';
    *modebuf = '+';
    modebuf[1] = '\0';
    send_ban_list(cptr, chptr);
    if (IsCapable(cptr, CAP_EBMODE))
	send_restrict_list(cptr, chptr);

    if (modebuf[1] || *parabuf)
    {
	if(IsCapable(cptr, CAP_TSMODE))
	    sendto_one(cptr, ":%s MODE %s %ld %s %s",
	 	       me.name, chptr->chname, chptr->channelts, modebuf, parabuf);
        else
	    sendto_one(cptr, ":%s MODE %s %s %s",
	 	       me.name, chptr->chname, modebuf, parabuf);
    }
}

/* m_mode parv[0] - sender parv[1] - channel */

int m_mode(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int mcount = 0, chanop=0;
    int stripped_mcount = 0;
    int noneb_mcount = 0;
    aChannel *chptr;
    int subparc = 2;
    /* Now, try to find the channel in question */
    if (parc > 1)
    {
	chptr = find_channel(parv[1], NullChn);
	if (chptr == NullChn)
	    return m_umode(cptr, sptr, parc, parv);
    }
    else
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		   me.name, parv[0], "MODE");
	return 0;
    }
    
    if (!check_channelname(sptr, (unsigned char *) parv[1]))
	return 0;
    
    if (is_chan_op(sptr, chptr) || (IsServer(sptr) && chptr->channelts!=0))
	chanop = 1;
    else if (IsULine(sptr) || ((IsSAdmin(sptr) || IsAdmin(sptr)) && !MyClient(sptr)) || IsUmodez(sptr))
	chanop = 2; /* extra speshul access */
	
	
    if (parc < 3)
    {
	*modebuf = *parabuf = *noneb_modebuf = '\0';
	modebuf[1] = '\0';
	channel_modes(sptr, modebuf, parabuf, noneb_modebuf, chptr);
	sendto_one(sptr, rpl_str(RPL_CHANNELMODEIS), me.name, parv[0],
		   chptr->chname, modebuf, parabuf);
	sendto_one(sptr, rpl_str(RPL_CREATIONTIME), me.name, parv[0],
		   chptr->chname, chptr->channelts);
	return 0;
    }

    if(IsServer(cptr) && IsCapable(cptr, CAP_TSMODE) && isdigit(parv[2][0]))
    {
       ts_val modets = atol(parv[2]);

       if(modets != 0 && (modets > chptr->channelts))
       {
          /* ignore this mode! */
          return 0;
       }

       subparc++;
    }
    mcount = set_mode(cptr, sptr, chptr, chanop, parc - subparc, parv + subparc,
		      modebuf, parabuf, stripped_modebuf, stripped_parabuf, &stripped_mcount,
		      noneb_modebuf, noneb_parabuf, &noneb_mcount);

    if (strlen(modebuf) > (size_t) 1)
	switch (mcount)
	{
	case 0:
	    break;
	case -1:
	    if (MyClient(sptr))
		sendto_one(sptr,
			   err_str(ERR_CHANOPRIVSNEEDED),
			   me.name, parv[0], chptr->chname);
	    else
	    {
		ircstp->is_fake++;
	    }
	    break;
	default:
		if (stripped_mcount == mcount)
		{
		    sendto_channel_butserv(chptr, sptr,
					   ":%s MODE %s %s %s", parv[0],
					   chptr->chname, modebuf,
					   parabuf);
		}
		else
		{
		    /* I mode vengono settati anche dai server, STRONZONE */
		    sendto_chanops_butserv(chptr, sptr, 1,
					   ":%s MODE %s %s %s", parv[0],
					   chptr->chname, modebuf,
					   parabuf);
		    if (stripped_mcount > 0)
			sendto_chanops_butserv(chptr, sptr, 0,
					       ":%s MODE %s %s %s", parv[0],
					       chptr->chname, stripped_modebuf,
					       stripped_parabuf);
		}

	    if (noneb_mcount == mcount)
	    {
		/* We got only baseline modes, no need to check for CAP_EBMODE */
		sendto_server(cptr, chptr, NOCAPS, CAP_TSMODE,
			      ":%s MODE %s %s %s",
			      parv[0], chptr->chname,
			      modebuf, parabuf);
		sendto_server(cptr, chptr, CAP_TSMODE, NOCAPS,
			      ":%s MODE %s %ld %s %s",
			      parv[0], chptr->chname, chptr->channelts,
			      modebuf, parabuf);
	    }
	    else
	    {
		/* Ok, fine, let's send out full modes first */
		sendto_server(cptr, chptr, CAP_EBMODE, CAP_TSMODE,
			      ":%s MODE %s %s %s",
			      parv[0], chptr->chname,
			      modebuf, parabuf);
		sendto_server(cptr, chptr, CAP_EBMODE | CAP_TSMODE, NOCAPS,
			      ":%s MODE %s %ld %s %s",
			      parv[0], chptr->chname, chptr->channelts,
			      modebuf, parabuf);
		/* Now send baseline modes only (if any) */
		if (noneb_mcount > 0)
		{
		    sendto_server(cptr, chptr, NOCAPS, CAP_TSMODE | CAP_EBMODE,
				  ":%s MODE %s %s %s",
				  parv[0], chptr->chname,
				  noneb_modebuf, noneb_parabuf);
		    sendto_server(cptr, chptr, CAP_TSMODE, CAP_EBMODE,
				  ":%s MODE %s %ld %s %s",
				  parv[0], chptr->chname, chptr->channelts,
				  noneb_modebuf, noneb_parabuf);
		}
	    }
	}
    return 0;
}

/* the old set_mode was pissing me off with it's disgusting
 * hackery, so I rewrote it.  Hope this works. }:> --wd
 */
static int set_mode(aClient *cptr, aClient *sptr, aChannel *chptr,
		    int level, int parc, char *parv[], char *mbuf, char *pbuf,
		    char *stripped_mbuf, char *stripped_pbuf, int *stripped_mcount,
		    char *noneb_mbuf, char *noneb_pbuf, int *noneb_mcount)
{
#define SM_ERR_NOPRIVS 0x0001 /* is not an op */
#define SM_ERR_MOREPARMS 0x0002 /* needs more parameters */	
#define SM_ERR_RESTRICTED 0x0004 /* not allowed to op others or be op'd */	
#define SM_ERR_NOTOPER    0x0008 /* not an irc op */
#define SM_MAXMODES MAXMODEPARAMSUSER

/* this macro appends to pbuf */
#define ADD_PARA(p)                     \
	do {                            \
	    pptr = p;                   \
	    if(pidx)                    \
	        pbuf[pidx++] = ' ';     \
	    while(*pptr)                \
	        pbuf[pidx++] = *pptr++; \
	} while (0)

#define ADD_STRIPPED_PARA(p)                              \
	do {                                              \
	    pptr = p;                                     \
	    if (stripped_pidx)                            \
	        stripped_pbuf[stripped_pidx++] = ' ';     \
	    while (*pptr)                                 \
	        stripped_pbuf[stripped_pidx++] = *pptr++; \
	} while (0)

#define ADD_NONEB_PARA(p)                                 \
	do {                                              \
	    pptr = p;                                     \
	    if (noneb_pidx)                               \
		noneb_pbuf[noneb_pidx++] = ' ';           \
	    while (*pptr)                                 \
		noneb_pbuf[noneb_pidx++] = *pptr++;       \
	} while (0)

    static int flags[] = 
    {
	MODE_PRIVATE, 'p', MODE_SECRET, 's',
	MODE_MODERATED, 'm', MODE_NOPRIVMSGS, 'n',
	MODE_TOPICLIMIT, 't', MODE_REGONLY, 'R',
	MODE_INVITEONLY, 'i', MODE_NOCOLOR, 'c', MODE_OPERONLY, 'O',
	MODE_MODREG, 'M', 
	MODE_NONICKCHG, 'd', MODE_NOSPAM, 'u',
	MODE_NOCTCP, 'C', MODE_SSLONLY, 'S',
	MODE_NOUNKNOWN, 'j', MODE_UNRESTRICT, 'U',
	0x0, 0x0
    };
    
    Link *lp; /* for walking lists */
    chanMember *cm; /* for walking channel member lists */
    aBan *bp; /* for walking banlists */
    char *modes=parv[0]; /* user's idea of mode changes */
    int args; /* counter for what argument we're on */
    int banlsent = 0; /* Only list bans once in a command. */
    char change='+'; /* by default we + things... */
    int errors=0; /*
		   * errors returned, set with bitflags
		   * so we only return them once
		   */
    /* from remote servers, ungodly numbers of modes can be sent, but
     * from local users only SM_MAXMODES are allowed */
    int maxmodes=((IsServer(sptr) || IsULine(sptr)) ? 512 : SM_MAXMODES);
    int nmodes=0; /* how many modes we've set so far */
    aClient *who = NULL; /* who we're doing a mode for */
    int chasing = 0;
    int i=0;
    char moreparmsstr[]="MODE   ";
    char nuhbuf[NICKLEN + USERLEN + HOSTLEN + 6]; /* for bans */
    char tmp[16]; /* temporary buffer */
    int pidx = 0; /* index into pbuf */
    char *pptr; /* temporary paramater pointer */
    char *morig = mbuf; /* beginning of mbuf */
    int stripped_pidx = 0; /*index into stripped_pbuf*/
    int stripped_nmodes = 0; /*How many stripped modes we've set so far*/
    int noneb_pidx = 0; /* Ditto for noneb_pbuf */
    int noneb_nmodes = 0; /* Ditto for noneb_mbuf */

    /* :cptr-name MODE chptr->chname [MBUF] [PBUF] (buflen - 3 max and NULL) */
    int prelen = strlen(cptr->name) + strlen(chptr->chname) + 16;
    int ishalfop = 0;


    args=1;
	
    if(parc<1)
	return 0;

    *mbuf++='+'; /* add the plus, even if they don't */
    *stripped_mbuf++='+';
    *noneb_mbuf++='+';
    /* go through once to clean the user's mode string so we can
     * have a simple parser run through it...*/

    if ((level<1) && is_half_op(sptr, chptr))
	ishalfop = 1;

    while(*modes && (nmodes<maxmodes)) 
    {
	switch(*modes) 
	{
	case '+':
	    if(*(stripped_mbuf-1) == '-')
		*(stripped_mbuf-1) = '+';
	    else if (change != '+')
		*stripped_mbuf++ = '+';

	    if(*(noneb_mbuf-1) == '-')
		*(noneb_mbuf-1) = '+';
	    else if (change != '+')
		*noneb_mbuf++ = '+';

            if(*(mbuf-1)=='-') 
            {
				*(mbuf-1)='+'; /* change it around now */
				change='+';
				break;
            }
            else if(change=='+') /* we're still doing a +, we don't care */
				break;
            change=*modes;
            *mbuf++='+';
            break;
	case '-':
	    if(*(stripped_mbuf-1) == '+')
		*(stripped_mbuf-1) = '-';
	    else if (change != '-')
		*stripped_mbuf++ = '-';

	    if(*(noneb_mbuf-1) == '+')
		*(noneb_mbuf-1) = '-';
	    else if (change != '-')
		*noneb_mbuf++ = '-';

            if(*(mbuf-1)=='+') 
            {
				*(mbuf-1)='-'; /* change it around now */
				change='-';
				break;
            }
            else if(change=='-')
				break; /* we're still doing a -, we don't care */
            change=*modes;
            *mbuf++='-';
            break;

	case 'O':
	    if (level < 2 && (level < 1 || !IsOper(sptr)))
	    {
		errors |= SM_ERR_NOTOPER;
		break;
	    } else {
		/* Azzurra changed: do not allow setting of an already set mode
		 */
		if (change=='+' && !(chptr->mode.mode & MODE_OPERONLY))
		{
		    chptr->mode.mode |= MODE_OPERONLY;
		    *mbuf++ = *modes;
		    *stripped_mbuf++ = *modes;
		    *noneb_mbuf++ = *modes;
		    stripped_nmodes++;
		    noneb_nmodes++;
		    nmodes++;
		}
		else if(change=='-' && chptr->mode.mode & MODE_OPERONLY)
		{
		    chptr->mode.mode &= ~MODE_OPERONLY;
		    *mbuf++ = *modes;
		    *stripped_mbuf++ = *modes;
		    *noneb_mbuf++ = *modes;
		    stripped_nmodes++;
		    noneb_nmodes++;
		    nmodes++;
		}
		else
		    break;
	    }
	    break;

	case 'B':
	    /* Special handling for MODE_HIDEBANS */
	    if (level < 1)
	    {
		errors |= SM_ERR_NOPRIVS;
		break;
	    }

	    if (change == '+' && !(chptr->mode.mode & MODE_HIDEBANS))
	    {
		chptr->mode.mode |= MODE_HIDEBANS;
		*mbuf++ = *modes;
		*stripped_mbuf++ = *modes;
		stripped_nmodes++;
		nmodes++;
		/* Don't add to noneb_mbuf */
	    }
	    else if (change == '-' && (chptr->mode.mode & MODE_HIDEBANS))
	    {
		chptr->mode.mode &= ~MODE_HIDEBANS;
		*mbuf++ = *modes;
		*stripped_mbuf++ = *modes;
		stripped_nmodes++;
		nmodes++;
		/* Don't add to noneb_mbuf */
	    }
	    break;

	case 'h':
	    /* Halfop can't be disabled anymore, just fall through */

	case 'o':
	    /* deny mode -/+o for half operators */
            if(level<1) 
            {
		errors |= SM_ERR_NOPRIVS;
		break;
            }

	case 'v':
	    /* allow mode -/+v for half operators */
	    if(level<1 && !ishalfop)
            {
		errors |= SM_ERR_NOPRIVS;
		break;
            }
            if(parv[args]==NULL)
            {
		/* silently drop the spare +o/v's */
		break;
            }
			
            who = find_chasing(sptr, parv[args], &chasing);
            cm = find_user_member(chptr->members, who);
            if(cm == NULL) 
            {
		sendto_one(sptr, err_str(ERR_USERNOTINCHANNEL),
			   me.name, cptr->name, parv[args], chptr->chname);
		/* swallow the arg */
		args++;
		break;
            }
            /* if we're going to overflow our mode buffer,
	     * drop the change instead */
            if((prelen + (mbuf - morig) + pidx + NICKLEN + 1) > 
	       REALMODEBUFLEN) 
            {
		args++;
		break;
            }
	    
	    /* if we have the user, set them +/-[vo] */

	    /* Azzurra changed: do not allow op/deop of an already opped/deopped user
	     */
	    if(change=='+' && !(cm->flags & (*modes=='o' ? CHFL_CHANOP :
					     *modes=='h' ? CHFL_HALFOP :
							   CHFL_VOICE)))
	    {
		cm->flags|=(*modes=='o' ? CHFL_CHANOP : 
			    *modes=='h' ? CHFL_HALFOP :
					  CHFL_VOICE);
	        /* we've decided their mode was okay, cool */
	        *mbuf++ = *modes;
	        nmodes++;
		*stripped_mbuf++ = *modes;
		stripped_nmodes++;
		*noneb_mbuf++ = *modes;
		noneb_nmodes++;

	    }
	    else if(change=='-' && cm->flags & (*modes=='o' ? CHFL_CHANOP :
						*modes=='h' ? CHFL_HALFOP :
							      CHFL_VOICE))
	    {
                cm->flags&=~((*modes=='o' ? CHFL_CHANOP : 
			      *modes=='h' ? CHFL_HALFOP :
					    CHFL_VOICE));
	        /* we've decided their mode was okay, cool */
	        *mbuf++ = *modes;
	        nmodes++;
		*stripped_mbuf++ = *modes;
		stripped_nmodes++;
		*noneb_mbuf++ = *modes;
		noneb_nmodes++;
	    }
	    else
		break;

	    ADD_PARA(cm->cptr->name);
	    ADD_STRIPPED_PARA(cm->cptr->name);
	    ADD_NONEB_PARA(cm->cptr->name);
	    args++;

	    if (IsServer(sptr) && *modes == 'o' && change=='+') 
	    {
                chptr->channelts = 0;
                sendto_ops("Server %s setting +o and blasting TS on %s",
			   sptr->name, chptr->chname);
	    }
	    break;

	case 'z':
	    /* if the user has no more arguments, then they just want
             * to see the bans, okay, cool. */
            if(level < 1 && parv[args] != NULL)
            {
		errors |= SM_ERR_NOPRIVS;
		break;
            }
            /* show them the bans, woowoo */
            if(parv[args]==NULL)
            {
		if (banlsent || IsServer(sptr))
		    break; /* Send only once -- and not to servers */
		/* Normal users should not see this anyway */
		if (level >= 1 || IsAnOper(sptr) || IsUmodeh(sptr) || is_half_op(sptr, chptr)) {
		    for(bp=chptr->restrictlist;bp;bp=bp->next)
		        sendto_one(sptr, rpl_str(RPL_RESTRICTLIST), me.name, cptr->name,
			          chptr->chname, bp->banstr, bp->who, bp->when);
		} else {
		    errors |= SM_ERR_NOPRIVS;
		    break;
		}
		sendto_one(cptr, rpl_str(RPL_ENDOFRESTRICTLIST), me.name,
			   cptr->name, chptr->chname);
		banlsent = 1;
		break; /* we don't pass this along, either.. */
            }
            /* do not allow : in restrict mask, or a null restrict */
            if(*parv[args]==':' || *parv[args] == '\0') 
            {
		args++;
		break;
            }
            /* make a 'pretty' ban mask here, then try and set it */
            /* okay kids, let's do this again.
             * the buffer returned by pretty_mask is from 
             * make_nick_user_host. This buffer is eaten by add/del banid.
             * Thus, some poor schmuck gets himself on the banlist.
	     * Fixed. - lucas */
            strcpy(nuhbuf, collapse(pretty_mask(parv[args])));
            parv[args] = nuhbuf;
            /* if we're going to overflow our mode buffer,
             * drop the change instead */
            if((prelen + (mbuf - morig) + pidx + strlen(nuhbuf) + 1) > 
	       REALMODEBUFLEN) 
            {
		args++;
		break;
            }

            /* if we can't add or delete (depending) the ban, change is
             * worthless anyhow */
	    
            if(!(change=='+' && !add_restrictid(sptr, chptr, parv[args])) && 
               !(change=='-' && !del_restrictid(chptr, parv[args])))
            {
		args++;
		break;
            }
	    
            *mbuf++ = 'z';
	    ADD_PARA(parv[args]);

	    args++;
            nmodes++;
            break;

	case 'b':
            /* if the user has no more arguments, then they just want
             * to see the bans, okay, cool. */
            if(level < 1 && parv[args] != NULL)
            {
		errors |= SM_ERR_NOPRIVS;
		break;
            }
            /* show them the bans, woowoo */
            if(parv[args]==NULL)
            {
		if (banlsent || IsServer(sptr))
		    break; /* Send only once -- and not to servers */

		if (level >= 1 || IsAnOper(sptr) || IsUmodeh(sptr)
		|| is_half_op(sptr, chptr) || !(chptr->mode.mode & MODE_HIDEBANS))
		{
		    for(bp=chptr->banlist;bp;bp=bp->next)
		        sendto_one(sptr, rpl_str(RPL_BANLIST), me.name, cptr->name,
				   chptr->chname, bp->banstr, bp->who, bp->when);
		}

		sendto_one(cptr, rpl_str(RPL_ENDOFBANLIST), me.name,
			   cptr->name, chptr->chname);
		banlsent = 1;
		break; /* we don't pass this along, either.. */
            }
	    
            /* do not allow : in bans, or a null ban */
            if(*parv[args]==':' || *parv[args] == '\0') 
            {
		args++;
		break;
            }

            /* make a 'pretty' ban mask here, then try and set it */
            /* okay kids, let's do this again.
             * the buffer returned by pretty_mask is from 
             * make_nick_user_host. This buffer is eaten by add/del banid.
             * Thus, some poor schmuck gets himself on the banlist.
	     * Fixed. - lucas */
            strcpy(nuhbuf, collapse(pretty_mask(parv[args])));
            parv[args] = nuhbuf;
            /* if we're going to overflow our mode buffer,
             * drop the change instead */
            if((prelen + (mbuf - morig) + pidx + strlen(nuhbuf) + 1) > 
	       REALMODEBUFLEN) 
            {
		args++;
		break;
            }

            /* if we can't add or delete (depending) the ban, change is
             * worthless anyhow */
	    
            if(!(change=='+' && !add_banid(sptr, chptr, parv[args])) && 
               !(change=='-' && !del_banid(chptr, parv[args])))
            {
		args++;
		break;
            }
	    
            *mbuf++ = 'b';
	    ADD_PARA(parv[args]);
	    *noneb_mbuf++ = 'b';
	    ADD_NONEB_PARA(parv[args]);
	    if (!(chptr->mode.mode & MODE_HIDEBANS)) {
		*stripped_mbuf++ = *modes;
		stripped_nmodes++;
	    }

	    args++;
            nmodes++;
	    noneb_nmodes++;
            break;

	case 'l':
            if(level<1) 
            {
		errors |= SM_ERR_NOPRIVS;
		break;
            }

            /* if it's a -, just change the flag, we have no arguments */
            if(change=='-')
            {
		if((prelen + (mbuf - morig) + pidx + 1) > REALMODEBUFLEN) 
		    break;
		*mbuf++ = 'l';
		chptr->mode.mode &= ~MODE_LIMIT;
		chptr->mode.limit = 0;
		nmodes++;
		*stripped_mbuf++ = *modes;
		stripped_nmodes++;
		*noneb_mbuf++ = *modes;
		noneb_nmodes++;

		break;
            }
            else 
            {
		if(parv[args] == NULL) 
		{
		    errors|=SM_ERR_MOREPARMS;
		    break;
		}

		/* if we're going to overflow our mode buffer,
		 * drop the change instead */
		if((prelen + (mbuf - morig) + pidx + 16) > REALMODEBUFLEN) 
		{
		    args++;
		    break;
		}
               
		i = atoi(parv[args]);

		/* toss out invalid modes */
		if(i < 1)
		{
		    args++;
		    break;
		}
		ircsprintf(tmp, "%d", i);
		chptr->mode.limit = i;
		chptr->mode.mode |= MODE_LIMIT;
		*mbuf++ = 'l';
		*stripped_mbuf++ = 'l';
		stripped_nmodes++;
		ADD_STRIPPED_PARA(tmp);
		*noneb_mbuf++ = 'l';
		noneb_nmodes++;
		ADD_NONEB_PARA(tmp);

		ADD_PARA(tmp);
		args++;
		nmodes++;
		break;
            }

	case 'k':
            if(level<1) 
            {
		errors |= SM_ERR_NOPRIVS;
		break;
            }
            if(parv[args]==NULL)
		break;

            /* do not allow keys to start with :! ack! - lucas */
            /* another ack: don't let people set null keys! */
	    /* and yet a third ack: no spaces in keys -epi  */
            if(*parv[args]==':' || *parv[args] == '\0' ||
	       strchr(parv[args], ' '))
            {
		args++;
		break;
            }
	    
	    /* Do not let *'s in keys in preperation for key hiding
	     * - Raist
	     */
	    
	    if (strchr(parv[args],'*')!=NULL) {
		args++;
		break;
	    }
	    
            /* if we're going to overflow our mode buffer,
             * drop the change instead */
            if((prelen + (mbuf - morig) + pidx + KEYLEN+2) > REALMODEBUFLEN) 
            {
		args++;
		break;
            }
	    
            /* if they're an op, they can futz with the key in
             * any manner they like, we're not picky */
            if(change=='+') 
            {
		strncpy(chptr->mode.key,parv[args],KEYLEN);
		ADD_PARA(chptr->mode.key);
		ADD_STRIPPED_PARA(chptr->mode.key);
		ADD_NONEB_PARA(chptr->mode.key);
	    }
            else 
            {
		/* Azzurra changed: allow mode -k only if the user passes the
		   right current key.
		 */
		if(myncmp(chptr->mode.key, parv[args], KEYLEN) == 0)
		{
		    strncpy(chptr->mode.key,parv[args],KEYLEN);
		    ADD_PARA(chptr->mode.key);
		    ADD_STRIPPED_PARA(chptr->mode.key);
		    ADD_NONEB_PARA(chptr->mode.key);
		    *chptr->mode.key = '\0';
		}
		else
		{
		    args++;
		    break;
		}
            }
            *mbuf++='k';
            args++;
            nmodes++;
	    *stripped_mbuf++ = 'k';
	    stripped_nmodes++;
	    *noneb_mbuf++ = 'k';
	    noneb_nmodes++;
            break;

	case 'r':
            if (!IsServer(sptr) && !IsULine(sptr)) 
            {
		sendto_one(sptr, err_str(ERR_ONLYSERVERSCANCHANGE),
			   me.name, cptr->name, chptr->chname);
		break;
            }
            else 
            {
		if((prelen + (mbuf - morig) + pidx + 1) > REALMODEBUFLEN) 
		    break;
		
		if(change=='+')
		    chptr->mode.mode|=MODE_REGISTERED;
		else
		    chptr->mode.mode&=~MODE_REGISTERED;
            }
            *mbuf++='r';
            nmodes++;
	    *stripped_mbuf++ = 'r';
	    stripped_nmodes++;
	    *noneb_mbuf++ = 'r';
	    noneb_nmodes++;

            break;
	    
	case 'i':
            if(level < 1) 
            {
		errors |= SM_ERR_NOPRIVS;
		break;
            }

	    /* Azzurra changed: set -i only if the channel is really +i
	     */
            if(change=='-' && (chptr->mode.mode & MODE_INVITEONLY))
		while ((lp=chptr->invites))
		    del_invite(lp->value.cptr, chptr);
	    /* Full operator status is needed for this! */
	case 'p':
	case 's':
	case 'S':
	case 'R':
	case 'j':
	case 'U':
            if(level<1) 
            {
		errors |= SM_ERR_NOPRIVS;
		break;
            }
            /* fall through to default case */

	default:
            /* phew, no more tough modes. }:>, the rest are all
	     * covered in one step 
	     * with the above array */
	    /* other modes can be modified also by half operators */
            if(level<1 && !ishalfop)
            {
		errors |= SM_ERR_NOPRIVS;
		break;
            }
            for(i=1;flags[i]!=0x0;i+=2) 
            {
		if((prelen + (mbuf - morig) + pidx + 1) > REALMODEBUFLEN) 
		    break;
		
		if(*modes==(char)flags[i]) 
		{
		    /* Azzurra changed: do not allow multiple set/unset of modes
		     */
		    if(change=='+' && !(chptr->mode.mode & flags[i-1]))
		    {
			chptr->mode.mode |= flags[i-1];
		        *mbuf++=*modes;
		        nmodes++;
			*stripped_mbuf++ = *modes;
			stripped_nmodes++;
			*noneb_mbuf++ = *modes;
			noneb_nmodes++;
		    }
		    else if(change=='-' && chptr->mode.mode & flags[i-1])
		    {		
			chptr->mode.mode &= ~flags[i-1];
		        *mbuf++=*modes;
		        nmodes++;
			*stripped_mbuf++ = *modes;
			stripped_nmodes++;
			*noneb_mbuf++ = *modes;
			noneb_nmodes++;
		    }

		    break;
		}
            }

	    /* Azzurra changed: do not echo "unknown mode" when setting
	     * an unknown mode
	     */
            break;
	}
	
	/* spit out more parameters error here */
	if(errors & SM_ERR_MOREPARMS && MyClient(sptr)) 
	{
	    moreparmsstr[5]=change;
	    moreparmsstr[6]=*modes;
	    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
		       sptr->name, moreparmsstr);
	    errors &= ~SM_ERR_MOREPARMS; /* oops, kill it in this case */
	}
	modes++;
    }

    /* clean up the end of the string... */
    if (*(mbuf-1) == '+' || *(mbuf-1) == '-')
	*(mbuf-1) = '\0';
    else
	*mbuf = '\0';
    pbuf[pidx] = '\0';

    if (*(stripped_mbuf-1) == '+' || *(stripped_mbuf-1) == '-')
	*(stripped_mbuf-1) = '\0';
    else
	*(stripped_mbuf) = '\0';
    stripped_pbuf[stripped_pidx] = '\0';

    if (*(noneb_mbuf-1) == '+' || *(noneb_mbuf-1) == '-')
	*(noneb_mbuf-1) = '\0';
    else
	*(noneb_mbuf) = '\0';
    noneb_pbuf[noneb_pidx] = '\0';

    if(MyClient(sptr)) 
    {
	if(errors & SM_ERR_NOPRIVS)
	    sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name,
		       sptr->name, chptr->chname);	  
	if(errors & SM_ERR_NOTOPER)
	    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, sptr->name);
	if(errors & SM_ERR_RESTRICTED)
	    sendto_one(sptr,":%s NOTICE %s :*** Notice -- You are "
		       "restricted and cannot chanop others",
		       me.name, sptr->name);
    }
    /* all done! */
    *stripped_mcount = stripped_nmodes;
    *noneb_mcount = noneb_nmodes;
    return nmodes;
#undef ADD_PARA
#undef ADD_STRIPPED_PARA
#undef ADD_NONEB_PARA
}

/*
 * can_join: check if an user can join a channel
 * retuns: =0 if user can join
 *         >0 if user cannot join (calling function will send an ERROR MESSAGE)
 *         <0 if user cannot join (calling function will NOT send an ERROR MESSAGE)
 */
static int can_join(aClient *sptr, aChannel *chptr, char *key)
{
    Link   *lp;
    int invited=0;
    for(lp=sptr->user->invited;lp;lp=lp->next) {
	if(lp->value.chptr==chptr) {
	    invited=1;
	    break;
	}
    }
    if (invited || IsULine(sptr) || IsUmodez(sptr))
	return 0;


    /* Don't traverse the restricted list if we are not linked to services
     * or the user has a registered nick
     */
    if (restriction_enabled && !IsRegNick(sptr) && is_restricted(sptr, chptr))
    	return (ERR_NEEDREGGEDNICK);
    if (is_banned(sptr, chptr))
	return (ERR_BANNEDFROMCHAN);
    if (chptr->mode.mode & MODE_INVITEONLY)
	return (ERR_INVITEONLYCHAN);
    if (chptr->mode.mode & MODE_REGONLY && !IsRegNick(sptr))
	return (ERR_NEEDREGGEDNICK);
    if (chptr->mode.mode & MODE_NOUNKNOWN && !IsKnownNick(sptr))
	return (ERR_NEEDREGGEDNICK);
    if (!(chptr->mode.mode & MODE_UNRESTRICT) && check_restricted_user(sptr)) {
        static unsigned int rjoin_count = 0;
	static time_t rjoin_last = 0;
	
	if (show_restricted_joins) {
		if (rjoin_last < NOW - restricted_joins_time) {
			rjoin_count = 0;
			rjoin_last = NOW;
		}
		
		if (rjoin_count < restricted_joins_num) {
			rjoin_count++;
			sendto_security(SPAMREPORT_CHANNEL, 
				"Blocked JOIN for %s (%s@%s) on channel %s (unidentified user)",
				sptr->name, sptr->user->username, sptr->user->host, chptr->chname);
		}
	}
	
        return -1; /* check_restircted_user has already sent an error message */
    }
    if (chptr->mode.mode & MODE_OPERONLY && !IsOper(sptr))
	return (ERR_NOPRIVILEGES);
    if (*chptr->mode.key && (BadPtr(key) || mycmp(chptr->mode.key, key)))
	return (ERR_BADCHANNELKEY);
    if (chptr->mode.limit && chptr->users >= chptr->mode.limit) 
	return (ERR_CHANNELISFULL);
    if (chptr->mode.mode & MODE_SSLONLY && !IsSSL(sptr))
	return (ERR_ONLYSSLCLIENTS);
    return 0;
}
/*
 * * Remove bells and commas from channel name
 */

void clean_channelname(unsigned char *cn)
{
    for (; *cn; cn++)
	/*
	 * All characters >33 are allowed, except commas, and the weird
	 * fake-space character mIRCers whine about -wd
	 */
	if (*cn < 33 || *cn == ',' || (*cn == 160))
	{
	    *cn = '\0';
	    return;
	}
    return;
}

/* we also tell the client if the channel is invalid. */
int check_channelname(aClient *cptr, unsigned char *cn)
{
    if(!MyClient(cptr))
	return 1;
    for(;*cn;cn++) {
	if(*cn<33 || *cn == ',' || *cn==160) {
	    sendto_one(cptr, getreply(ERR_BADCHANNAME), me.name, cptr->name,
		       cn);
	    return 0;
	}
    }
    return 1;
}

/*
 * *  Get Channel block for chname (and allocate a new channel *
 * block, if it didn't exist before).
 */
static aChannel *get_channel(aClient *cptr, char *chname, int flag)
{
    aChannel *chptr;
    int         len;

    if (BadPtr(chname))
	return NULL;

    len = strlen(chname);
    if (MyClient(cptr) && len > CHANNELLEN)
    {
	len = CHANNELLEN;
	*(chname + CHANNELLEN) = '\0';
    }
    if ((chptr = find_channel(chname, (aChannel *) NULL)))
	return (chptr);
    if (flag == CREATE)
    {
	chptr = make_channel();
	
	strncpyzt(chptr->chname, chname, len + 1);
	if (channel)
	    channel->prevch = chptr;
	chptr->prevch = NULL;
	chptr->nextch = channel;
	channel = chptr;
	chptr->channelts = timeofday;
	(void) add_to_channel_hash_table(chname, chptr);
	Count.chan++;
    }
    return chptr;
}

static void add_invite(aClient *cptr, aChannel *chptr)
{
    Link   *inv, **tmp;
    
    del_invite(cptr, chptr);
    /*
     * delete last link in chain if the list is max length
     */
    if (list_length(cptr->user->invited) >= MAXCHANNELSPERUSER)
    {
	/*
	 * This forgets the channel side of invitation     -Vesa inv =
	 * cptr->user->invited; cptr->user->invited = inv->next;
	 * free_link(inv);
	 */
	del_invite(cptr, cptr->user->invited->value.chptr);
	
    }
    
    /*
     * add client to channel invite list
     */
    inv = make_link();
    inv->value.cptr = cptr;
    inv->next = chptr->invites;
    chptr->invites = inv;
    /*
     * add channel to the end of the client invite list
     */
    for (tmp = &(cptr->user->invited); *tmp; tmp = &((*tmp)->next));
    inv = make_link();
    inv->value.chptr = chptr;
    inv->next = NULL;
    (*tmp) = inv;
}

/*
 * Delete Invite block from channel invite list and client invite list
 */
void del_invite(aClient *cptr, aChannel *chptr)
{
    Link  **inv, *tmp;

    for (inv = &(chptr->invites); (tmp = *inv); inv = &tmp->next)
	if (tmp->value.cptr == cptr)
	{
	    *inv = tmp->next;
	    free_link(tmp);
	    break;
	}
    
    for (inv = &(cptr->user->invited); (tmp = *inv); inv = &tmp->next)
	if (tmp->value.chptr == chptr)
	{
	    *inv = tmp->next;
	    free_link(tmp);
	    break;
	}
}

/*
 * *  Subtract one user from channel i (and free channel *  block, if
 * channel became empty).
 */
static void sub1_from_channel(aChannel *chptr)
{
    Link   *tmp;
    aBan	      *bp, *bprem;
    
    if (--chptr->users <= 0) {
	/*
	 * Now, find all invite links from channel structure
	 */
	while ((tmp = chptr->invites))
	    del_invite(tmp->value.cptr, chptr);

	bp = chptr->banlist;
	while (bp)
	{
	    bprem = bp;
	    bp = bp->next;
	    MyFree(bprem->banstr);
	    MyFree(bprem->who);
	    MyFree(bprem);
	}
	bp = chptr->restrictlist;
	while (bp) {
		bprem = bp;
		bp = bp->next;
		MyFree(bprem->banstr);
		MyFree(bprem->who);
		MyFree(bprem);
	}
	if (chptr->prevch)
	    chptr->prevch->nextch = chptr->nextch;
	else
	    channel = chptr->nextch;
	if (chptr->nextch)
	    chptr->nextch->prevch = chptr->prevch;
	(void) del_from_channel_hash_table(chptr->chname, chptr);
#ifdef FLUD
	free_fluders(NULL, chptr);
#endif
	free_channel(chptr);
	Count.chan--;
    }
}

/*
 * m_join 
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = channel password (key)
 */
int m_join(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    static char jbuf[BUFSIZE];
    Link   *lp;
    aConfItem *aconf=NULL;
    aChannel *chptr;
    char   *name, *key = NULL;
    int         i, flags = 0, chanlen=0;	
    int         allow_op = YES;
    char       *p = NULL, *p2 = NULL;

#ifdef ANTI_SPAMBOT
    int         successful_join_count = 0;	
    /* Number of channels successfully joined */
#endif
	
    if (!(sptr->user))
    {
	/* something is *fucked* - bail */
	return 0;
    }
	
    if (parc < 2 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		   me.name, parv[0], "JOIN");
	return 0;
    }
    
    *jbuf = '\0';
    /*
     * * Rebuild list of channels joined to be the actual result of the *
     * JOIN.  Note that "JOIN 0" is the destructive problem.
     */
    for (i = 0, name = strtoken(&p, parv[1], ","); name;
	 name = strtoken(&p, (char *) NULL, ","))
    {
	/*
	 * pathological case only on longest channel name. If not dealt
	 * with here, causes desynced channel ops since ChannelExists()
	 * doesn't see the same channel as one being joined. cute bug.
	 * Oct 11 1997, Dianora/comstud
	 */
	if (!check_channelname(sptr, (unsigned char *) name))
	    continue;
	
	chanlen=strlen(name);
	
	if (chanlen > CHANNELLEN) /* same thing is done in get_channel() */
	{
	    name[CHANNELLEN] = '\0';
	    chanlen=CHANNELLEN;
	}
	if (*name == '&' && !MyConnect(sptr))
	    continue;
	if (*name == '0' && !atoi(name))
	    *jbuf = '\0';
	else if (!IsChannelName(name))
	{
	    if (MyClient(sptr))
		sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL),
			   me.name, parv[0], name);
	    continue;
	}
	if (*jbuf)
	    (void) strcat(jbuf, ",");
	(void) strncat(jbuf, name, sizeof(jbuf) - i - 1);
	i += chanlen + 1;
    }
    
    p = NULL;
    if (parv[2])
	key = strtoken(&p2, parv[2], ",");
    parv[2] = NULL;		/*
				 * for m_names call later, parv[parc]
				 * * must == NULL 
				 */
    for (name = strtoken(&p, jbuf, ","); name;
	 key = (key) ? strtoken(&p2, NULL, ",") : NULL,
	     name = strtoken(&p, NULL, ","))
    {
	/*
	 * JOIN 0 sends out a part for all channels a user * has
	 * joined.
	 */
	if (*name == '0' && !atoi(name))
	{
	    if (sptr->user->channel == NULL)
		continue;
	    while ((lp = sptr->user->channel))
	    {
		chptr = lp->value.chptr;
		sendto_channel_butserv(chptr, sptr, PartFmt,
				       parv[0], chptr->chname);
		remove_user_from_channel(sptr, chptr);
	    }
	    /*
	     * Added /quote set for SPAMBOT
	     * 
	     * int spam_time = MIN_JOIN_LEAVE_TIME; int spam_num =
	     * MAX_JOIN_LEAVE_COUNT;
	     */
#ifdef ANTI_SPAMBOT		/* Dianora */
			
	    if (MyConnect(sptr) && !IsAnOper(sptr))
	    {
		if (sptr->join_leave_count >= spam_num)
		{
		    sendto_realops_lev(SPAM_LEV, "User %s (%s@%s) is a "
				   "possible spambot", sptr->name,
				   sptr->user->username, sptr->user->host);
		    sptr->oper_warn_count_down = OPER_SPAM_COUNTDOWN;
		}
		else
		{
		    int         t_delta;
		    
		    if ((t_delta = (NOW - sptr->last_leave_time)) >
			JOIN_LEAVE_COUNT_EXPIRE_TIME)
		    {
			int         decrement_count;
			
			decrement_count = (t_delta /
					   JOIN_LEAVE_COUNT_EXPIRE_TIME);
			
			if (decrement_count > sptr->join_leave_count)
			    sptr->join_leave_count = 0;
			else
			    sptr->join_leave_count -= decrement_count;
		    }
		    else
		    {
			if ((NOW - (sptr->last_join_time)) < spam_time)
			{
			    /* oh, its a possible spambot */
			    sptr->join_leave_count++;
			}
		    }
		    sptr->last_leave_time = NOW;
		}
	    }
#endif

	    sendto_match_servs(NULL, cptr, ":%s JOIN 0", parv[0]);
	    continue;
	}
	
	if (MyConnect(sptr))
	{
	    /* have we quarantined this channel? */
	    if(!IsAnOper(sptr) && !IsUmodez(sptr) && (aconf = find_conf_name(name, CONF_QUARANTINED_CHAN)))
            {
		sendto_one(sptr, getreply(ERR_CHANBANREASON), me.name, parv[0], name,
			BadPtr(aconf->passwd) ? "Reserved channel" :	
			aconf->passwd);
                continue;
	    }

	    /*
	     * local client is first to enter previously nonexistent
	     * channel so make them (rightfully) the Channel Operator.
	     */
	    flags = (ChannelExists(name)) ? 0 : CHFL_CHANOP;

	    /* Channel does not exist - prevent creation if JOIN comes from a restricted user */
	    if (flags != 0 && check_restricted_user(sptr))
		continue; /* Message already sent by check_restricted_user */

#ifdef NO_CHANOPS_WHEN_SPLIT
	    if (!IsAnOper(sptr) && server_was_split &&
		server_split_recovery_time)
	    {
		if ((server_split_time + server_split_recovery_time) < NOW)
		{
		    if (serv_fdlist.last_entry)
			server_was_split = NO;
		    else
		    {
			server_split_time = NOW;	/* still split */
			allow_op = NO;
		    }
		}
		else
		{
		    allow_op = NO;
		}
	    }
#endif
	    
	    if ((sptr->user->joined >= MAXCHANNELSPERUSER) && !IsUmodez(sptr) &&
		(!IsAnOper(sptr) || (sptr->user->joined >= 
				     MAXCHANNELSPERUSER * 3)))
	    {
		sendto_one(sptr, err_str(ERR_TOOMANYCHANNELS),
			   me.name, parv[0], name);

#ifdef ANTI_SPAMBOT
		if (successful_join_count)
		    sptr->last_join_time = NOW;
#endif
		return 0;
	    }
#ifdef ANTI_SPAMBOT		/*
				 * Dianora 
				 */
	    if (flags == 0)	/* if channel doesn't exist, don't penalize */
		successful_join_count++;
	    if (sptr->join_leave_count >= spam_num)
	    {
				/* Its already known as a possible spambot */
		
		if (sptr->oper_warn_count_down > 0)  /* my general paranoia */
		    sptr->oper_warn_count_down--;
		else
		    sptr->oper_warn_count_down = 0;
		
		if (sptr->oper_warn_count_down == 0)
		{
		    sendto_realops_lev(SPAM_LEV, "User %s (%s@%s) trying to "
				   "join %s is a possible spambot",
				   sptr->name,
				   sptr->user->username,
				   sptr->user->host,
				   name);
		    sptr->oper_warn_count_down = OPER_SPAM_COUNTDOWN;
		}
# ifndef ANTI_SPAMBOT_WARN_ONLY
		return 0;		/* Don't actually JOIN anything, but
					 * don't let spambot know that */
# endif
	    }
#endif
	}
	else
	{
	    /*
	     * complain for remote JOINs to existing channels * (they
	     * should be SJOINs) -orabidoo
	     */
	    if (!ChannelExists(name))
		ts_warn("User on %s remotely JOINing new channel",
			sptr->user->server);
	}

	chptr = get_channel(sptr, name, CREATE);
	
	if (IsMember(sptr, chptr))
	    continue;

	if (!chptr || (MyConnect(sptr) && (i = can_join(sptr, chptr, key))))
	{
            if (i==ERR_NEEDREGGEDNICK) /* we don't send error message if i<0 */
		sendto_one(sptr, getreply(i), me.name, parv[0], name, "join");
	    else if (i>0)
		sendto_one(sptr, getreply(i), me.name, parv[0], name);

#ifdef ANTI_SPAMBOT
	    if (successful_join_count > 0)
		successful_join_count--;
#endif
	    continue;
	}
	
/* only complain when the user can join the channel, the channel is
 * being created by this user, and this user is not allowed to be an op.
 * - lucas 
 */

#ifdef NO_CHANOPS_WHEN_SPLIT
	if (flags && !allow_op)
	    sendto_one(sptr, ":%s NOTICE %s :*** Notice -- Due to a network "
		       "split, you can not obtain channel operator status in "
		       "a new channel at this time.", me.name, sptr->name);
#endif
	
	/* Complete user entry to the new channel (if any) */
	if (allow_op)
	    add_user_to_channel(chptr, sptr, flags);
	else
	    add_user_to_channel(chptr, sptr, 0);
	/* Set timestamp if appropriate, and propagate */
	if (MyClient(sptr) && flags == CHFL_CHANOP) 
	{
	    chptr->channelts = timeofday;
	    
	    /* we keep channel "creations" to the server sjoin format,
	       so we can bounce modes and stuff if our ts is older. */
	    
	    if (allow_op)
	    {
		sendto_server(cptr, chptr, NOCAPS, CAP_NSJOIN,
			      ":%s SJOIN %ld %ld %s + :@%s",
			      me.name, chptr->channelts,
			      chptr->channelts, name, parv[0]);
		sendto_server(cptr, chptr, CAP_NSJOIN, NOCAPS,
			      ":%s SJOIN %ld %s + :@%s",
			      me.name, chptr->channelts, name, parv[0]);
	    }
	    else
	    {
		sendto_server(cptr, chptr, NOCAPS, CAP_NSJOIN,
			      ":%s SJOIN %ld %ld %s + :%s",
			      me.name, chptr->channelts,
			      chptr->channelts, name, parv[0]);
		sendto_server(cptr, chptr, CAP_NSJOIN, NOCAPS,
			      ":%s SJOIN %ld %s + :%s",
			      me.name, chptr->channelts, name, parv[0]);
	    }
	}
	else if (MyClient(sptr)) 
	{
            sendto_server(cptr, chptr, NOCAPS, CAP_NSJOIN,
			  oldCliSJOINFmt,
			  me.name, chptr->channelts,
			  chptr->channelts, name, parv[0]);
            sendto_server(cptr, chptr, CAP_NSJOIN, NOCAPS,
			  newCliSJOINFmt,
			  parv[0], chptr->channelts, name);
	}
	else 
	{
	    sendto_match_servs(chptr, cptr, ":%s JOIN :%s", parv[0], name);
	}

	/* notify all other users on the new channel */
	sendto_channel_butserv(chptr, sptr, ":%s JOIN :%s", parv[0], name);
		
	if (MyClient(sptr)) {
	    del_invite(sptr, chptr);
	    if (chptr->topic[0] != '\0') {
		sendto_one(sptr, rpl_str(RPL_TOPIC), me.name,
			   parv[0], name, chptr->topic);
		sendto_one(sptr, rpl_str(RPL_TOPICWHOTIME),
			   me.name, parv[0], name,
			   chptr->topic_nick,
			   chptr->topic_time);
	    }
	    parv[1] = name;
	    (void) m_names(cptr, sptr, 2, parv);
	}
    }

#ifdef ANTI_SPAMBOT
    if (MyConnect(sptr) && successful_join_count)
	sptr->last_join_time = NOW;
#endif
	
    return 0;
}

/*
 * m_part 
 * parv[0] = sender prefix 
 * parv[1] = channel
 * parv[2] = Optional part reason
 */
int m_part(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;
    char       *p, *name;
    char *reason = (parc > 2 && parv[2]) ? parv[2] : NULL;

    if (parc < 2 || parv[1][0] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		   me.name, parv[0], "PART");
	return 0;
    }
    
    name = strtoken(&p, parv[1], ",");
    
#ifdef ANTI_SPAMBOT		/* Dianora */
    /* if its my client, and isn't an oper */
    
    if (name && MyConnect(sptr) && !IsAnOper(sptr))
    {
	if (sptr->join_leave_count >= spam_num)
	{
	    sendto_realops_lev(SPAM_LEV, "User %s (%s@%s) is a possible spambot",
			   sptr->name,
			   sptr->user->username, sptr->user->host);
	    sptr->oper_warn_count_down = OPER_SPAM_COUNTDOWN;
	}
	else
	{
	    int         t_delta;

	    if ((t_delta = (NOW - sptr->last_leave_time)) >
		JOIN_LEAVE_COUNT_EXPIRE_TIME)
	    {
		int         decrement_count;

		decrement_count = (t_delta / JOIN_LEAVE_COUNT_EXPIRE_TIME);

		if (decrement_count > sptr->join_leave_count)
		    sptr->join_leave_count = 0;
		else
		    sptr->join_leave_count -= decrement_count;
	    }
	    else
	    {
		if ((NOW - (sptr->last_join_time)) < spam_time)
		{
		    /* oh, its a possible spambot */
		    sptr->join_leave_count++;
		}
	    }
	    sptr->last_leave_time = NOW;
	}
    }
#endif

    while (name)
    {
	chptr = get_channel(sptr, name, 0);
	if (!chptr)
	{
	    sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL),
		       me.name, parv[0], name);
	    name = strtoken(&p, (char *) NULL, ",");
	    continue;
	}

	if (!IsMember(sptr, chptr))
	{
	    sendto_one(sptr, err_str(ERR_NOTONCHANNEL),
		       me.name, parv[0], name);
	    name = strtoken(&p, (char *) NULL, ",");
	    continue;
	}
	/* Remove user from the old channel (if any) */

	if (parc < 3 || can_send(sptr, chptr, reason) ||
		check_for_spam(sptr, reason, chptr->chname, "PART") || chptr->mode.mode & MODE_NOSPAM)
	{
	    sendto_match_servs(chptr, cptr, PartFmt, parv[0], name);
	    sendto_channel_butserv(chptr, sptr, PartFmt, parv[0], name);
	}
	else
	{
	    sendto_match_servs(chptr, cptr, PartFmt2, parv[0], name, reason);
	    sendto_channel_butserv(chptr, sptr, PartFmt2, parv[0], name, reason);
	}

	remove_user_from_channel(sptr, chptr);
	name = strtoken(&p, (char *) NULL, ",");
    }
    return 0;
}

/*
 * m_kick
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = client to kick
 * parv[3] = kick comment
 */
int m_kick(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient    *who;
    aChannel   *chptr;
    int         chasing = 0;
    int         user_count;	/* count nicks being kicked, only allow 4 */
    char       *comment, *name, *p = NULL, *user, *p2 = NULL;
    int		level; /* access level to kick command */

    if (parc < 3 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		   me.name, parv[0], "KICK");
	return 0;
    }
    if (IsServer(sptr) && !IsULine(sptr))
	sendto_ops("KICK from %s for %s %s",
		   parv[0], parv[1], parv[2]);
    comment = (BadPtr(parv[3])) ? parv[0] : parv[3];
    if (strlen(comment) > (size_t) TOPICLEN)
	comment[TOPICLEN] = '\0';
    
    *nickbuf = *buf = '\0';
    name = strtoken(&p, parv[1], ",");
    
    while (name)
    {
	chptr = get_channel(sptr, name, !CREATE);
	if (!chptr)
	{
	    sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL),
		       me.name, parv[0], name);
	    name = strtoken(&p, (char *) NULL, ",");
	    continue;
	}

	/* define access level: 
	 * - level==0 normal client
	 * - level==1 half op
	 * - level==2 full op, umodez, ulined or server
	 */
	if (IsServer(sptr) || IsULine(sptr) || is_chan_op(sptr, chptr) || IsUmodez(sptr))
	    level = 2;
	else if (is_half_op(sptr, chptr))
	    level = 1;
	else
	    level = 0;

	if (level==0)
	{
	    /* was a user, not a server and user isn't seen as a chanop here */

	    if (MyConnect(sptr))
	    {
		/* user on _my_ server, with no chanops.. so go away */

		sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
			   me.name, parv[0], chptr->chname);
		name = strtoken(&p, (char *) NULL, ",");
		continue;
	    }
	    
	    if (chptr->channelts == 0)
	    {
		/* If its a TS 0 channel, do it the old way */

		sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
			   me.name, parv[0], chptr->chname);
		name = strtoken(&p, (char *) NULL, ",");
		continue;
	    }
	    /*
	     * Its a user doing a kick, but is not showing as chanop
	     * locally its also not a user ON -my- server, and the channel
	     * has a TS. There are two cases we can get to this point
	     * then...
	     * 
	     * 1) connect burst is happening, and for some reason a legit op
	     * has sent a KICK, but the SJOIN hasn't happened yet or been
	     * seen. (who knows.. due to lag...)
	     * 
	     * 2) The channel is desynced. That can STILL happen with TS
	     * 
	     * Now, the old code roger wrote, would allow the KICK to go
	     * through. Thats quite legit, but lets weird things like
	     * KICKS by users who appear not to be chanopped happen, or
	     * even neater, they appear not to be on the channel. This
	     * fits every definition of a desync, doesn't it? ;-) So I
	     * will allow the KICK, otherwise, things are MUCH worse. But
	     * I will warn it as a possible desync.
	     * 
	     * -Dianora
	     *
	     * sendto_one(sptr, err_str(ERR_DESYNC), me.name, parv[0],
	     * chptr->chname);
	     *
	     * After more discussion with orabidoo...
	     * 
	     * The code was sound, however, what happens if we have +h (TS4)
	     * and some servers don't understand it yet? we will be seeing
	     * servers with users who appear to have no chanops at all,
	     * merrily kicking users.... -Dianora
	     * 
	     */
	}

	user = strtoken(&p2, parv[2], ",");
	user_count = 4;
	while (user && user_count)
	{
	    user_count--;
	    if (!(who = find_chasing(sptr, user, &chasing)))
	    {
		user = strtoken(&p2, (char *) NULL, ",");
		continue;		/* No such user left! */
	    }
	    if(IsUmodez(who)) 
	    {
		sendto_one(sptr, err_str(ERR_CANNOTKICKMODEZ), me.name,
			parv[0]);
		user = strtoken(&p2, (char *) NULL, ",");
		continue;
	    }

	    if ((level==1) && (is_chan_op(who, chptr) || is_half_op(who, chptr))) 
	    {
		sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
			   me.name, parv[0], chptr->chname);
		user = strtoken(&p2, (char *) NULL, ",");
		continue;
	    }
	    else if (IsMember(who, chptr))
	    {
		sendto_channel_butserv(chptr, sptr,
				       ":%s KICK %s %s :%s", parv[0],
				       name, who->name, comment);
		sendto_match_servs(chptr, cptr,
				   ":%s KICK %s %s :%s",
				   parv[0], name,
				   who->name, comment);
		remove_user_from_channel(who, chptr);
	    }
	    else
		sendto_one(sptr, err_str(ERR_USERNOTINCHANNEL),
			   me.name, parv[0], user, name);
	    user = strtoken(&p2, (char *) NULL, ",");
	}				/* loop on parv[2] */

	name = strtoken(&p, (char *) NULL, ",");
    }				/* loop on parv[1] */

    return (0);
}

int count_channels(aClient *sptr)
{
    aChannel *chptr;
    int     count = 0;

    for (chptr = channel; chptr; chptr = chptr->nextch)
	count++;
    return (count);
}

void send_topic_burst(aClient *cptr)
{
    aChannel *chptr;
    aClient *acptr;
    for (chptr = channel; chptr; chptr = chptr->nextch)
    {
	if(chptr->topic[0] != '\0')
	    sendto_one(cptr, ":%s TOPIC %s %s %ld :%s", me.name, chptr->chname,
		       chptr->topic_nick, chptr->topic_time, chptr->topic);
    }
    for (acptr = client; acptr; acptr = acptr->next)
    {
	if(!IsPerson(acptr) || acptr->from == cptr)
	    continue;
	if(acptr->user->away)
	    sendto_one(cptr, ":%s AWAY :%s", acptr->name, acptr->user->away);
    }
}

/*
 * m_topic 
 * parv[0] = sender prefix 
 * parv[1] = topic text
 */
int m_topic(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel   *chptr = NullChn;
    char       *topic = NULL, *name, *tnick = sptr->name;
    time_t     ts = timeofday;
    int        member;	

    if (parc < 2) 
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
		   "TOPIC");
	return 0;
    }
	
    name = parv[1];
    chptr = find_channel(name, NullChn);
    if(!chptr) 
    {
	sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], name);
	return 0;
    }
    
    member = IsMember(sptr, chptr);
    
    if (parc == 2) /* user is requesting a topic */ 
    {	
	if(!member && (SecretChannel(chptr) && !IsAdmin(sptr) && !IsSAdmin(sptr) && !IsUmodez(sptr)))
	{
	    sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0],
		    name);
	    return 0;
	}
	
	if(!member && HiddenChannel(chptr) && !IsAdmin(sptr) && !IsSAdmin(sptr) && !IsUmodez(sptr))
	{
	    sendto_one(sptr, rpl_str(RPL_TOPIC), me.name, parv[0], chptr->chname, "<private>");
	    return 0;
	}

	if (chptr->topic[0] == '\0')
	{
	    sendto_one(sptr, rpl_str(RPL_NOTOPIC), me.name, parv[0], chptr->chname);
	}
	else 
	{
	    sendto_one(sptr, rpl_str(RPL_TOPIC), me.name, parv[0], chptr->chname, chptr->topic);
	    sendto_one(sptr, rpl_str(RPL_TOPICWHOTIME), me.name, parv[0],
		       chptr->chname, chptr->topic_nick, chptr->topic_time);
	}
	return 0;
    }
    
    if(!member && !IsServer(sptr) && !IsULine(sptr) && !IsUmodez(sptr))
    {
	sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0], name);
	return 0;
    }
    
    if (parc > 3 && (!MyConnect(sptr) || IsULine(sptr) || IsServer(sptr) || IsUmodez(sptr)))
    {
	topic = (parc > 4 ? parv[4] : "");
	tnick = parv[2];
	ts = atoi(parv[3]);
    } 
    else 
    {
	topic = parv[2];
    }
    
    if (((!(chptr->mode.mode & MODE_TOPICLIMIT) || is_chan_op(sptr, chptr)
	|| is_half_op(sptr, chptr)) || IsULine(sptr) || IsServer(sptr)) || IsUmodez(sptr))
    {
	/* setting a topic */
	
	/* local topic is newer than remote topic and we have a topic
	   and we're in a synch (server setting topic) */

	if(IsServer(sptr) && !IsULine(sptr) && chptr->topic_time >= ts &&
	   chptr->topic[0])
	    return 0;
	
	strncpyzt(chptr->topic, topic, TOPICLEN + 1);
	strcpy(chptr->topic_nick, tnick);
	chptr->topic_time = ts;
	
	/* in this case I think it's better that we send all the info that df 
	 * sends with the topic, so I changed everything to work like that. 
	 * -wd */
	
	sendto_match_servs(chptr, cptr, ":%s TOPIC %s %s %lu :%s", parv[0],
			   chptr->chname, chptr->topic_nick, 
			   chptr->topic_time, chptr->topic);
	sendto_channel_butserv(chptr, sptr, ":%s TOPIC %s :%s", parv[0],
			       chptr->chname, chptr->topic);
    }
    else
	sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, parv[0],
		   chptr->chname);
	
    return 0;
}

/*
 * m_invite 
 * parv[0] - sender prefix 
 * parv[1] - user to invite 
 * parv[2] - channel number
 */
int m_invite(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient    *acptr;
    aChannel   *chptr;
    
    if (parc < 3 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		   me.name, parv[0], "INVITE");
	return -1;
    }

    if (!(acptr = find_person(parv[1], (aClient *) NULL)))
    {
	sendto_one(sptr, err_str(ERR_NOSUCHNICK),
		   me.name, parv[0], parv[1]);
	return 0;
    }
    
    if(!check_channelname(sptr, (unsigned char *)parv[2]))
	return 0;

    if (!(chptr = find_channel(parv[2], NullChn)))
    {	
	return 0;
    }
    
    if (chptr && !IsMember(sptr, chptr) && !IsULine(sptr) && !IsUmodez(sptr))
    {
	sendto_one(sptr, err_str(ERR_NOTONCHANNEL),
		   me.name, parv[0], parv[2]);
	return -1;
    }

    if (IsMember(acptr, chptr))
    {
	sendto_one(sptr, err_str(ERR_USERONCHANNEL),
		   me.name, parv[0], parv[1], parv[2]);
	return 0;
    }
    
    if (!is_chan_op(sptr, chptr) && (!IsULine(sptr)) && (!IsUmodez(sptr)))
    {

	sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
		   me.name, parv[0], chptr->chname);
	return -1;
    }

#ifdef ANTI_INVITE_FLOOD
    if (MyClient(sptr)) 
    {
	if((sptr->last_invite_time + invite_time) < NOW)
	{
		sptr->number_of_invites = 0;
		sptr->last_invite_sum = 0;
	}
	sptr->last_invite_time = NOW;
	sptr->number_of_invites++;
	
	if (invite_spam && sptr->number_of_invites > invite_num && 
	    !IsAnOper(sptr) && !IsUmodez(sptr)) {
		int invite_checksum = 0;
		int i;
		
		sendto_one(sptr,
			":%s NOTICE %s :*** Notice -- Too many invites. Please wait %d seconds before trying again.",
			me.name, sptr->name, invite_time);
		
		/* Don't show notices if the user sends multiple invites to the same user in
		* the same channel. We use a simple checksum to avoid wasting memory in the
		* client structure */
		for (i=0; i<strlen(acptr->name); i++)
		    invite_checksum += (int) *(acptr->name + i);
		for (i=0; i<strlen(chptr->chname); i++)
		    invite_checksum += (int) *(chptr->chname + i);
		if (sptr->last_invite_sum != invite_checksum)
		    sptr->last_invite_sum = invite_checksum;
		else
		    return 0;
		
		sendto_snotice("from %s: %s tried to MassInvite, failed invite #%d, target: %s, channel: %s",
			       me.name, sptr->name, sptr->number_of_invites, acptr->name, chptr->chname);
		sendto_serv_butone(NULL, ":%s SNOTICE :%s tried to MassInvite, failed invite #%d, target: %s, channel: %s",
				   me.name, sptr->name, sptr->number_of_invites, acptr->name, chptr->chname);
		return 0;
	}
    }
#endif

    if (MyConnect(sptr))
    {
	sendto_one(sptr, rpl_str(RPL_INVITING), me.name, parv[0],
		   acptr->name, ((chptr) ? (chptr->chname) : parv[2]));
	if (acptr->user->away)
	    sendto_one(sptr, rpl_str(RPL_AWAY), me.name, parv[0],
		       acptr->name, acptr->user->away);
    }
	
    if (MyConnect(acptr))
	if ((chptr && sptr->user && is_chan_op(sptr, chptr)) || IsULine(sptr) || IsUmodez(sptr))
	{
	    add_invite(acptr, chptr);
	    sendto_channelflag_butone(NULL, &me, TO_OPS, chptr,
			":%s NOTICE @%s :%s invited %s into channel %s.",me.name, chptr->chname,
			sptr->name, acptr->name, chptr->chname);
	}

    /* Don't notify invited user if the inviting user is shunned. -INT */
    if (!IsShunned(sptr))
	sendto_prefix_one(acptr, sptr, ":%s INVITE %s :%s", parv[0],
			  acptr->name, ((chptr) ? (chptr->chname) : parv[2]));

    return 0;
}


/*
 * The function which sends the actual channel list back to the user.
 * Operates by stepping through the hashtable, sending the entries back if
 * they match the criteria.
 * cptr = Local client to send the output back to.
 * numsend = Number (roughly) of lines to send back. Once this number has
 * been exceeded, send_list will finish with the current hash bucket,
 * and record that number as the number to start next time send_list
 * is called for this user. So, this function will almost always send
 * back more lines than specified by numsend (though not by much,
 * assuming CH_MAX is was well picked). So be conservative in your choice
 * of numsend. -Rak
 */

void send_list(aClient *cptr, int numsend)
{
    aChannel	*chptr;
    LOpts	*lopt = cptr->user->lopt;
    int		hashnum;
   
    char        **tmp;
    int          hide;
    /* istunix = true if cptr is the netsplit tunix client */
    int		istunix = (!strncmp(cptr->name, "tunix", 5));
    /* Channels to hide from tunix */ 
    static char *hidechan[] = { "*divx*",
	                        "#max*",
	                        "*warez*",
	                        "*xdcc*",
	                        "*0day*",
	                        NULL
                               };
    /* Topics to hide from tunix */
    static char *hidetopic[] = { "*xdcc*",
	                         "*warez*",
				 "*divx*",
				 "*fibre*",
				 "*dvd*rip*",
	                         NULL
			       };
    
    for (hashnum = lopt->starthash; hashnum < CH_MAX; hashnum++)
    {
	if (numsend > 0)
	    for (chptr = (aChannel *)hash_get_chan_bucket(hashnum); 
		 chptr; chptr = chptr->hnextch)
	    {
		if (SecretChannel(chptr) && !IsMember(cptr, chptr)
		    && !IsAdmin(cptr) && !IsSAdmin(cptr) && !IsUmodez(cptr))
		    continue;

	        /* Hide some channels and topics to the tunix client */
	        if ((hide_tunix == YES) && istunix)
		{
		   hide = NO;
		   for (tmp = hidechan; *tmp; tmp++)
		      if (!match(*tmp, chptr->chname))
		      {
		         hide = YES;
			 break;
		       }
		   
		   if (!hide)
		      for (tmp = hidetopic; *tmp; tmp++)
		        if (!match(*tmp, chptr->topic))
		        {
			   hide = YES;
			   break;
		        }
		   
		   if (hide)			
		       continue;
		}	       

		if ((!lopt->showall) &&
			((chptr->users < lopt->usermin) ||
			 ((lopt->usermax >= 0) && (chptr->users > lopt->usermax)) ||
			 (lopt->nolist && find_str_link(lopt->nolist, chptr->chname)) ||
			 (lopt->yeslist && !find_str_link(lopt->yeslist, chptr->chname))))
		    continue;

		sendto_one(cptr, rpl_str(RPL_LIST), me.name, cptr->name,
			   chptr->chname, chptr->users,
			   (HiddenChannel(chptr) && !IsMember(cptr, chptr) &&
			    !IsAdmin(cptr) && !IsSAdmin(cptr) && !IsUmodez(cptr)) ?
			   "<private>" : chptr->topic);

		numsend--;
	    }
	else
	    break;
    }
    
    /* All done */
    if (hashnum == CH_MAX)
    {
	Link *lp, *next;
	sendto_one(cptr, rpl_str(RPL_LISTEND), me.name, cptr->name);
	for (lp = lopt->yeslist; lp; lp = next)
	{
	    next = lp->next;
	    free_link(lp);
	}
	for (lp = lopt->nolist; lp; lp = next)
	{
	    next = lp->next;
	    free_link(lp);
	}
	
	MyFree(cptr->user->lopt);
	cptr->user->lopt = NULL;
	return;
    }
    
    /* 
     * We've exceeded the limit on the number of channels to send back
     * at once.
     */
    lopt->starthash = hashnum;
    return;
}


/*
 * m_list 
 * parv[0] = sender prefix
 * parv[1] = channel
 */
int m_list(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel	*chptr;

    char	*name, *p = NULL;
    LOpts	*lopt = NULL;
    Link	*lp, *next;
    int		usermax, usermin, error = 0, doall = 0;
    Link 	*yeslist = NULL, *nolist = NULL;
    
    static char *usage[] = {
	"   Usage: /raw LIST options (on mirc) or /quote LIST options (ircII)",
	"",
	"If you don't include any options, the default is to send you the",
	"entire unfiltered list of channels. Below are the options you can",
	"use, and what channels LIST will return when you use them.",
	">number  List channels with more than <number> people.",
	"<number  List channels with less than <number> people.",
	"*mask*   List channels that match *mask*",
	"!*mask*  List channels that do not match *mask*",
	NULL
    };

    /* Some starting san checks -- No interserver lists allowed. */
    if (cptr != sptr || !sptr->user)
	return 0;

    if (!unknown_list_allowed && !IsKnownNick(sptr))
    {
	sendto_one(sptr, err_str(ERR_NOUNKNOWNLISTS), me.name, parv[0]);
	return 0;
    }

    if (check_restricted_user(sptr))
	return 0;

    /* If a /list is in progress, then another one will cancel it */
    if ((lopt = sptr->user->lopt)!=NULL)
    {
	sendto_one(sptr, rpl_str(RPL_LISTEND), me.name, parv[0]);
	for (lp = lopt->yeslist; lp; lp = next)
	{
	    next = lp->next;
	    free_link(lp);
	}
	for (lp = lopt->nolist; lp; lp = next)
	{
	    next = lp->next;
	    free_link(lp);
	}
	MyFree(sptr->user->lopt);
	sptr->user->lopt = NULL;
	return 0;
    }

    /* if HTM, drop this too */
    if(lifesux)
    {
	sendto_one(sptr, rpl_str(RPL_LOAD2HI), me.name, sptr->name);
	return 0;
    }
    
    if (parc < 2 || BadPtr(parv[1]))
    {
	sendto_one(sptr, rpl_str(RPL_LISTSTART), me.name, parv[0]);
	lopt = sptr->user->lopt = (LOpts *) MyMalloc(sizeof(LOpts));
	memset(lopt, '\0', sizeof(LOpts));

	lopt->showall = 1;

	if (DBufLength(&cptr->sendQ) < 2048)
	    send_list(cptr, 64);

        return 0;
    }

    if ((parc == 2) && (parv[1][0] == '?') && (parv[1][1] == '\0'))
    {
	char **ptr = usage;
	for (; *ptr; ptr++)
	    sendto_one(sptr, rpl_str(RPL_COMMANDSYNTAX), me.name,
		       cptr->name, *ptr);
	return 0;
    }

    sendto_one(sptr, rpl_str(RPL_LISTSTART), me.name, parv[0]);

    usermin = 2;  /* By default, set the minimum to 2 users */
    usermax = -1; /* No maximum */

    for (name = strtoken(&p, parv[1], ","); name && !error;
	 name = strtoken(&p, (char *) NULL, ","))
    {

	switch (*name)
	{
	case '<':
	    usermax = atoi(name+1) - 1;
	    doall = 1;
	    break;
	case '>':
	    usermin = atoi(name+1) + 1;
	    doall = 1;
	    break;

	default: /* A channel, possibly with wildcards.
		  * Thought for the future: Consider turning wildcard
		  * processing on the fly.
		  * new syntax: !channelmask will tell ircd to ignore
		  * any channels matching that mask, and then
		  * channelmask will tell ircd to send us a list of
		  * channels only masking channelmask. Note: Specifying
		  * a channel without wildcards will return that
		  * channel even if any of the !channelmask masks
		  * matches it.
		  */
	    if (*name == '!')
	    {
		doall = 1;
		lp = make_link();
		lp->next = nolist;
		nolist = lp;
		DupString(lp->value.cp, name+1);
	    }
	    else if (strchr(name, '*') || strchr(name, '*'))
	    {
		doall = 1;
		lp = make_link();
		lp->next = yeslist;
		yeslist = lp;
		DupString(lp->value.cp, name);
	    }
	    else /* Just a normal channel */
	    {
		chptr = find_channel(name, NullChn);

		if (chptr && (!SecretChannel(chptr) || IsAdmin(sptr) || IsSAdmin(sptr) || IsUmodez(sptr)))
                {
		    char *topic = chptr->topic;
		    if(HiddenChannel(chptr) && (!IsMember(sptr, chptr) && !IsAdmin(sptr)
				&& !IsSAdmin(sptr) && !IsUmodez(sptr)))
		    {
			topic = "<private>";
		    }

		    sendto_one(sptr, rpl_str(RPL_LIST), me.name, parv[0],
			       chptr->chname, chptr->users, topic);
		}
	    }
	} /* switch */
    } /* while */

    if (doall)
    {
	lopt = sptr->user->lopt = (LOpts *) MyMalloc(sizeof(LOpts));
	memset(lopt, '\0', sizeof(LOpts));
	lopt->usermin = usermin;
	lopt->usermax = usermax;
	lopt->nolist = nolist;
	lopt->yeslist = yeslist;

	if (DBufLength(&cptr->sendQ) < 2048)
	    send_list(cptr, 64);

	return 0;
    }

    sendto_one(sptr, rpl_str(RPL_LISTEND), me.name, parv[0]);

    return 0;
}



/************************************************************************
 * m_names() - Added by Jto 27 Apr 1989
 * 12 Feb 2000 - geesh, time for a rewrite -lucas
 ************************************************************************/
/*
 * m_names 
 * parv[0] = sender prefix 
 * parv[1] = channel
 */

/* maximum names para to show to opers when abuse occurs */
#define TRUNCATED_NAMES 64

int m_names(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int mlen = strlen(me.name) + NICKLEN + 7;
    aChannel *chptr;
    aClient *acptr;
    int member;
    chanMember *cm;
    int idx, flag = 1, spos;
    char *s, *para = parv[1];

	if (parc < 2 || !MyConnect(sptr)) {

		sendto_one(sptr, rpl_str(RPL_ENDOFNAMES), me.name, parv[0], "*");
		return 0;
	}

	for(s = para; *s; s++) {

		if(*s == ',') {

			if (strlen(para) > TRUNCATED_NAMES)
				para[TRUNCATED_NAMES] = '\0';

			sendto_realops("names abuser %s %s", get_client_name(sptr, FALSE), para);
			sendto_one(sptr, err_str(ERR_TOOMANYTARGETS), me.name, sptr->name, "NAMES");
			return 0;
		}
	}

	if (!check_channelname(sptr, (unsigned char *)para))
		return 0;

	chptr = find_channel(para, (aChannel *) NULL);

	if (!chptr || !ShowChannel(sptr, chptr)) {

		sendto_one(sptr, rpl_str(RPL_ENDOFNAMES), me.name, parv[0], para);
		return 0;
	}

	/* cache whether this user is a member of this channel or not */
	member = (IsMember(sptr, chptr) || IsAdmin(sptr) || IsSAdmin(sptr) || IsUmodez(sptr));

	if (PubChannel(chptr))
		buf[0] = '=';
	else if (SecretChannel(chptr))
		buf[0] = '@';
	else
		buf[0] = '*';

	idx = 1;
	buf[idx++] = ' ';

	for(s = chptr->chname; *s; s++)
		buf[idx++] = *s;

	buf[idx++] = ' ';
	buf[idx++] = ':';

	/* If we go through the following loop and never add anything,
       we need this to be empty, otherwise spurious things from the
       LAST /names call get stuck in there.. - lucas */
	buf[idx] = '\0';

	spos = idx; /* starting point in buffer for names!*/

	for (cm = chptr->members; cm; cm = cm->next) {

		acptr = cm->cptr;

		if (IsInvisible(acptr) && !member)
			continue;

		if (cm->flags & CHFL_CHANOP)
			buf[idx++] = '@';
		else if(cm->flags & CHFL_HALFOP)
			buf[idx++] = '%';
		else if(cm->flags & CHFL_VOICE)
			buf[idx++] = '+';

		for(s = acptr->name; *s; s++)
			buf[idx++] = *s;

		buf[idx++] = ' ';
		buf[idx] = '\0';
		flag = 1;

		if(mlen + idx + NICKLEN > BUFSIZE - 3) {

			sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf);
			idx = spos;
			flag = 0;
		}
	}

	if (flag) 
		sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf);
    
	sendto_one(sptr, rpl_str(RPL_ENDOFNAMES), me.name, parv[0], para);
	return 0;
}
 
void send_user_joins(aClient *cptr, aClient *user)
{
    Link   *lp;
    aChannel *chptr;
    int     cnt = 0, len = 0, clen;
    char       *mask;

    *buf = ':';
    (void) strcpy(buf + 1, user->name);
    (void) strcat(buf, " JOIN ");
    len = strlen(user->name) + 7;

    for (lp = user->user->channel; lp; lp = lp->next)
    {
	chptr = lp->value.chptr;
	if (*chptr->chname == '&')
	    continue;
	if ((mask = strchr(chptr->chname, ':')))
	    if (match(++mask, cptr->name))
		continue;
	clen = strlen(chptr->chname);
	if (clen > (size_t) BUFSIZE - 7 - len)
	{
	    if (cnt)
		sendto_one(cptr, "%s", buf);
	    *buf = ':';
	    (void) strcpy(buf + 1, user->name);
	    (void) strcat(buf, " JOIN ");
	    len = strlen(user->name) + 7;
	    cnt = 0;
	}
	(void) strcpy(buf + len, chptr->chname);
	cnt++;
	len += clen;
	if (lp->next)
	{
	    len++;
	    (void) strcat(buf, ",");
	}
    }
    if (*buf && cnt)
	sendto_one(cptr, "%s", buf);

    return;
}

void kill_restrict_list(aClient *cptr, aChannel *chptr)
{
    aBan   *bp, *bpn;
    char   *cp;
    int         count = 0, send = 0;

    cp = modebuf;  
    *cp++ = '-';
    *cp = '\0';      

    *parabuf = '\0';

    for (bp = chptr->restrictlist; bp; bp = bp->next)
    {
	if (strlen(parabuf) + strlen(bp->banstr) + 10 < (size_t) MODEBUFLEN)
	{
	    if(*parabuf)
		strcat(parabuf, " ");
	    strcat(parabuf, bp->banstr);
	    count++;   
	    *cp++ = 'z';
	    *cp = '\0';
	}
	else if (*parabuf)
	    send = 1;

	if (count == MAXMODEPARAMS)
	    send = 1;

	if (send)
	{
	    sendto_chanops_butserv(chptr, &me, 1, ":%s MODE %s %s %s", cptr->name,
				   chptr->chname, modebuf, parabuf);
	    send = 0;
	    *parabuf = '\0';
	    cp = modebuf;
	    *cp++ = '-';
	    if (count != MAXMODEPARAMS)
	    {
		strcpy(parabuf, bp->banstr);
		*cp++ = 'z';
		count = 1;
	    }
	    else
		count = 0; 
	    *cp = '\0';
	}
    }

    if(*parabuf)
	sendto_chanops_butserv(chptr, &me, 1, ":%s MODE %s %s %s", cptr->name,
			       chptr->chname, modebuf, parabuf);

    /* physically destroy channel restrict list */   

    bp = chptr->restrictlist;
    while(bp)
    {
	bpn = bp->next;
	MyFree(bp->banstr);
	MyFree(bp->who);
	MyFree(bp);
	bp = bpn;
    }

    chptr->restrictlist = NULL;
}

void kill_ban_list(aClient *cptr, aChannel *chptr)
{  
    chanMember *cm;
    aBan   *bp, *bpn;
    char   *cp;
    int         count = 0, send = 0;
      
    cp = modebuf;  
    *cp++ = '-';
    *cp = '\0';      
    
    *parabuf = '\0';
         
    for (bp = chptr->banlist; bp; bp = bp->next)
    {  
	if (strlen(parabuf) + strlen(bp->banstr) + 10 < (size_t) MODEBUFLEN)
	{  
	    if(*parabuf)
		strcat(parabuf, " ");
	    strcat(parabuf, bp->banstr);
	    count++;   
	    *cp++ = 'b';
	    *cp = '\0';
	}
	else if (*parabuf)
	    send = 1;
   
	if (count == MAXMODEPARAMS)
	    send = 1;
    
	if (send)
	{
	    /* Do not send banlist reset MODE to non-privileged users if the channel is +B */
	    if (!(chptr->mode.mode & MODE_HIDEBANS))
		sendto_channel_butserv(chptr, &me, ":%s MODE %s %s %s", cptr->name,
				       chptr->chname, modebuf, parabuf);
	    else
		sendto_chanops_butserv(chptr, &me, 1, ":%s MODE %s %s %s", cptr->name,
				       chptr->chname, modebuf, parabuf);
	    send = 0;
	    *parabuf = '\0';
	    cp = modebuf;
	    *cp++ = '-';
	    if (count != MAXMODEPARAMS)
	    {
		strcpy(parabuf, bp->banstr);
		*cp++ = 'b';
		count = 1;
	    }
	    else
		count = 0; 
	    *cp = '\0';
	}
    }  

    if(*parabuf)
    {
	/* Ditto */
	if (!(chptr->mode.mode & MODE_HIDEBANS))
	    sendto_channel_butserv(chptr, &me, ":%s MODE %s %s %s", cptr->name,
				   chptr->chname, modebuf, parabuf);
	else
	    sendto_chanops_butserv(chptr, &me, 1, ":%s MODE %s %s %s", cptr->name,
				   chptr->chname, modebuf, parabuf);
    }

    /* physically destroy channel ban list */   

    bp = chptr->banlist;
    while(bp)
    {
	bpn = bp->next;
	MyFree(bp->banstr);
	MyFree(bp->who);
	MyFree(bp);
	bp = bpn;
    }

    chptr->banlist = NULL;
   
    /* reset bquiet on all channel members */
    for (cm = chptr->members; cm; cm = cm->next)
    {     
	if(MyConnect(cm->cptr))
	    cm->bans = 0;
    }
}

static inline void sjoin_sendit(aClient *cptr, aClient *sptr,
				aChannel *chptr, char *from)
{
    sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s %s", from,
			   chptr->chname, modebuf, parabuf);
}

/*
 * m_resynch
 * parv[0] - sender
 * parv[1] - channel
 *
 * Sent from a server I am directly connected to that is requesting I resend
 * EVERYTHING I know about channel.
 */
int m_resynch(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;

    if (!MyConnect(sptr) || !IsServer(sptr) || parc < 2 || parv[1][0] == '&')
        return 0;

    chptr = find_channel(parv[1], NullChn);
    
    sendto_realops_lev(DEBUG_LEV, "%s is requesting a resynch of %s%s", 
                       parv[0], parv[1], (chptr == NullChn) ? " [failed]" : "");

    if (chptr != NullChn)
        send_channel_modes(sptr, chptr);
    return 0;
}

/*
 * m_sjoin 
 * parv[0] - sender 
 * parv[1] - TS 
 * parv[2] - channel 
 * parv[3] - modes + n arguments (key and/or limit) 
 * parv[4+n] - flags+nick list (all in one parameter)
 * 
 * process a SJOIN, taking the TS's into account to either ignore the
 * incoming modes or undo the existing ones or merge them, and JOIN all
 * the specified users while sending JOIN/MODEs to non-TS servers and
 * to clients
 */

#define INSERTSIGN(x,y) \
if (what != x) { \
*mbuf++=y; \
what = x; \
}

#define ADD_PARA(p) para = p; if(pbpos) parabuf[pbpos++] = ' '; \
                     while(*para) parabuf[pbpos++] = *para++; 
#define ADD_SJBUF(p) para = p; if(sjbufpos) sjbuf[sjbufpos++] = ' '; \
                     while(*para) sjbuf[sjbufpos++] = *para++; 
	
int m_sjoin(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel   *chptr;
    aClient    *acptr;
    ts_val      newts, oldts, tstosend;
    static Mode mode, *oldmode;
    chanMember *cm;
    int         args = 0, haveops = 0, keepourmodes = 1, keepnewmodes = 1,
	doesop = 0, what = 0, pargs = 0, fl, people = 0,
	isnew, clientjoin = 0, pbpos, sjbufpos;
    char   *s, *s0, *para;
    static char numeric[16], sjbuf[BUFSIZE];
    char        keep_modebuf[REALMODEBUFLEN], keep_parabuf[REALMODEBUFLEN];
    char       *mbuf = modebuf, *p;

    /* if my client is SJOINing, it's just a local user being a dufus. 
     *  Ignore him.
     * parc >= 5 (new serv<->serv SJOIN format)
     * parc >= 6 (old serv<->serv SJOIN format)
     * parc == 3 (new serv<->serv cliSJOIN format)
     */

    if (MyClient(sptr) || (parc < 5 && IsServer(sptr)) ||
	(parc < 3 && IsPerson(sptr)))
	return 0;
    
    if(parc == 3 && IsPerson(sptr))
	clientjoin = 1;
    else 
	if(isdigit(parv[2][0]))
	{
	    int i;
	    
	    if(parc < 6) 
		return 0;
	    
	    for(i = 2; i < (parc - 1); i++)
		parv[i] = parv[i+1];

	    parc--;
	}

    if (!IsChannelName(parv[2]))
	return 0;

    newts = atol(parv[1]);
	
    isnew = ChannelExists(parv[2]) ? 0 : 1;
    chptr = get_channel(sptr, parv[2], CREATE);
    oldts = chptr->channelts;

    for (cm = chptr->members; cm; cm = cm->next)
	if (cm->flags & MODE_CHANOP)
	{
	    haveops++;
	    break;
	}

    if(clientjoin) /* we have a good old client sjoin, with timestamp */
    {
	if (isnew)
	    chptr->channelts = tstosend = newts;
	else if (newts == 0 || oldts == 0)
	    chptr->channelts = tstosend = 0;
	else if (newts == oldts)
	    tstosend = oldts;
	else if (newts < oldts) 
	{
	    if (haveops)
		tstosend = oldts;
	    else
		chptr->channelts = tstosend = newts;
	}
	else 
	    tstosend = oldts;

	/* parv[0] is the client that is joining. parv[0] == sptr->name */

	if (!IsMember(sptr, chptr)) 
	{
	    add_user_to_channel(chptr, sptr, 0);
	    sendto_channel_butserv(chptr, sptr, ":%s JOIN :%s", parv[0],
				   parv[2]);
	}

	sendto_server(cptr, chptr, NOCAPS, CAP_NSJOIN,
		      oldCliSJOINFmt, me.name,
		      tstosend, tstosend, parv[2], parv[0]);

	sendto_server(cptr, chptr, CAP_NSJOIN, NOCAPS,
		      newCliSJOINFmt, parv[0],
		      tstosend, parv[2]);

	return 0;
    }

    memset((char *) &mode, '\0', sizeof(mode));

    s = parv[3];
    while (*s)
	switch (*(s++))
	{
	case 'i':
	    mode.mode |= MODE_INVITEONLY;
	    break;
	case 'n':
	    mode.mode |= MODE_NOPRIVMSGS;
	    break;
	case 'p':
	    mode.mode |= MODE_PRIVATE;
	    break;
	case 's':
	    mode.mode |= MODE_SECRET;
	    break;
	case 'm':
	    mode.mode |= MODE_MODERATED;
	    break;
	case 't':
	    mode.mode |= MODE_TOPICLIMIT;
	    break;
	case 'r':
	    mode.mode |= MODE_REGISTERED;
	    break;
	case 'R':
	    mode.mode |= MODE_REGONLY;
	    break;
	case 'M':
	    mode.mode |= MODE_MODREG;
	    break;
	case 'c':
	    mode.mode |= MODE_NOCOLOR;
	    break;
	case 'O':
	    mode.mode |= MODE_OPERONLY;
	    break;
	case 'd':
	    mode.mode |= MODE_NONICKCHG;
	    break;
	case 'u':
	    mode.mode |= MODE_NOSPAM;
	    break;
	case 'C':
	    mode.mode |= MODE_NOCTCP;
	    break;
	case 'S':
	    mode.mode |= MODE_SSLONLY;
	    break;
	case 'j':
	    mode.mode |= MODE_NOUNKNOWN;
	    break;
	case 'U':
	    mode.mode |= MODE_UNRESTRICT;
	    break;
	case 'B':
	    mode.mode |= MODE_HIDEBANS;
	    break;
	case 'k':
	    strncpyzt(mode.key, parv[4 + args], KEYLEN + 1);
	    args++;
	    if (parc < 5 + args)
		return 0;
	    break;
	case 'l':
	    mode.limit = atoi(parv[4 + args]);
	    args++;
	    if (parc < 5 + args)
		return 0;
	    break;
	}


    doesop = (parv[4 + args][0] == '@' || parv[4 + args][1] == '@');

    oldmode = &chptr->mode;

    /* newts is the ts the remote server is providing */ 
    /* oldts is our channel TS */ 
    /* whichever TS is smaller wins. */ 
	
    if (isnew)
	chptr->channelts = tstosend = newts;
    else if (newts == 0 || oldts == 0)
	chptr->channelts = tstosend = 0;
    else if (newts == oldts)
	tstosend = oldts;
    else if (newts < oldts) 
    { 
       /* if remote ts is older, don't keep our modes. */ 
       kill_ban_list(sptr, chptr);
       kill_restrict_list(sptr, chptr);
       keepourmodes = 0; 
       chptr->channelts = tstosend = newts; 
    } 
    else /* if our TS is older, don't keep their modes */ 
    { 
       keepnewmodes = 0; 
       tstosend = oldts; 
    } 

    if (!keepnewmodes)
	mode = *oldmode;
    else if (keepourmodes)
    {
	mode.mode |= oldmode->mode;
	if (oldmode->limit > mode.limit)
	    mode.limit = oldmode->limit;
	if(*oldmode->key && *mode.key && strcmp(mode.key, oldmode->key) > 0)
	{
	    /* sketchy: keep the key that's lexographically greater
	       if we both have a differing key. */
	    strcpy(mode.key, oldmode->key);
	}
	else if(*oldmode->key && *mode.key == '\0')
	    strcpy(mode.key, oldmode->key);
    }
    
    pbpos = 0;
    
    /*
     * since the most common case is that the modes are exactly the same,
     *  this if will skip over the most common case... :)
     * 
     * this would look prettier in a for loop, but it's unrolled here
     *  so it's a bit faster.   - lucas
     * 
     * pass +: go through and add new modes that are in mode and not oldmode
     * pass -: go through and delete old modes that are in oldmode and not mode
     */
    
    if(mode.mode != oldmode->mode)
    {
        /* plus modes */
        if((MODE_PRIVATE & mode.mode) && !(MODE_PRIVATE & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++ = 'p';
	}
	if((MODE_SECRET & mode.mode) && !(MODE_SECRET & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++ = 's';
	}
	if((MODE_MODERATED & mode.mode) && !(MODE_MODERATED & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++ = 'm';
	}
	if((MODE_NOPRIVMSGS & mode.mode) && !(MODE_NOPRIVMSGS & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++ = 'n';
	}
	if((MODE_TOPICLIMIT & mode.mode) && !(MODE_TOPICLIMIT & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++ = 't';
	}
	if((MODE_INVITEONLY & mode.mode) && !(MODE_INVITEONLY & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++ = 'i';
	}
	if((MODE_REGISTERED & mode.mode) && !(MODE_REGISTERED & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++='r';
	}
	if((MODE_REGONLY & mode.mode) && !(MODE_REGONLY & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++='R';
	}
	if((MODE_MODREG & mode.mode) && !(MODE_MODREG & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++='M';
	}
	if((MODE_NOCOLOR & mode.mode) && !(MODE_NOCOLOR & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++='c';
	}
	if((MODE_OPERONLY & mode.mode) && !(MODE_OPERONLY & oldmode->mode))
	{			    
	    INSERTSIGN(1,'+')				       
	    *mbuf++='O';
	}
	if((MODE_NONICKCHG & mode.mode) && !(MODE_NONICKCHG & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++='d';
	}
	if((MODE_NOSPAM & mode.mode) && !(MODE_NOSPAM & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++='u';
	}
	if((MODE_NOCTCP & mode.mode) && !(MODE_NOCTCP & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++='C';
	}
	if((MODE_SSLONLY & mode.mode) && !(MODE_SSLONLY & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++='S';
	}
	if((MODE_NOUNKNOWN & mode.mode) && !(MODE_NOUNKNOWN & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++='j';
	}
	if((MODE_UNRESTRICT & mode.mode) && !(MODE_UNRESTRICT & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++='U';
	}
	if((MODE_HIDEBANS & mode.mode) && !(MODE_HIDEBANS & oldmode->mode))
	{
	    INSERTSIGN(1,'+')
	    *mbuf++='B';
	}

	/* minus modes */
	if((MODE_PRIVATE & oldmode->mode) && !(MODE_PRIVATE & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++ = 'p';
	}
	if((MODE_SECRET & oldmode->mode) && !(MODE_SECRET & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++ = 's';
	}
	if((MODE_MODERATED & oldmode->mode) && !(MODE_MODERATED & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++ = 'm';
	}
	if((MODE_NOPRIVMSGS & oldmode->mode) && !(MODE_NOPRIVMSGS & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++ = 'n';
	}
	if((MODE_TOPICLIMIT & oldmode->mode) && !(MODE_TOPICLIMIT & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++ = 't';
	}
	if((MODE_INVITEONLY & oldmode->mode) && !(MODE_INVITEONLY & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++ = 'i';
	}
	if((MODE_REGISTERED & oldmode->mode) && !(MODE_REGISTERED & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='r';
	}
	if((MODE_REGONLY & oldmode->mode) && !(MODE_REGONLY & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='R';
	}
	if((MODE_MODREG & oldmode->mode) && !(MODE_MODREG & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='M';
	}
	if((MODE_NOCOLOR & oldmode->mode) && !(MODE_NOCOLOR & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='c';
	}
	if((MODE_OPERONLY & oldmode->mode) && !(MODE_OPERONLY & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='O';
	}
	if((MODE_NONICKCHG & oldmode->mode) && !(MODE_NONICKCHG & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='d';
	}
	if((MODE_NOSPAM & oldmode->mode) && !(MODE_NOSPAM & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='u';
	}
	if((MODE_NOCTCP & oldmode->mode) && !(MODE_NOCTCP & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='C';
	}
	if((MODE_SSLONLY & oldmode->mode) && !(MODE_SSLONLY & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='S';
	}
	if((MODE_NOUNKNOWN & oldmode->mode) && !(MODE_NOUNKNOWN & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='j';
	}
	if((MODE_UNRESTRICT & oldmode->mode) && !(MODE_UNRESTRICT & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='U';
	}
	if((MODE_HIDEBANS & oldmode->mode) && !(MODE_HIDEBANS & mode.mode))
	{
	    INSERTSIGN(-1,'-')
	    *mbuf++='B';
	}
    }
	
    if (oldmode->limit && !mode.limit)
    {
	INSERTSIGN(-1,'-')
	*mbuf++ = 'l';
    }

    if (oldmode->key[0] && !mode.key[0])
    {
	INSERTSIGN(-1,'-')
	    *mbuf++ = 'k';
	ADD_PARA(oldmode->key)
	    pargs++;
    }

    if (mode.limit && oldmode->limit != mode.limit)
    {
	INSERTSIGN(1,'+')
	    *mbuf++ = 'l';
	sprintf(numeric, "%-15d", mode.limit);
	if ((s = strchr(numeric, ' ')))
	    *s = '\0';
	ADD_PARA(numeric);
	pargs++;
    }

    if (mode.key[0] && strcmp(oldmode->key, mode.key))
    {
	INSERTSIGN(1,'+')
	    *mbuf++ = 'k';
	ADD_PARA(mode.key)
	    pargs++;
    }
	
    chptr->mode = mode;
	
    if (!keepourmodes) /* deop and devoice everyone! */
    {
	what = 0;
	for (cm = chptr->members; cm; cm = cm->next) 
	{
	    if (cm->flags & MODE_CHANOP) 
	    {
		INSERTSIGN(-1,'-')
		    *mbuf++ = 'o';
		ADD_PARA(cm->cptr->name)
		    pargs++;
		if (pargs >= MAXMODEPARAMS) 
		{
		    *mbuf = '\0';
		    parabuf[pbpos] = '\0';
		    sjoin_sendit(cptr, sptr, chptr, parv[0]);
		    mbuf = modebuf;
		    *mbuf = '\0';
		    pargs = pbpos = what = 0;
		}
		cm->flags &= ~MODE_CHANOP;
	    }

	    if (cm->flags & MODE_HALFOP) 
	    {
		INSERTSIGN(-1,'-')
		    *mbuf++ = 'h';
		ADD_PARA(cm->cptr->name)
		    pargs++;
		if (pargs >= MAXMODEPARAMS) 
		{
		    *mbuf = '\0';
		    parabuf[pbpos] = '\0';
		    sjoin_sendit(cptr, sptr, chptr, parv[0]);
		    mbuf = modebuf;
		    *mbuf = '\0';
		    pargs = pbpos = what = 0;
		}
		cm->flags &= ~MODE_HALFOP;
	    }

	    if (cm->flags & MODE_VOICE) 
	    {
		INSERTSIGN(-1,'-')
		    *mbuf++ = 'v';
		ADD_PARA(cm->cptr->name)
		    pargs++;
		if (pargs >= MAXMODEPARAMS) 
		{
		    *mbuf = '\0';
		    parabuf[pbpos] = '\0';
		    sjoin_sendit(cptr, sptr, chptr, parv[0]);
		    mbuf = modebuf;
		    *mbuf = '\0';
		    pargs = pbpos = what = 0;
		}
		cm->flags &= ~MODE_VOICE;
	    }

	}
	/* 
	 * We know if we get here, and we're in a sync, we haven't sent our topic 
	 * to sptr yet. (since topic burst is sent after sjoin burst finishes) 
	 */ 
	if(chptr->topic[0]) 
	{ 
	    chptr->topic[0] = '\0'; 
	    sendto_channel_butserv(chptr, sptr, ":%s TOPIC %s :%s", sptr->name,
				   chptr->chname, chptr->topic);
	}
	sendto_channel_butserv(chptr, &me,
			       ":%s NOTICE %s :*** Notice -- TS for %s "
			       "changed from %ld to %ld",
			       me.name, chptr->chname, chptr->chname,
			       oldts, newts);
    }
    
    if (mbuf != modebuf) 
    {
	*mbuf = '\0';
	parabuf[pbpos] = '\0';
	sjoin_sendit(cptr, sptr, chptr, parv[0]);
    }
    
    *modebuf = '\0';
    *noneb_modebuf = '\0';
    parabuf[0] = '\0';
    if (parv[3][0] != '0' && keepnewmodes)
	channel_modes(sptr, modebuf, parabuf, noneb_modebuf, chptr);
    else 
    {
	modebuf[0] = '0';
	modebuf[1] = '\0';
	noneb_modebuf[0] = '0';
	noneb_modebuf[1] = '\0';
    }
    
    /* We do this down below now, so we can send out for two sjoin formats.
     * sprintf(t, ":%s SJOIN %ld %ld %s %s %s :", parv[0], tstosend, tstosend,
     *			  parv[2], modebuf, parabuf);
     * t += strlen(t);
     * the pointer "t" has been removed and is now replaced with an 
     * index into sjbuf for faster appending
     */
    
    strcpy(keep_modebuf, modebuf);
    strcpy(keep_parabuf, parabuf);
    
    sjbufpos = 0;
    mbuf = modebuf;
    pbpos = 0;
    pargs = 0;
    *mbuf++ = '+';
    
    for (s = s0 = strtoken(&p, parv[args + 4], " "); s;
	 s = s0 = strtoken(&p, (char *) NULL, " ")) 
    {
	fl = 0;
	
	for (;;) {
	    if (*s == '@') 
	    {
	    	fl |= MODE_CHANOP;
		s++;
	    } else if (*s == '+') {
	    	fl |= MODE_VOICE;
		s++;
	    } else if (*s == '%') {
	    	fl |= MODE_HALFOP;
		s++;
	    } else {
	    	break;
	    }
	}
	
	if (!keepnewmodes) 
	{
	    if (fl & MODE_CHANOP)
		fl = MODE_DEOPPED;
	    else
		fl = 0;
	}

	if (!(acptr = find_chasing(sptr, s, NULL)))
	    continue;
	if (acptr->from != cptr)
	    continue;
	people++;
	if (!IsMember(acptr, chptr)) 
	{
	    add_user_to_channel(chptr, acptr, fl);
	    sendto_channel_butserv(chptr, acptr, ":%s JOIN :%s", s, parv[2]);
	}
	if (keepnewmodes)
	{
	    ADD_SJBUF(s0)
	}
	else
	{
	    ADD_SJBUF(s)
	}
	if (fl & MODE_CHANOP) 
	{
	    *mbuf++ = 'o';
	    ADD_PARA(s)
	    pargs++;
	    if (pargs >= MAXMODEPARAMS) 
	    {
		*mbuf = '\0';
		parabuf[pbpos] = '\0';
		sjoin_sendit(cptr, sptr, chptr, parv[0]);
		mbuf = modebuf;
		*mbuf++ = '+';
		pargs = pbpos = 0;
	    }
	}
	if (fl & MODE_HALFOP) 
	{
	    *mbuf++ = 'h';
	    ADD_PARA(s)
	    pargs++;
	    if (pargs >= MAXMODEPARAMS) 
	    {
		*mbuf = '\0';
		parabuf[pbpos] = '\0';
		sjoin_sendit(cptr, sptr, chptr, parv[0]);
		mbuf = modebuf;
		*mbuf++ = '+';
		pargs = pbpos = 0;
	    }
	}	
	if (fl & MODE_VOICE) 
	{
	    *mbuf++ = 'v';
	    ADD_PARA(s)
	    pargs++;
	    if (pargs >= MAXMODEPARAMS) 
	    {
		*mbuf = '\0';
		parabuf[pbpos] = '\0';
		sjoin_sendit(cptr, sptr, chptr, parv[0]);
		mbuf = modebuf;
		*mbuf++ = '+';
		pargs = pbpos = 0;
	    }
	}
    }

    parabuf[pbpos] = '\0';

    *mbuf = '\0';
    if (pargs)
	sjoin_sendit(cptr, sptr, chptr, parv[0]);
    if (people) 
    {
	sjbuf[sjbufpos] = '\0';

	if(keep_parabuf[0] != '\0')
	{
	    /* Full modes first */
	    sendto_server(cptr, chptr, CAP_NSJOIN | CAP_EBMODE, NOCAPS,
			  newSJOINFmt, parv[0], tstosend,
			  parv[2], keep_modebuf, keep_parabuf, sjbuf);
	    sendto_server(cptr, chptr, CAP_EBMODE, CAP_NSJOIN, oldSJOINFmt, parv[0],
			  tstosend, tstosend, parv[2], keep_modebuf,
			  keep_parabuf, sjbuf);
	    /* Then baseline modes only */
	    sendto_server(cptr, chptr, CAP_NSJOIN, CAP_EBMODE,
			  newSJOINFmt, parv[0], tstosend,
			  parv[2], noneb_modebuf, keep_parabuf, sjbuf);
	    sendto_server(cptr, chptr, NOCAPS, CAP_NSJOIN | CAP_EBMODE,
			  oldSJOINFmt, parv[0],
			  tstosend, tstosend, parv[2], noneb_modebuf,
			  keep_parabuf, sjbuf);
	} 
	else
	{
	    /* Full modes first */
	    sendto_server(cptr, chptr, CAP_NSJOIN | CAP_EBMODE, NOCAPS,
			  newSJOINFmtNP, parv[0],
			  tstosend, parv[2], keep_modebuf, sjbuf);
	    sendto_server(cptr, chptr, CAP_EBMODE, CAP_NSJOIN,
			  oldSJOINFmtNP, parv[0],
			  tstosend, tstosend, parv[2], keep_modebuf,
			  sjbuf);
	    /* Then baseline modes only */
	    sendto_server(cptr, chptr, CAP_NSJOIN, CAP_EBMODE, newSJOINFmtNP, parv[0],
			  tstosend, parv[2], noneb_modebuf, sjbuf);
	    sendto_server(cptr, chptr, NOCAPS, CAP_NSJOIN | CAP_EBMODE,
			  oldSJOINFmtNP, parv[0],
			  tstosend, tstosend, parv[2], noneb_modebuf,
			  sjbuf);
	}
    }
    return 0;
}
#undef INSERTSIGN
#undef ADD_PARA
#undef ADD_SJBUF

/* m_samode - Just bout the same as df
 *  - Raistlin 
 * parv[0] = sender
 * parv[1] = channel
 * parv[2] = modes
 */
int m_samode(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int sendts;
    int stripped_mcount = 0;
    int noneb_mcount = 0;
    aChannel *chptr;

    if (check_registered(cptr))
	return 0;

    if (!IsPrivileged(cptr))
    {
	sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
	return 0;
    }
    
    if (!(IsAdmin(cptr) || IsSAdmin(cptr)))
	return 0;
    
    /* AZZURRA: fixed the damn "/samode #channel" bug, 
     * setting the last mode computed via set_mode ; sux
     */
    if(parc < 3)
	return 0;
    
    chptr = find_channel(parv[1], NullChn);

    if (chptr == NullChn)
	return 0;

    if(!check_channelname(sptr, (unsigned char *)parv[1]))
	return 0;

    sendts = set_mode(cptr, sptr, chptr, 2, parc - 2, parv + 2,
		      modebuf, parabuf, stripped_modebuf, stripped_parabuf, &stripped_mcount,
		      noneb_modebuf, noneb_parabuf, &noneb_mcount);
	
    if (strlen(modebuf) > (size_t)1)
    {
	if (stripped_mcount == sendts)
	{
	    sendto_channel_butserv(chptr, sptr,
				   ":%s MODE %s %s %s", parv[0],
				   chptr->chname, modebuf,
				   parabuf);
	}
	else
	{
	    /* Stesso discorso di set_mode */
	    sendto_chanops_butserv(chptr, sptr, 1,
				   ":%s MODE %s %s %s", parv[0],
				   chptr->chname, modebuf,
				   parabuf);
	    if (stripped_mcount > 0)
		sendto_chanops_butserv(chptr, sptr, 0,
				       ":%s MODE %s %s %s", parv[0],
				       chptr->chname, stripped_modebuf,
				       stripped_parabuf);
	}

	if (noneb_mcount == sendts)
	{
		/* No extended modes, don't check for CAP_EBMODE */
		sendto_server(cptr, chptr, NOCAPS, CAP_TSMODE,
			      ":%s MODE %s %s %s",
			      parv[0], chptr->chname, modebuf, parabuf);
		sendto_server(cptr, chptr, CAP_TSMODE, NOCAPS,
			      ":%s MODE %s 0 %s %s",
			      parv[0], chptr->chname, modebuf, parabuf);
	}
	else
	{
		/* Ok, fine, send out full modes first */
		sendto_server(cptr, chptr, CAP_EBMODE, CAP_TSMODE,
			      ":%s MODE %s %s %s",
			      parv[0], chptr->chname, modebuf, parabuf);
		sendto_server(cptr, chptr, CAP_EBMODE | CAP_TSMODE, NOCAPS,
			      ":%s MODE %s 0 %s %s",
			      parv[0], chptr->chname, modebuf, parabuf);
		/* And then only baseline modes */
		if (noneb_mcount > 0)
		{
		    sendto_server(cptr, chptr, NOCAPS, CAP_TSMODE | CAP_EBMODE,
				  ":%s MODE %s %s %s",
				  parv[0], chptr->chname, noneb_modebuf, noneb_parabuf);
		    sendto_server(cptr, chptr, CAP_TSMODE, CAP_EBMODE,
				  ":%s MODE %s 0 %s %s",
				  parv[0], chptr->chname, noneb_modebuf, noneb_parabuf);
		}
	}
	if(MyClient(sptr))
	{
	    sendto_serv_butone(NULL, ":%s GLOBOPS :%s used SAMODE (%s %s%s%s)",
			       me.name, sptr->name, chptr->chname, modebuf,
			       (*parabuf!=0 ? " " : ""), parabuf);
	    send_globops("from %s: %s used SAMODE (%s %s%s%s)",
			 me.name, sptr->name, chptr->chname, modebuf, 
			 (*parabuf!=0 ? " " : ""), parabuf);
	}
    }
    return 0;
}

char  *pretty_mask(char *mask)
{
    char  *cp, *user, *host;
    
    if ((user = strchr((cp = mask), '!')))
	*user++ = '\0';
    if ((host = strrchr(user ? user : cp, '@')))
    {
	*host++ = '\0';
	if (!user)
	    return make_nick_user_host(NULL, cp, host);
    }
    else if (!user && strchr(cp, '.'))
	return make_nick_user_host(NULL, NULL, cp);
    return make_nick_user_host(cp, user, host);
}
