/************************************************************************
 *   IRC - Internet Relay Chat, include/struct.h
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
 *
 *
 */

/* $Id$ */

#ifndef	__struct_include__
#define __struct_include__

#include "config.h"
#if !defined(CONFIG_H_LEVEL_12)
#error Incorrect config.h for this revision of ircd.
#endif

#include <stdio.h>
#include <sys/types.h>

#ifdef _FD_SETSIZE
#undef FD_SETSIZE
#define FD_SETSIZE _FD_SETSIZE
#endif

#include <netinet/in.h>
#include <netdb.h>
#if defined( HAVE_STDDEF_H )
#include <stddef.h>
#endif
#ifdef ORATIMING
#include <sys/time.h>
#endif

#ifdef USE_SYSLOG
#include <syslog.h>
#if defined( HAVE_SYS_SYSLOG_H )
#include <sys/syslog.h>
#endif
#endif

#ifdef USE_SSL
#include <openssl/rsa.h>       /* OpenSSL stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
//#define OPENSSL_NO_KRB5		/* Define if getting krb5.h errors. */
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "hash.h"

typedef struct ConfItem aConfItem;
typedef struct Client aClient;
typedef struct Channel aChannel;
typedef struct User anUser;
typedef struct Server aServer;
typedef struct SLink Link;
typedef struct ChanLink chanMember;
typedef struct SMode Mode;
typedef struct Watch aWatch;
typedef struct Ban aBan;
typedef struct ListOptions LOpts;
typedef struct spam_ Spam;
typedef long ts_val;

typedef struct MotdItem aMotd;

#include "class.h"
#include "dbuf.h"		/* THIS REALLY SHOULDN'T BE HERE!!! --msa */

#define	HOSTLEN		63	/* Length of hostname.  Updated to */

/* comply with RFC1123 */

#define HOSTIPLEN	40	/* Maximum length of IP address (40 supports IPv6) */

#define	NICKLEN		30	

/* Necessary to put 9 here instead of 10  if  
 * s_msg.c/m_nick has been corrected.  This 
 * preserves compatibility with old * servers --msa 
 */

#define MAX_DATE_STRING 32	/* maximum string length for a date string */

#define	USERLEN		    10
#define	REALLEN	 	    50
#define	TOPICLEN	    307
#define	KILLLEN	            400
#define	CHANNELLEN          32

#define	PASSWDLEN 	    63

#define	KEYLEN		    23
#define	BUFSIZE		    512	/* WARNING: *DONT* CHANGE THIS!!!! */
#define	MAXRECIPIENTS       20
#define	MAXBANS	 	    100

#define MOTDLINELEN	    90

#define        MAXSILES        10
#define        MAXSILELENGTH   128

#define MAXDCCALLOW 5
#define DCC_LINK_ME	0x01	/* This is my dcc allow */
#define DCC_LINK_REMOTE 0x02    /* I need to remove these dcc allows from
				 * these clients when I die
				 */
#define MAXDCCFILELEN   225     /* Max file length for dcc send */
#define MAXDCCFILESPACES 15     /* Max file spaces for dcc send */


#define	USERHOST_REPLYLEN	(NICKLEN+HOSTLEN+USERLEN+5)

/*
 * 'offsetof' is defined in ANSI-C. The following definition * is not
 * absolutely portable (I have been told), but so far * it has worked
 * on all machines I have needed it. The type * should be size_t but...
 * --msa
 */

#ifndef offsetof
#define	offsetof(t,m) (int)((&((t *)0L)->m))
#endif

#define	elementsof(x) (sizeof(x)/sizeof(x[0]))

/* flags for bootup options (command line flags) */

#define	BOOT_CONSOLE     1
#define	BOOT_QUICK	 2
#define	BOOT_DEBUG	 4
#define	BOOT_TTY	 16
#define	BOOT_OPER	 32
#define BOOT_STDERR	 128
#define	STAT_LOG	 -6	/* logfile for -x */
#define	STAT_CONNECTING	 -4
#define	STAT_HANDSHAKE	 -3
#define	STAT_ME		 -2
#define	STAT_UNKNOWN	 -1
/* the line of truth lies here (truth == registeredness) */
#define	STAT_SERVER	 0
#define	STAT_CLIENT	 1

/* status macros. */

#define	IsRegisteredUser(x)	((x)->status == STAT_CLIENT)
#define	IsRegistered(x)		((x)->status >= STAT_SERVER)
#define	IsConnecting(x)		((x)->status == STAT_CONNECTING)
#define	IsHandshake(x)		((x)->status == STAT_HANDSHAKE)
#define	IsMe(x)			((x)->status == STAT_ME)
#define	IsUnknown(x)		((x)->status == STAT_UNKNOWN)
#define	IsServer(x)		((x)->status == STAT_SERVER)
#define	IsClient(x)		((x)->status == STAT_CLIENT)
#define	IsLog(x)		((x)->status == STAT_LOG)

#define	SetConnecting(x)	((x)->status = STAT_CONNECTING)
#define	SetHandshake(x)		((x)->status = STAT_HANDSHAKE)
#define	SetMe(x)		((x)->status = STAT_ME)
#define	SetUnknown(x)		((x)->status = STAT_UNKNOWN)
#define	SetServer(x)		((x)->status = STAT_SERVER)
#define	SetClient(x)		((x)->status = STAT_CLIENT)
#define	SetLog(x)		((x)->status = STAT_LOG)

#define	FLAGS_PINGSENT     0x000001   /* Unreplied ping sent */
#define	FLAGS_DEADSOCKET   0x000002   /* Local socket is dead--Exiting soon */
#define	FLAGS_KILLED       0x000004   /* Prevents "QUIT" from being sent for
				       * this */
#define	FLAGS_BLOCKED      0x000008   /* socket is in a blocked condition */
#define FLAGS_REJECT_HOLD  0x000010   /* client has been klined */
#define	FLAGS_CLOSING      0x000020   /* set when closing to suppress errors */
#define	FLAGS_LISTEN       0x000040   /* used to mark clients which we listen()
				       * on */
#define	FLAGS_CHKACCESS    0x000080   /* ok to check clients access if set */
#define	FLAGS_DOINGDNS	   0x000100   /* client is waiting for a DNS 
				       * response */
#define	FLAGS_AUTH	   0x000200   /* client is waiting on rfc931 
				       * response */
#define	FLAGS_WRAUTH	   0x000400   /* set if we havent writen to ident 
				       * server */
#define	FLAGS_LOCAL	   0x000800   /* set for local clients */
#define	FLAGS_GOTID	   0x001000   /* successful ident lookup achieved */
#define	FLAGS_DOID	   0x002000   /* I-lines say must use ident return */
#define	FLAGS_NONL	   0x004000   /* No \n in buffer */
#define FLAGS_NORMALEX     0x008000   /* Client exited normally */
#define FLAGS_SENDQEX      0x010000   /* Sendq exceeded */
#define FLAGS_IPHASH       0x020000   /* iphashed this client */
#define FLAGS_ULINE 	   0x040000   /* client is U-lined */
#define FLAGS_USERBURST	   0x080000   /* server in nick/channel netburst */
#define FLAGS_TOPICBURST   0x100000   /* server in topic netburst */
#define FLAGS_BURST	   (FLAGS_USERBURST | FLAGS_TOPICBURST)
#define FLAGS_SOBSENT      0x200000   /* we've sent an SOB, just have to 
				       * send an EOB */
#define FLAGS_EOBRECV      0x400000   /* we're waiting on an EOB */
#define FLAGS_BAD_DNS	   0x800000   /* spoofer-guy */
#define FLAGS_SERV_NEGO	   0x1000000  /* This is a server that has passed
				       * connection tests, but is a stat < 0
				       * for handshake purposes */
#define FLAGS_RC4IN        0x2000000  /* This link is rc4 encrypted. */
#define FLAGS_RC4OUT       0x4000000  /* This link is rc4 encrypted. */
#define FLAGS_ZIPPED_IN	   0x8000000  /* This link is gzipped. */
#define FLAGS_ZIPPED_OUT   0x10000000 /* This link is gzipped. */

#define FLAGS_JAVA         0x0001 /* This link uses JavaCR */
#define FLAGS_SSL          0x0002 /* This link uses SSL */
#define FLAGS_SHUNNED      0x0004 /* This link is shunned */
#define FLAGS_IPV6         0x0008 /* This link uses IPv6 */
#define FLAGS_SVSNICKED	   0x0010 /* This person has been svsnicked (can change nickname for 10 seconds) */
#define FLAGS_REGISTERED   0x0020 /* This person has identified to a registered nick during this session. This flag is not reset when the client issues a /nick command (unlike umode +r) */
#define FLAGS_WEBIRC       0x0040 /* Perform WEBIRC spoofing (skip multiple getpeername() and crap like that) */
#define FLAGS_6TO4         0x0080 /* User is behind a 6to4 tunnel */
#define FLAGS_TEREDO       0x0100 /* User is behind a Teredo tunnel */
#define FLAGS_HAPROXY      0x0200 /* This port support HAProxy IP address spoofing */
#define FLAGS_STUD         0x0400 /* Ditto, but upstream uses SSL/TLS */

/* Capabilities of the ircd or clients */

#define CAP_TS3     0x0000001	/* Supports the TS3 Protocol */
#define CAP_NOQUIT  0x0000002	/* Supports NOQUIT */
#define CAP_NSJOIN  0x0000004	/* server supports new smart sjoin */
#define CAP_BURST   0x0000008	/* server supports BURST command */
#define CAP_UNCONN  0x0000010	/* server supports UNCONNECT */
#define CAP_DKEY    0x0000020	/* server supports dh-key exchange
				 * using "DKEY" */
#define CAP_ZIP     0x0000040	/* server supports gz'd links */
#define CAP_DOZIP   0x0000080	/* output to this link shall be gzipped */
#define CAP_DODKEY  0x0000100	/* do I do dkey with this link? */
#define CAP_NICKIP  0x0000200	/* IP in the NICK line? */
#define CAP_TSMODE  0x0000400	/* MODE's parv[2] is chptr->channelts for channel mode */
#define CAP_EBMODE  0x0000800	/* server supports extended ban modes (+z) and banlist hiding (+B) */

#define NOCAPS        0		/* Empty capability set */

#define SetTS3(x)   	((x)->capabilities |= CAP_TS3)

#define SetNoQuit(x) 	((x)->capabilities |= CAP_NOQUIT)

#define SetSSJoin(x)	((x)->capabilities |= CAP_NSJOIN)

#define SetBurst(x)	((x)->capabilities |= CAP_BURST)

#define SetUnconnect(x)	((x)->capabilities |= CAP_UNCONN)

#define SetDKEY(x)	((x)->capabilities |= CAP_DKEY)
#define CanDoDKEY(x)    ((x)->capabilities & CAP_DKEY)
/* N: line, flag E */
#define WantDKEY(x)	((x)->capabilities & CAP_DODKEY)

#define SetZipCapable(x) ((x)->capabilities |= CAP_ZIP)
#define IsZipCapable(x)	((x)->capabilities & CAP_ZIP)
/* this is set in N: line, flag Z */
#define DoZipThis(x) 	((x)->capabilities & CAP_DOZIP)
#define SetNICKIP(x)    ((x)->capabilities |= CAP_NICKIP)

#define SetTSMODE(x)	((x)->capabilities |= CAP_TSMODE)

#define SetEBMODE(x)	((x)->capabilities |= CAP_EBMODE)

/* Generic capabilities matching macros */
#define IsCapable(x, cap)	(((x)->capabilities & (cap)) == cap)
#define NotCapable(x, cap)	(((x)->capabilities & (cap)) == 0)

/* flag macros. */
#define IsULine(x) ((x)->flags & FLAGS_ULINE)

/* User Modes */
#define UMODE_o     0x00001	/* umode +o - Oper */
#define UMODE_O     0x00002	/* umode +O - Local Oper */
#define UMODE_i     0x00004	/* umode +i - Invisible */
#define UMODE_w     0x00008	/* umode +w - Get wallops */
#define UMODE_s     0x00010	/* umode +s - Server notices */
#define UMODE_c     0x00020	/* umode +c - Client connections/exits */
#define UMODE_r     0x00040	/* umode +r - registered nick */
#define UMODE_k     0x00080	/* umode +k - Server kill messages */
#define UMODE_f     0x00100	/* umode +f - Server flood messages */
#define UMODE_y     0x00200	/* umode +y - Stats/links */
#define UMODE_d     0x00400	/* umode +d - Debug info */
#define UMODE_g     0x01000	/* umode +g - Globops */
#define UMODE_b     0x02000	/* umode +b - Chatops */
#define UMODE_a     0x04000	/* umode +a - Services Admin */
#define UMODE_A     0x08000     /* umode +A - Server Admin */
#define UMODE_n     0x10000	/* umode +n - Routing Notices */
#define UMODE_h     0x20000     /* umode +h - Helper */
#define UMODE_m     0x40000     /* umode +m - spambot notices */
#define UMODE_R     0x80000     /* unmode +R - No non registered msgs */
#define UMODE_D     0x100000    /* umode +D - Hidden dccallow umode */
#define UMODE_e     0x200000    /* umode +e - oper notices for the above +D */
#define UMODE_F     0x400000	/* umode +F - no cptr->since message rate throttle */
#define UMODE_K     0x800000	/* umode +K - U: lined server kill messages */
/* Azzurra */    
#define UMODE_x     0x1000000   /* umode +x - host cloaking. */
#define UMODE_z     0x2000000   /* umode +z - services agent. */
#define UMODE_S     0x4000000	/* umode +S - SSL user */
#define UMODE_I     0x8000000	/* umode +I - no idle show */

/* for sendto_ops_lev */

#define CCONN_LEV	1
#define REJ_LEV		2
#define SKILL_LEV	3
#define SPY_LEV		4
#define DEBUG_LEV	5
#define FLOOD_LEV 	6
#define SPAM_LEV 	7
#define DCCSEND_LEV	8
#define USKILL_LEV	9

/* SEND_UMODES:
 *  we send these to remote servers.
 * ALL_UMODES
 *  we send these to our clients.
 *  if you don't put something in ALL_UMODES, 
 *  that mode will be 'silent.'
 */

#define	SEND_UMODES (UMODE_i|UMODE_o|UMODE_r|UMODE_a|UMODE_A|\
                     UMODE_h|UMODE_R|UMODE_x|UMODE_y|UMODE_z|\
		     UMODE_S|UMODE_I|UMODE_m)
#define ALL_UMODES (SEND_UMODES|UMODE_w|UMODE_s|UMODE_c|UMODE_r|\
		    UMODE_k|UMODE_f|UMODE_d|UMODE_g|UMODE_b|UMODE_n|\
		    UMODE_h|UMODE_O|UMODE_R|UMODE_e|UMODE_F|UMODE_K)

#ifdef DEFAULT_HELP_MODE
#define OPER_UMODES (UMODE_o|UMODE_w|UMODE_s|UMODE_y|UMODE_d|UMODE_g|\
                     UMODE_n|UMODE_h)

#else

#define OPER_UMODES (UMODE_o|UMODE_w|UMODE_s|UMODE_y|UMODE_d|UMODE_g|UMODE_n)

#endif

#define LOCOP_UMODES (UMODE_O|UMODE_w|UMODE_s|UMODE_y|UMODE_d|UMODE_g|\
                      UMODE_n|UMODE_h)

#define	FLAGS_ID (FLAGS_DOID|FLAGS_GOTID)

#define	IsOper(x)		((x)->umode & UMODE_o)
#define	IsLocOp(x)		((x)->umode & UMODE_O)
#define	IsInvisible(x)		((x)->umode & UMODE_i)
#define	IsAnOper(x)		((x)->umode & (UMODE_o|UMODE_O))
#define IsARegNick(x)           ((x)->umode & (UMODE_r))
#define IsRegNick(x)            ((x)->umode & UMODE_r)
#define IsSAdmin(x)             ((x)->umode & UMODE_a)
#define IsAdmin(x)              ((x)->umode & UMODE_A)
#define IsUmodef(x)             ((x)->umode & UMODE_f)
#define IsUmodec(x)             ((x)->umode & UMODE_c)
#define IsUmodey(x)             ((x)->umode & UMODE_y)
#define IsUmoded(x)             ((x)->umode & UMODE_d)
#define IsUmodeb(x)             ((x)->umode & UMODE_b)
#define IsUmoden(x)             ((x)->umode & UMODE_n)
#define IsUmodem(x)             ((x)->umode & UMODE_m)
#define IsUmodeh(x)             ((x)->umode & UMODE_h)
#define IsUmodee(x)             ((x)->umode & UMODE_e)
#define	IsUmodeK(x)		((x)->umode & UMODE_K)

/* Azzurra */
#define IsUmodex(x)		((x)->umode & UMODE_x)
#define IsUmodez(x)		((x)->umode & UMODE_z)
#define IsUmodeS(x)		((x)->umode & UMODE_S) /*AZZURRA-SSL*/
#define IsHiddenIdle(x)		((x)->umode & UMODE_I)
/* end Azzurra */
#define IsNoNonReg(x)           ((x)->umode & UMODE_R)
#define	IsPerson(x)		((x)->user && IsClient(x))
#define	IsPrivileged(x)		(IsAnOper(x) || IsServer(x))
#define	SendWallops(x)		((x)->umode & UMODE_w)
#define	SendServNotice(x)	((x)->umode & UMODE_s)
#define SendCConnNotice(x)	((x)->umode & UMODE_c)
#define SendRejNotice(x)	((x)->umode & UMODE_c)
#define SendSkillNotice(x)	((x)->umode & UMODE_k)
#define SendSUkillNotice(x)	((x)->umode & UMODE_K)
#define SendSpyNotice(x)	((x)->umode & UMODE_y)
#define SendDCCNotice(x)	((x)->umode & UMODE_e)
#define SendFloodNotice(x)      ((x)->umode & UMODE_f)
#define SendSpamNotice(x)       ((x)->umode & UMODE_m)
#define SendDebugNotice(x)	((x)->umode & UMODE_d)
#define SendGlobops(x)          ((x)->umode & UMODE_g)
#define SendChatops(x)          ((x)->umode & UMODE_b)
#define SendRnotice(x)          ((x)->umode & UMODE_n)
#define NoMsgThrottle(x)	((x)->umode & UMODE_F)
#define	IsListening(x)		((x)->flags & FLAGS_LISTEN)
#define	DoAccess(x)		((x)->flags & FLAGS_CHKACCESS)
#define	IsLocal(x)		((x)->flags & FLAGS_LOCAL)
#define	IsDead(x)		((x)->flags & FLAGS_DEADSOCKET)

/* AZZURRA stuff. */
#define IsJava(x)		((x)->flags2 & FLAGS_JAVA) 
#define SetJava(x)		((x)->flags2 |= FLAGS_JAVA)
#define IsSSL(x)		((x)->flags2 & FLAGS_SSL)
#define SetSSL(x)		((x)->flags2 |= FLAGS_SSL) 
#define ClearSSL(x)		((x)->flags2 &= ~FLAGS_SSL)
#define SetSSLUmode(x)		((x)->umode |= UMODE_S)
#define SetCloak(x)		((x)->umode |= UMODE_x)
/* SHUN macros. */
#define IsShunned(x)	((x)->flags2 & FLAGS_SHUNNED)
#define SetShun(x)	((x)->flags2 |= FLAGS_SHUNNED)
#define UnShun(x)	((x)->flags2 &= ~FLAGS_SHUNNED)
/* end of SHUN macros. */
#define SetIPv6(x)		((x)->flags2 |= FLAGS_IPV6)
#define IsIPv6(x)		((x)->flags2 & FLAGS_IPV6) 
/* svsnicked stuff */
#define IsSVSnicked(x)		((x)->flags2 & FLAGS_SVSNICKED)
#define SetSVSnicked(x)		((x)->flags2 |= FLAGS_SVSNICKED)
#define UnsetSVSnicked(x)	((x)->flags2 &= ~FLAGS_SVSNICKED)
/* +j stuff */
#define SetKnownNick(x)		((x)->flags2 |= FLAGS_REGISTERED)
#define IsKnownNick(x)		((x)->flags2 & FLAGS_REGISTERED)
/* end of AZZURRA stuff. */
#define SetWEBIRC(x)            ((x)->flags2 |= FLAGS_WEBIRC)
#define IsWEBIRC(x)             ((x)->flags2 & FLAGS_WEBIRC)
/* 6to4 */
#define Set6to4(x)          ((x)->flags2 |= FLAGS_6TO4)
#define Is6to4(x)           ((x)->flags2 & FLAGS_6TO4)
/* Teredo */
#define SetTeredo(x)        ((x)->flags2 |= FLAGS_TEREDO)
#define IsTeredo(x)         ((x)->flags2 & FLAGS_TEREDO)
/* 6to4+Teredo */
#define ClearTunnel(x)      ((x)->flags2 &= ~(FLAGS_TEREDO|FLAGS_6TO4))
#define IsTunnel(x)         ((x)->flags2 & (FLAGS_6TO4|FLAGS_TEREDO))
/* HAProxy */
#define IsHAProxy(x)		((x)->flags2 & FLAGS_HAPROXY)
#define SetHAProxy(x)		((x)->flags2 |= FLAGS_HAPROXY)
#define ClearHAProxy(x)		((x)->flags2 &= ~FLAGS_HAPROXY)
/* Stud */
#define IsStud(x)		((x)->flags2 & FLAGS_STUD)
#define SetStud(x)		((x)->flags2 |= FLAGS_STUD)

#define	SetOper(x)		((x)->umode |= UMODE_o)
#define SetRegNick(x)           ((x)->umode |= UMODE_r)
#define SetNoNonReg(x)          ((x)->umode |= UMODE_R)
#define SetSAdmin(x)            ((x)->umode |= UMODE_a)
#define	SetLocOp(x)    		((x)->umode |= UMODE_O)
#define	SetInvisible(x)		((x)->umode |= UMODE_i)
#define	SetWallops(x)  		((x)->umode |= UMODE_w)
#define	SetDNS(x)		((x)->flags |= FLAGS_DOINGDNS)
#define	DoingDNS(x)		((x)->flags & FLAGS_DOINGDNS)
#define	SetAccess(x)		((x)->flags |= FLAGS_CHKACCESS)
#define	DoingAuth(x)		((x)->flags & FLAGS_AUTH)
#define	NoNewLine(x)		((x)->flags & FLAGS_NONL)
#define SeenDCCNotice(x)        ((x)->umode & UMODE_D)
#define SetDCCNotice(x)         ((x)->umode |= UMODE_D)

#define SetHiddenIdle(x)	((x)->umode |= UMODE_I)

#define SetNegoServer(x)	((x)->flags |= FLAGS_SERV_NEGO)
#define IsNegoServer(x)		((x)->flags & FLAGS_SERV_NEGO)
#define ClearNegoServer(x)	((x)->flags &= ~FLAGS_SERV_NEGO)
#define IsRC4OUT(x)		((x)->flags & FLAGS_RC4OUT)
#define SetRC4OUT(x)		((x)->flags |= FLAGS_RC4OUT)
#define IsRC4IN(x)		((x)->flags & FLAGS_RC4IN)
#define SetRC4IN(x)		((x)->flags |= FLAGS_RC4IN)
#define RC4EncLink(x)		(((x)->flags & (FLAGS_RC4IN|FLAGS_RC4OUT)) ==\
                                 (FLAGS_RC4IN|FLAGS_RC4OUT))

#define ZipIn(x)		((x)->flags & FLAGS_ZIPPED_IN)
#define SetZipIn(x)		((x)->flags |= FLAGS_ZIPPED_IN)
#define ZipOut(x)		((x)->flags & FLAGS_ZIPPED_OUT)
#define SetZipOut(x)		((x)->flags |= FLAGS_ZIPPED_OUT)

#define ClearSAdmin(x)          ((x)->umode &= ~UMODE_a)
#define ClearAdmin(x)           ((x)->umode &= ~UMODE_A)
#define ClearUmodef(x)          ((x)->umode &= ~UMODE_f)
#define ClearUmodem(x)          ((x)->umode &= ~UMODE_m)
#define ClearUmodec(x)          ((x)->umode &= ~UMODE_c)
#define ClearUmodey(x)          ((x)->umode &= ~UMODE_y)
#define ClearUmoded(x)          ((x)->umode &= ~UMODE_d)
#define ClearUmodeb(x)          ((x)->umode &= ~UMODE_b)
#define ClearUmoden(x)          ((x)->umode &= ~UMODE_n)
#define ClearUmodeh(x)          ((x)->umode &= ~UMODE_h)
#define ClearUmodee(x)          ((x)->umode &= ~UMODE_e)
#define ClearUmodeK(x)		((x)->umode &= ~UMODE_K)
#define ClearUmodek(x)		((x)->umode &= ~UMODE_k)
#define ClearUmodes(x)		((x)->umode &= ~UMODE_s)
#define ClearNoNonReg(x)        ((x)->umode &= ~UMODE_R)
#define	ClearOper(x)		((x)->umode &= ~UMODE_o)
#define ClearLocOp(x)		((x)->umode &= ~UMODE_O)
#define	ClearInvisible(x)	((x)->umode &= ~UMODE_i)
#define	ClearWallops(x)		((x)->umode &= ~UMODE_w)
#define ClearNoMsgThrottle(x)	((x)->umode &= ~UMODE_F)
#define ClearSkillNotice(x)	((x)->umode &= ~UMODE_k)
/* Azzurra */
#define ClearUmodex(x)		((x)->umode &= ~UMODE_x)
#define ClearUmodez(x)		((x)->umode &= ~UMODE_z)
#define ClearHiddenIdle(x)	((x)->umode &= ~UMODE_I)
#define ClearGlobops(x)		((x)->umode &= ~UMODE_g)
/* Azzurra */
#define	ClearDNS(x)		((x)->flags &= ~FLAGS_DOINGDNS)
#define	ClearAuth(x)		((x)->flags &= ~FLAGS_AUTH)
#define	ClearAccess(x)		((x)->flags &= ~FLAGS_CHKACCESS)

/* flags2 macros. */

/* Oper flags */

/* defined operator access levels */ 
#define OFLAG_REHASH	0x00000001  /* Oper can /rehash server */
#define OFLAG_DIE	0x00000002  /* Oper can /die the server */
#define OFLAG_RESTART	0x00000004  /* Oper can /restart the server */
#define OFLAG_HELPOP	0x00000010  /* Oper can send /HelpOps */
#define OFLAG_GLOBOP	0x00000020  /* Oper can send /GlobOps */
#define OFLAG_WALLOP	0x00000040  /* Oper can send /WallOps */
#define OFLAG_LOCOP	0x00000080  /* Oper can send /LocOps */
#define OFLAG_LROUTE	0x00000100  /* Oper can do local routing */
#define OFLAG_GROUTE	0x00000200  /* Oper can do global routing */
#define OFLAG_LKILL	0x00000400  /* Oper can do local kills */
#define OFLAG_GKILL	0x00000800  /* Oper can do global kills */
#define OFLAG_KLINE	0x00001000  /* Oper can /kline users */
#define OFLAG_UNKLINE	0x00002000  /* Oper can /unkline users */
#define OFLAG_LNOTICE	0x00004000  /* Oper can send local serv notices */
#define OFLAG_GNOTICE	0x00008000  /* Oper can send global notices */
#define OFLAG_ADMIN	0x00010000  /* Admin */
#define OFLAG_UMODEc	0x00020000  /* Oper can set umode +c : client connect */
#define OFLAG_UMODEf	0x00040000  /* Oper can set umode +f : flood notices */
#define OFLAG_SADMIN    0x00080000  /* Oper can be a services admin */
#define OFLAG_ZLINE	0x00100000  /* Oper can use /zline and /unzline */
#define OFLAG_UMODEy    0x00200000  /* Oper can set umode +y : spy */
#define OFLAG_UMODEd    0x00400000  /* Oper can set umode +d : debug */
#define OFLAG_UMODEb    0x00800000  /* Oper can set umode +b : chatops */
#define OFLAG_UMODEF	0x01000000  /* Oper can set umode +F : no flood throttling */
#define OFLAG_LSHOWIP	0x02000000  /* Oper can see IP address of local users */
#define OFLAG_GSHOWIP	0x04000000  /* Oper can see IP address of global users */
#define OFLAG_SPAM	0x08000000  /* Oper can see spam notices and /stats S */

#define OFLAG_LOCAL	(OFLAG_REHASH|OFLAG_HELPOP|OFLAG_GLOBOP|OFLAG_WALLOP|\
                         OFLAG_LOCOP|OFLAG_LROUTE|OFLAG_LKILL|OFLAG_KLINE|\
                         OFLAG_UNKLINE|OFLAG_LNOTICE|OFLAG_UMODEc|OFLAG_UMODEf|OFLAG_UMODEd|\
			 OFLAG_UMODEb|OFLAG_UMODEy)
#define OFLAG_GLOBAL	(OFLAG_LOCAL|OFLAG_GROUTE|OFLAG_GKILL|OFLAG_GNOTICE)
#define OFLAG_ISGLOBAL	(OFLAG_GROUTE|OFLAG_GKILL|OFLAG_GNOTICE)


#define OPCanZline(x)	        ((x)->oflag & OFLAG_ZLINE)
#define OPCanRehash(x)	        ((x)->oflag & OFLAG_REHASH)
#define OPCanDie(x)	        ((x)->oflag & OFLAG_DIE)
#define OPCanRestart(x)	        ((x)->oflag & OFLAG_RESTART)
#define OPCanHelpOp(x)	        ((x)->oflag & OFLAG_HELPOP)
#define OPCanGlobOps(x)	        ((x)->oflag & OFLAG_GLOBOP)
#define OPCanWallOps(x)	        ((x)->oflag & OFLAG_WALLOP)
#define OPCanLocOps(x)	        ((x)->oflag & OFLAG_LOCOP)
#define OPCanLRoute(x)	        ((x)->oflag & OFLAG_LROUTE)
#define OPCanGRoute(x)	        ((x)->oflag & OFLAG_GROUTE)
#define OPCanLKill(x)	        ((x)->oflag & OFLAG_LKILL)
#define OPCanGKill(x)	        ((x)->oflag & OFLAG_GKILL)
#define OPCanKline(x)	        ((x)->oflag & OFLAG_KLINE)
#define OPCanUnKline(x)	        ((x)->oflag & OFLAG_UNKLINE)
#define OPCanLNotice(x)	        ((x)->oflag & OFLAG_LNOTICE)
#define OPCanGNotice(x)	        ((x)->oflag & OFLAG_GNOTICE)
#define OPIsAdmin(x)	        ((x)->oflag & OFLAG_ADMIN)
#define OPIsSAdmin(x)	        ((x)->oflag & OFLAG_SADMIN)
#define OPCanUModec(x)	        ((x)->oflag & OFLAG_UMODEc)
#define OPCanUModef(x)	        ((x)->oflag & OFLAG_UMODEf)
#define OPCanUModey(x)          ((x)->oflag & OFLAG_UMODEy)     
#define OPCanUModed(x)          ((x)->oflag & OFLAG_UMODEd)     
#define OPCanUModeb(x)          ((x)->oflag & OFLAG_UMODEb)
#define OPCanLShowIP(x)		((x)->oflag & OFLAG_LSHOWIP)
#define OPCanGShowIP(x)		((x)->oflag & OFLAG_GSHOWIP)
#define OPCanSpam(x)		((x)->oflag & OFLAG_SPAM)
#define OPClearRehash(x)	((x)->oflag &= ~OFLAG_REHASH)
#define OPClearDie(x)		((x)->oflag &= ~OFLAG_DIE)  
#define OPClearRestart(x)	((x)->oflag &= ~OFLAG_RESTART)
#define OPClearHelpOp(x)	((x)->oflag &= ~OFLAG_HELPOP)
#define OPClearGlobOps(x)	((x)->oflag &= ~OFLAG_GLOBOP)
#define OPClearWallOps(x)	((x)->oflag &= ~OFLAG_WALLOP)
#define OPClearLocOps(x)	((x)->oflag &= ~OFLAG_LOCOP)
#define OPClearLRoute(x)	((x)->oflag &= ~OFLAG_LROUTE)
#define OPClearGRoute(x)	((x)->oflag &= ~OFLAG_GROUTE)
#define OPClearLKill(x)		((x)->oflag &= ~OFLAG_LKILL)
#define OPClearGKill(x)		((x)->oflag &= ~OFLAG_GKILL)
#define OPClearKline(x)		((x)->oflag &= ~OFLAG_KLINE)
#define OPClearUnKline(x)	((x)->oflag &= ~OFLAG_UNKLINE)
#define OPClearLNotice(x)	((x)->oflag &= ~OFLAG_LNOTICE)
#define OPClearGNotice(x)	((x)->oflag &= ~OFLAG_GNOTICE)
#define OPClearAdmin(x)		((x)->oflag &= ~OFLAG_ADMIN)
#define OPClearSAdmin(x)	((x)->oflag &= ~OFLAG_SADMIN)
#define OPClearUModec(x)	((x)->oflag &= ~OFLAG_UMODEc)
#define OPClearUModef(x)	((x)->oflag &= ~OFLAG_UMODEf)
#define OPClearUModey(x)	((x)->oflag &= ~OFLAG_UMODEy) 
#define OPClearUModed(x)	((x)->oflag &= ~OFLAG_UMODEd) 
#define OPClearUModeb(x)	((x)->oflag &= ~OFLAG_UMODEb)
#define OPClearZLine(x)		((x)->oflag &= ~OFLAG_ZLINE)
#define OPClearUModeF(x)	((x)->oflag &= ~OFLAG_UMODEF)
#define OPClearLShowIP(x)	((x)->oflag &= ~OFLAG_LSHOWIP)
#define OPClearGShowIP(x)	((x)->oflag &= ~OFLAG_GSHOWIP)
#define OPClearSpam(x)		((x)->oflag &= ~OFLAG_SPAM)

/* defined debugging levels */
#define	DEBUG_FATAL  0
#define	DEBUG_ERROR  1 /* report_error() and other errors that are found */
#define	DEBUG_NOTICE 3
#define	DEBUG_DNS    4 /* used by all DNS related routines - a *lot* */
#define	DEBUG_INFO   5 /* general usful info */
#define	DEBUG_NUM    6 /* numerics */
#define	DEBUG_SEND   7 /* everything that is sent out */
#define	DEBUG_DEBUG  8 /* anything to do with debugging, ie unimportant :) */
#define	DEBUG_MALLOC 9 /* malloc/free calls */
#define	DEBUG_LIST  10 /* debug list use */
/* defines for curses in client */
#define	DUMMY_TERM	0
#define	CURSES_TERM	1
#define	TERMCAP_TERM	2

/*
 *  IPv4 or IPv6 structures?
 */

char mydummy[64];
char mydummy2[64];

#ifdef INET6

# define WHOSTENTP(x) ((x)[0]|(x)[1]|(x)[2]|(x)[3]|(x)[4]|(x)[5]|(x)[6]|(x)[7]|(x)[8]|(x)[9]|(x)[10]|(x)[11]|(x)[12]|(x)[13]|(x)[14]|(x)[15])

# define	AFINET		AF_INET6
# define	SOCKADDR_IN	sockaddr_in6
# define	SOCKADDR	sockaddr
# define	SIN_FAMILY	sin6_family
# define	SIN_PORT	sin6_port
# define	SIN_ADDR	sin6_addr
# define	S_ADDR		s6_addr
# define	IN_ADDR		in6_addr
# define	INADDRANY_STR "0::0"

# if defined(linux) || defined(__NetBSD__) || defined(__FreeBSD__) || defined(bsdi)
#  ifndef s6_laddr
#   define s6_laddr        s6_addr32
#  endif
# endif

#else
# define	AFINET		AF_INET
# define	SOCKADDR_IN	sockaddr_in
# define	SOCKADDR	sockaddr
# define	SIN_FAMILY	sin_family
# define	SIN_PORT	sin_port
# define	SIN_ADDR	sin_addr
# define	S_ADDR		s_addr
# define	IN_ADDR		in_addr
# define	INADDRANY_STR "0.0.0.0"

# define WHOSTENTP(x) (x)
#endif

struct Counter 
{
    int         server;      /* servers */
    int         myserver;    /* my servers */
    int         myulined;    /* my ulined servers */
    int         oper;        /* Opers */
    int         chan;        /* Channels */
    int         local;       /* Local Clients */
    int         total;       /* total clients */
    int         invisi;      /* invisible clients */
    int         unknown;     /* unknown connections */
    int         max_loc;     /* MAX local clients */
    int         max_tot;     /* MAX global clients */
    ts_val      start;       /* when we started collecting info */
    u_long      today;	     /* Client Connections today */
    ts_val      day;	     /* when today started */
    u_long	weekly;	     /* connections this week */
    ts_val	week;	     /* when this week started */
    u_long	monthly;     /* connections this month */
    ts_val	month;	     /* when this month started */
    u_long	yearly;	     /* this is gonna be big */
    ts_val	year;	     /* when this year started (HEH!) */
};

struct MotdItem 
{
    char        line[MOTDLINELEN];
    struct MotdItem *next;
};

/* lets speed this up... also removed away information. *tough* Dianora */
typedef struct Whowas 
{
    int         hashv;
    char        name[NICKLEN + 1];
    char        username[USERLEN + 1];
    char        hostname[HOSTLEN + 1];
    char	virthost[HOSTLEN + 1];
    char       *servername;
    char        realname[REALLEN + 1];
    time_t      logoff;
    struct Client *online;  /* Pointer to new nickname for chasing or NULL */
    
    struct Whowas *next;    /* for hash table... */
    
    struct Whowas *prev;    /* for hash table... */
    struct Whowas *cnext;   /* for client struct linked list */
    struct Whowas *cprev;   /* for client struct linked list */
} aWhowas;

struct ConfItem 
{
    unsigned int status;   /* If CONF_ILLEGAL, delete when no clients */
    unsigned int flags;    /* i-lines and akills use this */
    int         clients;   /* Number of *LOCAL* clients using this */
    struct IN_ADDR ipnum;  /* ip number of host field */
    char       *host;
    char       *localhost;
    char       *passwd;
    char       *name;
    int         port;
    time_t      hold;      /* Hold action until this time (calendar time) */
    aClass     *class;     /* Class of connection */
    struct ConfItem *next;
};

#define SPAM_BLOCK_NOMESSAGE	0 /* Block spam without messages */
#define SPAM_BLOCK_NOTICE	1 /* Block spam with spam notice */
#define SPAM_BLOCK_SECURITY	2 /* Block spam and notify security channel */
#define SPAM_BLOCK_NOTICE_SECURITY 3 /* Block spam with spam notice and
				      * notify security channel */
#define SPAM_NOBLOCK_SECURITY	4 /* Notify security channel about spam */
#define SPAM_AUTOSHUN		5 /* Block spam autoshunning user, sends
				   * a spam notice and notify security channel */
#define SPAM_DEFAULT		SPAM_BLOCK_NOTICE_SECURITY /* default policy */

struct spam_
{
    /* take care about padding here..*/
    Spam *next;
    char *msg;
    char *reason;
    int count;
    int type;
		int daycount, weekcount, monthcount;
		time_t creationtime;
};

#define	CONF_ILLEGAL	        0x80000000
#define	CONF_MATCH	        0x40000000

#define	CONF_CLIENT	        0x0002
#define	CONF_CONNECT_SERVER	0x0004
#define	CONF_NOCONNECT_SERVER	0x0008
#define	CONF_LOCOP		0x0010
#define	CONF_OPERATOR		0x0020
#define	CONF_ME			0x0040
#define	CONF_KILL		0x0080
#define	CONF_ADMIN		0x0100
#define	CONF_CLASS		0x0200
#define	CONF_SERVICE		0x0400
#define	CONF_LISTEN_PORT	0x1000
#define	CONF_HUB		0x2000
#define CONF_ELINE		0x4000
#define CONF_FLINE		0x8000
#ifdef WEBIRC
#define CONF_WEBIRC             0x10000
#endif
#define	CONF_ZLINE		0x20000
#define CONF_QUARANTINED_NICK 	0x40000
#define CONF_ULINE 		0x80000
#define CONF_DRPASS		0x100000    /* die/restart pass, from df465 */
#define CONF_AKILL		0x200000
#define CONF_SQLINE     	0x400000
#define CONF_MONINFO		0x800000    /* proxy monitor info */
#define CONF_GCOS               0x1000000
#define CONF_SGLINE             0x2000000
#define CONF_SZLINE             0x4000000   /* Services placed zlines */
#define CONF_QUARANTINED_CHAN	0x8000000
#define CONF_HELPER		0x10000000
#define CONF_SPAM		0x20000000
#define CONF_QUARANTINE         (CONF_QUARANTINED_NICK|CONF_QUARANTINED_CHAN)
#define	CONF_OPS		(CONF_OPERATOR | CONF_LOCOP)
#define	CONF_SERVER_MASK	(CONF_CONNECT_SERVER | CONF_NOCONNECT_SERVER)
#define	CONF_CLIENT_MASK	(CONF_CLIENT | CONF_SERVICE | CONF_OPS | \
				 CONF_SERVER_MASK)
#define	IsIllegal(x)	        ((x)->status & CONF_ILLEGAL)

/* did the password field specify OPER? */
#define CONF_FLAGS_I_OPERPORT      0x0002
/* does NAME in I:HOST::NAME have an @? */ 
#define CONF_FLAGS_I_NAME_HAS_AT   0x0004 
/* does HOST in I:HOST::NAME have an @? */ 
#define CONF_FLAGS_I_HOST_HAS_AT   0x0008 
/* did the password field specify HELPER? */
#define CONF_FLAGS_I_HELPERPORT	   0x0010
/* did the password field specify FASTWEB? */
#define CONF_FLAGS_I_FASTWEBPORT   0x0020
/* did the i-line specify a restricted connection? */
#define CONF_FLAGS_I_RESTRICTED    0x0040

/* Client structures */
struct User
{
    Link       *channel;       /* chain of channel pointer blocks */
    Link       *invited;       /* chain of invite pointer blocks */
    char       *away;          /* pointer to away message */
    time_t      last;
    int         joined;        /* number of channels joined */
    char        username[USERLEN + 1];
    char        host[HOSTLEN + 1];
    char	virthost[HOSTLEN + 1];
    char       *server;        /* pointer to scached server name */
#ifdef OS_SOLARIS
    uint_t    servicestamp;    /* solaris is gay -epi */
#else
    u_int32_t servicestamp;    /* Services id - Raistlin */
#endif
    /*
     * In a perfect world the 'server' name should not be needed, a
     * pointer to the client describing the server is enough. 
     * Unfortunately, in reality, server may not yet be in links while
     * USER is introduced... --msa
     */
    Link       *silence;      /* chain of silenced users */
    LOpts 	   *lopt;     /* Saved /list options */
    Link       *dccallow;     /* chain of dcc send allowed users */
#if (RIDICULOUS_PARANOIA_LEVEL>=1)
    char       *real_oper_host;
    char       *real_oper_username;
    char       *real_oper_ip;
    char       *real_helper_host;
    char       *real_helper_username;
    char       *real_helper_ip;
#endif
    time_t       svsnick_time;
};

struct Server
{
    char       *up;		  /* Pointer to scache name */
    char        bynick[NICKLEN + 1];
    char        byuser[USERLEN + 1];
    char        byhost[HOSTLEN + 1];
    aConfItem  *nline;		  /* N-line pointer for this server */
    int         dkey_flags; 	  /* dkey flags */
#ifdef HAVE_ENCRYPTION_ON
    void       *sessioninfo_in;   /* pointer to opaque sessioninfo structure */
    void       *sessioninfo_out;  /* pointer to opaque sessioninfo structure */
    void       *rc4_in;           /* etc */
    void       *rc4_out;          /* etc */
#endif
    void       *zip_out;
    void       *zip_in;
};

struct Client 
{
    struct Client *next, *prev, *hnext;
    anUser     *user;       /* ...defined, if this is a User */
    aServer    *serv;       /* ...defined, if this is a server */
    aWhowas    *whowas;     /* Pointers to whowas structs */
    time_t      lasttime;   /* ...should be only LOCAL clients? --msa */
    time_t      firsttime;  /* time client was created */
    time_t      since;      /* last time we parsed something */
    ts_val      tsinfo;     /* TS on the nick, SVINFO on servers */
    long        flags;      /* client flags */
    long	flags2;     /* sorry, 32bit are simply not enough. */
    long        umode;      /* We can illeviate overflow this way */
    aClient    *from;       /* == self, if Local Client, *NEVER* NULL! */
    aClient    *uplink;     /* this client's uplink to the network */
    int         fd;         /* >= 0, for local clients */
    int         hopcount;   /* number of servers to this 0 = local */
    short       status;     /* Client type */
    char        nicksent;
    char        name[HOSTLEN + 1];  /* Unique name of the client, nick or
				     * host */
    char        info[REALLEN + 1];  /* Free form additional client 
				     * information */
#ifdef FLUD
    Link       *fludees;
#endif
    
    struct IN_ADDR ip;      /* keep real ip# too */
    char        hostip[HOSTIPLEN + 1]; /* Keep real ip as string 
					* too - Dianora */
    
    Link *watch; /* user's watch list */
    int watches; /* how many watches this user has set */

    unsigned long pasvdccid;	/* ID used to remember passive dcc sends -INT */
        
/*
####### #     # ### #     #  #####   #####
   #    #     #  #  ##    # #     # #     #
   #    #     #  #  # #   # #       #
   #    #######  #  #  #  # #  ####  #####
   #    #     #  #  #   # # #     #       #
   #    #     #  #  #    ## #     # #     #
   #    #     # ### #     #  #####   #####

######  ####### #       ####### #     #
#     # #       #       #     # #  #  #
#     # #       #       #     # #  #  #
######  #####   #       #     # #  #  #
#     # #       #       #     # #  #  #
#     # #       #       #     # #  #  #
######  ####### ####### #######  ## ##

 #####  ####### #     # #     # #######
#     # #     # #     # ##    #    #
#       #     # #     # # #   #    #
#       #     # #     # #  #  #    #
#       #     # #     # #   # #    #
#     # #     # #     # #    ##    #
 #####  #######  #####  #     #    #

   #    ######  #######    #       #######  #####     #    #
  # #   #     # #          #       #     # #     #   # #   #
 #   #  #     # #          #       #     # #        #   #  #
#     # ######  #####      #       #     # #       #     # #
####### #   #   #          #       #     # #       ####### #
#     # #    #  #          #       #     # #     # #     # #
#     # #     # #######    ####### #######  #####  #     # #######

####### #     # #       #     # ### ### ###
#     # ##    # #        #   #  ### ### ###
#     # # #   # #         # #   ### ### ###
#     # #  #  # #          #     #   #   #
#     # #   # # #          #
#     # #    ## #          #    ### ### ###
####### #     # #######    #    ### ### ###

*/

#ifdef USE_SSL /*AZZURRA*/
    SSL *ssl;
    X509 *client_cert;
#endif /*SSL*/

    /*
     * The following fields are allocated only for local clients 
     * (directly connected to this server with a socket.  The first
     * of them MUST be the "count"--it is the field to which the
     * allocation is tied to! Never refer to  these fields, if (from != self).
     */
    
    int         count;		/* Amount of data in buffer */
#ifdef FLUD
    time_t      fludblock;
    struct fludbot *fluders;
#endif
#ifdef ANTI_SPAMBOT
    time_t      last_join_time;	 /* when this client last joined a channel */
    time_t      last_leave_time; /* when this client last left a channel */
    int         join_leave_count;	/* count of JOIN/LEAVE in less 
					 * than MIN_JOIN_LEAVE_TIME seconds */
    int         oper_warn_count_down;	/* warn opers of this possible spambot 
					 * every time this gets to 0 */
#endif
    char        buffer[BUFSIZE];        /* Incoming message buffer */
    short       lastsq;	         /* # of 2k blocks when sendqueued called 
				  * last */
    struct DBuf        sendQ;	 /* Outgoing message queue--if socket full */
    struct DBuf        recvQ;	 /* Hold for data incoming yet to be parsed */
    long        sendM;		 /* Statistics: protocol messages send */
    long        sendK;		 /* Statistics: total k-bytes send */
    long        receiveM;	 /* Statistics: protocol messages received */
    long        receiveK;	 /* Statistics: total k-bytes received */
    u_short     sendB;		 /* counters to count upto 1-k lots of bytes */
    u_short     receiveB;	 /* sent and received. */
    long        lastrecvM;       /* to check for activity --Mika */
    int         priority;
    aClient    *acpt;	         /* listening client which we accepted from */
    Link       *confs;		 /* Configuration record associated */
    int         authfd;	         /* fd for rfc931 authentication */
    char        username[USERLEN + 1]; /* username here now for auth stuff */
    unsigned short port;	 /* and the remote port# too :-) */
    unsigned short lport;        /* add local port as well (saves us quite a few lookups) */
    struct hostent *hostp;
#ifdef ANTI_NICK_FLOOD
    time_t      last_nick_change;
    int         number_of_nick_changes;
#endif
#ifdef ANTI_INVITE_FLOOD // AZZURRA
    time_t	last_invite_time;
    int		last_invite_sum; /* Checksum (user/channel) of last invite */
    int		number_of_invites;
#endif
#ifdef NO_AWAY_FLUD
    time_t	    alas;	/* last time of away set */
    int	    acount;	        /* count of away settings */
#endif
    
    char        sockhost[HOSTLEN + 1];	/* This is the host name from
					 * the socket and after which the 
					 * connection was accepted. */
    char        passwd[PASSWDLEN + 1];
    /* try moving this down here to prevent weird problems... ? */
    int         oflag;          /* Operator Flags */
    int sockerr;                /* what was the last error returned for
				 * this socket? */
    int capabilities;           /* what this server/client supports */
    int pingval;	        /* cache client class ping value here */
    int sendqlen;	        /* cache client max sendq here */

#ifdef MSG_TARGET_LIMIT
    struct {
       struct Client *cli;
       time_t sent;
    } targets[MSG_TARGET_MAX];              /* structure for target rate limiting */
    time_t last_target_complain;
    unsigned int num_target_errors;
#endif

#ifdef WEBIRC
    char         webirc_host[HOSTLEN + 1];  /* hostname set via WEBIRC */
    char         webirc_ip[HOSTIPLEN + 1];  /* IP address set via WEBIRC */
#endif

#ifdef INET6
    char        tunnel_host[HOSTIPLEN + 1]; /* IPv4 endpoint of a 6to4/Teredo tunnel (if any) */
#endif

};

#define	CLIENT_LOCAL_SIZE sizeof(aClient)
#define	CLIENT_REMOTE_SIZE offsetof(aClient,count)
/* statistics structures */
struct stats
{
    unsigned int is_cl;     /* number of client connections */
    unsigned int is_sv;     /* number of server connections */
    unsigned int is_ni;     /* connection but no idea who it was */
    unsigned short is_cbs;  /* bytes sent to clients */
    unsigned short is_cbr;  /* bytes received to clients */
    unsigned short is_sbs;  /* bytes sent to servers */
    unsigned short is_sbr;  /* bytes received to servers */
    unsigned long is_cks;   /* k-bytes sent to clients */
    unsigned long is_ckr;   /* k-bytes received to clients */
    unsigned long is_sks;   /* k-bytes sent to servers */
    unsigned long is_skr;   /* k-bytes received to servers */
    time_t      is_cti;     /* time spent connected by clients */
    time_t      is_sti;     /* time spent connected by servers */
    unsigned int is_ac;     /* connections accepted */
    unsigned int is_ref;    /* accepts refused */
    unsigned int is_unco;   /* unknown commands */
    unsigned int is_wrdi;   /* command going in wrong direction */
    unsigned int is_unpf;   /* unknown prefix */
    unsigned int is_empt;   /* empty message */
    unsigned int is_num;    /* numeric message */
    unsigned int is_kill;   /* number of kills generated on collisions */
    unsigned int is_fake;   /* MODE 'fakes' */
    unsigned int is_asuc;   /* successful auth requests */
    unsigned int is_abad;   /* bad auth requests */
    unsigned int is_udp;    /* packets recv'd on udp port */
    unsigned int is_loc;    /* local connections made */
#ifdef FLUD
    unsigned int is_flud;   /* users/channels flood protected */
#endif	                    /* FLUD */
};

/* mode structure for channels */

struct SMode 
{
    unsigned int mode;
    int         limit;
    char        key[KEYLEN + 1];
};

/* Message table structure */

struct Message 
{
    char       *cmd;
    int         (*func) ();
    unsigned int count;	 /* number of times command used */
    int         parameters;
    char        flags;
    
    /* bit 0 set means that this command is allowed to be used only on
     * the average of once per 2 seconds -SRB */
    
    /* I could have defined other bit maps to above instead of the next
     * two flags that I added. so sue me. -Dianora */
    
    char        allow_unregistered_use;	/* flag if this command can be used 
					 * if unregistered */
    
    char        reset_idle;	/* flag if this command causes idle time to be 
				 * reset */
    unsigned long bytes;
};

typedef struct msg_tree 
{
    char       *final;
    struct Message *msg;
    struct msg_tree *pointers[26];
} MESSAGE_TREE;

/*
 * Move BAN_INFO information out of the SLink struct its _only_ used
 * for bans, no use wasting the memory for it in any other type of
 * link. Keep in mind, doing this that it makes it slower as more
 * Malloc's/Free's have to be done, on the plus side bans are a smaller
 * percentage of SLink usage. Over all, the th+hybrid coding team came
 * to the conclusion it was worth the effort.
 * 
 * - Dianora
 */

struct Ban 
{
    char       *banstr;
    char       *who;
    time_t      when;
    u_char	    type;
    aBan 	   *next;
};

/* channel member link structure, used for chanmember chains */
struct ChanLink 
{
    struct ChanLink *next;
    aClient *cptr;
    int flags;
    int bans;	/* for bquiet: number of bans against this user */
};

/* general link structure used for chains */

struct SLink 
{
    struct SLink *next;
    union
    {
	aClient    *cptr;
	aChannel   *chptr;
	aConfItem  *aconf;
	aBan       *banptr;
	aWatch *wptr;
	char       *cp;
    } value;
    int         flags;
};

/* channel structure */

struct Channel 
{
    struct Channel *nextch, *prevch, *hnextch;
    int         hashv;		/* raw hash value */
    Mode        mode;
    char        topic[TOPICLEN + 1];
    char        topic_nick[NICKLEN + 1];
    time_t      topic_time;
    int         users;
    chanMember       *members;
    Link       *invites;
    aBan       *banlist;
    aBan	*restrictlist;
    ts_val      channelts;
#ifdef FLUD
    time_t      fludblock;
    struct fludbot *fluders;
#endif
    char        chname[CHANNELLEN+1];
};

#define	TS_CURRENT	5	/* current TS protocol version */
#define	TS_MIN		3  	/* minimum supported TS protocol version */
#define	TS_DOESTS	0x20000000
#define	DoesTS(x)	((x)->tsinfo == TS_DOESTS)
/* Channel Related macros follow */

/* Channel related flags */

#define	CHFL_CHANOP     0x0001	/* Channel operator */
#define	CHFL_VOICE      0x0002	/* the power to speak */
#define	CHFL_DEOPPED 	0x0004	/* deopped by us, modes need to be bounced */
#define	CHFL_BAN	0x0008	/* ban channel flag */
#define CHFL_HALFOP	0x0010	/* Channel half operator */

/* ban mask types */

#define MTYP_FULL      0x01    /* mask is nick!user@host */
#define MTYP_USERHOST  0x02    /* mask is user@host */
#define MTYP_HOST      0x04    /* mask is host only */

/* Channel Visibility macros */

#define	MODE_CHANOP	CHFL_CHANOP
#define MODE_HALFOP	CHFL_HALFOP
#define	MODE_VOICE	CHFL_VOICE
#define	MODE_DEOPPED  	CHFL_DEOPPED
#define	MODE_PRIVATE  	0x00008
#define	MODE_SECRET   	0x00010
#define	MODE_MODERATED  0x00020
#define	MODE_TOPICLIMIT 0x00040
#define	MODE_INVITEONLY 0x00080
#define	MODE_NOPRIVMSGS 0x00100
#define	MODE_KEY	0x00200
#define	MODE_BAN	0x00400
#define	MODE_LIMIT	0x00800
#define MODE_REGISTERED	0x01000
#define MODE_REGONLY	0x02000
#define MODE_NOCOLOR	0x04000
#define MODE_OPERONLY   0x08000
#define MODE_MODREG     0x10000
#define MODE_LISTED	0x20000
#define MODE_NONICKCHG	0x40000
#define MODE_NOSPAM	0x80000
#define MODE_NOCTCP	0x100000
#define MODE_SSLONLY	0x200000
#define MODE_NOUNKNOWN	0x400000 /* cmode +j, allow only registered users to join */
#define MODE_UNRESTRICT	0x800000 /* cmode +U, allow restricted users to join */
#define MODE_RESTRICT	0x1000000 /*cmode +z, disallow a matching client to join without a registered nick*/
#define MODE_HIDEBANS	0x2000000 /*Comde +B, hide bans to normal users*/

/* mode flags which take another parameter (With PARAmeterS) */

#define	MODE_WPARAS	(MODE_CHANOP|MODE_HALFOP|MODE_VOICE|MODE_BAN|MODE_KEY|MODE_LIMIT|MODE_RESTRICT)

/*
 * Undefined here, these are used in conjunction with the above modes
 * in the source. #define       MODE_DEL       0x40000000 #define
 * MODE_ADD       0x80000000
 */

#define	HoldChannel(x)		(!(x))

/*name invisible */

#define	SecretChannel(x)	((x) && ((x)->mode.mode & MODE_SECRET))

/* channel not shown but names are */

#define	HiddenChannel(x)	((x) && ((x)->mode.mode & MODE_PRIVATE))

/* channel visible */

#define	ShowChannel(v,c)	(PubChannel(c) || IsMember((v),(c)))
#define	PubChannel(x)		((!x) || ((x)->mode.mode &\
                                 (MODE_PRIVATE | MODE_SECRET)) == 0)

#define IsMember(blah,chan) ((blah && blah->user && \
		find_channel_link((blah->user)->channel, chan)) ? 1 : 0)

#define	IsChannelName(name) ((name) && (*(name) == '#' || *(name) == '&'))

/* Misc macros */

#define	BadPtr(x) (!(x) || (*(x) == '\0'))

#define	isvalid(c) (((c) >= 'A' && (c) < '~') || isdigit(c) || (c) == '-')

#define	MyConnect(x)			((x)->fd >= 0)
#define	MyClient(x)			(MyConnect(x) && IsClient(x))
#define	MyOper(x)			(MyConnect(x) && IsOper(x))

/* Check if user x can override UMODE_x for user y */
#define CanOverrideUmodex(x,y)	(IsAdmin(x) || IsSAdmin(x) || \
				 (IsAnOper(x) && (OPCanGShowIP(x) || \
				  (OPCanLShowIP(x) && MyClient(y)))))

/* This macro checks if x can see the IP of y -INT */
#define CanShowIP(x,y)		(!IsUmodex(y) || CanOverrideUmodex(x,y))

/* Ditto, but override UMODE_x if and only if z is non-zero (used in m_who.c) */
#define CanShowIPCond(x,y,z)	(!IsUmodex(y) || ((z) && CanOverrideUmodex(x,y)))

/* String manipulation macros */

/* strncopynt --> strncpyzt to avoid confusion, sematics changed N must
 * be now the number of bytes in the array --msa */

#define	strncpyzt(x, y, N) do{(void)strncpy(x,y,N);x[N-1]='\0';}while(0)
#define	StrEq(x,y)	(!strcmp((x),(y)))

/* used in SetMode() in channel.c and m_umode() in s_msg.c */

#define	MODE_NULL      0
#define	MODE_ADD       0x40000000
#define	MODE_DEL       0x20000000

/* defines for message destinations. Used in m_message() in s_user.c
 * and in sendto_channelflag_butone() in send.c */
#define TO_NICK           0x0001
#define TO_CHAN           0x0002
#define TO_OPS            0x0004
#define TO_VOICE          0x0008
#define TO_HALFOP	  0x0010

/* return values for hunt_server() */

#define	HUNTED_NOSUCH	(-1)	/* if the hunted server is not found */
#define	HUNTED_ISME	0	/* if this server should execute the command */
#define	HUNTED_PASS	1	/* if message passed onwards successfully */

/* used when sending to #mask or $mask */

#define	MATCH_SERVER  1
#define	MATCH_HOST    2

/* used for async dns values */

#define	ASYNC_NONE	(-1)
#define	ASYNC_CLIENT	0
#define	ASYNC_CONNECT	1
#define	ASYNC_CONF	2
#define	ASYNC_SERVER	3

/* misc variable externs */

extern char version[128], *infotext[];
extern char *generation, *creation;

/* misc defines */

#define ZIP_NEXT_BUFFER -4
#define RC4_NEXT_BUFFER -3
#define	FLUSH_BUFFER	-2
#define	UTMP		"/etc/utmp"
#define	COMMA		","

#ifdef ORATIMING
/*
 * Timing stuff (for performance measurements): compile with
 * -DORATIMING and put a TMRESET where you want the counter of time
 * spent set to 0, a TMPRINT where you want the accumulated results,
 * and TMYES/TMNO pairs around the parts you want timed -orabidoo
 */

extern struct timeval tsdnow, tsdthen;
extern unsigned long tsdms;

#define TMRESET tsdms=0;
#define TMYES gettimeofday(&tsdthen, NULL);
#define TMNO gettimeofday(&tsdnow, NULL);\
             if (tsdnow.tv_sec!=tsdthen.tv_sec) \
                 tsdms+=1000000*(tsdnow.tv_sec-tsdthen.tv_sec);\
                 tsdms+=tsdnow.tv_usec; tsdms-=tsdthen.tv_usec;
#define TMPRINT sendto_ops("Time spent: %ld ms", tsdms);
#else
#define TMRESET
#define TMYES
#define TMNO
#define TMPRINT
#endif

/* allow 5 minutes after server rejoins the network before allowing
 * chanops new channel */

#ifdef NO_CHANOPS_WHEN_SPLIT
#define MAX_SERVER_SPLIT_RECOVERY_TIME 5
#endif

#ifdef FLUD
struct fludbot 
{
    struct Client *fluder;
    int         count;
    time_t      first_msg, last_msg;
    struct fludbot *next;
};

#endif /* FLUD */

struct Watch 
{
    aWatch  *hnext;
    time_t   lasttime;
    Link  *watch;
    char  nick[1];
};

struct ListOptions 
{
    LOpts *next;
    Link  *yeslist, *nolist;
    int   starthash;
    short int   showall;
    unsigned short usermin;
    int   usermax;
};

typedef struct SearchOptions 
{
    int umodes;
    char *nick;
    char *user;
    char *host;
    char *gcos;
    char *ip;
    int class;
    int class_value;
    int ts;
    int ts_value;
    aChannel *channel;
    aClient *server;
    unsigned int channelflags;
    char umode_plus:1;
    char nick_plus:1;
    char user_plus:1;
    char host_plus:1;
    char gcos_plus:1;
    char ip_plus:1;
    char chan_plus:1;
    char serv_plus:1;
    char away_plus:1;
    char check_away:1;
    char check_umode:1;
    char show_chan:1;
    char search_chan:1;
    char spare:3; /* spare space for more stuff(?) */
    char* away_msg;
    char away_msg_plus:1;
    char check_nochan:1;
    char show_realhost:1;
    int maxhits;
} SOpts;

#define IsSendable(x)      (DBufLength(&x->sendQ) < 16384)
#define DoList(x)          (((x)->user) && ((x)->user->lopt))

/* internal defines for cptr->sockerr */
#define IRCERR_BUFALLOC	   -11
#define IRCERR_ZIP	   -12
#define IRCERR_SSL         -13

#define LANG_IT		1
#define LANG_EN		0

#endif /* __struct_include__ */
