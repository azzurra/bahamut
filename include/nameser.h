/*
 * Copyright (c) 1983, 1989 Regents of the University of California.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its
 * contributors'' in the documentation or other materials provided with
 * the distribution and in all advertising materials mentioning
 * features or use of this software. Neither the name of the University
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission. THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE.
 * 
 * @(#)nameser.h        5.24 (Berkeley) 6/1/90
 */

/* $Id$ */

/* Define constants based on rfc883 */

#define PACKETSZ	512	/* maximum packet size */
#define MAXDNAME	256	/* maximum domain name */
#define MAXCDNAME	255	/* maximum compressed domain name */
#define MAXLABEL	63	/* maximum length of domain label */

#define QFIXEDSZ	4 	/* Number of bytes of fixed size 
				 * data in query structure */
#define RRFIXEDSZ	10 	/* number of bytes of fixed size data
				 * in resource record */
#define NAMESERVER_PORT	53 	/* Internet nameserver port number */

/* Currently defined opcodes */

#define QUERY		0x0	/* standard query */
#define IQUERY		0x1	/* inverse query */
#define STATUS		0x2	/* nameserver status query */

/* non standard */

#define UPDATEA		0x9	/* add resource record */
#define UPDATED		0xa	/* delete a specific resource record */
#define UPDATEDA	0xb	/* delete all nemed resource record */
#define UPDATEM		0xc	/* modify a specific resource record */
#define UPDATEMA	0xd	/* modify all named resource record */
#define ZONEINIT	0xe	/* initial zone transfer */
#define ZONEREF		0xf	/* incremental zone referesh */

/* Currently defined response codes */

#ifdef	NOERROR			/* defined by solaris2 in 
#undef	NOERROR			 * <sys/stream.h> to be -1 */
#endif

#define NOERROR		0	/* no error */
#define FORMERR		1	/* format error */
#define SERVFAIL	2	/* server failure */
#define NXDOMAIN	3	/* non existent domain */
#define NOTIMP		4	/* not implemented */
#define REFUSED		5	/* query refused */

/* non standard  */

#define NOCHANGE	0xf	/* update failed to change db */

/* Type values for resources and queries */

#define T_A		1	/* host address */
#define T_NS		2	/* authoritative server */
#define T_MD		3	/* mail destination */
#define T_MF		4	/* mail forwarder */
#define T_CNAME		5	/* connonical name */
#define T_SOA		6	/* start of authority zone */
#define T_MB		7	/* mailbox domain name */
#define T_MG		8	/* mail group member */
#define T_MR		9	/* mail rename name */
#define T_NULL		10	/* null resource record */
#define T_WKS		11	/* well known service */
#define T_PTR		12	/* domain name pointer */
#define T_HINFO		13	/* host information */
#define T_MINFO		14	/* mailbox information */
#define T_MX		15	/* mail routing information */
#define T_TXT		16	/* text strings */
#define T_AAAA		28	/* IPv6 */

/* non standard */

#define T_UINFO		100	/* user (finger) information */
#define T_UID		101	/* user ID */
#define T_GID		102	/* group ID */
#define T_UNSPEC	103	/* Unspecified format (binary data) */

/* Query type values which do not appear in resource records */

#define T_AXFR		252	/* transfer zone of authority */
#define T_MAILB		253	/* transfer mailbox records */
#define T_MAILA		254	/* transfer mail agent records */
#define T_ANY		255	/* wildcard match */

/* Values for class field */

#define C_IN		1	/* the arpa internet */
#define C_CHAOS		3	/* for chaos net at MIT */
#define C_HS		4	/* for Hesiod name server at MIT */

/* Query class values which do not appear in resource records */

#define C_ANY		255	/* wildcard match */

/* Status return codes for T_UNSPEC conversion routines */

#define CONV_SUCCESS 0
#define CONV_OVERFLOW -1
#define CONV_BADFMT -2
#define CONV_BADCKSUM -3
#define CONV_BADBUFLEN -4

/*
 * Structure for query header, the order of the fields is machine and
 * compiler dependent, in our case, the bits within a byte are assignd
 * least significant first, while the order of transmition is most
 * significant first.  This requires a somewhat confusing
 * rearrangement.
 */

typedef struct
{
    u_short     id;		/* query identification number */
#ifdef WORDS_BIGENDIAN
    
    /* fields in third byte */
    
    u_char      qr:1;		/* response flag */
    u_char      opcode:4;	/* purpose of message */
    u_char      aa:1;		/* authoritive answer */
    u_char      tc:1;		/* truncated message */
    u_char      rd:1;		/* recursion desired */
    
    /* fields in fourth byte */
    
    u_char      ra:1;		/* recursion available */
    u_char      pr:1;		/* primary server required (non standard) */
    u_char      unused:2;	/* unused bits */
    u_char      rcode:4;		/* response code */
    
#else
    
    /* fields in third byte */

    u_char      rd:1;		/* recursion desired */
    u_char      tc:1;		/* truncated message */
    u_char      aa:1;		/* authoritive answer */
    u_char      opcode:4;	/* purpose of message */
    u_char      qr:1;		/* response flag */
    
    /* fields in fourth byte */
    
    u_char      rcode:4;		/* response code */
    u_char      unused:2;	/* unused bits */
    u_char      pr:1;		/* primary server required (non standard) */
    u_char      ra:1;		/* recursion available */
    
#endif

    /* remaining bytes */
    
    u_short     qdcount;		/* number of question entries */
    u_short     ancount;		/* number of answer entries */
    u_short     nscount;		/* number of authority entries */
    u_short     arcount;		/* number of resource entries */
} HEADER;

/* Defines for handling compressed domain names */

#define INDIR_MASK	0xc0

/* Structure for passing resource records around. */

struct rrec 
{
    short       r_zone;		/* zone number */
    short       r_class;		/* class number */
    short       r_type;		/* type number */
#ifdef	__alpha
    u_int       r_ttl;		/* time to live */
#else
    u_long      r_ttl;		/* time to live */
#endif
    int         r_size;		/* size of data area */
    char       *r_data;		/* pointer to data */
};

extern u_short _getshort();

#ifdef __alpha
extern u_int _getlong();
#else
extern u_long _getlong();
#endif

/*
 * Inline versions of get/put short/long. Pointer is advanced; we
 * assume that both arguments are lvalues and will already be in
 * registers. cp MUST be u_char *.
 */

#define GETSHORT(s, cp) { \
	(s) = *(cp)++ << 8; \
	(s) |= *(cp)++; \
}

#define GETLONG(l, cp) { \
	(l) = *(cp)++ << 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; \
}

#define PUTSHORT(s, cp) { \
	*(cp)++ = (s) >> 8; \
	*(cp)++ = (s); \
}

/* Warning: PUTLONG destroys its first argument.*/

#define PUTLONG(l, cp) { \
	(cp)[3] = l; \
	(cp)[2] = (l >>= 8); \
	(cp)[1] = (l >>= 8); \
	(cp)[0] = l >> 8; \
	(cp) += sizeof(u_long); \
}
