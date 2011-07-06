/************************************************************************
 *   Bahamut / Azzurra src/cloak.c
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

#include "struct.h"

#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include "inet.h"
#include <string.h>
#include "h.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sha1.h"

extern char *cloak_key;		/* in ircd.c --vjt */
extern char *cloak_host;
extern size_t cloak_key_len;

typedef enum
{
    HT_IPv4,
    HT_IPv6,
    HT_FQDN,
    HT_INVALID
} host_type_t;

static __inline host_type_t host_type(const char *host, unsigned int *dotCountPtr, unsigned int *colCountPtr);
static __inline void expand_ipv6(const char *host, unsigned int colCount, char *ip6buf);

int
cloak_init(void)
{
    int fd, rv;
    
    DupString(cloak_host, CLOAK_HOST);

    if ((fd = open(CKPATH, O_RDONLY)) != -1)
    {
	struct stat st;
	char *buf;
	
	if(fstat(fd, &st) == 0)
	{
	    /* FIXME: this should be off_t */
	    ssize_t sz = st.st_size;

	    if(sz > MIN_CLOAK_KEY_LEN)
	    {
		if(sz > MAX_CLOAK_KEY_LEN) /* are we NASA ? */
		    sz = MAX_CLOAK_KEY_LEN;

		buf = MyMalloc(sz + 1);
		if ((rv = read(fd, (void *) buf, sz)) != sz)
		{
		    int oerrno = errno;
		    close(fd);
#if defined(USE_SYSLOG)
		    syslog(LOG_ERR, "Error while reading "CKPATH": %s",
			    rv == -1 ? strerror(oerrno) : "short read");
#endif
		    fprintf(stderr, "Error while reading "CKPATH": %s\n",
			    rv == -1 ? strerror(oerrno) : "short read");
		    return 0;
		}
		buf[sz] = '\0';
		cloak_key = buf;
		cloak_key_len = strlen(cloak_key);
	    }
	    else
	    {
		close(fd);
#if defined(USE_SYSLOG)
		syslog(LOG_ERR, "Key provided in "CKPATH" is too short. (%d < %d)",
			sz, MIN_CLOAK_KEY_LEN);
#endif
		fprintf(stderr, "Key provided in "CKPATH" is too short. (%d < %d)\n",
			sz, MIN_CLOAK_KEY_LEN);
		return 0;
	    }
	}
	else
	{
	    close(fd);
#if defined(USE_SYSLOG)
	    syslog(LOG_ERR, "failed to stat "CKPATH": %s",
		    strerror(errno));
#endif
	    fprintf(stderr, "Failed to stat "CKPATH": %s\n",
		    strerror(errno));
	    return 0;
	}
    }
    else
    {
#if defined(USE_SYSLOG)
	syslog(LOG_ERR, "Cannot open "CKPATH": %s",
		strerror(errno));
#endif
	fprintf(stderr, "Cannot open "CKPATH": %s\n",
		strerror(errno));
	return 0;
    }

    /* phew. */

#if defined(USE_SYSLOG)
    syslog(LOG_NOTICE, "Server cloaking code, host: %s, key: `%s' (%d bits)",
	    cloak_host, cloak_key, cloak_key_len * 8);
#endif

    return 1;
}


/* Fowler / Noll / Vo (FNV) Hash..     
   Noll, Landon Curt  (LCN2)  lcn2-mail@ASTHE.COM
   chongo <was here> /\../\ 

   #define HASH(sta,end,hash) { while (end != sta)hash=((hash*0x01000193)^(*end--));}

*/

#define FNV_prime 16777619U

static __inline int32_t
fnv_hash (const char *p, int32_t s)
{
    int32_t h = 0;
    int32_t i = 0;

    for (; i < s; i++)
	h = ((h * FNV_prime ) ^ (p[i]));

    return h;
}

#define SHABUFLEN (SHA1_DIGEST_LENGTH * 2)

char *
sha1_hash(const char *s, size_t size)
{
    static char shabuf[SHABUFLEN + 1];
    unsigned char digestbuf[SHA1_DIGEST_LENGTH];
    int i;
    SHA1_CTX digest;

    SHA1Init(&digest);
    SHA1Update(&digest, (unsigned char *) s, size);
    SHA1Update(&digest, (unsigned char *) cloak_key, cloak_key_len);
    SHA1Final(digestbuf, &digest);

    for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
	snprintf(shabuf+2*i, sizeof(shabuf) - 2*i, "%02x", digestbuf[i]);
    shabuf[SHABUFLEN] = '\0';

    return shabuf;
}

char *
cloak_key_checksum(void)
{
    return(sha1_hash(cloak_key, cloak_key_len));
}

int
cloakhost(char *host, char *dest)
{
    char virt[HOSTLEN + 1], ip6buffer[INET6_ADDRSTRLEN], *p;
    unsigned int dotCount, colCount;
    int32_t csum;
    host_type_t htype;

    htype = host_type(host, &dotCount, &colCount);
    memset(virt, 0x0, HOSTLEN+1);

    if (htype == HT_IPv6)
    {
	/* Expand address before hashing */
	expand_ipv6(host, colCount, ip6buffer);
	Debug((DEBUG_INFO, "%s expanded to %s (%u columns)", host, ip6buffer, colCount));
	csum = fnv_hash(sha1_hash(ip6buffer, strlen(ip6buffer)), SHABUFLEN);
    }
    else if (htype == HT_IPv4 || htype == HT_FQDN)
	csum = fnv_hash(sha1_hash(host, strlen(host)), SHABUFLEN);

    switch (htype)
    {
	case HT_INVALID:
	    return 0;
	case HT_FQDN:
	    if (dotCount == 1)
	    {
		snprintf(virt, HOSTLEN, "%s%c%X.%s",
			 cloak_host,
			 (csum < 0 ? '=' : '-'),
			 (csum < 0 ? -csum : csum), host);
	    }
	    else if (dotCount > 1)
	    {
		int chlen = strlen(cloak_host) + 10; /* -12345678. */

		p = (char *) strchr((char *)host, '.');

		while((strlen(p) + chlen) > HOSTLEN)
		{
		    /* controllare i return value non sarebbe una cattiva idea... */
		    if ((p = (char *) strchr((char *) ++p, '.')) == NULL)
			return 0;
		}
		snprintf(virt, HOSTLEN, "%s%c%X.%s",
			 cloak_host,
			 (csum < 0 ? '=' : '-'),
			 (csum < 0 ? -csum : csum), p + 1);
	    }
	    else
		return 0;
	break;

	case HT_IPv4:
	{
	    char ipmask[16];

	    strncpy(ipmask, host, sizeof(ipmask));
	    ipmask[sizeof(ipmask) - 1] = '\0';
	    if ((p = strchr(ipmask, '.')) != NULL)
		if ((p = strchr(p + 1, '.')) != NULL)
		    *p = '\0';

	    if (p == NULL)
		snprintf(virt, HOSTLEN, "%s%c%X",
			 cloak_host, csum < 0 ? '=' : '-',
			 csum < 0 ? -csum : csum);
	    else
		snprintf(virt, HOSTLEN, "%s.%s%c%X",
			 ipmask, cloak_host, csum < 0 ? '=' : '-',
			 csum < 0 ? -csum : csum);
	    break;
	}

	case HT_IPv6:
	{
	    /* FFFFFFFUUUUUUUU */
	    int rv;
	    struct in6_addr ip6addr;
	    memset(ip6buffer, 0, sizeof(ip6buffer));
	    /* Get raw bytes... */
	    rv = inet_pton(AF_INET6, host, &ip6addr);
	    if (rv <= 0)
	    {
		Debug((DEBUG_ERROR, "inet_pton failed: rv = %d, errno = %d", rv, errno));
		return 0;
	    }
	    /* ...blank out the lowest 80 bits... */
	    memset(&(ip6addr.s6_addr[6]), 0, 10);
	    /* ...and get back the "presentation format" */
	    if (inet_ntop(AF_INET6, &ip6addr, ip6buffer, INET6_ADDRSTRLEN) == NULL)
	    {
		Debug((DEBUG_ERROR, "inet_ntop failed: errno = %d", errno));
		return 0;
	    }
	    /* Now append the checksum (eg. "2001:db8::Azzurra-12345678") */
	    snprintf(virt, HOSTLEN, "%s%s%c%X",
		     ip6buffer, cloak_host, csum < 0 ? '=' : '-',
		     csum < 0 ? -csum : csum);
	    break;
	}
    }

    memcpy(dest, virt, HOSTLEN);
    return 1;
}

static __inline host_type_t
host_type(const char *host, unsigned int *dotCountPtr, unsigned int *colCountPtr)
{
    const char *ptr;
    char ch;
    unsigned int dotCount, numCount, alphaCount, hexCount, columnCount;
    uint8_t lastIsDot;

    if (host == NULL)
	return HT_INVALID;

    ptr = host;
    dotCount = numCount = alphaCount = hexCount = columnCount = 0;
    lastIsDot = 0;

    while ((ch = *ptr) != '\0')
    {
	switch (ch)
	{
	    /* both isdigit(ch) and isxdigit(ch) are true */
	    case '0':
	    case '1':
	    case '2':
	    case '3':
	    case '4':
	    case '5':
	    case '6':
	    case '7':
	    case '8':
	    case '9':
		++numCount;
		++hexCount;
		lastIsDot = 0;
		break;

	    /* both isalpha(ch) and isxdigit(ch) are true */
	    case 'a':
	    case 'A':
	    case 'b':
	    case 'B':
	    case 'c':
	    case 'C':
	    case 'd':
	    case 'D':
	    case 'e':
	    case 'E':
	    case 'f':
	    case 'F':
		++alphaCount;
		++hexCount;
		lastIsDot = 0;
		break;

	    case '.':
		if (lastIsDot || columnCount > 0)
		    return HT_INVALID;
		++dotCount;
		lastIsDot = 1;
		break;

	    case ':':
		if (dotCount > 0)
		    return HT_INVALID;
		++columnCount;
		lastIsDot = 0;
		break;

	    /* Be lazy and don't check RFC 1035 compliance */
	    default:
		++alphaCount;
		lastIsDot = 0;
		break;
	}
	ptr++;
    }

    if (dotCountPtr != NULL)
	*dotCountPtr = dotCount;
    if (colCountPtr != NULL)
	*colCountPtr = columnCount;

    /* We know what's inside host, let's guess the type */
    if (lastIsDot)
	return HT_INVALID;
    else if (columnCount && hexCount)
	return HT_IPv6;
    else if (dotCount == 3 && numCount > 3 && alphaCount == 0)
	return HT_IPv4;
    else if (dotCount >= 1 && alphaCount >= 2)
	return HT_FQDN;
    else
	return HT_INVALID;
}

static __inline void
expand_ipv6(const char *host, unsigned int colCount, char ip6buf[INET6_ADDRSTRLEN])
{
    char *ptr = ip6buf;
    int i = 0, len;

    if (colCount > 7)
    {
	/* Invalid address */
	Debug((DEBUG_ERROR, "invalid IPv6 address: %s", host));
	memcpy(ptr, host, strlen(host) + 1);
	return;
    }
    memcpy(ptr, "0000:0000:0000:0000:0000:0000:0000:0000", 40);

    len = strlen(host);

    /* Scan the buffer backwards */
    ptr = ip6buf + 38;

    /* Skip the end of the string */
    host += len - 1;

    while (len > 0)
    {
	switch (*host)
	{
	    case ':':
		if (*(host + 1) == ':')
		{
		    /* Double colon, move left as many fields as were collapsed */
		    ptr -= (8 - colCount) * 5;
		    i = 0;
		    break;
		}

		/* 4 + ':' == 5 */
		ptr -= (5 - i);
		i = 0;
		break;

	    default:
		*(ptr--) = *host;
		i++;
		break;
	}
	host--;
	len--;
    }
}
