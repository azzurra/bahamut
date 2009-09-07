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

#ifdef AZZURRA
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include <string.h>
#include "h.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

extern unsigned char *cloak_key;		/* in ircd.c --vjt */
extern unsigned char *cloak_host;
extern unsigned short cloak_key_len;

int cloak_init(void)
{
    int fd;

    OpenSSL_add_all_algorithms();
    
    DupString(cloak_host, CLOAK_HOST);

    if ((fd = open(CKPATH, O_RDONLY)))
    {
	struct stat st;
	char *buf;
	
	if(fstat(fd, &st) == 0)
	{
	    int sz = st.st_size;

	    if(sz > MIN_CLOAK_KEY_LEN)
	    {
		if(sz > MAX_CLOAK_KEY_LEN) /* are we NASA ? */
		    sz = MAX_CLOAK_KEY_LEN;

		buf = MyMalloc(sz + 1);
		read(fd, (void *) buf, sz);
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

#define FNV_prime 16777619UL

__inline long
fnv_hash (const char *p, int s)
{
    long h = 0;
    int i = 0;

    for (; i < s; i++)
	h = ((h * FNV_prime ) ^ (p[i]));

    return h;
}

/* This is LARGE */
#define SHABUFLEN EVP_MAX_MD_SIZE*2

char *sha1_hash(const char *s, size_t size) {

    static char shabuf[SHABUFLEN + 1];
    unsigned char mdbuf[EVP_MAX_MD_SIZE];
    int mdlen, i;
    EVP_MD_CTX digest;

    EVP_MD_CTX_init(&digest);

    EVP_DigestInit_ex(&digest, EVP_sha1(), NULL);
    EVP_DigestUpdate(&digest, (char *) s, size);
    EVP_DigestUpdate(&digest, (char *) cloak_key, cloak_key_len);
    EVP_DigestFinal_ex(&digest, mdbuf, &mdlen);
    EVP_MD_CTX_cleanup(&digest);

    for (i = 0; i < mdlen; i++)
        snprintf(shabuf+2*i, sizeof(shabuf) - 2*i, "%02x", mdbuf[i]);
    shabuf[2*mdlen] = '\0';
    
    return shabuf;
}

char *cloak_key_checksum(void)
{
    return(sha1_hash(cloak_key, cloak_key_len));
}

int
cloakhost(char *host, char *dest)
{
   char virt[HOSTLEN + 1], isdns = 0, *p;
   char *shabuf;
   unsigned short i;
   long csum;

   shabuf = sha1_hash(host, strlen(host));
   csum = fnv_hash(shabuf, strlen(shabuf));

   for (p = host, i = 0; *p; p++) {
      if(!isdns && isalpha(*p))
	  isdns = 1;
      else if (*p == '.')
	  i++;
   }

   memset(virt, 0x0, HOSTLEN+1);

   if (isdns) {
      if (i == 1)
      {
	  // XXX: Fix the domainname len > HOSTLEN case
	  // 
	  snprintf(virt, HOSTLEN, "%s%c%lX.%s",
		  cloak_host,
		  (csum < 0 ? '=' : '-'),
		  (csum < 0 ? -csum : csum), host);
      } else if (i > 1) {
	  int chlen = strlen(cloak_host) + 10; // -12345678.

	  p = (char *) strchr((char *)host, '.');

	  // XXX: Fix the domainname len > HOSTLEN case.. this will cause a crash.
	  // 
	  while((strlen(p) + chlen) > HOSTLEN)
	  {
	      // controllare i return value non sarebbe una cattiva idea...
	      if ((p = (char *) strchr((char *) ++p, '.')) == NULL)
		return 0;
	  }
	  snprintf(virt, HOSTLEN, "%s%c%lX.%s",
		    cloak_host,
		    (csum < 0 ? '=' : '-'),
		    (csum < 0 ? -csum : csum), p + 1);
      } else
	  return 0;
   } else {
      char ipmask[16];

      strncpy(ipmask, host, sizeof(ipmask));
      ipmask[sizeof(ipmask) - 1] = '\0';
      if((p = strchr(ipmask, '.')) != NULL)
	  if((p = strchr(p + 1, '.')) != NULL)
	      *p = '\0';

      if (p == NULL)
	 snprintf(virt, HOSTLEN, "%s%c%lX",
		    cloak_host, csum < 0 ? '=' : '-',
		    csum < 0 ? -csum : csum);
      else
	 snprintf(virt, HOSTLEN, "%s.%s%c%lX",
		    ipmask, cloak_host, csum < 0 ? '=' : '-',
		    csum < 0 ? -csum : csum);
   }

   memcpy(dest, virt, HOSTLEN);
   return 1;
}

#endif
