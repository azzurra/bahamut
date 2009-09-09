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
extern int expected_cloak_key_len;

extern struct cpan_ctx *pa_ctx;
extern struct cpan_ctx *np_ctx;

int cloak_init(void)
{
    int fd;
    const EVP_CIPHER *cipher;

    OpenSSL_add_all_algorithms();

    if ((cipher = EVP_get_cipherbyname(CPAN_CIPHER_NAME)) == NULL)
    {
#if defined(USE_SYSLOG)
	syslog(LOG_ERR, "Unable to load cipher " CPAN_CIPHER_NAME ", aborting.");
#endif
	fprintf(stderr, "Unable to load cipher " CPAN_CIPHER_NAME ", aborting.\n");
	return 0;
    }

    /* Compute expected key length */
    expected_cloak_key_len = EVP_CIPHER_key_length(cipher);
    expected_cloak_key_len += EVP_CIPHER_block_size(cipher);
    expected_cloak_key_len *= 2;

    DupString(cloak_host, CLOAK_HOST);

    if ((fd = open(CKPATH, O_RDONLY)))
    {
	struct stat st;
	char *buf;
	
	if(fstat(fd, &st) == 0)
	{
	    int sz = st.st_size;

	    if(sz >= expected_cloak_key_len)
	    {
		if(sz > expected_cloak_key_len) /* Truncate the key */
		    sz = expected_cloak_key_len;

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
			sz, expected_cloak_key_len);
#endif
		fprintf(stderr, "Key provided in "CKPATH" is too short. (%d < %d)\n",
			sz, expected_cloak_key_len);
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

    /* We have keys and initial pads, initialize the encryption contexts */
    if (((pa_ctx = cpan_init(cipher, cloak_key)) == NULL)
	|| ((np_ctx = cpan_init(cipher, cloak_key + (expected_cloak_key_len / 2))) == NULL))
    {
#if defined(USE_SYSLOG)
	syslog(LOG_ERR, "Cannot initialize CryptoPan contexts, aborting.");
#endif
	fprintf(stderr, "Cannot initialize CryptoPan contexts, aborting.\n");
        return 0;
    }

#if defined(USE_SYSLOG)
    syslog(LOG_NOTICE, "Server cloaking code, host: %s, key: `%s' (%d bits)",
	    cloak_host, cloak_key, cloak_key_len * 8);
#endif

    return 1;
}

/* This is LARGE */
#define SHABUFLEN EVP_MAX_MD_SIZE*2

char *cloak_key_checksum(void)
{
   static char shabuf[SHABUFLEN + 1];
   unsigned char mdbuf[EVP_MAX_MD_SIZE];
   int mdlen = 0, i, rv = 0;
   EVP_MD_CTX digest;

   shabuf[0] = '\0';
   EVP_MD_CTX_init(&digest);

   rv = EVP_DigestInit_ex(&digest, EVP_sha1(), NULL)
     && EVP_DigestUpdate(&digest, (char *) cloak_key, cloak_key_len)
     && EVP_DigestFinal_ex(&digest, mdbuf, &mdlen);
   EVP_MD_CTX_cleanup(&digest);

   if (rv)
   {
      for (i = 0; i < mdlen; i++)
         snprintf(shabuf+2*i, sizeof(shabuf) - 2*i, "%02x", mdbuf[i]);
      shabuf[2*mdlen] = '\0';
   }
   return shabuf;
}

/* Both ipaddr AND the return value are in network byte order */
static int
encrypt_ip(unsigned long ipaddr)
{
    unsigned long paddr, tmp = 0;
    unsigned int i;

    /* First round of cpan (prefix-preserving) */
    paddr = cpan_anonymize(pa_ctx, ipaddr);
    if (paddr == ipaddr)
	return ipaddr;
    /* Reverse bits of ciphertext */
    for (i = 0; i < 32; i++)
    {
        tmp <<= 1;
	tmp |= paddr & 1;
	paddr >>= 1;
    }
    /* Second round of cpan (full randomization) */
    paddr = cpan_anonymize(np_ctx, tmp);
    if (paddr == tmp)
	return ipaddr;
    else
	return paddr;
}

int
cloakhost(aClient *cptr)
{
   char isdns = 0, *p;
   unsigned short i;
   unsigned long csum;
   unsigned long clientaddr;
   char *virt = cptr->user->virthost, *host = cptr->user->host;

#ifdef INET6
   struct in_addr saddr;

   /* Skip non-IPv4 clients */
   if (IsIPv6(cptr) || index(cptr->hostip, '.') == 0 || !inet_pton(AF_INET, cptr->hostip, (void *)clientaddr))
      return 0;

#else
   clientaddr = cptr->ip.s_addr;
#endif /* INET6 */

   if (clientaddr == 0)
      /* Don't cloak masked clients */
      return 0;

   csum = ntohl(encrypt_ip(cptr->ip.s_addr));
   if (csum == ntohl(cptr->ip.s_addr))
      /* Internal failure */
      return 0;

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
	  snprintf(virt, HOSTLEN, "%s-%lX.%s",
		  cloak_host, csum, host);
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
	  snprintf(virt, HOSTLEN, "%s-%lX.%s",
		    cloak_host, csum, p + 1);
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
	 snprintf(virt, HOSTLEN, "%s-%lX",
		    cloak_host, csum);
      else
	 snprintf(virt, HOSTLEN, "%s.%s-%lX",
		    ipmask, cloak_host, csum);
   }

   return 1;
}

#endif
