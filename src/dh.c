/************************************************************************
 *   IRC - Internet Relay Chat, src/dh.c
 *   Copyright (C) 2000 Lucas Madar
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

/*
 * Diffie-Hellman key exchange for bahamut ircd.
 * Lucas Madar <lucas@dal.net> -- 2000
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

struct session_info {
    DH *dh;
    char *session_shared;
    int session_shared_length;
};

DH *get_dh2048(void);

/*
 * Do not change these unless
 * you also change the prime below
 */

#define KEY_BITS 512

#define RAND_BITS KEY_BITS
#define RAND_BYTES (RAND_BITS / 8)
#define RAND_BYTES_HEX ((RAND_BYTES * 2) + 1)

static int verify_is_hex(char *string)
{
    int l = strlen(string);
    char tmp[4] = {'\0', '\0', '\0', '\0'};
    int tmpidx = 0;

    if(l & 0x01) /* check if it's odd length */
    {  
	l++;
	tmp[tmpidx++] = '0'; /* pad with zero */
    }
   
    while(*string)
    {
	tmp[tmpidx++] = *string++;
	if(tmpidx == 2)
	{
	    char *eptr = NULL; /* AZZURRA */
	    unsigned char x;
   
	    tmpidx = 0;
   
	    x = strtol(tmp, &eptr, 16);
	    if((eptr != NULL) && (*eptr != '\0'))
	    {
		return 0;
	    }
	}
    }
    return 1;
}

static int make_entropy()
{
    char randbuf[RAND_BYTES * 4];
    FILE *fp;
    int i;
    int tmp; /*Ugly hack --Sonic*/

	printf("No random state found, trying to generate entropy from /dev/random...\n");
	printf("This may take a moment.\n");
	printf("To speed up this process, do something else on the system for a bit.\n");
   
    fp = fopen("/dev/random", "r");
    if(!fp)
    {  
	printf("Could not load random values from /dev/random: %s\n", strerror(errno));
	printf("ircd needs a %d byte random seed.\n", RAND_BYTES);
	printf("You can place a file containing random data called .ircd.entropy\n");
	printf("in the directory with your ircd.conf. This file must be at least %d bytes\n", RAND_BYTES);
	return 0;
    }
   
    for(i = 0; i < (RAND_BYTES * 4); i++)
    {
	int cv;
	
	cv = fgetc(fp);
	
	if(cv == EOF)
	{
	    if(ferror(fp))
	    {
		printf("Error while reading from random source: %s. hrmm.\n", strerror(errno)); 
		fclose(fp);
		return 0;
	    }
			
	    clearerr(fp);
	    usleep(100);
	    i--;
	    continue;
	}
	
	randbuf[i] = cv;
	if(i && (i % 64 == 0))
	{
	    printf(" %d%% ", (int)(((float) i / (float) (RAND_BYTES * 4)) * 100.0));
	    fflush(stdout);
	}
	else
	{
	    printf(".");
	    fflush(stdout);
	}
    }
	
    printf("Done.\n");
    fclose(fp);
	
    fp = fopen(".ircd.entropy", "w");
    if(!fp)
    {
	printf("Could not open .ircd.entropy for writing: %s\n", strerror(errno));
	return 0;
    }
    
    tmp = fwrite(randbuf, RAND_BYTES * 4, 1, fp);
    fclose(fp);
    
    RAND_load_file(".ircd.entropy", -1);

    return 1;
}

static int init_random()
{
    int ret;
    time_t now;
    
    ret = RAND_load_file(".ircd.entropy", -1);
    if(ret <= 0)
    {
	if(!make_entropy())
	return -1;
    }
    else
	printf("%d bytes of entropy loaded.\n", ret);

    now = time(NULL); 
	
    /* this is probably not too good, but it saves just writing
       the whole state back to disk with no changes. */
    RAND_seed(&now, 4);
    RAND_write_file(".ircd.entropy");
    
    return 0;
}

int dh_init()
{
    ERR_load_crypto_strings();
    printf("Generating random state...\n");
    if(init_random() == -1)
	return -1;
    printf("Random state successful.\n");
    return 0; 
}

int dh_generate_shared(void *session, char *public_key)
{
    BIGNUM *tmp;
    int len;
    struct session_info *si = (struct session_info *) session;
    
    if(verify_is_hex(public_key) == 0 || !si || si->session_shared)
	return 0;
    
    tmp = NULL;
    BN_hex2bn(&tmp, public_key);
    if(!tmp)
	return 0;
    
    si->session_shared_length = DH_size(si->dh);
    si->session_shared = (char *) malloc(DH_size(si->dh));
    len = DH_compute_key((unsigned char *)(si->session_shared), tmp, si->dh);
    BN_free(tmp);

    if(len < 0)
	return 0;

    si->session_shared_length = len;
    
    return 1;
}

void *dh_start_session()
{
    struct session_info *si;

    si = (struct session_info *) malloc(sizeof(struct session_info));
    if(!si) abort();

    memset(si, 0, sizeof(struct session_info));

    si->dh = get_dh2048();
    if (si->dh == NULL)
    {
	free(si);
	return NULL;
    }

    if(!DH_generate_key(si->dh))
    {
	DH_free(si->dh);
	free(si);
	return NULL;
    }

    return (void *) si;
}

void dh_end_session(void *session)
{
    struct session_info *si = (struct session_info *) session;

    if(si->dh)
    {
	DH_free(si->dh);
	si->dh = NULL;
    }

    if(si->session_shared)
    {
	memset(si->session_shared, 0, si->session_shared_length);
	free(si->session_shared);
	si->session_shared = NULL;
    }
	
    free(si);
}

char *dh_get_s_public(char *buf, int maxlen, void *session)
{
    struct session_info *si = (struct session_info *) session;
    char *tmp;

    if(!si || !si->dh)
	    return NULL;

    const BIGNUM* pubkey = DH_get0_pub_key(si->dh);
    if (!pubkey)
        return NULL;

    tmp = BN_bn2hex(pubkey);
    if(!tmp)
	    return NULL;

    if(strlen(tmp) + 1 > maxlen)
    {
	    OPENSSL_free(tmp);
	    return NULL;
    }

    strcpy(buf, tmp);
    OPENSSL_free(tmp);

    return buf;
}

int dh_get_s_shared(char *buf, int *maxlen, void *session)
{
    struct session_info *si = (struct session_info *) session;

    if(!si || !si->session_shared || *maxlen < si->session_shared_length)
	return 0;   

    *maxlen = si->session_shared_length;
    memcpy(buf, si->session_shared, *maxlen);

    return 1;
}

/* RFC 3526 Group 14 - 2048-bit MODP Diffie-Hellman parameters */
static unsigned char dh2048_p[] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
    0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
    0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
    0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
    0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
    0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
    0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
    0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
    0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
    0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
    0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
    0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
    0xCA,0x18,0x21,0x7C,0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,0x9B,0x27,0x83,0xA2,
    0xEC,0x07,0xA2,0x8F,0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,
    0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,0x39,0x95,0x49,0x7C,
    0xEA,0x95,0x6A,0xE5,0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
    0x15,0x72,0x8E,0x5A,0x8A,0xAC,0xAA,0x68,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF
};
static unsigned char dh2048_g[] = { 0x02 };

DH *get_dh2048(void)
{
    DH *dh;

    dh = DH_new();
    if (dh == NULL)
        return NULL;

    BIGNUM *p = BN_bin2bn(dh2048_p, sizeof(dh2048_p), NULL);
    BIGNUM *g = BN_bin2bn(dh2048_g, sizeof(dh2048_g), NULL);

    if (p == NULL || g == NULL)
    {
        DH_free(dh);
        return NULL;
    } else {
        DH_set0_pqg(dh, p, NULL, g);
    }
    return dh;
}
