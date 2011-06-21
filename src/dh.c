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

DH *get_dh1024(void);

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

    si->dh = get_dh1024();
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

    if(!si || !si->dh || !si->dh->pub_key)
	return NULL;  

    tmp = BN_bn2hex(si->dh->pub_key);
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

/* 'SKIP' Diffie-Hellman parameters for 1024 bit DHE */
static unsigned char dh1024_p[] = {
    0xF4,0x88,0xFD,0x58,0x4E,0x49,0xDB,0xCD,0x20,0xB4,0x9D,0xE4,
    0x91,0x07,0x36,0x6B,0x33,0x6C,0x38,0x0D,0x45,0x1D,0x0F,0x7C,
    0x88,0xB3,0x1C,0x7C,0x5B,0x2D,0x8E,0xF6,0xF3,0xC9,0x23,0xC0,
    0x43,0xF0,0xA5,0x5B,0x18,0x8D,0x8E,0xBB,0x55,0x8C,0xB8,0x5D,
    0x38,0xD3,0x34,0xFD,0x7C,0x17,0x57,0x43,0xA3,0x1D,0x18,0x6C,
    0xDE,0x33,0x21,0x2C,0xB5,0x2A,0xFF,0x3C,0xE1,0xB1,0x29,0x40,
    0x18,0x11,0x8D,0x7C,0x84,0xA7,0x0A,0x72,0xD6,0x86,0xC4,0x03,
    0x19,0xC8,0x07,0x29,0x7A,0xCA,0x95,0x0C,0xD9,0x96,0x9F,0xAB,
    0xD0,0x0A,0x50,0x9B,0x02,0x46,0xD3,0x08,0x3D,0x66,0xA4,0x5D,
    0x41,0x9F,0x9C,0x7C,0xBD,0x89,0x4B,0x22,0x19,0x26,0xBA,0xAB,
    0xA2,0x5E,0xC3,0x55,0xE9,0x2F,0x78,0xC7
};
static unsigned char dh1024_g[] = { 0x02 };

DH *get_dh1024(void)
{
    DH *dh;

    dh = DH_new();
    if (dh == NULL)
        return NULL;

    dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
    dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);

    if (dh->p == NULL || dh->g == NULL)
    {
        DH_free(dh);
        return NULL;
    }
    return dh;
}
