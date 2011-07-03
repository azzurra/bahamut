
#define CRYPT_SHA1_DIGEST_LEN	40


/* @(#)shs1.h	12.2 23 Nov 1995 01:15:42 */
/*
 * shs1 - new NIST Secure Hash Standard-1 (SHS1)
 *
 * Written 2 September 1992, Peter C. Gutmann.
 *
 * This file was Modified by:
 *
 *	 Landon Curt Noll  (chongo@toad.com)	chongo <was here> /\../\
 *
 * This code has been placed in the public domain.  Please do not
 * copyright this code.
 *
 * LANDON CURT NOLL DISCLAIMS ALL WARRANTIES WITH  REGARD  TO
 * THIS  SOFTWARE,  INCLUDING  ALL IMPLIED WARRANTIES OF MER-
 * CHANTABILITY AND FITNESS.  IN NO EVENT SHALL  LANDON  CURT
 * NOLL  BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM  LOSS  OF
 * USE,  DATA  OR  PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR  IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * See shs1drvr.c for version and modification history.
 */

#if !defined(SHS1_H)
#define SHS1_H

#include <sys/types.h>
#include <sys/stat.h>

/*
 * determine if we are checked in
 */
#define SHS1_H_WHAT "@(#)"	/* @(#) if checked in */

/*
 * These macros are in common with shs.h, shs1.h and md5.h.  We use
 * HASH_MACROS to gaurd against multiple inclusion by external progs
 * that may want to use multiple hash codes in one module.
 */
#if !defined(HASH_MACROS)
#define HASH_MACROS

/*
 * Useful defines/typedefs
 */
typedef unsigned char BYTE;	/* must be a 1 byte unsigned value */
typedef unsigned int  UINT;	/* must be at least a 2 byte unsigned value */
typedef unsigned long ULONG;	/* must be at least a 4 byte unsigned value */

#endif /* HASH_MACROS */

/* SHS1_CHUNKSIZE must be a power of 2 - fixed value defined by the algorithm */
#define SHS1_CHUNKSIZE (1<<6)
#define SHS1_CHUNKWORDS (SHS1_CHUNKSIZE/4)

/* SHS1_DIGESTSIZE is a the length of the digest as defined by the algorithm */
#define SHS1_DIGESTSIZE (20)
#define SHS1_DIGESTWORDS (SHS1_DIGESTSIZE/4)

/* SHS1_LOW - where low 32 bits of 64 bit count is stored during final */
#define SHS1_LOW 15

/* SHS1_HIGH - where high 32 bits of 64 bit count is stored during final */
#define SHS1_HIGH 14

/* SHS1_BLOCKSIZE is how large a chunk multiStream processes at a time */
#define SHS1_BLOCKSIZE (SHS1_CHUNKSIZE<<8)

/* SHS1_READSIZE must be a multiple of SHS1_BLOCKSIZE */
#define SHS1_READSIZE (SHS1_BLOCKSIZE<<2)
#define SHS1_READWORDS (SHS1_READSIZE/4)

/* maximum part of pre_file used */
#define SHS1_MAX_PRE_FILE 32768

/*
 * SHS1_SWAP_BYTE_SEX(ULONG *dest, ULONG *src)
 *
 *	dest	- array of SHS1_CHUNKWORDS ULONG of fixed data (may be src)
 *	src	- array of SHS1_CHUNKWORDS ULONG of what to fix
 *
 * This macro will either switch to the opposite byte sex (Big Endian vs.
 *  Little Endian).
 */
#define SHS1_SWAP_BYTE_SEX(dest, src) {	/* swap byte sex if needed */	\
    int tmp_i;	/* index */						\
    for (tmp_i=0; tmp_i < SHS1_CHUNKWORDS; ++tmp_i) {			\
	((ULONG*)(dest))[tmp_i] =					\
	  (((ULONG*)(src))[tmp_i] << 16) |				\
	  (((ULONG*)(src))[tmp_i] >> 16);				\
	((ULONG*)(dest))[tmp_i] =					\
	  ((((ULONG*)(dest))[tmp_i] & 0xff00ff00UL) >> 8) |		\
	  ((((ULONG*)(dest))[tmp_i] & 0x00ff00ffUL) << 8);		\
    }									\
}

/*
 * SHS1_ROUNDUP(x,y) - round x up to the next multiple of y
 */
#define SHS1_ROUNDUP(x,y) ((((x)+(y)-1)/(y))*(y))

/* 
 * SHS1_TRANSFORM(SHS1_INFO *a, ULONG *b, ULONG *c)
 *
 * 	a	pointer to our current digest state
 *	b	pointer to SHS1_CHUNKSIZE words of byte sex fixed data
 *	c	pointer to SHS1_CHUNKSIZE words that do not need to be fixed
 */
#ifdef WORDS_BIGENDIAN
# define SHS1_TRANSFORM(a,b,c)						\
    shs1Transform(((SHS1_INFO *)(a))->digest, (ULONG *)(c))
#else
# define SHS1_TRANSFORM(a,b,c) { 					\
    SHS1_SWAP_BYTE_SEX((b), (c));					\
    shs1Transform(((SHS1_INFO *)(a))->digest, (ULONG *)(b));		\
}
#endif

/*
 * SHS1COUNT(SHS1_INFO*, ULONG) - update the 64 bit count in an SHS1_INFO
 *
 * We will count bytes and convert to bit count during the final
 * transform.
 */
#define SHS1COUNT(shs1info, count) {					\
    ULONG tmp_countLo;						\
    tmp_countLo = (shs1info)->countLo;				\
    if (((shs1info)->countLo += (count)) < tmp_countLo) {	\
	(shs1info)->countHi++;					\
    }								\
}

/*
 * The structure for storing SHS1 info
 *
 * We will assume that bit count is a multiple of 8.
 */
typedef struct {
    ULONG digest[SHS1_DIGESTWORDS];	/* message digest */
    ULONG countLo;			/* 64 bit count: bits 3-34 */
    ULONG countHi;			/* 64 bit count: bits 35-63 */
    ULONG datalen;			/* length of data in data */
    ULONG data[SHS1_CHUNKWORDS];		/* SHS1 chunk buffer */
} SHS1_INFO;

/*
 * Used to remove arguments in function prototypes for non-ANSI C
 */
#if defined(__STDC__) && __STDC__ == 1
# define PROTO
#endif
#ifdef PROTO
# define P(a) a
#else	/* !PROTO */
# define P(a) ()
#endif	/* ?PROTO */

/* shs1.c */
void shs1Init P((SHS1_INFO*));
void shs1Update P((SHS1_INFO*, BYTE*, ULONG));
void shs1fullUpdate P((SHS1_INFO*, BYTE*, ULONG));
void shs1Final P((SHS1_INFO*));
extern char *shs1_what;

/* shs1io.c */
/* // Shaka 22/04/02 - don't needed
void shs1Stream P((BYTE*, UINT, FILE*, SHS1_INFO*));
void shs1File P((BYTE*, UINT, char*, int, SHS1_INFO*));
extern ULONG shs1_zero[];
*/

#endif /* SHS1_H */
