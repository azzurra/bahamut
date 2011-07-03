
/* @(#)shs1.c	12.2 23 Nov 1995 01:15:43 */
/*
 * shs1 - implements new NIST Secure Hash Standard-1 (SHS1)
 *
 * Written 2 September 1992, Peter C. Gutmann.
 *
 * This file was Modified/Re-written by:
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

#include <stdio.h>
#include <string.h>

#include "shs1.h"

#include "align.h"

char *shs1_what="@(#)";	/* #(@) if checked in */

/*
* The SHS1 f()-functions.  The f1 and f3 functions can be optimized
* to save one boolean operation each - thanks to Rich Schroeppel,
* rcs@cs.arizona.edu for discovering this.
*
* f1: ((x&y) | (~x&z)) == (z ^ (x&(y^z)))
* f3: ((x&y) | (x&z) | (y&z)) == ((x&y) | (z&(x|y)))
*/
#define f1(x,y,z)       (z ^ (x&(y^z)))		/* Rounds  0-19 */
#define f2(x,y,z)       (x^y^z)			/* Rounds 20-39 */
#define f3(x,y,z)       ((x&y) | (z&(x|y)))	/* Rounds 40-59 */
#define f4(x,y,z)       (x^y^z)			/* Rounds 60-79 */

/* The SHS1 Mysterious Constants */
#define K1      0x5A827999L	/* Rounds  0-19 */
#define K2      0x6ED9EBA1L	/* Rounds 20-39 */
#define K3      0x8F1BBCDCL	/* Rounds 40-59 */
#define K4      0xCA62C1D6L	/* Rounds 60-79 */

/* SHS1 initial values */
#define h0init  0x67452301L
#define h1init  0xEFCDAB89L
#define h2init  0x98BADCFEL
#define h3init  0x10325476L
#define h4init  0xC3D2E1F0L

/* 32-bit rotate left - kludged with shifts */
#define LEFT_ROT(X,n)  (((X)<<(n)) | ((X)>>(32-(n))))

/*
*
* The initial expanding function.  The hash function is defined over an
* 80-word expanded input array W, where the first 16 are copies of the input
* data, and the remaining 64 are defined by
*
*      W[i] = LEFT_ROT(W[i-16] ^ W[i-14] ^ W[i-8] ^ W[i-3], 1)
*
* NOTE: The expanding function used in rounds 16 to 79 was changed from the
*	 original SHA (in FIPS Pub 180) to one that also left circular shifted
*	 by one bit for Secure Hash Algorithm-1 (FIPS Pub 180-1).
*/
#define exor(W,i,t) \
	(t = (W[i&15] ^ W[(i-14)&15] ^ W[(i-8)&15] ^ W[(i-3)&15]), \
	W[i&15] = LEFT_ROT(t, 1))

/*
* The prototype SHS1 sub-round.  The fundamental sub-round is:
*
*      a' = e + LEFT_ROT(a,5) + f(b,c,d) + k + data;
*      b' = a;
*      c' = LEFT_ROT(b,30);
*      d' = c;
*      e' = d;
*
* but this is implemented by unrolling the loop 5 times and renaming the
* variables ( e, a, b, c, d ) = ( a', b', c', d', e' ) each iteration.
* This code is then replicated 20 times for each of the 4 functions, using
* the next 20 values from the W[] array each time.
*/
#define subRound(a, b, c, d, e, f, k, data) \
	(e += LEFT_ROT(a,5) + f(b,c,d) + k + data, b = LEFT_ROT(b,30))

/* forward declarations */
static void shs1Transform P((ULONG*, ULONG*));
#ifndef WORDS_BIGENDIAN
static ULONG in[SHS1_CHUNKWORDS];
#endif

/*
* shs1Init - initialize the SHS1 state
*/
void shs1Init(dig)
	SHS1_INFO *dig;
{
	/* Set the h-vars to their initial values */
	dig->digest[0] = h0init;
	dig->digest[1] = h1init;
	dig->digest[2] = h2init;
	dig->digest[3] = h3init;
	dig->digest[4] = h4init;

	/* Initialise bit count */
	dig->countLo = 0;
	dig->countHi = 0;
	dig->datalen = 0;
}


/*
* shs1Transform - perform the SHS1 transformatio
*
* Note that this code, like MD5, seems to break some optimizing compilers.
* It may be necessary to split it into sections, eg based on the four
* subrounds.  One may also want to roll each subround into a loop.
*/
static void shs1Transform(digest, W)
	ULONG *digest;
	ULONG *W;
{
	ULONG A, B, C, D, E;	/* Local vars */
	ULONG t;			/* temp storage for exor() */

	/* Set up first buffer and local data buffer */
	A = digest[0];
	B = digest[1];
	C = digest[2];
	D = digest[3];
	E = digest[4];

	/* Heavy mangling, in 4 sub-rounds of 20 interations each. */
	subRound(A, B, C, D, E, f1, K1, W[ 0]);
	subRound(E, A, B, C, D, f1, K1, W[ 1]);
	subRound(D, E, A, B, C, f1, K1, W[ 2]);
	subRound(C, D, E, A, B, f1, K1, W[ 3]);
	subRound(B, C, D, E, A, f1, K1, W[ 4]);
	subRound(A, B, C, D, E, f1, K1, W[ 5]);
	subRound(E, A, B, C, D, f1, K1, W[ 6]);
	subRound(D, E, A, B, C, f1, K1, W[ 7]);
	subRound(C, D, E, A, B, f1, K1, W[ 8]);
	subRound(B, C, D, E, A, f1, K1, W[ 9]);
	subRound(A, B, C, D, E, f1, K1, W[10]);
	subRound(E, A, B, C, D, f1, K1, W[11]);
	subRound(D, E, A, B, C, f1, K1, W[12]);
	subRound(C, D, E, A, B, f1, K1, W[13]);
	subRound(B, C, D, E, A, f1, K1, W[14]);
	subRound(A, B, C, D, E, f1, K1, W[15]);
	subRound(E, A, B, C, D, f1, K1, exor(W,16,t));
	subRound(D, E, A, B, C, f1, K1, exor(W,17,t));
	subRound(C, D, E, A, B, f1, K1, exor(W,18,t));
	subRound(B, C, D, E, A, f1, K1, exor(W,19,t));

	subRound(A, B, C, D, E, f2, K2, exor(W,20,t));
	subRound(E, A, B, C, D, f2, K2, exor(W,21,t));
	subRound(D, E, A, B, C, f2, K2, exor(W,22,t));
	subRound(C, D, E, A, B, f2, K2, exor(W,23,t));
	subRound(B, C, D, E, A, f2, K2, exor(W,24,t));
	subRound(A, B, C, D, E, f2, K2, exor(W,25,t));
	subRound(E, A, B, C, D, f2, K2, exor(W,26,t));
	subRound(D, E, A, B, C, f2, K2, exor(W,27,t));
	subRound(C, D, E, A, B, f2, K2, exor(W,28,t));
	subRound(B, C, D, E, A, f2, K2, exor(W,29,t));
	subRound(A, B, C, D, E, f2, K2, exor(W,30,t));
	subRound(E, A, B, C, D, f2, K2, exor(W,31,t));
	subRound(D, E, A, B, C, f2, K2, exor(W,32,t));
	subRound(C, D, E, A, B, f2, K2, exor(W,33,t));
	subRound(B, C, D, E, A, f2, K2, exor(W,34,t));
	subRound(A, B, C, D, E, f2, K2, exor(W,35,t));
	subRound(E, A, B, C, D, f2, K2, exor(W,36,t));
	subRound(D, E, A, B, C, f2, K2, exor(W,37,t));
	subRound(C, D, E, A, B, f2, K2, exor(W,38,t));
	subRound(B, C, D, E, A, f2, K2, exor(W,39,t));

	subRound(A, B, C, D, E, f3, K3, exor(W,40,t));
	subRound(E, A, B, C, D, f3, K3, exor(W,41,t));
	subRound(D, E, A, B, C, f3, K3, exor(W,42,t));
	subRound(C, D, E, A, B, f3, K3, exor(W,43,t));
	subRound(B, C, D, E, A, f3, K3, exor(W,44,t));
	subRound(A, B, C, D, E, f3, K3, exor(W,45,t));
	subRound(E, A, B, C, D, f3, K3, exor(W,46,t));
	subRound(D, E, A, B, C, f3, K3, exor(W,47,t));
	subRound(C, D, E, A, B, f3, K3, exor(W,48,t));
	subRound(B, C, D, E, A, f3, K3, exor(W,49,t));
	subRound(A, B, C, D, E, f3, K3, exor(W,50,t));
	subRound(E, A, B, C, D, f3, K3, exor(W,51,t));
	subRound(D, E, A, B, C, f3, K3, exor(W,52,t));
	subRound(C, D, E, A, B, f3, K3, exor(W,53,t));
	subRound(B, C, D, E, A, f3, K3, exor(W,54,t));
	subRound(A, B, C, D, E, f3, K3, exor(W,55,t));
	subRound(E, A, B, C, D, f3, K3, exor(W,56,t));
	subRound(D, E, A, B, C, f3, K3, exor(W,57,t));
	subRound(C, D, E, A, B, f3, K3, exor(W,58,t));
	subRound(B, C, D, E, A, f3, K3, exor(W,59,t));

	subRound(A, B, C, D, E, f4, K4, exor(W,60,t));
	subRound(E, A, B, C, D, f4, K4, exor(W,61,t));
	subRound(D, E, A, B, C, f4, K4, exor(W,62,t));
	subRound(C, D, E, A, B, f4, K4, exor(W,63,t));
	subRound(B, C, D, E, A, f4, K4, exor(W,64,t));
	subRound(A, B, C, D, E, f4, K4, exor(W,65,t));
	subRound(E, A, B, C, D, f4, K4, exor(W,66,t));
	subRound(D, E, A, B, C, f4, K4, exor(W,67,t));
	subRound(C, D, E, A, B, f4, K4, exor(W,68,t));
	subRound(B, C, D, E, A, f4, K4, exor(W,69,t));
	subRound(A, B, C, D, E, f4, K4, exor(W,70,t));
	subRound(E, A, B, C, D, f4, K4, exor(W,71,t));
	subRound(D, E, A, B, C, f4, K4, exor(W,72,t));
	subRound(C, D, E, A, B, f4, K4, exor(W,73,t));
	subRound(B, C, D, E, A, f4, K4, exor(W,74,t));
	subRound(A, B, C, D, E, f4, K4, exor(W,75,t));
	subRound(E, A, B, C, D, f4, K4, exor(W,76,t));
	subRound(D, E, A, B, C, f4, K4, exor(W,77,t));
	subRound(C, D, E, A, B, f4, K4, exor(W,78,t));
	subRound(B, C, D, E, A, f4, K4, exor(W,79,t));

	/* Build message digest */
	digest[0] += A;
	digest[1] += B;
	digest[2] += C;
	digest[3] += D;
	digest[4] += E;
}


/*
* shs1Update - update SHS1 with arbitrary length data
*
* This code does not assume that the buffer size is a multiple of
* SHS1_CHUNKSIZE bytes long.  This code handles partial chunk between
* calls to shs1Update().
*/
void shs1Update(dig, buffer, count)
	SHS1_INFO *dig;
	BYTE *buffer;
	ULONG count;
{
	ULONG datalen = dig->datalen;

	/*
	* Catch the case of a non-empty data buffer
	*/
	if (datalen > 0) {

		/* determine the size we need to copy */
		ULONG cpylen = SHS1_CHUNKSIZE - datalen;

		/* case: new data will not fill the buffer */
		if (cpylen > count) {
			memcpy((char *)dig->data+datalen, (char *)buffer, count);
			dig->datalen = datalen+count;
			return;

			/* case: buffer will be filled */
		} else {
			memcpy((char *)dig->data+datalen, (char *)buffer, cpylen);
			SHS1_TRANSFORM(dig, in, dig->data);
			buffer += cpylen;
			count -= cpylen;
			dig->datalen = 0;
		}
	}

	/*
	* Process data in SHS1_CHUNKSIZE chunks
	*/
	if (count >= SHS1_CHUNKSIZE) {
		shs1fullUpdate(dig, buffer, count);
		buffer += (count/SHS1_CHUNKSIZE)*SHS1_CHUNKSIZE;
		count %= SHS1_CHUNKSIZE;
	}

	/*
	* Handle any remaining bytes of data.
	* This should only happen once on the final lot of data
	*/
	if (count > 0) {
		memcpy((char *)dig->data, (char *)buffer, count);
	}
	dig->datalen = count;
}


/*
* shs1fullUpdate - update SHS1 with chunk multiple length data
*
* This function assumes that count is a multiple of SHS1_CHUNKSIZE and that
* no partial chunk is left over from a previous call.
*/
void shs1fullUpdate(dig, buffer, count)
	SHS1_INFO *dig;
	BYTE *buffer;
	ULONG count;
{
	/*
	* Process data in SHS1_CHUNKSIZE chunks
	*/
	while (count >= SHS1_CHUNKSIZE) {
#if defined(MUST_ALIGN)
		if ((long)buffer & (sizeof(ULONG)-1)) {
			memcpy((char *)in, (char *)buffer, SHS1_CHUNKSIZE);
			SHS1_TRANSFORM(dig, in, in);
		} else {
			SHS1_TRANSFORM(dig, in, buffer);
		}
#else
		SHS1_TRANSFORM(dig, in, buffer);
#endif
		buffer += SHS1_CHUNKSIZE;
		count -= SHS1_CHUNKSIZE;
	}
}


/*
* shs1Final - perform final SHS1 transforms
*
* At this point we have less than a full chunk of data remaining
* (and possibly no data) in the shs1 state data buffer.
*
* First we append a final 0x80 byte.
*
* Next if we have more than 56 bytes, we will zero fill the remainder
* of the chunk, transform and then zero fill the first 56 bytes.
* If we have 56 or fewer bytes, we will zero fill out to the 56th
* chunk byte.  Regardless, we wind up with 56 bytes data.
*
* Finally we append the 64 bit length on to the 56 bytes of data
* remaining.  This final chunk is transformed.
*/
void shs1Final(dig)
	SHS1_INFO *dig;
{
	int count = dig->datalen;
	ULONG lowBitcount = dig->countLo;
	ULONG highBitcount = dig->countHi;

	/*
	* Set the first char of padding to 0x80.
	* This is safe since there is always at least one byte free
	*/
	((BYTE *)dig->data)[count++] = 0x80;

	/* Pad out to 56 mod SHS1_CHUNKSIZE */
	if (count > 56) {
		/* Two lots of padding:  Pad the first chunk to SHS1_CHUNKSIZE bytes */
		memset((BYTE *)dig->data + count, 0, SHS1_CHUNKSIZE - count);
		SHS1_TRANSFORM(dig, dig->data, dig->data);

		/* Now fill the next chunk with 56 bytes */
		memset((BYTE *)dig->data, 0, 56);
	} else {
		/* Pad chunk to 56 bytes */
		memset((BYTE *)dig->data + count, 0, 56 - count);
	}
#ifndef WORDS_BIGENDIAN
	SHS1_SWAP_BYTE_SEX(dig->data, dig->data);
#endif

	/*
	* Append length in bits and transform
	*
	* We assume that bit count is a multiple of 8 because we have
	* only processed full bytes.
	*/ 
	dig->data[SHS1_HIGH] = (highBitcount << 3) | (lowBitcount >> 29);
	dig->data[SHS1_LOW] = (lowBitcount << 3);
	shs1Transform(dig->digest, dig->data);
	dig->datalen = 0;
}
