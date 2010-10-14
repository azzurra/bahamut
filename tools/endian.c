/* @(#)endian.c	12.1 17 Nov 1995 04:22:20 */
/*
 * endian - Determine the byte order of a long on your machine.
 *
 * Big Endian:	    Amdahl, 68k, Pyramid, Mips, Sparc, ...
 * Little Endian:   Vax, 32k, Spim (Dec Mips), i386, i486, ...
 *
 * This makefile was written by:
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
 * See shsdrvr.c and md5drvr.c for version and modification history.
 */

#include <stdio.h>
#include <stdlib.h>

/* byte order array */
char byte[8] = { (char)0x12, (char)0x36, (char)0x48, (char)0x59,
		 (char)0x01, (char)0x23, (char)0x45, (char)0x67 };

main()
{
    /* pointers into the byte order array */
    int *intp = (int *)byte;

    /* Print the standard <machine/endian.h> defines */
    printf("#define BIG_ENDIAN\t4321\n");
    printf("#define LITTLE_ENDIAN\t1234\n");

    /* Determine byte order */
    if (intp[0] == 0x12364859) {
	/* Most Significant Byte first */
	printf("#define BYTE_ORDER\tBIG_ENDIAN\n");
    } else if (intp[0] == 0x59483612) {
	/* Least Significant Byte first */
	printf("#define BYTE_ORDER\tLITTLE_ENDIAN\n");
    } else {
	fprintf(stderr, "Unknown int Byte Order, set BYTE_ORDER in Makefile\n");
	exit(1);
    }
    exit(0);
}
