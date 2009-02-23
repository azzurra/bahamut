/* @(#)must_align.c	12.2 17 Nov 1995 04:46:11 */
/*
 * must_align - determine if longs must be aligned
 *
 * This file was written by:
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

void buserr();		/* catch alignment errors */

main()
{
    char byte[2*sizeof(unsigned long)];	/* mis-alignment buffer */
    unsigned long *p;	/* mis-alignment pointer */
    int i;

#if !defined(MUST_ALIGN)
    /* setup to catch alignment bus errors */
    signal(SIGBUS, buserr);
    signal(SIGSEGV, buserr);	/* some systems will generate SEGV instead! */

    /* mis-align our long fetches */
    for (i=0; i < sizeof(long); ++i) {
	p = (unsigned long *)(byte+i);
	*p = i;
	*p += 1;
    }

    /* if we got here, then we can mis-align longs */
    printf("#undef MUST_ALIGN\n");

#else
    /* force alignment */
    printf("#define MUST_ALIGN\n");
#endif
    exit(0);
}


/*
 * buserr - catch an alignment error
 */
void
buserr()
{
    /* alignment is required */
    printf("#define MUST_ALIGN\n");
    exit(0);
}
