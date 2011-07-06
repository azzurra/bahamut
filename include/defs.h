#if !defined( DEFS_H_INCLUDED )
# define DEFS_H_INCLUDED 1

/*
 * None of the following should need to be changed by hand.  
 */

/* $Id$ */

# if !defined( HAVE_BCOPY )
#	define bcopy(a,b,c) memcpy(b,a,c)
# endif
# if !defined( HAVE_BCMP )
#	define bcmp memcmp
# endif
# if !defined( HAVE_BZERO )
#	define bzero(a,b) memset(a,0,b)
# endif

# if defined( __osf__ )
#	define OSF
#	undef BSD
#	include <sys/param.h>
#	if !defined( BSD )
#	 define BSD
#	endif
# endif

# if !defined(HAVE_DN_SKIPNAME)
#	if defined(HAVE___DN_SKIPNAME)
#		define dn_skipname __dn_skipname
#	else
#		error Could not find dn_skipname() or __dn_skipname()
# 	endif
# endif

# if !defined(HAVE_RES_MKQUERY)
#	if defined(HAVE___RES_MKQUERY)
#		define res_mkquery __res_mkquery
#	else
#		error Could not find res_mkquery() or __res_mkquery()
# 	endif
# endif

# if !defined(HAVE_DN_EXPAND)
#	if defined(HAVE___DN_EXPAND)
#		define dn_expand __dn_expand
#	else
#		error Could not find dn_expand() or __dn_expand()
# 	endif
# endif

# if !defined(HAVE_WRITEV)
# error Your platform does not support writev()
# endif

/* FIXME: we should provide an alternative to mkstemp() */
# if !defined(HAVE_MKSTEMP)
# error Your platform does not support mkstemp()
# endif

/*
 * The following OS specific stuff is a compatibility kludge it would
 * be nice to get rid of all of this eventually.
 */
#if defined(OS_SOLARIS2) && !defined( SOL20 )
# define SOL20 1
# define USE_POLL 1		/* Get around stupid select() limitations */
#endif

#if defined( OS_ESIX ) && !defined( ESIX )
# define ESIX 1
#endif

#if defined( OS_NEXT ) && !defined( NEXT )
# define NEXT 1
#endif

#if defined( ultrix ) && !defined( ULTRIX )
# define ULTRIX 1
#endif

#if (defined( sgi ) || defined( __sgi )) && !defined( SGI )
# define SGI 1
#endif

#if defined( aix ) || defined( OS_AIX )
# include <sys/machine.h>
# define BSD_INCLUDES
# if !defined( AIX )
#	define AIX 1
# endif
# define USE_POLL 1		/* KLUGE - only define on AIX 4.x!! -cab */
#endif

#if defined( OS_MIPS )
# undef SYSV
# undef BSD
# define BSD 1			/* mips only works in a bsd43 environment */
# if !defined( MIPS )
#	define MIPS 1
# endif
#endif

#if defined( BSD_RELIABLE_SIGNALS ) \
    && (defined( SYSV_UNRELIABLE_SIGNALS ) || defined( POSIX_SIGNALS ))
error You defined too many signal types in setup.h
#elif defined( SYSV_UNRELIABLE_SIGNALS ) && defined( POSIX_SIGNALS )
error You defined too many signal types in setup.h
#endif

#if defined( BSD_RELIABLE_SIGNALS ) || defined( POSIX_SIGNALS )
# define HAVE_RELIABLE_SIGNALS
#endif

#ifdef HAVE_POLL
#define USE_POLL 1
#endif

#endif				/* DEFS_H_INCLUDED */
