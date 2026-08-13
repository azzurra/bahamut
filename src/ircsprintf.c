#include "ircsprintf.h"

/* Scratch buffer for the backward itoa/xtoa conversions below. Must hold
 * the widest possible output: a 64-bit unsigned long is up to 20 decimal
 * digits (or 16 hex), and the conversion writes digits backward from the
 * end (see `s = &num[sizeof(num)-1]`). The old size of 12 underflowed for
 * any value needing more than 11 digits — reachable via %lu/%ld, and also
 * via %d/%i/%u when the arg was pulled with the wrong width (fixed below) —
 * and clobbered adjacent globals. Keep the last byte as the NUL terminator
 * the forward `while(*s)` read relies on. */
char num[24] = { 0 };
char itoa_tab[10] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'  };
char xtoa_tab[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
		      'a', 'b', 'c', 'd', 'e', 'f'  };
char nullstring[]="(null)";

#ifdef WANT_SNPRINTF
inline int irc_printf(char *str, size_t size, const char *pattern, va_list vl) 
#else
inline int irc_printf(char *str, const char *pattern, va_list vl) 
#endif
{
    char *s;
    char *buf=str;
    const char *format=pattern;
    va_list ap;
    unsigned long i, u;
    int len=0;

    VA_COPY(ap, vl);
#ifdef WANT_SNPRINTF
    if(!size) 
    {
#endif
	while(*format)
	{
	    u = 0;
	    switch(*format)
	    {
	    case '%':
		format++;
		switch(*format)
		{
		case 's': /* most popular ;) */
		    s=va_arg(ap, char *);
		    if(s==NULL)
			s=nullstring;
		    while(*s)
			buf[len++]=*s++;
		    format++;
		    break;
		case 'l':
		    /* long-width conversion: %l, %ld, %lu */
		    if (*(format+1) == 'u')
		    {
			u=1;
			format++;
		    }
		    else if (*(format+1) == 'd')
		    {
			u=0;
			format++;
		    }
		    else
			u=0;
		    /* Pull the argument at the type it was passed as: reading a
		     * `long` through va_arg(ap, unsigned long) is only defined
		     * when the value is representable in both types (C99
		     * 7.15.1.1p2), which a negative TS or LONG_MIN is not. It
		     * happens to work wherever the two share representation and
		     * argument slot, but that is the ABI being kind, not a
		     * guarantee. Convert after the read instead, where the
		     * conversion is well defined. */
		    if (u)
			i=va_arg(ap, unsigned long);
		    else
			i=(unsigned long)va_arg(ap, long);
		    goto emit_dec;
		case 'u':
		    /* %u is an unsigned int, NOT a long. Reading it as an
		     * unsigned long (as the old `case 'u': format--` route into
		     * the %l path did) pulls the undefined upper 32 bits of the
		     * argument slot on LP64 ABIs, yielding a huge value that
		     * overflowed the itoa buffer above. Read the correct width. */
		    u=1;
		    i=va_arg(ap, unsigned int);
		    goto emit_dec;
		case 'd':
		case 'i':
		    /* %d/%i are int-width; same fix as %u. Sign-extend to
		     * long width here so the test below needs to know
		     * nothing about the width the argument came in at. */
		    u=0;
		    i=(unsigned long)(long)va_arg(ap, int);
		  emit_dec:
		    /* The sign lives in the top bit of `i`, which is a long:
		     * bit 63 on LP64, not bit 31. The old `i & 0x80000000`
		     * hardcoded bit 31, so a %ld/%li whose value merely had
		     * bit 31 set printed as negative — and ts_val is a long
		     * (include/struct.h), so from 2038-01-19 03:14:08 UTC
		     * every timestamp on the wire (NICK/SJOIN bursts, TS
		     * comparisons peers echo back) would have gone out with
		     * an inverted sign. Test the whole width instead. */
		    if(!u)
			if((long)i < 0)
			{
			    buf[len++]='-'; /* it's negative.. */
			    i = 0UL - i; /* magnitude; wraps LONG_MIN right */
			}
		    s=&num[sizeof(num)-1];
		    do
		    {
			*--s=itoa_tab[i%10];
			i/=10;
		    } while(i!=0);
		    while(*s)
			buf[len++]=*s++;
		    format++;
		    break;
		case 'n':
		    /* oo, sneaky...it really is just a long, though! */
		case 'x':
		case 'X':
		    i=va_arg(ap, long);
		    buf[len++]='0';
		    buf[len++]='x';
		    s=&num[sizeof(num)-1];
		    do
		    {
			*--s=xtoa_tab[i%16];
			i/=16;
		    } while(i!=0);
		    while(*s)
			buf[len++]=*s++;
		    format++;
		    break;
		case 'c':
		    buf[len++]= (char) va_arg(ap, int);
		    format++;
		    break;
		default:
		    /* yick, unknown type...default to returning what our 
		       s[n]printf friend would */
		    return vsprintf(str, pattern, vl);
		    break;
		}
		break;
	    default:
		buf[len++]=*format++;
		break;
	    }
	}
	buf[len]=0;
	return len;
#ifdef WANT_SNPRINTF
    }
    else
    {
	while(*format && len<size)
	{
	    u = 0;
	    switch(*format)
	    {
	    case '%':
		format++;
		switch(*format)
		{
		case 's': /* most popular ;) */
		    s=va_arg(ap, char *);
		    if(s==NULL)
			s=nullstring;
		    while(*s && len<size)
			buf[len++]=*s++;
		    format++;
		    break;
		case 'l':
		    /* long-width conversion: %l, %ld, %lu */
		    if (*(format+1) == 'u')
		    {
			u=1;
			format++;
		    }
		    else if (*(format+1) == 'd')
		    {
			u=0;
			format++;
		    }
		    else
			u=0;
		    /* Pull the argument at the type it was passed as: reading a
		     * `long` through va_arg(ap, unsigned long) is only defined
		     * when the value is representable in both types (C99
		     * 7.15.1.1p2), which a negative TS or LONG_MIN is not. It
		     * happens to work wherever the two share representation and
		     * argument slot, but that is the ABI being kind, not a
		     * guarantee. Convert after the read instead, where the
		     * conversion is well defined. */
		    if (u)
			i=va_arg(ap, unsigned long);
		    else
			i=(unsigned long)va_arg(ap, long);
		    goto emit_dec_n;
		case 'u':
		    /* %u is int-width, not long — see the matching comment
		     * in the size==0 branch above. */
		    u=1;
		    i=va_arg(ap, unsigned int);
		    goto emit_dec_n;
		case 'd':
		case 'i':
		    u=0;
		    i=(unsigned long)(long)va_arg(ap, int);
		  emit_dec_n:
		    /* Width-independent sign test — see the matching comment
		     * in the size==0 branch above. */
		    if(!u)
			if((long)i < 0)
			{
			    buf[len++]='-'; /* it's negative.. */
			    i = 0UL - i; /* magnitude; wraps LONG_MIN right */
			}
		    s=&num[sizeof(num)-1];
		    do
		    {
			*--s=itoa_tab[i%10];
			i/=10;
		    } while(i!=0);
		    while(*s && len<size)
			buf[len++]=*s++;
		    format++;
		    break;
		case 'n':
		    /* oo, sneaky...it really is just a long, though! */
		case 'x':
		case 'X':
		    i=va_arg(ap, long);
		    buf[len++]='0';
		    if(len<size)
			buf[len++]='x';
		    else
			break;
		    s=&num[sizeof(num)-1];
		    do
		    {
			*--s=xtoa_tab[i%16];
			i/=16;
		    } while(i!=0);
		    while(*s && len<size)
			buf[len++]=*s++;
		    format++;
		    break;
		case 'c':
		    buf[len++]= (char) va_arg(ap, int);
		    format++;
		    break;
		default:
		    /* yick, unknown type...default to returning what our 
		       s[n]printf friend would */
		    return vsnprintf(str, size, pattern, vl);
		    break;
		}
		break;
	    default:
		buf[len++]=*format++;
		break;
	    }
	}
	buf[len]=0;
	return len;
    }
#endif /* WANT_SNPRINTF */
}

int ircsprintf(char *str, const char *format, ...)
{
    int ret;
    va_list vl;
    va_start(vl, format);
#ifdef WANT_SNPRINTF
    ret=irc_printf(str, 0, format, vl);
#else
    ret=irc_printf(str, format, vl);
#endif
    va_end(vl);
    return ret;
}

#ifdef WANT_SNPRINTF
int ircsnprintf(char *str, size_t size, const char *format, ...)
{
    int ret;
    va_list vl;
    va_start(vl, format);
    ret=irc_printf(str, size, format, vl);
    va_end(vl);
    return ret;
}
#endif

int ircvsprintf(char *str, const char *format, va_list ap)
{
    int ret;
#ifdef WANT_SNPRINTF
    ret=irc_printf(str, 0, format, ap);
#else
    ret=irc_printf(str, format, ap);
#endif
    return ret;
}

#ifdef WANT_SNPRINTF
int ircvsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    int ret;
    ret=irc_printf(str, size, format, ap);
    return ret;
}
#endif
