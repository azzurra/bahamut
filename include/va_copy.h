#include <stdarg.h>

/* AZZURRA */
#ifdef va_copy
#define VA_COPY va_copy
#elif defined(__va_copy)
#define VA_COPY __va_copy
#else
#define VA_COPY( x, y ) x = y
#endif

