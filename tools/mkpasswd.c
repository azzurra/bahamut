/* simple password generator by Nelson Minar (minar@reed.edu)
 * copyright 1991, all rights reserved.
 * You can use this code as long as my name stays with it.
 *
 * Modified by INT to use the MD5 extension provided by GLIBC2
 */

#include "sys.h"
#include <time.h>
#include <string.h>

#ifndef lint
/* static char *rcs_version = "$Id$"; */
#endif

#if defined __GLIBC__ && __GLIBC__ >= 2
#define USE_MD5
#endif

#define MIN(a,b) (((a)<(b))?(a):(b))

extern char *getpass();
extern char *crypt();
/* extern long random(); */
/* extern int srandom(unsigned); */

int main(argc, argv)
int argc;
char *argv[];
{
  static char saltChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
  char salt[13];
  char user_salt[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
  char * plaintext;
#ifdef USE_MD5
  int i;
#endif

  if (argc < 2) {
    srandom(time(0));		/* may not be the BEST salt, but its close */
#ifdef USE_MD5
    /* Salt for MD5 -INT */
    strcpy(salt, "$1$");
    salt[3] = saltChars[random() % 64];
    salt[4] = saltChars[random() % 64];
    salt[5] = saltChars[random() % 64];
    salt[6] = saltChars[random() % 64];
    salt[7] = saltChars[random() % 64];
    salt[8] = saltChars[random() % 64];
    salt[9] = saltChars[random() % 64];
    salt[10] = saltChars[random() % 64];
    salt[11] = '$';
    salt[12] = 0;
#else
    /* Salt for DES -INT */
    salt[0] = saltChars[random() % 64];
    salt[1] = saltChars[random() % 64];
    salt[2] = 0;
#endif
  }
  else {
#ifdef USE_MD5
    /* Salt for MD5 -INT */
    strcpy(salt, "$1$");
    for (i=0; i<MIN(strlen(argv[1]), 8); i++) {
        if (strchr(saltChars, argv[1][i]) == NULL)
	        fprintf(stderr, "illegal salt %s\n", argv[1]), exit(1);
        user_salt[i] = argv[1][i];
    }

    strncat(salt, user_salt, i);
    strcat(salt, "$");
#else
    /* Salt for DES -INT */
    salt[0] = argv[1][0];
    salt[1] = argv[1][1];
    salt[2] = '\0';
    if ((strchr(saltChars, salt[0]) == NULL) || (strchr(saltChars, salt[1]) == NULL))
      fprintf(stderr, "illegal salt %s\n", salt), exit(1);
#endif
  }

  plaintext = getpass("plaintext: ");

  printf("%s\n", crypt(plaintext, salt));
  return 0;
}

