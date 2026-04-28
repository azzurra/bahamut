#!/bin/sh
. tools/ssl-search.sh
cat Makefile | sed "s#^\(SSLFLAGS=\).*#\1 $SSL_INCLUDE#" > Makefile.tmp
cat Makefile.tmp | sed "s#^\(LDFLAGS=\).*#\1 $SSL_LIB#" > Makefile
rm -f Makefile.tmp
