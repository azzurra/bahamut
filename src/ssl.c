/************************************************************************
 *   IRC - Internet Relay Chat, src/ssl.c
 *   Copyright (C) 2002 Barnaba Marcello <vjt@users.sf.net>
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
 *
 *   SSL functions . . .
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include <sys/types.h>
#include "h.h"

#ifdef USE_SSL

#include <openssl/dh.h>

/* from dh.c */
extern DH *get_dh1024(void);

#define SAFE_SSL_READ	1
#define SAFE_SSL_WRITE	2
#define SAFE_SSL_ACCEPT	3

/* Because I'm paranoid --morph */
#define IRCD_CIPHER_LIST "HIGH:!ADH:!MD5"

extern int errno;

SSL_CTX *ircdssl_ctx;
int ssl_capable = 0;

int initssl(void)
{
    DH *dh_tmp = NULL;

    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    ircdssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ircdssl_ctx) {
	ERR_print_errors_fp(stderr);
	return 0;
    }

    /* Kill SSLv2 support */
    SSL_CTX_set_options(ircdssl_ctx, SSL_OP_NO_SSLv2);

    if (SSL_CTX_use_certificate_chain_file(ircdssl_ctx,
		IRCDSSL_CPATH) <= 0) {
	ERR_print_errors_fp(stderr);
	SSL_CTX_free(ircdssl_ctx);
	return 0;
    }
    if (SSL_CTX_use_PrivateKey_file(ircdssl_ctx,
		IRCDSSL_KPATH, SSL_FILETYPE_PEM) <= 0) {
	ERR_print_errors_fp(stderr);
	SSL_CTX_free(ircdssl_ctx);
	return 0;
    }
    if (!SSL_CTX_check_private_key(ircdssl_ctx)) {
	fprintf(stderr, "Server certificate does not match Server key");
	SSL_CTX_free(ircdssl_ctx);
	return 0;
    }
    if (!SSL_CTX_set_cipher_list(ircdssl_ctx, IRCD_CIPHER_LIST))
    {
	ERR_print_errors_fp(stderr);
	SSL_CTX_free(ircdssl_ctx);
	return 0;
    }
    if ((dh_tmp = get_dh1024()) == NULL)
    {
	ERR_print_errors_fp(stderr);
	SSL_CTX_free(ircdssl_ctx);
	return 0;
    }
    if (!SSL_CTX_set_tmp_dh(ircdssl_ctx, dh_tmp))
    {
	ERR_print_errors_fp(stderr);
	SSL_CTX_free(ircdssl_ctx);
	DH_free(dh_tmp);
	return 0;
    }
    DH_free(dh_tmp);

    return 1;
}

static void disable_ssl(int do_errors)
{
    if(do_errors)
    {
	char buf[384];
	unsigned long e;

	while((e = ERR_get_error()))
	{
	    ERR_error_string_n(e, buf, sizeof(buf) - 1);
	    sendto_realops("SSL ERROR: %s", buf);
	}
    }

    if(ircdssl_ctx)
    {
	SSL_CTX_free(ircdssl_ctx);
    }

    sendto_ops("Disabling SSL support due to unrecoverable SSL errors. /REHASH again to retry.");
    ssl_capable = 0;

    return;
}

int rehash_ssl(void)
{
    DH *dh_tmp = NULL;

    if(ircdssl_ctx)
    {
	SSL_CTX_free(ircdssl_ctx);
    }

    if(!(ircdssl_ctx = SSL_CTX_new(SSLv23_server_method())))
    {
	disable_ssl(1);
	return 0;
    }

    /* Kill SSLv2 support */
    SSL_CTX_set_options(ircdssl_ctx, SSL_OP_NO_SSLv2);

    if (SSL_CTX_use_certificate_chain_file(ircdssl_ctx,
		IRCDSSL_CPATH) <= 0)
    {
	disable_ssl(1);

	return 0;
    }

    if (SSL_CTX_use_PrivateKey_file(ircdssl_ctx,
		IRCDSSL_KPATH, SSL_FILETYPE_PEM) <= 0)
    {
	disable_ssl(1);

	return 0;
    }

    if (!SSL_CTX_check_private_key(ircdssl_ctx))
    {
	sendto_realops("SSL ERROR: Server certificate does not match server key");
	disable_ssl(0);

	return 0;
    }

    if (!SSL_CTX_set_cipher_list(ircdssl_ctx, IRCD_CIPHER_LIST))
    {
	disable_ssl(1);
	return 0;
    }

    if ((dh_tmp = get_dh1024()) == NULL)
    {
	disable_ssl(1);
	return 0;
    }

    if (!SSL_CTX_set_tmp_dh(ircdssl_ctx, dh_tmp))
    {
	disable_ssl(1);
	DH_free(dh_tmp);
	return 0;
    }
    DH_free(dh_tmp);

    return 1;
}

static int fatal_ssl_error(int, int, aClient *);

int safe_SSL_read(aClient *acptr, void *buf, int sz)
{
    int len, ssl_err;

    len = SSL_read(acptr->ssl, buf, sz);
    if (len <= 0)
    {
	switch(ssl_err = SSL_get_error(acptr->ssl, len)) {
	    case SSL_ERROR_SYSCALL:
		if (errno == EWOULDBLOCK || errno == EAGAIN ||
			errno == EINTR) {
	    case SSL_ERROR_WANT_READ:
		    errno = EWOULDBLOCK;
		    return -1;
		}
	    case SSL_ERROR_SSL:
		if(errno == EAGAIN)
		    return -1;
	    default:
		return fatal_ssl_error(ssl_err, SAFE_SSL_READ, acptr);
	}
    }
    return len;
}

int safe_SSL_write(aClient *acptr, const void *buf, int sz)
{
    int len, ssl_err;

    len = SSL_write(acptr->ssl, buf, sz);
    if (len <= 0)
    {
	switch(ssl_err = SSL_get_error(acptr->ssl, len)) {
	    case SSL_ERROR_SYSCALL:
		if (errno == EWOULDBLOCK || errno == EAGAIN ||
			errno == EINTR) {
	    case SSL_ERROR_WANT_WRITE:
		    errno = EWOULDBLOCK;
		    return -1;
		}
	    case SSL_ERROR_SSL:
		if(errno == EAGAIN)
		    return -1;
	    default:
		return fatal_ssl_error(ssl_err, SAFE_SSL_WRITE, acptr);
	}
    }
    return len;
}

int safe_SSL_accept(aClient *acptr, int fd) {

    int ssl_err;

    if((ssl_err = SSL_accept(acptr->ssl)) <= 0) {
	switch(ssl_err = SSL_get_error(acptr->ssl, ssl_err)) {
	    case SSL_ERROR_SYSCALL:
		if (errno == EINTR || errno == EWOULDBLOCK
			|| errno == EAGAIN)
	    case SSL_ERROR_WANT_READ:
	    case SSL_ERROR_WANT_WRITE:
		    /* handshake will be completed later . . */
		    return 1;
	    default:
		return fatal_ssl_error(ssl_err, SAFE_SSL_ACCEPT, acptr);

	}
	/* NOTREACHED */
	return -1;
    }
    return 1;
}

int SSL_smart_shutdown(SSL *ssl) {
    char i;
    int rc;

    rc = 0;
    for(i = 0; i < 4; i++) {
	if((rc = SSL_shutdown(ssl)))
	    break;
    }

    return rc;
}

static int fatal_ssl_error(int ssl_error, int where, aClient *sptr)
{
    /* don`t alter errno */
    int errtmp = errno;
#if defined( SSL_DEBUG ) || defined( USE_SYSLOG )
    char *errstr = strerror(errtmp);
#endif
    char *ssl_errstr, *ssl_func;

    switch(where) {
	case SAFE_SSL_READ:
	    ssl_func = "SSL_read()";
	    break;
	case SAFE_SSL_WRITE:
	    ssl_func = "SSL_write()";
	    break;
	case SAFE_SSL_ACCEPT:
	    ssl_func = "SSL_accept()";
	    break;
	default:
	    ssl_func = "undefined SSL func [this is a bug] reporto to vjt@azzurra.org";
    }

    switch(ssl_error) {
    	case SSL_ERROR_NONE:
	    ssl_errstr = "No error";
	    break;
	case SSL_ERROR_SSL:
	    ssl_errstr = "Internal OpenSSL error or protocol error";
	    break;
	case SSL_ERROR_WANT_READ:
	    ssl_errstr = "OpenSSL functions requested a read()";
	    break;
	case SSL_ERROR_WANT_WRITE:
	    ssl_errstr = "OpenSSL functions requested a write()";
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    ssl_errstr = "OpenSSL requested a X509 lookup which didn`t arrive";
	    break;
	case SSL_ERROR_SYSCALL:
	    ssl_errstr = "Underlying syscall error";
	    break;
	case SSL_ERROR_ZERO_RETURN:
	    ssl_errstr = "Underlying socket operation returned zero";
	    break;
	case SSL_ERROR_WANT_CONNECT:
	    ssl_errstr = "OpenSSL functions wanted a connect()";
	    break;
	default:
	    ssl_errstr = "Unknown OpenSSL error (huh?)";
    }

#ifdef SSL_DEBUG
    sendto_realops_lev(DEBUG_LEV, "%s to "
		"%s!%s@%s aborted with%serror (%s). [%s]",
		ssl_func, *sptr->name ? sptr->name : "<unknown>",
		(sptr->user && sptr->user->username) ? sptr->user->
		username : "<unregistered>", sptr->sockhost,
		(errno > 0) ? " " : " no ", errstr, ssl_errstr);
#endif
#ifdef USE_SYSLOG
    syslog(LOG_ERR, "SSL error in %s: %s [%s]", ssl_func, errstr,
	    ssl_errstr);
#endif

    /* if we reply() something here, we might just trigger another
     * fatal_ssl_error() call and loop until a stack overflow...
     * the client won`t get the ERROR : ... string, but this is
     * the only way to do it.
     * IRC protocol wasn`t SSL enabled .. --vjt
     */

    errno = errtmp ? errtmp : EIO; /* Stick a generic I/O error */
    sptr->sockerr = IRCERR_SSL;
    sptr->flags |= FLAGS_DEADSOCKET;
    return -1;
}
#endif
