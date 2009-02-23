#ifndef __SSL_INCLUDE__
#define __SSL_INCLUDE__

int safe_SSL_read(aClient *, void *, int);
int safe_SSL_write(aClient *, const void *, int);
int safe_SSL_accept(aClient *, int);
int SSL_smart_shutdown(SSL *);
int initssl(void);
int rehash_ssl(void);

#endif
