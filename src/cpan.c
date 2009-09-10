/************************************************************************
 *   Bahamut / Azzurra src/cpan.c
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2, or (at your option)
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
 */

#include "struct.h"

#ifdef AZZURRA
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include <string.h>
#include "h.h"

static char *get_libcrypto_error(void);

struct cpan_ctx *cpan_init(const EVP_CIPHER *cipher, const unsigned char *key)
{
    struct cpan_ctx *ctx;
    int tmp = 0, keylen;
    char *errptr;

    if (cipher == NULL || key == NULL)
    {
#if defined(USE_SYSLOG)
        syslog(LOG_CRIT, "cpan_init called with NULL arguments");
#endif
        sendto_realops_lev(DEBUG_LEV, "cpan_init called with NULL arguments");
        return NULL;
    }

    ctx = (struct cpan_ctx *)MyMalloc(sizeof(struct cpan_ctx));

    /* Perform one-shot initialization */
    ctx->cipher = cipher;
    ctx->blocksize = EVP_CIPHER_block_size(ctx->cipher);
    ctx->pad = (unsigned char *)MyMalloc(ctx->blocksize);

    keylen = EVP_CIPHER_key_length(ctx->cipher);

    /* Initialize the encryption context */
    EVP_CIPHER_CTX_init(&ctx->evp);
    if (!EVP_EncryptInit_ex(&ctx->evp, ctx->cipher, NULL, key, NULL)
        || !EVP_EncryptUpdate(&ctx->evp, ctx->pad, &tmp, key + keylen, ctx->blocksize))
    {
        errptr = get_libcrypto_error();
#if defined(USE_SYSLOG)
        syslog(LOG_ERR, "cpan_init: cipher context initialization failed: %s", 
               errptr);
#endif
        sendto_realops_lev(DEBUG_LEV, "cpan_init: cipher context initialization failed: %s\n",
                errptr);
        cpan_cleanup(ctx);
        return NULL;
    }

    return ctx;
}

void cpan_cleanup(struct cpan_ctx *ctx)
{
    if (ctx == NULL)
    {
#if defined(USE_SYSLOG)
        syslog(LOG_CRIT, "cpan_cleanup called with NULL argument");
#endif
        sendto_realops_lev(DEBUG_LEV, "cpan_cleanup called with NULL argument");
        return;
    }
    (void) EVP_CIPHER_CTX_cleanup(&ctx->evp);

    if (ctx->pad)
    {
        memset(ctx->pad, 0, ctx->blocksize);
        MyFree(ctx->pad);
    }
    MyFree(ctx);
}

/* It is quite unlikely that a given IPv4 address would be
 * anonymized as itself, so we signal an error by returning
 * the original address.
 */
uint32_t cpan_anonymize(struct cpan_ctx *ctx, uint32_t orig_addr)
{
    uint8_t *rin_input, *rin_output;
    uint32_t result = 0, first4bytes_pad, newpad, oaddr, mask;
    int pos, outlen;
    char *errptr;

    if (ctx == NULL)
    {
#if defined(USE_SYSLOG)
        syslog(LOG_CRIT, "cpan_anonymize called with NULL context");
#endif
        sendto_realops_lev(DEBUG_LEV, "cpan_anonymize called with NULL context");
        return orig_addr;
    }

    outlen = ctx->blocksize;
    rin_input = (uint8_t *)MyMalloc(ctx->blocksize);
    rin_output = (uint8_t *)MyMalloc(ctx->blocksize);
    memcpy(rin_input, ctx->pad, ctx->blocksize);

    /* Incoming address is in network byte order, perform all
     * operations in host byte order
     */
    oaddr = ntohl(orig_addr);

    first4bytes_pad = *(uint32_t *)ctx->pad;

    /* Generate a bit for each prefix with length ranging from 1
     * to 32 using the given cipher as a PRNG.
     * The bits are combined into a 32bit pseudorandom one-time pad.
     */
    for (pos = 0; pos < 32; pos++)
    {
        mask = -1 << (32 - pos);
        newpad = (first4bytes_pad << pos) | (first4bytes_pad >> (32 - pos));
        if (pos == 0)
        {
            /* Some architectures thinks that -1 << 32 is
             * 0xFFFFFFFF instead of 0. Go figures.
             */
            mask = 0;
            newpad = first4bytes_pad;
        }

        /* Convert the encryption function input in network byte order */
        *(uint32_t *)rin_input = htonl(newpad ^ (oaddr & mask));

        if (EVP_EncryptUpdate(&ctx->evp, rin_output, &outlen, rin_input, ctx->blocksize) == 0)
        {
            errptr = get_libcrypto_error();
#if defined(USE_SYSLOG)
            syslog(LOG_ERR, "cpan_anonymize failed: %s", errptr);
#endif
            sendto_realops_lev(DEBUG_LEV, "cpan_anonymize failed: %s", errptr);
            goto cleanup;
        }

        /* Take the MSB of the output (host byte order) and combine it with
         * the pseudorandom one-time pad
         */
        result |= ((ntohl(*(uint32_t *)rin_output)) & 0x8000000) >> pos;
    }

    /* XOR the original address with the given one-time pad and
     * convert the result into network byte order
     */
    orig_addr = htonl(oaddr ^ result);

cleanup:
    MyFree(rin_output);
    MyFree(rin_input);

    return orig_addr;
}

/* Ugly hack */
static char *get_libcrypto_error(void)
{
    static char buf[384];
    unsigned long e;

    e = ERR_get_error();
    if (e)
        ERR_error_string_n(e, buf, sizeof(buf) - 1);
    else
        strncpyzt(buf, "No error", sizeof(buf) - 1);

    return buf;
}

/* vim:ts=4:sw=4:et:
 */

#endif
