/************************************************************************
 *   IRC - Internet Relay Chat, tools/uncloak.c
 *   Copyright (C) 2009 Matteo Panella <morpheus@azzurra.org>
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
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "h.h"
#include "inet.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

static struct cpan_ctx *pa_ctx;
static struct cpan_ctx *np_ctx;
static unsigned char *cloak_key;
static unsigned short cloak_key_len;
static int expected_cloak_key_len;

char *MyMalloc(size_t sz)
{
    char *rv = malloc(sz);

    if (rv == NULL)
        abort();

    memset(rv, 0, sz);
    return rv;
}

int cloak_init(void)
{
    int fd;
    const EVP_CIPHER *cipher;

    OpenSSL_add_all_algorithms();

    if ((cipher = EVP_get_cipherbyname(CPAN_CIPHER_NAME)) == NULL)
    {
        fprintf(stderr, "Unable to load cipher " CPAN_CIPHER_NAME ", aborting.\n");
        return 0;
    }

    /* Compute expected key length */
    expected_cloak_key_len = EVP_CIPHER_key_length(cipher);
    expected_cloak_key_len += EVP_CIPHER_block_size(cipher);
    expected_cloak_key_len *= 2;

    if ((fd = open(CKPATH, O_RDONLY)))
    {
        struct stat st;
        char *buf;
        
        if(fstat(fd, &st) == 0)
        {
            int sz = st.st_size;

            if(sz >= expected_cloak_key_len)
            {
                if(sz > expected_cloak_key_len) /* Truncate the key */
                    sz = expected_cloak_key_len;

                buf = MyMalloc(sz + 1);
                read(fd, (void *) buf, sz);
                buf[sz] = '\0';
                cloak_key = buf;
                cloak_key_len = strlen(cloak_key);
            }
            else
            {
                close(fd);
                fprintf(stderr, "Key provided in "CKPATH" is too short. (%d < %d)\n",
                    sz, expected_cloak_key_len);
                return 0;
            }
        }
        else
        {
            close(fd);
            fprintf(stderr, "Failed to stat "CKPATH": %s\n",
                strerror(errno));
            return 0;
        }
    }
    else
    {
        fprintf(stderr, "Cannot open "CKPATH": %s\n",
            strerror(errno));
        return 0;
    }

    /* We have keys and initial pads, initialize the encryption contexts */
    if (((pa_ctx = cpan_init(cipher, cloak_key)) == NULL)
	|| ((np_ctx = cpan_init(cipher, cloak_key + (expected_cloak_key_len / 2))) == NULL))
    {
        fprintf(stderr, "Cannot initialize CryptoPan contexts, aborting.\n");
            return 0;
    }

    return 1;
}

/* Initialize a cpan context */
struct cpan_ctx *cpan_init(const EVP_CIPHER *cipher, const unsigned char *key)
{
    struct cpan_ctx *ctx;
    int tmp = 0, keylen;

    if (cipher == NULL || key == NULL)
        return NULL;

    ctx = (struct cpan_ctx *) MyMalloc(sizeof(struct cpan_ctx));

    /* Perform one-shot initialization */
    ctx->cipher = cipher;
    ctx->blocksize = EVP_CIPHER_block_size(ctx->cipher);
    ctx->pad = (unsigned char *)MyMalloc(ctx->blocksize);

    keylen = EVP_CIPHER_key_length(ctx->cipher);

    /* Initialize the encryption function */
    EVP_CIPHER_CTX_init(&ctx->evp);

    if (!EVP_EncryptInit_ex(&ctx->evp, cipher, NULL, key, NULL)
     || !EVP_EncryptUpdate(&ctx->evp, ctx->pad, &tmp, key+keylen, ctx->blocksize))

    {
        /* AAAAAAAAAAARGH */
        cpan_cleanup(ctx);
        return NULL;
    }

    return ctx;
}

void cpan_cleanup(struct cpan_ctx *ctx)
{
    if (ctx == NULL)
        return;
    EVP_CIPHER_CTX_cleanup(&ctx->evp);

    if (ctx->pad)
    {
        memset(ctx->pad, 0, ctx->blocksize);
        free(ctx->pad);
    }
    free(ctx);
}

int cpan_reload_key(struct cpan_ctx *ctx, const unsigned char *key)
{
    int keylen, tmp;
    if (ctx == NULL || key == NULL)
        return 0;

    /* Terminate and reinitialize the cipher context */
    EVP_CIPHER_CTX_cleanup(&ctx->evp);
    EVP_CIPHER_CTX_init(&ctx->evp);

    keylen = EVP_CIPHER_key_length(ctx->cipher);

    if (!EVP_EncryptInit_ex(&ctx->evp, ctx->cipher, NULL, key, NULL)
     || !EVP_EncryptUpdate(&ctx->evp, ctx->pad, &tmp, key+keylen, ctx->blocksize))
    {
        /* Now what? */
        return 0;
    }

    return 1;
}

uint32_t cpan_deanonymize(struct cpan_ctx *ctx, uint32_t orig_addr)
{
    uint8_t *rin_output, *rin_input;
    uint32_t first4bytes_pad, newpad, oaddr;
    int32_t pos, outlen, mask;

    if (ctx == NULL)
        return orig_addr;

    outlen = ctx->blocksize;
    rin_input = (uint8_t *)MyMalloc(ctx->blocksize);
    rin_output = (uint8_t *)MyMalloc(ctx->blocksize);
    memcpy(rin_input, ctx->pad, ctx->blocksize);

    /* Original address is in network byte order, perform all operations in
     * host byte order
     */
    oaddr = ntohl(orig_addr);

    first4bytes_pad = *(uint32_t *)ctx->pad;

    for (pos = 0; pos < 32; pos++)
    {
        mask = -1 << (32 - pos);
        newpad = (first4bytes_pad << pos) | (first4bytes_pad >> (32 - pos));
        if (pos == 0)
        {
            /* Workaround for braindead compilers */
            mask = 0;
            newpad = first4bytes_pad;
        }
        *(uint32_t *)rin_input = htonl(newpad ^ (oaddr & mask));
        if (EVP_EncryptUpdate(&ctx->evp, rin_output, &outlen, rin_input, ctx->blocksize) == 0)
            goto cleanup;

        oaddr ^= ((ntohl(*(uint32_t *)rin_output)) & 0x8000000) >> pos;
    }
    orig_addr = htonl(oaddr);

cleanup:
    free(rin_output);
    free(rin_input);
    return orig_addr;
}

uint32_t decrypt_ip(uint32_t masked_ip)
{
    uint32_t orig_ip, tmp = 0;
    int i;

    /* First round: deanonymize through the non prefx-preserving stage */
    orig_ip = cpan_deanonymize(np_ctx, masked_ip);
    if (orig_ip == masked_ip)
        return masked_ip;

    /* Second round: invert bits and deanonymize through the
     * prefix-preserving stage */
    for (i = 0; i < 32; i++)
    {
        tmp <<= 1;
        tmp |= orig_ip & 1;
        orig_ip >>= 1;
    }
    orig_ip = cpan_deanonymize(pa_ctx, tmp);
    if (orig_ip == tmp)
        return masked_ip;

    /* We're done */
    return orig_ip;
}

int main(int argc, char **argv)
{
    uint32_t csum;
    struct in_addr orig_ip;
    char *errptr = NULL;
    int i;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s checksum [checksum ...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!cloak_init())
        exit(EXIT_FAILURE);

    for (i = 1; i < argc; i++)
    {
        csum = htonl(strtoul(argv[i], &errptr, 16));
        if (errptr == argv[i] || *errptr != '\0')
        {
            fprintf(stderr, "Invalid checksum (%s)\n", argv[i]);
            continue;
        }
        orig_ip.s_addr = decrypt_ip(csum);
        if (orig_ip.s_addr == csum)
        {
            fprintf(stderr, "%s: cryptopan failure\n", argv[i]);
            continue;
        }
        printf("0x%08X -> %s\n", ntohl(csum), inet_ntoa(orig_ip));
    }
    cpan_cleanup(np_ctx);
    cpan_cleanup(pa_ctx);
    memset(cloak_key, 0, cloak_key_len);
    free(cloak_key);
    exit(EXIT_SUCCESS);
}

/* vim:ts=4:sw=4:et:
 */
