/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/schnorr.h>

typedef enum OPTION_choice
{
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_IN,
    OPT_OUT,
    OPT_NOOUT,
    OPT_TEXT,
    OPT_PUBIN,
    OPT_PUBOUT,
    OPT_SIGN,
    OPT_VERIFY,
    OPT_SIGNATURE,
    OPT_GENERATE
} OPTION_CHOICE;

const OPTIONS schnorr_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, 's', "Input key"},
    {"out", OPT_OUT, '>', "Output file "},
    {"noout", OPT_NOOUT, '-', "Don't print key out"},
    {"text", OPT_TEXT, '-', "Print the key in text"},
    {"pubin", OPT_PUBIN, '-', "Expect a public key in input file"},
    {"pubout", OPT_PUBOUT, '-', "Output public key, not private"},
    {"sign", OPT_SIGN, 's', "Sign digest using private key"},
    {"verify", OPT_VERIFY, 's', "Verify a signature using public key"},
    {"signature", OPT_SIGNATURE, '<', "File with signature to verify"},
    {"generate", OPT_GENERATE, '-', "Generate a key pair"},
    {NULL}};

int schnorr_main(int argc, char **argv)
{
    // BIO *out = NULL;

    char *infile = NULL, *outfile = NULL, *prog;
    OPTION_CHOICE o;
    int text = 0, noout = 0;
    int i, pubin = 0, pubout = 0, ret = 1;
    int sign = 0, verify = 0, generate = 0;
    char *keyfile = NULL, *sigfile = NULL;

    prog = opt_init(argc, argv, schnorr_options);
    while ((o = opt_next()) != OPT_EOF)
    {
        switch (o)
        {
        case OPT_EOF:
        case OPT_ERR:
        opthelp:
            ret = 0;
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(schnorr_options);
            ret = 0;
            goto end;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_PUBIN:
            pubin = 1;
            break;
        case OPT_PUBOUT:
            pubout = 1;
            break;
        case OPT_SIGN:
            sign = 1;
            keyfile = opt_arg();
            break;
        case OPT_SIGNATURE:
            sigfile = opt_arg();
            break;
        case OPT_VERIFY:
            verify = 1;
            keyfile = opt_arg();
            break;
        case OPT_GENERATE:
            generate = 1;
            break;
        }
    }

    argc = opt_num_rest();
    if (argc > 1)
        goto opthelp;

    if (generate)
    {
        if (outfile != NULL)
        {
            printf("outputfile : %s\n", outfile);
            EC_KEY *key;
            int ret_code = Gen(&key);
            if (ret_code != 0)
            {
                printf("Error generating a key pair!\n");
                goto end;
            }
            ret_code = Write_Schnorr_Private_Key(key, outfile);
            if (ret_code != 0)
            {
                printf("Error writing a key pair!\n");
                goto end;
            }
        }
        else
        {
            goto opthelp;
        }
        ret = 0;
        goto end;
    }

    if (text)
    {
        BIO *out = BIO_new_fp(stdout, 0);
        EVP_PKEY *pk = EVP_PKEY_new();
        pk = load_key(infile, FORMAT_PEM, 1, NULL, NULL, "Private Key");
        EVP_PKEY_print_private(out, pk, 0, NULL);
    }

    if (noout)
    {
        ret = 0;
        goto end;
    }

    ret = 0;
end:
    return ret;
}
