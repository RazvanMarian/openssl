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
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
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
    int pubin = 0, pubout = 0, ret = 1;
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
            pubin = verify = 1;
            keyfile = opt_arg();
            break;
        case OPT_GENERATE:
            generate = 1;
            break;
        }
    }

    argc = opt_num_rest();
    argv = opt_rest();
    if (argc > 1)
        goto opthelp;

    if (generate)
    {
        if (outfile != NULL)
        {
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

    if (pubout)
    {
        if (infile != NULL && outfile != NULL)
        {
            EC_KEY *key_pair = EC_KEY_new();
            if (Read_Schnorr_Private_key(&key_pair, infile) != 0)
            {
                BIO_printf(bio_err, "%s: Could not open the file to be signed.\n", prog);
                goto end;
            }

            if (Write_Schnorr_Public_Key(key_pair, outfile) != 0)
            {
                BIO_printf(bio_err, "%s: Could not open the file to be signed.\n", prog);
                goto end;
            }

            printf("Public key written to %s.\n", outfile);
        }
        else
        {
            goto opthelp;
        }
    }

    if (text)
    {
        BIO *out = BIO_new_fp(stdout, 0);
        EVP_PKEY *pk = EVP_PKEY_new();
        pk = load_key(infile, FORMAT_PEM, 1, NULL, NULL, "Private Key");
        EVP_PKEY_print_private(out, pk, 0, NULL);
        BIO_free_all(out);
    }

    if (noout)
    {
        ret = 0;
        goto end;
    }

    if (sign)
    {
        if (argv[0] != NULL && keyfile != NULL && outfile != NULL)
        {
            char *file_to_be_signed = argv[0];

            // read file input
            FILE *f_in = fopen(file_to_be_signed, "rb");
            if (f_in == NULL)
            {
                BIO_printf(bio_err, "%s: Could not open the file to be signed.\n", prog);
                goto end;
            }
            fseek(f_in, 0, SEEK_END);
            long fsize = ftell(f_in);
            fseek(f_in, 0, SEEK_SET); /* same as rewind(f); */

            char *file_content = malloc(fsize + 1);
            if (fread(file_content, fsize, 1, f_in) == 0)
            {
                BIO_printf(bio_err, "%s: Could not read from the file to be signed.\n", prog);
                goto end;
            }
            fclose(f_in);
            file_content[fsize] = 0;
            //*******************************

            // Compute file hash
            unsigned char *file_hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
            SHA256((unsigned char *)file_content, fsize, file_hash);

            // load private key

            EC_KEY *private_key = EC_KEY_new();
            if (Read_Schnorr_Private_key(&private_key, keyfile) != 0)
            {
                BIO_printf(bio_err, "%s: Could not load the private key.\n", prog);
                goto end;
            }

            // sign the document
            schnorr_signature *signature = Schnorr_SIG_new();

            if (Schnorr_Sign(private_key, (const char *)file_hash, SHA256_DIGEST_LENGTH, signature) != 0)
            {
                BIO_printf(bio_err, "%s: Error signing the file.\n", prog);
                goto end;
            }

            if (Write_Schnorr_Signature(signature, outfile) != 0)
            {
                BIO_printf(bio_err, "%s: Error writing the signature in the output file.\n", prog);
                goto end;
            }

            printf("The file %s was signed. The signature should be in %s.\n", file_to_be_signed, outfile);
        }
        else
        {
            goto opthelp;
        }
    }

    if (verify)
    {
        if (pubin && sigfile != NULL && argv[0] != NULL)
        {
            char *file_to_be_verified = argv[0];

            // read file input
            FILE *f_in = fopen(file_to_be_verified, "rb");
            if (f_in == NULL)
            {
                BIO_printf(bio_err, "%s: Could not open the file to be signed.\n", prog);
                goto end;
            }
            fseek(f_in, 0, SEEK_END);
            long fsize = ftell(f_in);
            fseek(f_in, 0, SEEK_SET); /* same as rewind(f); */

            char *file_content = malloc(fsize + 1);
            if (fread(file_content, fsize, 1, f_in) == 0)
            {
                BIO_printf(bio_err, "%s: Could not read from the file to be signed.\n", prog);
                goto end;
            }
            fclose(f_in);
            file_content[fsize] = 0;
            //*******************************

            // Compute file hash
            unsigned char *file_hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
            SHA256((unsigned char *)file_content, fsize, file_hash);

            EC_KEY *public_key = EC_KEY_new();
            if (Read_Schnorr_Public_Key(&public_key, keyfile) != 0)
            {
                BIO_printf(bio_err, "%s: Could not load the private key.\n", prog);
                goto end;
            }

            schnorr_signature *signature = Schnorr_SIG_new();
            if (Read_Schnorr_Signature(signature, sigfile) != 0)
            {
                BIO_printf(bio_err, "%s: Could not read the signature from the specified file.\n", prog);
                goto end;
            }

            if (Verify_Sign(public_key, (const char *)file_hash, SHA256_DIGEST_LENGTH, signature) != 0)
            {
                BIO_printf(bio_err, "%s: Could not verify the signature. Signature IS NOT OK.\n", prog);
                goto end;
            }
            printf("Verified OK!\n");
        }
        else
        {
            goto opthelp;
        }
    }
    ret = 0;
end:
    return ret;
}
