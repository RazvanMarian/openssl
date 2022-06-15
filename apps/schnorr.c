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
#include <string.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/schnorr.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>

X509 *create_certificate(EC_KEY *key, int flag);

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
    OPT_GENERATE,
    OPT_MULTIPLE_SIGN,
    OPT_MULTIPLE_SIGNER,
    OPT_MULTIPLE_VERIFY,
    OPT_MULTIPLE_VERIFIER,
    OPT_SIGNED_DATA,
    OPT_VERIFY_PKCS7
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
    {"verifypkcs7", OPT_VERIFY_PKCS7, '-', "Verify a signature using public key"},
    {"signature", OPT_SIGNATURE, '<', "File with signature to verify"},
    {"genschnorr", OPT_GENERATE, '-', "Generate a key pair"},
    {"multiplesign", OPT_MULTIPLE_SIGN, 's', "Aggregate signature"},
    {"signer", OPT_MULTIPLE_SIGNER, 's', "Aggregate signer private key"},
    {"multipleverify", OPT_MULTIPLE_VERIFY, 's', "Aggregate verification"},
    {"verifier", OPT_MULTIPLE_VERIFIER, 's', "Aggregate verifier public key"},
    {"pkcs7", OPT_SIGNED_DATA, '-', "Verify a pkcs7 schnorr signature structure"},
    {NULL}};

int schnorr_main(int argc, char **argv)
{
    // BIO *out = NULL;

    char *infile = NULL, *outfile = NULL, *prog;
    OPTION_CHOICE o;
    int text = 0, noout = 0;
    int pubin = 0, pubout = 0, ret = 1;
    int sign = 0, verify = 0, generate = 0;
    int multiple_sign = 0, multiple_verify = 0, signed_data = 0;
    int signers_number = 0, participant_counter = 0, verifier_counter = 0;
    char *keyfile = NULL, *sigfile = NULL, **key_files = NULL;

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
        case OPT_VERIFY_PKCS7:
            pubin = verify = 1;
            signed_data = 1;
            break;
        case OPT_GENERATE:
            generate = 1;
            break;
        case OPT_SIGNED_DATA:
            signed_data = 1;
            break;
        case OPT_MULTIPLE_SIGN:

            multiple_sign = 1;
            signers_number = atoi(opt_arg());
            key_files = (char **)malloc(sizeof(char *) * signers_number);
            break;
        case OPT_MULTIPLE_SIGNER:

            if (participant_counter < signers_number)
            {
                key_files[participant_counter] = strdup(opt_arg());
                participant_counter++;
            }
            else
                goto opthelp;

            break;

        case OPT_MULTIPLE_VERIFY:

            pubin = multiple_verify = 1;
            signers_number = atoi(opt_arg());
            key_files = (char **)malloc(sizeof(char *) * signers_number);
            break;
        case OPT_MULTIPLE_VERIFIER:

            if (verifier_counter < signers_number)
            {
                key_files[verifier_counter] = strdup(opt_arg());
                verifier_counter++;
            }
            else
                goto opthelp;

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
            int ret_code = SCHNORR_generate_key(&key);
            if (ret_code != 0)
            {
                printf("Error generating a key pair!\n");
                goto end;
            }
            ret_code = SCHNORR_write_private_key(key, outfile);
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
            if (SCHNORR_read_private_key(&key_pair, infile) != 0)
            {
                BIO_printf(bio_err, "%s: Could not open the file to be signed.\n", prog);
                goto end;
            }

            if (SCHNORR_write_public_key(key_pair, outfile) != 0)
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

    if (multiple_sign)
    {
        if (signers_number != participant_counter)
        {
            goto opthelp;
        }

        if (argv[0] != NULL && key_files != NULL && outfile != NULL)
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

            EC_KEY **keys = (EC_KEY **)malloc(sizeof(EC_KEY *) * signers_number);

            int res;
            for (int i = 0; i < signers_number; i++)
            {

                res = SCHNORR_read_private_key(&keys[i], key_files[i]);
                if (res != 0)
                {
                    BIO_printf(bio_err, "%s: Could not load the private key.\n", prog);
                    goto end;
                }
            }

            // sign the document
            SCHNORR_SIG *signature = SCHNORR_SIG_new();

            if (SCHNORR_multiple_sign(keys, signers_number, (const char *)file_hash, SHA256_DIGEST_LENGTH, signature) != 0)
            {
                BIO_printf(bio_err, "%s: Error signing the file.\n", prog);
                goto end;
            }

            if (signed_data)
            {
                X509 **certificates = (X509 **)malloc(sizeof(X509 *) * signers_number);

                for (int i = 0; i < signers_number; i++)
                {
                    certificates[i] = create_certificate(keys[i], 0);
                }

                SCHNORR_SIGNED_DATA *data = SCHNORR_create_pkcs7(keys, certificates, signers_number, signature);

                write_schnorr_signed_data_asn1(data, outfile);
            }
            else
            {

                if (SCHNORR_write_signature(signature, outfile) != 0)
                {
                    BIO_printf(bio_err, "%s: Error writing the signature in the output file.\n", prog);
                    goto end;
                }
            }

            printf("The file %s was signed. The signature should be in %s.\n", file_to_be_signed, outfile);
        }
        else
        {
            goto opthelp;
        }
    }

    if (multiple_verify)
    {
        if (signers_number != verifier_counter)
        {
            goto opthelp;
        }

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

            EC_KEY **keys = (EC_KEY **)malloc(sizeof(EC_KEY *) * signers_number);

            int res;
            for (int i = 0; i < signers_number; i++)
            {

                res = SCHNORR_read_public_key(&keys[i], key_files[i]);
                if (res != 0)
                {
                    BIO_printf(bio_err, "%s: Could not load the public key.\n", prog);
                    goto end;
                }
            }

            SCHNORR_SIG *signature = SCHNORR_SIG_new();
            if (SCHNORR_read_signature(signature, sigfile) != 0)
            {
                BIO_printf(bio_err, "%s: Could not read the signature from the specified file.\n", prog);
                goto end;
            }

            if (SCHNORR_multiple_verify(keys, signers_number, (const char *)file_hash, SHA256_DIGEST_LENGTH, signature) != 0)
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
            if (SCHNORR_read_private_key(&private_key, keyfile) != 0)
            {
                BIO_printf(bio_err, "%s: Could not load the private key.\n", prog);
                goto end;
            }

            // sign the document
            SCHNORR_SIG *signature = SCHNORR_SIG_new();

            if (SCHNORR_sign(private_key, (const char *)file_hash, SHA256_DIGEST_LENGTH, signature) != 0)
            {
                BIO_printf(bio_err, "%s: Error signing the file.\n", prog);
                goto end;
            }

            if (signed_data)
            {
                EC_KEY **keys = (EC_KEY **)malloc(sizeof(EC_KEY *));
                keys[0] = EC_KEY_dup(private_key);

                X509 **certificates = (X509 **)malloc(sizeof(X509 *));

                certificates[0] = create_certificate(keys[0], 0);

                SCHNORR_SIGNED_DATA *data = SCHNORR_create_pkcs7(keys, certificates, 1, signature);

                write_schnorr_signed_data_asn1(data, outfile);
            }
            else
            {

                if (SCHNORR_write_signature(signature, outfile) != 0)
                {
                    BIO_printf(bio_err, "%s: Error writing the signature in the output file.\n", prog);
                    goto end;
                }
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

            if (signed_data == 1)
            {
                SCHNORR_SIGNED_DATA *data;
                read_schnorr_signed_data_asn1(&data, sigfile);

                STACK_OF(X509) *x509_stack = SCHNORR_get_signers_certificates(data);
                if (x509_stack == NULL)
                {
                    printf("eroare preluare certificate\n");
                    return -1;
                }

                SCHNORR_SIG *signature = SCHNORR_get_signature(data);
                if (signature == NULL)
                {
                    printf("eroare preluare semnatura\n");
                    return -1;
                }
                int signers_number = sk_X509_num(x509_stack);

                EC_KEY **keys = (EC_KEY **)malloc(sizeof(EC_KEY *) * signers_number);
                for (int i = 0; i < signers_number; i++)
                {
                    X509 *cert = sk_X509_value(x509_stack, i);
                    EVP_PKEY *pkey = X509_get_pubkey(cert);

                    keys[i] = EVP_PKEY_get0_EC_KEY(pkey);
                }
                if (SCHNORR_multiple_verify(keys, signers_number, file_hash, SHA256_DIGEST_LENGTH, signature) != 0)
                {
                    printf("eroare verificare\n");
                    return -1;
                }
            }
            else
            {
                EC_KEY *public_key = EC_KEY_new();
                if (SCHNORR_read_public_key(&public_key, keyfile) != 0)
                {
                    BIO_printf(bio_err, "%s: Could not load the private key.\n", prog);
                    goto end;
                }

                SCHNORR_SIG *signature = SCHNORR_SIG_new();
                if (SCHNORR_read_signature(signature, sigfile) != 0)
                {
                    BIO_printf(bio_err, "%s: Could not read the signature from the specified file.\n", prog);
                    goto end;
                }

                if (SCHNORR_verify(public_key, (const char *)file_hash, SHA256_DIGEST_LENGTH, signature) != 0)
                {
                    BIO_printf(bio_err, "%s: Could not verify the signature. Signature IS NOT OK.\n", prog);
                    goto end;
                }
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

X509 *create_certificate(EC_KEY *key, int flag)
{

    int ret;

    // Setare cheie publica cerere certificat
    EVP_PKEY *pKey = EVP_PKEY_new();
    ret = EVP_PKEY_set1_EC_KEY(pKey, key);
    if (ret != 1)
    {
        printf("eroare setare cheie evp!\n");
        return NULL;
    }

    // Incarcare certificat CA
    FILE *fp;
    if (!(fp = fopen("myCA.pem", "r")))
    {
        printf("Eroare la citirea certificatului CA-ului\n");
        return NULL;
    }

    X509 *cacert;
    if (!(cacert = PEM_read_X509(fp, NULL, NULL, NULL)))
    {
        printf("Eroare incarcare certificat CA in memorie!\n");
        return NULL;
    }
    fclose(fp);

    // Importare cheie privata CA
    EVP_PKEY *ca_privkey = EVP_PKEY_new();

    if (!(fp = fopen("myCA.key", "r")))
    {
        printf("Eroare deschidere fisier cheie CA\n");
        return NULL;
    }

    if (!(ca_privkey = PEM_read_PrivateKey(fp, NULL, NULL, (void *)"1234")))
    {
        printf("Eroare citire cheie privata CA\n");
        return NULL;
    }

    fclose(fp);

    // Creare certificat
    X509 *newcert;
    if (!(newcert = X509_new()))
    {
        printf("Eroare alocare certificat nou!\n");
        return NULL;
    }

    if (X509_set_version(newcert, 2) != 1)
    {
        printf("Eroare setare versiune certificat\n");
        return NULL;
    }

    // Setare serial number certificat
    ASN1_INTEGER *aserial = ASN1_INTEGER_new();
    ASN1_INTEGER_set(aserial, 1);
    if (!X509_set_serialNumber(newcert, aserial))
    {
        printf("Eroare setare serie certificat!\n");
        return NULL;
    }

    // Extragere subject name din request
    X509_NAME *name;
    if (!(name = X509_get_subject_name(newcert)))
        printf("Eroare preluare subiect din cerere!\n");

    // Setare subject name in certificatul nou
    if (X509_set_subject_name(newcert, name) != 1)
    {
        printf("Eroare setare subject name certificat!\n");
        return NULL;
    }

    // Extragere subject name din certificatul CA
    if (!(name = X509_get_subject_name(cacert)))
    {
        printf("Eroare preluare subject name de la certificatul CA!\n");
        return NULL;
    }

    // Setare issuer name
    if (X509_set_issuer_name(newcert, name) != 1)
    {
        printf("Eroare setare issuer name!\n");
        return NULL;
    }

    // Setare cheie publica certificat
    if (X509_set_pubkey(newcert, pKey) != 1)
    {
        printf("Eroare setare cheie publica certificat!\n");
        return NULL;
    }

    // Setare valabilitate 365 de zile
    if (!(X509_gmtime_adj(X509_get_notBefore(newcert), 0)))
    {
        printf("Eroare setare start date!\n");
        return NULL;
    }

    if (!(X509_gmtime_adj(X509_get_notAfter(newcert), 31536000L)))
    {
        printf("Eroare setare expiration date!\n");
        return NULL;
    }

    // Adaugare extensie x509V3
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cacert, newcert, NULL, NULL, 0);
    X509_EXTENSION *ext;

    // Semnarea certificatului cu cheia privata a CA-ului
    EVP_MD const *digest = NULL;
    digest = EVP_sha256();

    if (!X509_sign(newcert, ca_privkey, digest))
    {
        printf("Eroare setare digest type!\n");
        return NULL;
    }

    return newcert;
}
