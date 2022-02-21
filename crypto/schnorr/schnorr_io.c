#include "schnorr_local.h"

int Write_Schnorr_Private_Key(EC_KEY *key, const char *filename)
{
    BIO *output = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    output = BIO_new_file(filename, "wb");

    if (!PEM_write_bio_ECPrivateKey(output, key, NULL, NULL, 0, 0, NULL))
    {
        printf("Eroare scriere cheie privata in format PEM\n");
        return -1;
    }

    // Free
    BIO_free_all(output);
    return 0;
}

int Write_Schnorr_Public_Key(EC_KEY *key, const char *filename)
{
    BIO *output = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    output = BIO_new_file(filename, "wb");

    if (!PEM_write_bio_EC_PUBKEY(output, key))
    {
        printf("Eroare scriere cheie publica in format PEM\n");
        return -1;
    }

    // Free
    BIO_free_all(output);
    return 0;
}

int Read_Schnorr_Private_key(EC_KEY **key, const char *filename)
{
    BIO *output = NULL;
    *key = EC_KEY_new();

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    output = BIO_new_file(filename, "rb");

    if (!PEM_read_bio_ECPrivateKey(output, key, 0, NULL))
    {
        printf("Eroare citire cheie privata in format PEM\n");
        return -1;
    }

    // Free
    BIO_free_all(output);
    return 0;
}

int Read_Schnorr_Public_Key(EC_KEY **key, const char *filename)
{
    BIO *output = NULL;
    *key = EC_KEY_new();

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    output = BIO_new_file(filename, "rb");

    if (!PEM_read_bio_EC_PUBKEY(output, key, 0, NULL))
    {
        printf("Eroare citire cheie publica in format PEM\n");
        return -1;
    }

    // Free
    BIO_free_all(output);

    return 0;
}

int Write_Schnorr_Signature(schnorr_signature *signature, const char *filename)
{
    unsigned char *r = (unsigned char *)malloc(BN_num_bytes((*signature).r) * sizeof(unsigned char));
    unsigned char *s = (unsigned char *)malloc(BN_num_bytes((*signature).s) * sizeof(unsigned char));

    int size_r = BN_bn2binpad((*signature).r, r, SIGNATURE_COMPONENT_SIZE);
    if (size_r == 0)
    {
        printf("Eroare la conversia componentei r!\n");
        return -1;
    }

    int size_s = BN_bn2binpad((*signature).s, s, SIGNATURE_COMPONENT_SIZE);
    if (size_s == 0)
    {
        printf("Eroare la conversia componentei s!\n");
        return -1;
    }

    FILE *fout = fopen(filename, "wb");
    if (fout == NULL)
    {
        printf("Nu s-a putut deschide fisierul pentru scrierea semnaturii!\n");
        return -1;
    }

    int res = fwrite(r, sizeof(unsigned char), size_r, fout);
    if (res != size_r)
    {
        printf("Eroare la scrierea componentei r!\n");
        return -1;
    }

    res = fwrite(s, sizeof(unsigned char), size_s, fout);
    if (res != size_s)
    {
        printf("Eroare la scrierea componentei s!\n");
        return -1;
    }
    fclose(fout);
    return 0;
}

int Read_Schnorr_Signature(schnorr_signature *sig, const char *filename)
{
    unsigned char *r = (unsigned char *)malloc(SIGNATURE_COMPONENT_SIZE * sizeof(unsigned char));
    unsigned char *s = (unsigned char *)malloc(SIGNATURE_COMPONENT_SIZE * sizeof(unsigned char));

    FILE *fin = fopen(filename, "rb");
    if (fin == NULL)
    {
        printf("Fisierul nu a puut fi deschis\n");
        return -1;
    }

    int ret = fread(r, sizeof(unsigned char), SIGNATURE_COMPONENT_SIZE, fin);
    if (ret != SIGNATURE_COMPONENT_SIZE)
    {
        printf("Eroare la citirea semnaturii!\n");
        return -1;
    }

    ret = fread(s, sizeof(unsigned char), SIGNATURE_COMPONENT_SIZE, fin);
    if (ret != SIGNATURE_COMPONENT_SIZE)
    {
        printf("Eroare la citirea semnaturii!\n");
        return -1;
    }

    (*sig).r = BN_bin2bn(r, SIGNATURE_COMPONENT_SIZE, NULL);
    if ((*sig).r == NULL)
    {
        printf("Eroare la conversia semnaturii in BN!\n");
        return -1;
    }

    (*sig).s = BN_bin2bn(s, SIGNATURE_COMPONENT_SIZE, NULL);
    if ((*sig).s == NULL)
    {
        printf("Eroare la conversia semnaturii in BN!\n");
        return -1;
    }

    return 0;
}