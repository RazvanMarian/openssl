#include "schnorr_local.h"

char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                         'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                         'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                         'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                         'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                         'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                         'w', 'x', 'y', 'z', '0', '1', '2', '3',
                         '4', '5', '6', '7', '8', '9', '+', '/'};
char *decoding_table = NULL;
int mod_table[] = {0, 2, 1};

ASN1_SEQUENCE(SCHNORR_SIGNER_INFO) =
    {
        ASN1_SIMPLE(SCHNORR_SIGNER_INFO, version, ASN1_INTEGER),
        ASN1_SIMPLE(SCHNORR_SIGNER_INFO, signature_id, ASN1_INTEGER),
        ASN1_SIMPLE(SCHNORR_SIGNER_INFO, issuer_and_serial, PKCS7_ISSUER_AND_SERIAL),
        ASN1_SIMPLE(SCHNORR_SIGNER_INFO, digest_alg, X509_ALGOR),
        ASN1_SET_OF(SCHNORR_SIGNER_INFO, auth_attr, X509_ATTRIBUTE),
        ASN1_SET_OF(SCHNORR_SIGNER_INFO, unauth_attr, X509_ATTRIBUTE)

} ASN1_SEQUENCE_END(SCHNORR_SIGNER_INFO);

DECLARE_ASN1_FUNCTIONS(SCHNORR_SIGNER_INFO);
IMPLEMENT_ASN1_FUNCTIONS(SCHNORR_SIGNER_INFO);
DEFINE_STACK_OF(SCHNORR_SIGNER_INFO);

ASN1_SEQUENCE(SCHNORR_SIGNATURE_ASN1) =
    {
        ASN1_SIMPLE(SCHNORR_SIGNATURE_ASN1, id, ASN1_INTEGER),
        ASN1_SIMPLE(SCHNORR_SIGNATURE_ASN1, enc_digest, ASN1_OCTET_STRING)

} ASN1_SEQUENCE_END(SCHNORR_SIGNATURE_ASN1);

DECLARE_ASN1_FUNCTIONS(SCHNORR_SIGNATURE_ASN1);
IMPLEMENT_ASN1_FUNCTIONS(SCHNORR_SIGNATURE_ASN1);
DEFINE_STACK_OF(SCHNORR_SIGNATURE_ASN1);

ASN1_SEQUENCE(SCHNORR_SIGNED_DATA) =
    {
        ASN1_SIMPLE(SCHNORR_SIGNED_DATA, version, ASN1_INTEGER),
        ASN1_SET_OF(SCHNORR_SIGNED_DATA, md_algs, X509_ALGOR),
        ASN1_SET_OF(SCHNORR_SIGNED_DATA, cert, X509),
        ASN1_SET_OF(SCHNORR_SIGNED_DATA, crl, X509_CRL),
        ASN1_SET_OF(SCHNORR_SIGNED_DATA, signer_info, SCHNORR_SIGNER_INFO),
        ASN1_SET_OF(SCHNORR_SIGNED_DATA, signature, SCHNORR_SIGNATURE_ASN1)

} ASN1_SEQUENCE_END(SCHNORR_SIGNED_DATA);

DECLARE_ASN1_FUNCTIONS(SCHNORR_SIGNED_DATA);
IMPLEMENT_ASN1_FUNCTIONS(SCHNORR_SIGNED_DATA);

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length)
{

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = (char *)malloc(*output_length);
    if (encoded_data == NULL)
        return NULL;

    for (int i = 0, j = 0; i < input_length;)
    {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

void build_decoding_table()
{

    decoding_table = (char *)malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char)encoding_table[i]] = i;
}

void base64_cleanup()
{
    free(decoding_table);
}

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length)
{

    if (decoding_table == NULL)
        build_decoding_table();

    if (input_length % 4 != 0)
        return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=')
        (*output_length)--;
    if (data[input_length - 2] == '=')
        (*output_length)--;

    unsigned char *decoded_data = (unsigned char *)malloc(*output_length);
    if (decoded_data == NULL)
        return NULL;

    for (int i = 0, j = 0; i < input_length;)
    {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (j < *output_length)
            decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length)
            decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length)
            decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

unsigned char *SCHNORR_signature_2bin(SCHNORR_SIG *signature)
{
    unsigned char *r = (unsigned char *)malloc(BN_num_bytes(SCHNORR_SIG_get_r(signature)) * sizeof(unsigned char));
    unsigned char *s = (unsigned char *)malloc(BN_num_bytes(SCHNORR_SIG_get_s(signature)) * sizeof(unsigned char));

    unsigned char *sig = (unsigned char *)malloc((BN_num_bytes(SCHNORR_SIG_get_s(signature)) + BN_num_bytes(SCHNORR_SIG_get_s(signature))) * sizeof(unsigned char));

    int size_r = BN_bn2bin(SCHNORR_SIG_get_r(signature), r);
    if (size_r == 0)
    {
        printf("Eroare la conversia componentei r!\n");
        return NULL;
    }

    int size_s = BN_bn2bin(SCHNORR_SIG_get_s(signature), s);
    if (size_s == 0)
    {
        printf("Eroare la conversia componentei s!\n");
        return NULL;
    }

    memcpy(sig, s, 32);
    memcpy(sig + 32, r, 32);

    return sig;
}

SCHNORR_SIGNER_INFO *create_schnorr_si(EC_KEY *key, X509 *cert)
{
    X509_NAME *name = X509_get_issuer_name(cert);

    SCHNORR_SIGNER_INFO *signer_info = (SCHNORR_SIGNER_INFO *)malloc(sizeof(SCHNORR_SIGNER_INFO));

    // versiune
    ASN1_INTEGER *a = ASN1_INTEGER_new();
    ASN1_INTEGER_set(a, 1);
    signer_info->version = a;

    // signature id
    ASN1_INTEGER *b = ASN1_INTEGER_new();
    ASN1_INTEGER_set(b, 0);
    signer_info->signature_id = b;

    // issuer_and_serial
    signer_info->issuer_and_serial = PKCS7_ISSUER_AND_SERIAL_new();
    signer_info->issuer_and_serial->issuer = name;
    signer_info->issuer_and_serial->serial = X509_get_serialNumber(cert);

    // digest
    signer_info->digest_alg = X509_ALGOR_new();
    X509_ALGOR_set_md(signer_info->digest_alg, EVP_sha256());

    // atribute - testare
    X509_ATTRIBUTE *attr = X509_ATTRIBUTE_new();

    X509_ATTRIBUTE_create_by_NID(&attr, NID_sha256, 0, "12342615", 8);

    // X509_ATTRIBUTE_create_by_txt(&attr, "myatr", 1, (const unsigned char*)"ceva", 4);
    signer_info->auth_attr = sk_X509_ATTRIBUTE_new_null();
    sk_X509_ATTRIBUTE_push(signer_info->auth_attr, attr);

    signer_info->unauth_attr = sk_X509_ATTRIBUTE_new_null();
    sk_X509_ATTRIBUTE_push(signer_info->unauth_attr, attr);

    // pkey
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, key);
    signer_info->pkey = pkey;

    return signer_info;
}

STACK_OF(X509) * SCHNORR_get_signers_certificates(SCHNORR_SIGNED_DATA *signed_data)
{
    if (signed_data == NULL)
        return NULL;
    if (signed_data->cert == NULL)
        return NULL;

    return signed_data->cert;
}

SCHNORR_SIG *SCHNORR_get_signature(SCHNORR_SIGNED_DATA *signed_data)
{
    if (signed_data == NULL)
        return NULL;
    if (signed_data->signature == NULL)
        return NULL;

    SCHNORR_SIGNATURE_ASN1 *signature_asn1 = sk_SCHNORR_SIGNATURE_ASN1_pop(signed_data->signature);
    if (signature_asn1 == NULL)
        return NULL;

    BIGNUM *id = BN_new();
    ASN1_INTEGER_to_BN(signature_asn1->id, id);
    if (!BN_is_zero(id))
    {
        printf("not yet supported\n");
        return NULL;
    }

    SCHNORR_SIG *sig = SCHNORR_SIG_new();
    const unsigned char *sig_string = ASN1_STRING_get0_data(signature_asn1->enc_digest);

    unsigned char *r = (unsigned char *)malloc(SIGNATURE_COMPONENT_SIZE * sizeof(unsigned char));
    unsigned char *s = (unsigned char *)malloc(SIGNATURE_COMPONENT_SIZE * sizeof(unsigned char));

    memcpy(s, sig_string, 32);
    memcpy(r, sig_string + 32, 32);

    if (SCHNORR_SIG_set_r(sig, BN_bin2bn(r, SIGNATURE_COMPONENT_SIZE, NULL)) == -1)
    {
        printf("Eroare la conversia semnaturii in BN!\n");
        return -1;
    }

    if (SCHNORR_SIG_set_s(sig, BN_bin2bn(s, SIGNATURE_COMPONENT_SIZE, NULL)) == -1)
    {
        printf("Eroare la conversia semnaturii in BN!\n");
        return -1;
    }

    free(r);
    free(s);
    return sig;
}

SCHNORR_SIGNED_DATA *SCHNORR_create_pkcs7(EC_KEY **keys, X509 **certificates, int signers_number, SCHNORR_SIG *sig)
{
    // signed data
    SCHNORR_SIGNED_DATA *signed_data = (SCHNORR_SIGNED_DATA *)malloc(sizeof(SCHNORR_SIGNED_DATA));
    if (signed_data == NULL)
    {
        printf("Error allocating schnorr signed data\n");
        return NULL;
    }
    // versiune
    ASN1_INTEGER *a = ASN1_INTEGER_new();
    ASN1_INTEGER_set(a, 1);
    signed_data->version = a;
    if (signed_data->version == NULL)
    {
        printf("Error setting signed data version\n");
        return NULL;
    }

    // digestalg
    signed_data->md_algs = sk_X509_ALGOR_new_null();
    X509_ALGOR *algor = X509_ALGOR_new();
    X509_ALGOR_set_md(algor, EVP_sha256());
    sk_X509_ALGOR_push(signed_data->md_algs, algor);
    if (signed_data->md_algs == NULL)
    {
        printf("Error setting md_algs\n");
        return NULL;
    }

    // certs && signer infos
    signed_data->cert = sk_X509_new_null();
    signed_data->signer_info = sk_SCHNORR_SIGNER_INFO_new_null();

    for (int i = 0; i < signers_number; i++)
    {
        sk_X509_push(signed_data->cert, certificates[i]);

        SCHNORR_SIGNER_INFO *signer_info = create_schnorr_si(keys[i], certificates[i]);
        if (signer_info == NULL)
        {
            printf("Error creating signer info\n");
            return NULL;
        }

        sk_SCHNORR_SIGNER_INFO_push(signed_data->signer_info, signer_info);
    }

    // enc digest
    SCHNORR_SIGNATURE_ASN1 *signature_asn1 = (SCHNORR_SIGNATURE_ASN1 *)malloc(sizeof(SCHNORR_SIGNATURE_ASN1));
    ASN1_INTEGER_set(a, 0);
    signature_asn1->id = a;
    signature_asn1->enc_digest = ASN1_OCTET_STRING_new();
    unsigned char *buffer = SCHNORR_signature_2bin(sig);
    ASN1_OCTET_STRING_set(signature_asn1->enc_digest, buffer, 64);

    signed_data->signature = sk_SCHNORR_SIGNATURE_ASN1_new_null();
    sk_SCHNORR_SIGNATURE_ASN1_push(signed_data->signature, signature_asn1);

    // content si crl
    signed_data->crl = sk_X509_CRL_new_null();
    signed_data->contents = NULL;

    return signed_data;
}

int write_schnorr_signed_data_asn1(SCHNORR_SIGNED_DATA *signed_data, const char *filename)
{

    int len = i2d_SCHNORR_SIGNED_DATA(signed_data, NULL);
    if (len <= 0)
        return -1;
    unsigned char *buf = (unsigned char *)OPENSSL_malloc(len);
    unsigned char *aux2 = buf;
    i2d_SCHNORR_SIGNED_DATA(signed_data, &aux2);

    FILE *fout = fopen(filename, "wb");

    fprintf(fout, "-----BEGIN SCHNORR SIGNATURE-----\n");

    size_t length;
    char *base64asn1 = base64_encode(buf, len, &length);

    fwrite(base64asn1, length, 1, fout);
    fprintf(fout, "\n");
    fprintf(fout, "-----END SCHNORR SIGNATURE-----\n");
    fclose(fout);

    return 0;
}

int read_schnorr_signed_data_asn1(SCHNORR_SIGNED_DATA **signed_data, const char *filename)
{
    FILE *fin = fopen(filename, "rb");
    if (fin == NULL)
        return -1;

    fseek(fin, 0, SEEK_END);
    int length = ftell(fin);
    rewind(fin);

    unsigned char *buffer = (unsigned char *)malloc(sizeof(unsigned char) * length - 67);
    fseek(fin, 34, 0);

    fread(buffer, 1, length - 67, fin);
    fclose(fin);

    size_t len;
    unsigned char *buf = base64_decode((const char *)buffer, length - 67, &len);

    *signed_data = (SCHNORR_SIGNED_DATA *)malloc(sizeof(SCHNORR_SIGNED_DATA));

    (*signed_data)->signer_info = sk_SCHNORR_SIGNER_INFO_new_null();
    (*signed_data)->signature = sk_SCHNORR_SIGNATURE_ASN1_new_null();
    (*signed_data)->md_algs = sk_X509_ALGOR_new_null();
    (*signed_data)->cert = sk_X509_new_null();
    (*signed_data)->crl = sk_X509_CRL_new_null();
    (*signed_data)->contents = (PKCS7 *)malloc(sizeof(PKCS7));
    (*signed_data)->version = ASN1_INTEGER_new();

    d2i_SCHNORR_SIGNED_DATA(signed_data, (const unsigned char **)(&buf), length);
}