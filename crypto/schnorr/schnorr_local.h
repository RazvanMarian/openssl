#include <openssl/schnorr.h>
#include <openssl/crypto.h>

// Base point coordinates
#define xG "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#define yG "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

#define BASE_ERROR 100
#define MEMORY_ERROR 101
#define GROUP_ERROR 102
#define POINT_ERROR 104
#define POINT_CONVERSION_ERROR 105
#define CALCULATION_ERROR 106
#define GENERATE_ERROR 107
#define ORDER_ERROR 108
#define SIGNATURE_ERROR 110
#define KEY_ERROR 112
#define VERIFICATION_ERROR 114

#define SIGNATURE_COMPONENT_SIZE 32

typedef struct SCHNORR_SIG_st
{
    BIGNUM *r;
    BIGNUM *s;
} SCHNORR_SIG;

typedef struct schnorr_signature
{
    ASN1_INTEGER *id;
    ASN1_OCTET_STRING *enc_digest;
} SCHNORR_SIGNATURE_ASN1;

typedef struct schnorr_signed_data
{
    ASN1_INTEGER *version; /* version 1 */
    STACK_OF(X509_ALGOR) * md_algs;
    STACK_OF(X509) * cert;
    STACK_OF(X509_CRL) * crl; /* [ 1 ] */
    STACK_OF(SCHNORR_SIGNER_INFO) * signer_info;
    struct pkcs7_st *contents;
    STACK_OF(SCHNORR_SIGNATURE_ASN1) * enc_digest;
} SCHNORR_SIGNED_DATA;

typedef struct schnorr_signer_info_st
{
    ASN1_INTEGER *version; /* version 1 */
    ASN1_INTEGER *signature_id;
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    X509_ALGOR *digest_alg;
    STACK_OF(X509_ATTRIBUTE) * auth_attr;
    STACK_OF(X509_ATTRIBUTE) * unauth_attr;
    EVP_PKEY *pkey;
} SCHNORR_SIGNER_INFO;
