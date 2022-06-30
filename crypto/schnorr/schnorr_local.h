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

typedef struct schnorr_signed_data
{
    ASN1_INTEGER *version; /* version 1 */
    STACK_OF(X509_ALGOR) * md_algs;
    STACK_OF(X509) * cert;
    STACK_OF(X509_CRL) * crl; /* [ 1 ] */
    STACK_OF(SCHNORR_SIGNER_INFO) * signer_info;
    struct pkcs7_st *contents;
} SCHNORR_SIGNED_DATA;

typedef struct schnorr_signer_info_st
{
    ASN1_INTEGER *version; /* version 1 */
    STACK_OF(PKCS7_ISSUER_AND_SERIAL) * issuers_and_serials;
    X509_ALGOR *digest_alg;
    STACK_OF(X509_ATTRIBUTE) * auth_attr;
    STACK_OF(X509_ATTRIBUTE) * unauth_attr;
    ASN1_OCTET_STRING *encrypted_digest;
    EVP_PKEY *pkey;
} SCHNORR_SIGNER_INFO;
