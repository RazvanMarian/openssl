
#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/safestack.h>

    typedef struct SCHNORR_SIG_st SCHNORR_SIG;

    typedef struct schnorr_signed_data SCHNORR_SIGNED_DATA;

    typedef struct schnorr_signature SCHNORR_SIGNATURE_ASN1;

    typedef struct schnorr_signer_info_st SCHNORR_SIGNER_INFO;

    int SCHNORR_generate_key(EC_KEY **key);

    SCHNORR_SIG *SCHNORR_SIG_new(void);

    void SCHNORR_SIG_free(SCHNORR_SIG *sig);

    EC_KEY *SCHNORR_generate_aggregate_public_key(EC_KEY **keys, int signers_number);

    EC_KEY *SCHNORR_generate_aggregate_private_key(EC_KEY **keys, int signers_number);

    int SCHNORR_sign(EC_KEY *key, const char *message, int message_length, SCHNORR_SIG *sig);

    int SCHNORR_verify(EC_KEY *key, const char *message, int message_length, SCHNORR_SIG *sig);

    int SCHNORR_multiple_sign(EC_KEY **keys, int signers_number, const char *message, int message_length, SCHNORR_SIG *sig);

    int SCHNORR_multiple_verify(EC_KEY **keys, int signers_number, const char *message, int message_length, SCHNORR_SIG *sig);

    int SCHNORR_write_private_key(EC_KEY *key, const char *filename);

    int SCHNORR_write_public_key(EC_KEY *key, const char *filename);

    int SCHNORR_read_private_key(EC_KEY **key, const char *filename);

    int SCHNORR_read_public_key(EC_KEY **key, const char *filename);

    int SCHNORR_write_signature(SCHNORR_SIG *signature, const char *filename);

    int SCHNORR_read_signature(SCHNORR_SIG *sig, const char *filename);

    BIGNUM *SCHNORR_SIG_get_r(SCHNORR_SIG *sig);

    BIGNUM *SCHNORR_SIG_get_s(SCHNORR_SIG *sig);

    int SCHNORR_SIG_set_r(SCHNORR_SIG *sig, BIGNUM *r);

    int SCHNORR_SIG_set_s(SCHNORR_SIG *sig, BIGNUM *s);

    SCHNORR_SIGNED_DATA *SCHNORR_create_pkcs7(EC_KEY **keys, X509 **certificates, int signers_number, SCHNORR_SIG *sig);

    int write_schnorr_signed_data_asn1(SCHNORR_SIGNED_DATA *signed_data, const char *filename);

    int read_schnorr_signed_data_asn1(SCHNORR_SIGNED_DATA **signed_data, const char *filename);

    STACK_OF(X509) * SCHNORR_get_signers_certificates(SCHNORR_SIGNED_DATA *signed_data);

    SCHNORR_SIG *SCHNORR_get_signature(SCHNORR_SIGNED_DATA *signed_data);

#ifdef __cplusplus
}
#endif