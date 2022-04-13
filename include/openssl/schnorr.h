
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

    typedef struct SCHNORR_SIG_st SCHNORR_SIG;

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

#ifdef __cplusplus
}
#endif