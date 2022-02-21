
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

    typedef struct schnorr_signature schnorr_signature;

    int Schnorr_Sign(EC_KEY *key, const char *message, int message_length, schnorr_signature *sig);

    int Verify_Sign(EC_KEY *key, const char *message, int message_length, schnorr_signature *sig);

    int Schnorr_Multiple_Sign(EC_KEY **keys, int signers_number, const char *message, int message_length, schnorr_signature *sig);

    int Verify_Multiple_Sign(EC_KEY **keys, int signers_number, const char *message, int message_length, schnorr_signature *sig);

    int Write_Schnorr_Private_Key(EC_KEY *key, const char *filename);

    int Write_Schnorr_Public_Key(EC_KEY *key, const char *filename);

    int Read_Schnorr_Private_key(EC_KEY **key, const char *filename);

    int Read_Schnorr_Public_Key(EC_KEY **key, const char *filename);

    int Write_Schnorr_Signature(schnorr_signature *signature, const char *filename);

    int Read_Schnorr_Signature(schnorr_signature *sig, const char *filename);

    int Gen(EC_KEY **key);

    schnorr_signature* Schnorr_SIG_new(void);

    void Schnorr_SIG_free(schnorr_signature *sig);
#ifdef __cplusplus
}
#endif