#include "schnorr_local.h"

int SCHNORR_sign(EC_KEY *key, const char *message, int message_length, SCHNORR_SIG *sig)
{
    EC_POINT *G, *Q;
    BIGNUM *x, *y, *k, *order, *xQ;
    EC_GROUP *group;
    int error = 0;

    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == NULL)
    {
        printf("The curve group does not exist!\n");
        error = GROUP_ERROR;
        goto clear;
    }

    // Getting the order of the curve
    order = BN_new();
    if (order == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    if (EC_GROUP_get_order(group, order, NULL) == 0)
    {
        printf("Order error\n");
        error = ORDER_ERROR;
        goto clear;
    }
    //*************************************************************************************************

    // Generate random integer k between [1,order]
    k = BN_new();
    if (k == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    BN_rand_range(k, order);
    //*************************************************************************************************

    // BASE POINT G
    G = EC_POINT_new(group);
    if (G == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    x = BN_new();
    y = BN_new();
    if (x == NULL || y == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    BN_hex2bn(&x, xG);
    BN_hex2bn(&y, yG);

    if (!EC_POINT_set_affine_coordinates(group, G, x, y, NULL))
    {
        printf("The point does not belong to the curve!\n");
        error = POINT_ERROR;
        goto clear;
    }
    //*************************************************************************************************

    // Calculate Q = k * G
    Q = EC_POINT_new(group);
    if (Q == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    EC_POINT_mul(group, Q, NULL, G, k, NULL);
    if (!EC_POINT_is_on_curve(group, Q, NULL))
    {
        printf("The point does not belong to the curve!\n");
        error = POINT_ERROR;
        goto clear;
    }
    //*************************************************************************************************

    // Get xQ
    xQ = BN_new();
    if (xQ == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    EC_POINT_get_affine_coordinates(group, Q, xQ, NULL, NULL);

    unsigned char *xQ_OS = (unsigned char *)malloc(BN_num_bytes(xQ));
    BN_bn2bin(xQ, (unsigned char *)xQ_OS);
    //*************************************************************************************************

    // M || xQ
    unsigned char *temp = (unsigned char *)malloc(message_length + BN_num_bytes(xQ));
    memcpy(temp, message, message_length);
    memcpy(temp + message_length, xQ_OS, BN_num_bytes(xQ));
    //*************************************************************************************************

    // Hash ( M || xQ)
    unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    SHA256(temp, message_length + BN_num_bytes(xQ), hash);

    free(temp);
    free(xQ_OS);
    //*************************************************************************************************

    // Calculate r = Hash(M || xQ)
    (*sig).r = BN_new();

    if ((*sig).r == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }

    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, (*sig).r);
    BN_CTX *ctx = BN_CTX_new();
    BN_mod((*sig).r, (*sig).r, order, ctx);
    free(hash);

    //*************************************************************************************************

    // Apoi s = (k - r * private_key) mod n
    // Output r,s
    const BIGNUM *private_key = BN_new();
    private_key = EC_KEY_get0_private_key(key);

    BIGNUM *temporary = BN_new();
    (*sig).s = BN_new();

    BN_mod_mul(temporary, (*sig).r, private_key, order, ctx);
    BN_mod_sub((*sig).s, k, temporary, order, ctx);

clear:
    EC_POINT_free(G);
    EC_POINT_free(Q);
    BN_free(order);
    BN_free(x);
    BN_free(y);
    BN_free(k);
    BN_free(xQ);
    EC_GROUP_free(group);
    return error;
}

int SCHNORR_verify(EC_KEY *key, const char *message, int message_length, SCHNORR_SIG *sig)
{
    BIGNUM *order, *x, *y;
    EC_POINT *G, *Q;
    EC_GROUP *group;
    int error = 0;

    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == NULL)
    {
        printf("The curve group does not exist!\n");
        error = GROUP_ERROR;
        goto clear;
    }

    // Getting the order of the curve
    order = BN_new();
    if (order == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    if (EC_GROUP_get_order(group, order, NULL) == 0)
    {
        printf("Order error\n");
        error = ORDER_ERROR;
        goto clear;
    }
    //*************************************************************************************************

    // Check if is in the normal bounds
    BIGNUM *test = BN_new();
    BN_one(test);
    if ((BN_cmp((*sig).s, order) == 1) || (BN_cmp((*sig).s, test) == -1))
    {
        printf("S component of the signature is out of bounds\n");
        error = VERIFICATION_ERROR;
        goto clear;
    }
    BN_free(test);
    //*************************************************************************************************

    // BASE POINT G
    G = EC_POINT_new(group);
    if (G == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    x = BN_new();
    y = BN_new();
    if (x == NULL || y == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    BN_hex2bn(&x, xG);
    BN_hex2bn(&y, yG);

    if (!EC_POINT_set_affine_coordinates(group, G, x, y, NULL))
    {
        printf("The point does not belong to the curve!\n");
        error = POINT_ERROR;
        goto clear;
    }
    //*************************************************************************************************

    // Q = s * G
    Q = EC_POINT_new(group);
    // s * G
    EC_POINT_mul(group, Q, NULL, G, (*sig).s, NULL);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    EC_POINT *T = EC_POINT_new(group);

    // r * P
    EC_POINT_mul(group, T, NULL, P, (*sig).r, NULL);

    // s * G + r * P
    EC_POINT_add(group, Q, Q, T, NULL);

    if (EC_POINT_is_at_infinity(group, Q))
    {
        printf("Verification error\n");
        error = VERIFICATION_ERROR;
        goto clear;
    }

    // get xQ
    BIGNUM *xQ = BN_new();
    if (xQ == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    EC_POINT_get_affine_coordinates(group, Q, xQ, NULL, NULL);

    unsigned char *xQ_OS = (unsigned char *)malloc(BN_num_bytes(xQ));
    BN_bn2bin(xQ, (unsigned char *)xQ_OS);
    //*************************************************************************************************

    // M || xQ
    unsigned char *temp = (unsigned char *)malloc(message_length + BN_num_bytes(xQ));
    memcpy(temp, message, message_length);
    memcpy(temp + message_length, xQ_OS, BN_num_bytes(xQ));
    //*************************************************************************************************

    // Hash ( M || xQ)
    unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    SHA256(temp, message_length + BN_num_bytes(xQ), hash);
    //*************************************************************************************************

    // Calculate v = Hash(M || xQ)
    BIGNUM *v = BN_new();
    if (v == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }

    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, v);
    free(hash);
    free(xQ_OS);
    BN_free(xQ);

    BN_CTX *ctx = BN_CTX_new();
    BN_mod(v, v, order, ctx);
    BN_CTX_free(ctx);
    //*************************************************************************************************

    // Compare v with r
    // if v == r => verification successful
    if (BN_cmp(v, (*sig).r) == 0)
    {
        printf("VERIFICATION OK\n");
    }
    else
    {
        printf("Verification error\n");
        error = VERIFICATION_ERROR;
        goto clear;
    }
    BN_free(v);

clear:
    EC_POINT_free(G);
    EC_POINT_free(Q);
    BN_free(order);
    BN_free(x);
    BN_free(y);
    EC_GROUP_free(group);
    return error;
}

int SCHNORR_multiple_sign(EC_KEY **keys, int signers_number, const char *message, int message_length, SCHNORR_SIG *sig)
{

    EC_POINT *G, *Q;
    BIGNUM *x, *y, *order, *xQ;
    BIGNUM *k = BN_new();
    BN_zero(k);
    EC_GROUP *group;
    int error = 0;

    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == NULL)
    {
        printf("The curve group does not exist!\n");
        error = GROUP_ERROR;
        goto clear;
    }

    // Getting the order of the curve
    order = BN_new();
    if (order == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    if (EC_GROUP_get_order(group, order, NULL) == 0)
    {
        printf("Order error\n");
        error = ORDER_ERROR;
        goto clear;
    }
    //*************************************************************************************************

    BN_CTX *ctx = BN_CTX_new();
    // Generate random integers k between [1,order]
    for (int i = 0; i < signers_number; i++)
    {
        BIGNUM *ks = BN_new();
        if (ks == NULL)
        {
            printf("Memory error\n");
            error = MEMORY_ERROR;
            goto clear;
        }
        BN_rand_range(ks, order);
        BN_mod_add(k, k, ks, order, ctx);
    }

    //*************************************************************************************************

    // BASE POINT G
    G = EC_POINT_new(group);
    if (G == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    x = BN_new();
    y = BN_new();
    if (x == NULL || y == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    BN_hex2bn(&x, xG);
    BN_hex2bn(&y, yG);

    if (!EC_POINT_set_affine_coordinates(group, G, x, y, NULL))
    {
        printf("The point does not belong to the curve!\n");
        error = POINT_ERROR;
        goto clear;
    }
    //*************************************************************************************************
    // Calculate Q = k * G
    Q = EC_POINT_new(group);
    if (Q == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    EC_POINT_mul(group, Q, NULL, G, k, NULL);
    if (!EC_POINT_is_on_curve(group, Q, NULL))
    {
        printf("The point does not belong to the curve!\n");
        error = POINT_ERROR;
        goto clear;
    }

    //*************************************************************************************************

    // Get xQ
    xQ = BN_new();
    if (xQ == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    EC_POINT_get_affine_coordinates(group, Q, xQ, NULL, NULL);

    unsigned char *xQ_OS = (unsigned char *)malloc(BN_num_bytes(xQ));
    BN_bn2bin(xQ, (unsigned char *)xQ_OS);
    //*************************************************************************************************

    // M || xQ
    unsigned char *temp = (unsigned char *)malloc(message_length + BN_num_bytes(xQ));
    memcpy(temp, message, message_length);
    memcpy(temp + message_length, xQ_OS, BN_num_bytes(xQ));
    //*************************************************************************************************

    // Hash ( M || xQ)
    unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    SHA256(temp, message_length + BN_num_bytes(xQ), hash);
    free(temp);
    free(xQ_OS);
    //*************************************************************************************************

    // Calculate r = Hash(M || xQ)
    (*sig).r = BN_new();
    if ((*sig).r == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }

    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, (*sig).r);
    BN_mod((*sig).r, (*sig).r, order, ctx);
    free(hash);
    //*************************************************************************************************

    // Calculate the aggregate private key
    BIGNUM *private_key = BN_new();
    BN_zero(private_key);
    for (int i = 0; i < signers_number; i++)
    {
        const BIGNUM *temp_key = EC_KEY_get0_private_key(keys[i]);
        BN_mod_add(private_key, private_key, temp_key, order, ctx);
    }

    //*************************************************************************************************
    // Apoi s = (k - r * private_key) mod n
    // Output r,s

    BIGNUM *temporary = BN_new();
    (*sig).s = BN_new();

    BN_mod_mul(temporary, (*sig).r, private_key, order, ctx);
    BN_mod_sub((*sig).s, k, temporary, order, ctx);

clear:
    EC_POINT_free(G);
    EC_POINT_free(Q);
    BN_free(order);
    BN_free(x);
    BN_free(y);
    BN_free(k);
    BN_free(xQ);
    EC_GROUP_free(group);

    return error;
}

int SCHNORR_multiple_verify(EC_KEY **keys, int signers_number, const char *message, int message_length, SCHNORR_SIG *sig)
{
    BIGNUM *order, *x, *y;
    EC_POINT *G, *Q;
    EC_GROUP *group;
    int error = 0;

    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == NULL)
    {
        printf("The curve group does not exist!\n");
        error = GROUP_ERROR;
        goto clear;
    }

    // Getting the order of the curve
    order = BN_new();
    if (order == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    if (EC_GROUP_get_order(group, order, NULL) == 0)
    {
        printf("Order error\n");
        error = ORDER_ERROR;
        goto clear;
    }
    //*************************************************************************************************

    // Check if is in the normal bounds
    BIGNUM *test = BN_new();
    BN_one(test);
    if ((BN_cmp((*sig).s, order) == 1) || (BN_cmp((*sig).s, test) == -1))
    {
        printf("S component of the signature is out of bounds\n");
        error = VERIFICATION_ERROR;
        goto clear;
    }
    BN_free(test);
    //*************************************************************************************************

    // BASE POINT G
    G = EC_POINT_new(group);
    if (G == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    x = BN_new();
    y = BN_new();
    if (x == NULL || y == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    BN_hex2bn(&x, xG);
    BN_hex2bn(&y, yG);

    if (!EC_POINT_set_affine_coordinates(group, G, x, y, NULL))
    {
        printf("The point does not belong to the curve!\n");
        error = POINT_ERROR;
        goto clear;
    }
    //*************************************************************************************************
    // Calculate Q = s*G + r*Sum(P)
    // Q = s * G
    Q = EC_POINT_new(group);
    // s * G
    EC_POINT_mul(group, Q, NULL, G, (*sig).s, NULL);
    EC_POINT *P = EC_POINT_new(group);

    for (int i = 0; i < signers_number; i++)
    {
        const EC_POINT *temporar = EC_KEY_get0_public_key(keys[i]);
        if (i == 0)
            EC_POINT_copy(P, temporar);
        else
            EC_POINT_add(group, P, P, temporar, NULL);
    }

    EC_POINT *T = EC_POINT_new(group);

    // r * P
    EC_POINT_mul(group, T, NULL, P, (*sig).r, NULL);

    // s * G + r * P
    EC_POINT_add(group, Q, Q, T, NULL);

    if (EC_POINT_is_at_infinity(group, Q))
    {
        printf("Verification error\n");
        error = VERIFICATION_ERROR;
        goto clear;
    }
    //*************************************************************************************************
    //  get xQ
    BIGNUM *xQ = BN_new();
    if (xQ == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    EC_POINT_get_affine_coordinates(group, Q, xQ, NULL, NULL);

    unsigned char *xQ_OS = (unsigned char *)malloc(BN_num_bytes(xQ));
    BN_bn2bin(xQ, (unsigned char *)xQ_OS);
    //*************************************************************************************************
    // M || xQ
    unsigned char *temp = (unsigned char *)malloc(message_length + BN_num_bytes(xQ));
    memcpy(temp, message, message_length);
    memcpy(temp + message_length, xQ_OS, BN_num_bytes(xQ));
    //*************************************************************************************************

    // Hash ( M || xQ)
    unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    SHA256(temp, message_length + BN_num_bytes(xQ), hash);
    //*************************************************************************************************

    // Calculate v = Hash(M || xQ)
    BIGNUM *v = BN_new();
    if (v == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, v);
    free(hash);
    free(xQ_OS);
    BN_free(xQ);

    BN_CTX *ctx = BN_CTX_new();
    BN_mod(v, v, order, ctx);
    BN_CTX_free(ctx);
    //*************************************************************************************************

    // Compare v with r
    // if v == r => verification successful
    if (BN_cmp(v, (*sig).r) == 0)
        BN_free(v);
    else
    {
        BN_free(v);
        printf("Verification error\n");
        error = VERIFICATION_ERROR;
        goto clear;
    }

clear:
    EC_POINT_free(G);
    EC_POINT_free(Q);
    BN_free(order);
    BN_free(x);
    BN_free(y);
    EC_GROUP_free(group);
    return error;
}

BIGNUM *SCHNORR_SIG_get_r(SCHNORR_SIG *sig)
{
    if ((*sig).r != NULL)
        return (*sig).r;

    return NULL;
}

BIGNUM *SCHNORR_SIG_get_s(SCHNORR_SIG *sig)
{
    if ((*sig).s != NULL)
        return (*sig).s;

    return NULL;
}

int SCHNORR_SIG_set_r(SCHNORR_SIG *sig, BIGNUM *r)
{
    if (r != NULL)
    {
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (group == NULL)
        {
            printf("The curve group does not exist!\n");
            return -1;
        }

        // Getting the order of the curve
        BIGNUM *order = BN_new();
        if (order == NULL)
        {
            return -1;
        }
        if (EC_GROUP_get_order(group, order, NULL) == 0)
        {
            return -1;
        }

        BIGNUM *test = BN_new();
        BN_one(test);
        if ((BN_cmp(r, order) == 1) || (BN_cmp(r, test) == -1))
        {
            printf("r component of the signature is out of bounds\n");
            return -1;
        }
        BN_free(test);

        (*sig).r = BN_dup(r);
        if ((*sig).r != NULL)
            return 0;

        return -1;
    }

    return -1;
}

int SCHNORR_SIG_set_s(SCHNORR_SIG *sig, BIGNUM *s)
{
    if (s != NULL)
    {
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (group == NULL)
        {
            printf("The curve group does not exist!\n");
            return -1;
        }

        // Getting the order of the curve
        BIGNUM *order = BN_new();
        if (order == NULL)
        {
            return -1;
        }
        if (EC_GROUP_get_order(group, order, NULL) == 0)
        {
            return -1;
        }

        BIGNUM *test = BN_new();
        BN_one(test);
        if ((BN_cmp(s, order) == 1) || (BN_cmp(s, test) == -1))
        {
            printf("s component of the signature is out of bounds\n");
            return -1;
        }
        BN_free(test);

        (*sig).s = BN_dup(s);
        if ((*sig).s != NULL)
            return 0;

        return -1;
    }

    return -1;
}