#include "schnorr_local.h"


SCHNORR_SIG* SCHNORR_SIG_new()
{
    SCHNORR_SIG* sig = OPENSSL_zalloc(sizeof(*sig));
    if(sig == NULL)
    {
        printf("Eroare alocare semnatura schnorr!");
    }
    return sig;
}

void SCHNORR_SIG_free(SCHNORR_SIG *sig)
{
    if (sig == NULL)
        return;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    OPENSSL_free(sig);
}

int SCHNORR_generate_key(EC_KEY **key)
{
    EC_POINT *Q, *G;
    BIGNUM *a, *x, *y, *order;
    EC_GROUP *group;
    int error = 0;

    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == NULL)
    {
        printf("The curve group does not exist!\n");
        error = GROUP_ERROR;
        goto clear;
    }

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

    if (!EC_POINT_is_on_curve(group, G, NULL))
    {
        printf("The point does not belong to the curve!\n");
        error = POINT_ERROR;
        goto clear;
    }

    //*************************************************************************************************************
    order = BN_new();
    if (EC_GROUP_get_order(group, order, NULL) == 0)
    {
        printf("Order error\n");
        error = ORDER_ERROR;
        goto clear;
    }

    a = BN_new();
    if (a == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }

    Q = EC_POINT_new(group);
    if (Q == NULL)
    {
        printf("Memory error\n");
        error = MEMORY_ERROR;
        goto clear;
    }

    // Generate random integer a between [1,order]
    BN_rand_range(a, order);
    // Calculate Q = a * P
    EC_POINT_mul(group, Q, NULL, G, a, NULL);

    if (!EC_POINT_is_on_curve(group, Q, NULL))
    {
        printf("The point does not belong to the curve!\n");
        error = POINT_ERROR;
        goto clear;
    }

    *key = EC_KEY_new();
    if (!EC_KEY_set_group(*key, group))
    {
        printf("Key generation error!\n");
        error = KEY_ERROR;
        goto clear;
    }

    if (!EC_KEY_set_private_key(*key, a))
    {
        printf("Key generation error!\n");
        error = KEY_ERROR;
        goto clear;
    }

    if (!EC_KEY_set_public_key(*key, Q))
    {
        printf("Key generation error!\n");
        error = KEY_ERROR;
        goto clear;
    }

clear:
    EC_POINT_free(G);
    EC_POINT_free(Q);
    EC_GROUP_free(group);
    BN_free(a);
    BN_free(x);
    BN_free(y);
    BN_free(order);

    return error;
}
