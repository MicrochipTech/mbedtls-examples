#ifndef _ATCA_MBEDTLS_CONFIG_

/* Include the default configuration that the system is using */
#include "mbedtls/config.h"

/* Define additional features of the mbedtls library that are needed */

#define MBEDTLS_ECDH_GEN_PUBLIC_ALT
#define MBEDTLS_ECDH_COMPUTE_SHARED_ALT
#define MBEDTLS_ECDSA_SIGN_ALT

#undef MBEDTLS_ECP_DP_SECP192R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP384R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP521R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP192K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP256K1_ENABLED
#undef MBEDTLS_ECP_DP_BP256R1_ENABLED
#undef MBEDTLS_ECP_DP_BP384R1_ENABLED
#undef MBEDTLS_ECP_DP_BP512R1_ENABLED
#undef MBEDTLS_ECP_DP_CURVE25519_ENABLED
#undef MBEDTLS_ECP_DP_CURVE448_ENABLED


/* How to prune the cipher suites mbedtls will allow */
#define MBEDTLS_SSL_CIPHERSUITES    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, \
                                    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, \
                                    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM, \
                                    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, \
                                    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, \
                                    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, \
                                    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, \
                                    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8

#endif //_ATCA_MBEDTLS_CONFIG_
