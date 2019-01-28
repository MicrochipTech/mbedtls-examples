#ifndef _ATCA_MBEDTLS_CONFIG_

/* Include the default configuration that the system is using */
#include "mbedtls/config.h"

/* Define additional features of the mbedtls library that are needed */

//#define MBEDTLS_ECDH_GEN_PUBLIC_ALT
//#define MBEDTLS_ECDH_COMPUTE_SHARED_ALT
#define MBEDTLS_ECDSA_SIGN_ALT


#define MBEDTLS_SSL_CIPHERSUITES    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, \
                                    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, \
                                    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM, \
                                    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, \
                                    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, \
                                    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, \
                                    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, \
                                    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8

#endif //_ATCA_MBEDTLS_CONFIG_
