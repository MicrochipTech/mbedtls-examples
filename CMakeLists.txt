cmake_minimum_required(VERSION 2.6.4)
project (mbedtls-examples)

# Global Build Settings
set(ENABLE_TESTING OFF CACHE INTERNAL "")
include_directories(source cryptoauthlib/lib mbedtls/include scripts)

# Configure mbedtls 
set(ENABLE_PROGRAMS OFF CACHE INTERNAL "")
set(ENABLE_ZLIB_SUPPORT OFF CACHE INTERNAL "")
set(LINK_WITH_PTHREAD OFF CACHE INTERNAL "")
set(UNSAFE_BUILD OFF CACHE INTERNAL "")
set(USE_PKCS11_HELPER_LIBRARY OFF CACHE INTERNAL "")
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE INTERNAL "")
set(INSTALL_MBEDTLS_HEADERS OFF CACHE INTERNAL "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DMBEDTLS_CONFIG_FILE=\\\"mbedtls_config.h\\\"")

# Add mbedtls
add_subdirectory(mbedtls)

# Configure cryptoauthlib
set(ATCA_STATIC_LIB ON CACHE INTERNAL "")
set(ATCA_MBEDTLS ON CACHE INTERNAL "")
set(ATCA_PKCS11 OFF CACHE INTERNAL "")

# Add cryptoauthlib
add_subdirectory(cryptoauthlib/lib)


# Add the example programs
add_executable(connect source/connect.c source/cert_chain.c)
target_link_libraries(connect cryptoauth mbedtls)

add_executable(configure source/configure.c)
target_link_libraries(configure cryptoauth mbedtls)

add_executable(provision source/provision.c source/cert_chain.c)
target_link_libraries(provision cryptoauth mbedtls)

add_executable(tests source/tests.c source/cert_chain.c)
target_link_libraries(tests cryptoauth mbedtls)
