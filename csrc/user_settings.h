#ifndef _ASHEN_USER_SETTINGS_H_
#define _ASHEN_USER_SETTINGS_H_

#define WOLFTPM_FWTPM
#define WOLFTPM_SMALL_STACK
#define WOLFTPM_V185
#define WOLFTPM_FWTPM_MASKED_SECRETS

#undef WOLFTPM_FWTPM_NV_APPEND_ONLY
#define FWTPM_NV_MAX_SIZE (16 * 1024)
#define FWTPM_MAX_PRIMARY_CACHE 4
#define FWTPM_MAX_NV_INDICES    8
#define FWTPM_MAX_NV_DATA       512

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_MAIN_DRIVER
#define NO_WRITEV
#define NO_DEV_RANDOM
#define WOLFSSL_USER_IO
#define WOLFSSL_NO_SOCK
#define WOLFSSL_IGNORE_FILE_WARN
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_ASN_TEMPLATE
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_GENERAL_ALIGNMENT 4

#define NO_STM32_HASH
#define NO_STM32_CRYPTO

#define WOLFSSL_SP
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_SMALL
#define SP_WORD_SIZE 32
#define WOLFSSL_HAVE_SP_ECC
#if defined(__ARM_ARCH) && !defined(ASHEN_HOST_BUILD)
    #define WOLFSSL_SP_ARM_CORTEX_M_ASM
    #define WOLFSSL_SP_ASM
#endif

#define NO_RSA
#define NO_DSA
#define NO_DH
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_PSK
#define NO_OLD_TLS

#define HAVE_ECC
#define ECC_USER_CURVES
#undef  NO_ECC256
#define HAVE_ECC384
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT
#define WOLFSSL_PUBLIC_MP
#define WOLFSSL_KEY_GEN

#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_WC_MLDSA
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

#define HAVE_AESGCM
#define HAVE_AES_DECRYPT
#define WOLFSSL_AES_CFB
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_KEYWRAP
#define GCM_SMALL

#define HAVE_HKDF
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_SHA512

#define HAVE_HASHDRBG
#define WC_RESEED_INTERVAL (1000000)
#define NO_OLD_RNGNAME
#define CUSTOM_RAND_GENERATE_SEED ashen_rand_generate_seed
extern int ashen_rand_generate_seed(unsigned char* output, unsigned int sz);

#define XMALLOC_OVERRIDE
#define XMALLOC(s, h, t)     ashen_c_malloc((s))
#define XFREE(p, h, t)       ashen_c_free((p))
#define XREALLOC(p, n, h, t) ashen_c_realloc((p), (n))
extern void* ashen_c_malloc(unsigned long size);
extern void  ashen_c_free(void* ptr);
extern void* ashen_c_realloc(void* ptr, unsigned long size);

#endif /* _ASHEN_USER_SETTINGS_H_ */
