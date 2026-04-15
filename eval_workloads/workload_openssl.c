/*
    OpenSSL: CVE-2022-0778
    
    Target symbol: BN_mod_sqrt
    
    The vulnerability is an infinite loop in BN_mod_sqrt when given
    a specially crafted non-prime modulus. We call it with a valid
    prime modulus — normal operation, no hang.
*/

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int main(void) {
    SSL_library_init();
    SSL_load_error_strings();
    printf("[openssl] SSL_library_init() called\n");

    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (ctx) {
        printf("[openssl] SSL_CTX_new() called successfully\n");
        SSL_CTX_free(ctx);
    }

    // BN_mod_sqrt (target symbol for CVE-2022-0778)
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *a = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *result = BN_new();

    BN_set_word(a, 4);
    BN_set_word(p, 7);

    BIGNUM *ret = BN_mod_sqrt(result, a, p, bn_ctx);
    if (ret) {
        char *hex = BN_bn2dec(result);
        printf("[openssl] BN_mod_sqrt(4, 7) = %s\n", hex);
        OPENSSL_free(hex);
    } else {
        printf("[openssl] BN_mod_sqrt() returned NULL (unexpected)\n");
    }

    BN_free(a);
    BN_free(p);
    BN_free(result);
    BN_CTX_free(bn_ctx);

    printf("[openssl] Workload complete.\n");
    return 0;
}
