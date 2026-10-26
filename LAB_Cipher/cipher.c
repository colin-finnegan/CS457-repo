#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/provider.h>

#define ALGORITHM EVP_des_cfb

void handleErrors(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

unsigned encrypt(const uint8_t *plaintext, unsigned plaintext_len,
                const uint8_t *key, const uint8_t *iv, uint8_t *ciphertext) {
    
    int status;
    unsigned len = 0, encryptedLen = 0;
    
    // Load legacy provider for DES support
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (legacy == NULL) {
        handleErrors("Failed to load legacy provider");
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("encrypt: failed to create CTX");
    
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptInit_ex");
    
    status = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if (status != 1)
        handleErrors("encrypt: failed to EVP_EncryptUpdate");
    encryptedLen += len;
    
    status = EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    if (status != 1)
        handleErrors("encrypt: failed to EVP_EncryptFinal_ex");
    encryptedLen += len;
    
    EVP_CIPHER_CTX_free(ctx);
    OSSL_PROVIDER_unload(legacy);
    
    return encryptedLen;
}

void hex2bytes(const char *hex, uint8_t *bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        sscanf(hex + 2*i, "%2hhx", &bytes[i]);
    }
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Convert hex strings to bytes
    uint8_t key[8];
    uint8_t iv[8];
    uint8_t p1[2], p2[2], p3[2];
    
    hex2bytes("56789011223344FF", key, 8);
    hex2bytes("AABBCCDDEEFF1122", iv, 8);
    hex2bytes("CC11", p1, 2);
    hex2bytes("BB22", p2, 2);
    hex2bytes("DD55", p3, 2);
    
    // Combine all plaintext blocks into one buffer
    uint8_t plaintext[6];
    memcpy(plaintext, p1, 2);
    memcpy(plaintext + 2, p2, 2);
    memcpy(plaintext + 4, p3, 2);
    
    uint8_t ciphertext[6];
    
    printf("=== DES CFB Encryption Lab ===\n");
    print_hex("Key", key, 8);
    print_hex("IV", iv, 8);
    print_hex("P1", p1, 2);
    print_hex("P2", p2, 2);
    print_hex("P3", p3, 2);
    print_hex("Combined Plaintext", plaintext, 6);
    
    // Encrypt all blocks at once (CFB is a stream cipher)
    unsigned ciphertext_len = encrypt(plaintext, 6, key, iv, ciphertext);
    
    printf("\nEncryption Results:\n");
    print_hex("Total Ciphertext", ciphertext, ciphertext_len);
    
    // Extract individual ciphertext blocks
    uint8_t c1[2], c2[2], c3[2];
    memcpy(c1, ciphertext, 2);
    memcpy(c2, ciphertext + 2, 2);
    memcpy(c3, ciphertext + 4, 2);
    
    printf("Ciphertext Blocks:\n");
    print_hex("C1", c1, 2);
    print_hex("C2", c2, 2);
    print_hex("C3", c3, 2);
    
    // Clean up
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}