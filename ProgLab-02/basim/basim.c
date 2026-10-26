/*----------------------------------------------------------------------------
pLAB-02   Key Exchange using Public-Key Encryption

Written By:  Colin Finnegan
Submitted on: 9/24/2025

*/

#include "../myCrypto.h"

void main(int argc, char *argv[])
{
    int fd_ctrl, fd_data, fd_plain;
    size_t encrKey_len, iv_len;
    uint8_t *encryptedKey, sessionKey[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

    if (argc < 3)
    {
        printf("Basim is missing command-line arguments. Usage: %s <ctrlFD> <dataFD>\n", argv[0]);
        exit(-1);
    }
    fd_ctrl = atoi(argv[1]);
    fd_data = atoi(argv[2]);

    // Open log file
    FILE *log = fopen("basim/logBasim.txt", "w");
    if (!log)
    {
        fprintf(stderr, "Basim: Could not create log file\n");
        exit(-1);
    }

    fprintf(log, "This is Basim. Will receive encrypted data from FD %d "
                 "and session key/IV from FD %d\n",
            fd_data, fd_ctrl);

    // Read encrypted session key and IV from control pipe
    read(fd_ctrl, &encrKey_len, sizeof(encrKey_len));
    encryptedKey = malloc(encrKey_len);
    read(fd_ctrl, encryptedKey, encrKey_len);
    read(fd_ctrl, &iv_len, sizeof(iv_len));
    read(fd_ctrl, iv, iv_len);

    fprintf(log, "\nReceived encrypted session key of length %lu bytes\n", encrKey_len);
    fprintf(log, "Received IV of length %lu bytes\n", iv_len);

    // Load Basim's private key
    EVP_PKEY *rsa_privK = getRSAfromFile("basim/basim_priv_key.pem", 0);
    if (!rsa_privK)
    {
        fprintf(log, "Unable to read Basim's Private key\n");
        fclose(log);
        exit(-1);
    }

    fprintf(log, "\n**** Size of Basim's Private Key is %d bits\n", EVP_PKEY_get_bits(rsa_privK));

    // Create context for RSA decryption
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa_privK, NULL);
    if (!ctx)
    {
        fprintf(log, "Unable to create context with Basim's private key\n");
        fclose(log);
        exit(-1);
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        fprintf(log, "Unable to initialize context for RSA decryption\n");
        fclose(log);
        exit(-1);
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        fprintf(log, "Unable to set padding for RSA decryption\n");
        fclose(log);
        exit(-1);
    }

    // First, determine length of decrypted key
    size_t decrKey_len;
    if (EVP_PKEY_decrypt(ctx, NULL, &decrKey_len, encryptedKey, encrKey_len) <= 0)
    {
        fprintf(log, "Unable to determine decrypted session key length\n");
        fclose(log);
        exit(-1);
    }

    // Now decrypt session key
    if (EVP_PKEY_decrypt(ctx, sessionKey, &decrKey_len, encryptedKey, encrKey_len) <= 0)
    {
        fprintf(log, "Decryption of session key FAILED\n");
        fclose(log);
        exit(-1);
    }

    fprintf(log, "\nSuccessfully decrypted session key of length %lu bytes\n", decrKey_len);
    BIO_dump_fp(log, (const char *)sessionKey, decrKey_len);

    free(encryptedKey);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(rsa_privK);
    close(fd_ctrl);

    // Open output file for decrypted video
    fd_plain = open("bunny.decr", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd_plain == -1)
    {
        fprintf(log, "Basim: Could not create output file 'bunny.decr'\n");
        fclose(log);
        exit(-1);
    }

    // Decrypt bunny.mp4 (from data pipe -> bunny.decr)
    decryptFile(fd_data, fd_plain, sessionKey, iv);

    fprintf(log, "\nDecryption complete. Output written to bunny.decr\n");

    close(fd_plain);
    close(fd_data);
    fclose(log);
}
