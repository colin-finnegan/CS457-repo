/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   amal.c

Written By:  Team #3
     1- Colin Finnegan

Submitted on: 10/12/2025
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{
    uint8_t digest[EVP_MAX_MD_SIZE] ;
    int     i , fd_in , fd_ctrl , fd_data  ;
    FILE    *log ;
    
    char *developerName = "Colin Finnegan" ;  
    
    printf( "\nThis is Amal's code by '%s'\n\n" , developerName ) ;

     // Parse file descriptors from dispatcher args
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <fd_ctrl> <fd_data>\n", argv[0]);
        exit(1);
    }
    fd_ctrl = atoi(argv[1]);   // control pipe (signature)
    fd_data = atoi(argv[2]);   // data pipe (file)
    
    // Open a log file for Amal
    log = fopen("amal/logAmal.txt", "w");
    if (!log) {
        perror("amal/logAmal.txt");
        exit(1);
    }

    fprintf(log, "\nThis is Amal's code by '%s'.\n\n", developerName);
    fprintf(log, "Amal: I will send digest to FD %d and file to FD %d\n",
                 fd_ctrl, fd_data);

    // Open the bunny.mp4 file
    fd_in = open("bunny.mp4", O_RDONLY);
    if (fd_in < 0) {
        perror("open bunny.mp4");
        exit(1);
    }

    // Compute the digest of the file AND forward the file to Basim
    size_t mdLen = fileDigest(fd_in, fd_data, digest);

    fprintf(log, "\nAmal: Here is the digest of the file:\n");
    BIO_dump_fp(log, digest, mdLen);

    // Load Amal's RSA private key
    EVP_PKEY *rsa_privK = NULL;
    FILE *privFile = fopen("amal/amal_priv_key.pem", "r");
    if (!privFile) {
        fprintf(stderr, "Error: could not open amal/amal_priv_key.pem\n");
        exit(1);
    }
    rsa_privK = PEM_read_PrivateKey(privFile, NULL, NULL, NULL);
    fclose(privFile);
    if (!rsa_privK) {
        fprintf(stderr, "Error: could not read Amal's private key\n");
        exit(1);
    }

    // Sign the digest
    uint8_t *signature = malloc(EVP_PKEY_size(rsa_privK));
    size_t   signature_len = 0;

    if (!privKeySign(&signature, &signature_len, rsa_privK, digest, mdLen)) {
        fprintf(log, "Unable to sign digest using Amal's Private key\n");
        EVP_PKEY_free(rsa_privK);
        free(signature);
        exit(-1);
    }

    fprintf(log, "\nAmal: Here is my signature on the file:\n");
    BIO_dump_fp(log, signature, signature_len);

    // Send the signature to Basim via the control pipe
    // First send the length (so Basim knows how many bytes to expect)
    write(fd_ctrl, &signature_len, sizeof(size_t));
    write(fd_ctrl, signature, signature_len);

    // Cleanup
    close(fd_in);
    fclose(log);
    EVP_PKEY_free(rsa_privK);
    free(signature);

    return 0;
}

