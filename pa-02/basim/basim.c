/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   basim.c

Written By:  Team #3
     1- Colin Finnegan

Submitted on: 10/12/2025
----------------------------------------------------------------------------*/

#include "../myCrypto.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main ( int argc , char * argv[] )
{
    uint8_t digest[EVP_MAX_MD_SIZE] ;
    int     i , fd_out , fd_ctrl , fd_data  ;
    size_t  mdLen ;
    FILE    *log ;
    
    char *developerName = "Colin Finnegan" ;  

    printf( "\nThis is Basim's code by '%s'.\n\n" ,  developerName ) ;

    // Parse FD arguments
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <fd_ctrl> <fd_data>\n", argv[0]);
        exit(1);
    }
    fd_ctrl = atoi(argv[1]);   // Control pipe (signature)
    fd_data = atoi(argv[2]);   // Data pipe (file)
    
    // Open log file
    log = fopen("basim/logBasim.txt", "w");
    if (!log) {
        perror("basim/logBasim.txt");
        exit(1);
    }

    fprintf(log, "\nThis is Basim's code by '%s'.\n\n", developerName);
    fprintf(log, "Basim: I will receive digest from FD %d and file from FD %d\n",
            fd_ctrl, fd_data);

    // Create bunny.cpy to store incoming file
    fd_out = open("bunny.cpy", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_out < 0) {
        perror("open bunny.cpy");
        exit(1);
    }

    fprintf(log, "Basim: Starting to receive incoming file and compute its digest\n");

    // Receive file over Data Pipe and compute digest
    mdLen = fileDigest(fd_data, fd_out, digest);

    fprintf(log, "\nBasim: Here is locally-computed digest of incoming file:\n");
    BIO_dump_fp(log, digest, mdLen);

    // Close bunny.cpy
    close(fd_out);

    // Load Amal's RSA public key
    EVP_PKEY *rsa_pubK = NULL;
    FILE *pubFile = fopen("basim/amal_pub_key.pem", "r");  // symbolic link points here
    if (!pubFile) {
        fprintf(stderr, "Error: could not open basim/amal_pub_key.pem\n");
        exit(1);
    }
    rsa_pubK = PEM_read_PUBKEY(pubFile, NULL, NULL, NULL);
    fclose(pubFile);
    if (!rsa_pubK) {
        fprintf(stderr, "Error: could not read Amal's public key\n");
        exit(1);
    }

    // Receive signature from Control Pipe
    size_t signature_len;
    read(fd_ctrl, &signature_len, sizeof(size_t));  // first read length
    uint8_t *signature = malloc(signature_len);
    if (!signature) {
        perror("malloc signature");
        EVP_PKEY_free(rsa_pubK);
        exit(1);
    }
    read(fd_ctrl, signature, signature_len);        // then read actual signature

    fprintf(log, "\nBasim: I received the following signature from Amal:\n");
    BIO_dump_fp(log, signature, signature_len);

    // Verify the signature
    fprintf(log, "\nBasim: I found that Amal's signature is ");
    if (pubKeyVerify(signature, signature_len, rsa_pubK, digest, mdLen))
        fprintf(log, "VALID\n");
    else
        fprintf(log, "INVALID\n");

    // Cleanup
    free(signature);
    EVP_PKEY_free(rsa_pubK);
    fclose(log);

    return 0;
}

