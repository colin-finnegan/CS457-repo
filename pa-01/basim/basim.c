/*----------------------------------------------------------------------------
PA-01: Symmetric Encryption of Large Data

FILE:   basim.c

Written By: Colin Finneganx    
Submitted on: 9/17/2025
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{
    //
    // Define any variable you need here
    //
    int fd_ctrl, fd_data, fd_key, fd_iv, fd_decr;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int key_len, iv_len;
    char *decrypted = "bunny.decr";

    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if( argc < 3 )
    {
        printf("Basim is missing command-line arguments. Usage: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_ctrl = atoi( argv[1] ) ;
    fd_data = atoi( argv[2] ) ;

    FILE *log = fopen("basim/logBasim.txt" , "w" );
    if ( ! log ) {
        fprintf( stderr , "This is Basim. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Basim. Will read encrypted data from FD %d\n" , fd_data );
                   
    // Get the session symmetric key
    fd_key = open("basim/key.bin" , O_RDONLY );
    if ( fd_key == -1 ) {
        fprintf( log , "\nCould not open Basim's key.bin\n");
        exit(-1) ;
    }

    key_len = read ( fd_key , key , sizeof(key) ) ;
    fprintf( log, "\nUsing this symmetric key of length %d bytes\n" , key_len );
    BIO_dump_fp ( log, (const char*)key, key_len );
    close( fd_key ) ;

    // Get the session Initial Vector 
    fd_iv = open( "basim/iv.bin" , O_RDONLY ) ;
    if ( fd_iv == -1 ) {
        fprintf( log , "\nCould not open Basim's iv.bin\n");
        exit(-1) ;
    }

    iv_len = read ( fd_iv , iv , sizeof(iv) ) ;
    fprintf( log, "\nUsing this IV of length %d bytes\n" , iv_len );
    BIO_dump_fp ( log, (const char*)iv, iv_len );
    close( fd_iv ) ;

    // Open the file for the output decrypted file
    fd_decr = open( decrypted , O_WRONLY | O_CREAT | O_TRUNC , 0644 );
    if( fd_decr == -1 ) {
        fprintf( log , "\nCould not open '%s'\n" , decrypted );
        exit(-1) ;
    }
   
    fflush( log ) ;
	
    /* Finally, decrypt the ciphertext file */
    decryptFile( fd_data , fd_decr , key , iv );

    /* Clean up */
    close(fd_data);
    close(fd_decr);

    fflush(log);
    fclose(log);

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
