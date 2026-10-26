/*----------------------------------------------------------------------------
pLAB-02   Key Exchange using Public-Key Encryption

Written By:  1- Dr. Mohamed Aboutabl
Submitted on: 9/24/2025
----------------------------------------------------------------------------*/
/*
    I am Amal. I will encrypt a file to Basim.
    I will exchange the session key with his encrypted using her RSA public key.

    Adapted from: openssl Documentation
*/

#include "../myCrypto.h"

void main( int argc , char * argv[] ) 
{
    // key & IV for symmetric encryption of data
    uint8_t  sessionKey[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ;    
    char     *plaintextFile  = "bunny.mp4" ;
    int      fd_plain , fd_ctrl , fd_data ;
    
    if( argc < 3 )
    {
        printf("Amal is missing command-line arguments. Usage: %s <ctrlFD> <dataFD>\n" 
               , argv[0]) ;
        exit( -1 ) ;
    }
    fd_ctrl = atoi( argv[1] ) ;
    fd_data = atoi( argv[2] ) ;

    // Open Log File
    FILE *log = fopen("amal/logAmal.txt" , "w" );
    if ( ! log )
    { 
        fprintf( stderr , "Amal: Could not create log file\n"); 
        exit( -1 ) ; 
    }
    fprintf( log , "This is Amal. Will send encrypted data to FD %d " 
                   "and session key/IV to FD %d\n" , fd_data , fd_ctrl );

    // Open Plaintext File
    fd_plain = open( plaintextFile , O_RDONLY )  ;
    if( fd_plain == -1 )  
    {
        fprintf( log , "\nCould not open '%s'\n" , plaintextFile ) ; 
        fclose( log );  exit( -1 ) ;
    }
 
    // Get Basim's RSA Public key generated outside this program by the opessl tool 
    EVP_PKEY  *rsa_pubK = NULL  ;

    rsa_pubK  = getRSAfromFile( "amal/basim_pub_key.pem"  , 1 ) ;
    if( ! rsa_pubK ) 
    {
        fprintf( log, "Unable to read Basim's Public key\n" ); 
        fclose( log ) ;  exit( -1 ) ; 
    }

    fprintf( log, "\n**** Size of Basim's Public Key is %d bits\n" , EVP_PKEY_get_bits( rsa_pubK ) );

    // Generate a random session key , and an IV
    RAND_bytes( sessionKey , SYMMETRIC_KEY_LEN );
    fprintf( log, "\nUsing this symmetric session key of length %d bytes\n" 
                , SYMMETRIC_KEY_LEN );
    BIO_dump_fp ( log, (const char *) sessionKey , SYMMETRIC_KEY_LEN );

    size_t iv_len = INITVECTOR_LEN ;
    RAND_bytes( iv  , iv_len  );
    fprintf( log, "\nUsing this Initial Vector of length %lu bytes\n" 
                , iv_len );
    BIO_dump_fp ( log, (const char *) iv , iv_len );

    // Create and Initialize a context for RSA public-key encryption
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new( rsa_pubK , NULL /* NULL means use default RSA engine*/ );
    if ( ! ctx )
    {
        fprintf( log, "Unable to creat a new context with Basim's public key\n" ); 
        fclose( log ) ;  exit( -1 ) ; 
    }

    if ( EVP_PKEY_encrypt_init( ctx ) <= 0)
    {
        fprintf( log, "Unable to initialize the context for Basim's public key encryption\n" ); 
        fclose( log ) ;  exit( -1 ) ;
    }

    if (  EVP_PKEY_CTX_set_rsa_padding( ctx, RSA_PKCS1_OAEP_PADDING ) <= 0  )
    {
        fprintf( log, "Unable to set the PADDING mode of the context for Basim's public key encryption\n" ); 
        fclose( log ) ;  exit( -1 ) ;
    }


    // Encrypt the session key using Basim's Public Key
    
    // First, determine how big the size of the ciphertext could be
    size_t encrKey_len ; 
    if ( EVP_PKEY_encrypt( ctx, NULL, &encrKey_len, sessionKey , SYMMETRIC_KEY_LEN ) <= 0)
    {
        fprintf( log, "Unable to determine output length if Basim's public key encryption\n" ); 
        fclose( log ) ;  exit( -1 ) ;
    }
    
    // Next allocate memory for the ciphertext
    uint8_t *encryptedKey = malloc( encrKey_len ) ;  
    if( ! encryptedKey ) 
    { 
        fprintf( log, "Insufficient memory to Encrypt Session Key\n" );  
        fclose( log ) ;  exit( -1 ) ;
    }

    // Finally, encrypt the session key using Basim's public key
    if ( EVP_PKEY_encrypt( ctx, encryptedKey, &encrKey_len, sessionKey , SYMMETRIC_KEY_LEN ) <= 0)
    {
        fprintf( log, "Encryption of the session key using Basim's Public Key FAILED\n" ); 
        fclose( log ) ;  exit( -1 ) ;
    }
    
    // Send the encrypted session key, followed by the IV to the AtoB Control Pipe 
    write( fd_ctrl , &encrKey_len , sizeof(encrKey_len) ) ;
    write( fd_ctrl , encryptedKey , encrKey_len         ) ;
    write( fd_ctrl , &iv_len      , sizeof(iv_len)      ) ;
    write( fd_ctrl , iv           , iv_len              ) ;

    free ( encryptedKey );
    EVP_PKEY_CTX_free( ctx ) ;
    EVP_PKEY_free( rsa_pubK ) ;
	
	close( fd_ctrl ) ;
    
    /* Finally, encrypt the plaintext file using the symmetric session key */
    encryptFile( fd_plain, fd_data , sessionKey , iv );
    
    close( fd_plain ) ;
    close( fd_data  ) ;
    close( fd_ctrl  ) ;
    fclose( log ); 

}

