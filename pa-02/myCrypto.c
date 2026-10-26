/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By:  Team #3
     1- Colin Finnegan

Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "\n%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}


unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText )
{
//
//       ALL PREVIOUS CODE FROM pLab-01
//           MUST  EXIST  HERE
//

	int 	 status ;
	unsigned len=0 , encryptedLen=0 ;

	/* Create and initialise the context */
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;
	if( ! ctx )
		handleErrors("encrypt: failed to creat CTX");

	// Initialise the encryption operation.
	status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ;
	if( status != 1 )
		handleErrors("encrypt: failed to EncryptInit_ex");

	// Call EncryptUpdate as many times as needed (e.g. inside a loop)
	// to perform regular encryption
	status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len) ;
	if( status != 1 )
		handleErrors("encrypt: failed to EncryptUpdate");
	encryptedLen += len;

	// If additional ciphertext may still be generated,
	// the pCipherText pointer must be first advanced forward
	pCipherText += len ;

	// Finalize the encryption.
	status = EVP_EncryptFinal_ex( ctx, pCipherText , &len ) ;
	if( status != 1 )
		handleErrors("encrypt: failed to EncryptFinal_ex");
	encryptedLen += len; // len could be 0 if no additional cipher text was generated

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return encryptedLen ;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
//
//       ALL PREVIOUS CODE FROM pLab-01
//           MUST  EXIST  HERE
//

	int 	 status ;
	unsigned len=0 , decryptedLen=0 ;

	/* Create and initialise the context */
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;
	if( ! ctx )
		handleErrors("decrypt: failed to creat CTX");

	// Initialise the decryption operation.
	status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ;
	if( status != 1 )
		handleErrors("decrypt: failed to DecryptInit_ex");

	// Call DecryptUpdate as many times as needed (e.g. inside a loop)
	// to perform regular decryption
	status = EVP_DecryptUpdate( ctx, pDecryptedText, &len, pCipherText, cipherText_len) ;
	if( status != 1 )
		handleErrors("decrypt: failed to DecryptUpdate");
	decryptedLen += len;

	// If additionl decrypted text may still be generated,
	// the pDecryptedText pointer must be first advanced forward
	pDecryptedText += len ;

	// Finalize the decryption.
	status = EVP_DecryptFinal_ex( ctx, pDecryptedText , &len ) ;
	if( status != 1 )
		handleErrors("decrypt: failed to DecryptFinal_ex");
	decryptedLen += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return decryptedLen;
}


//-----------------------------------------------------------------------------


static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application

//-----------------------------------------------------------------------------

int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    int bytesRead, bytesWritten;
	int cipherLen, totalCipherLen = 0;
	
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("encryptFile: failed to create CTX");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors("encryptFile: EncryptInit failed");
	
	while ((bytesRead = read(fd_in, plaintext, PLAINTEXT_LEN_MAX)) > 0)
	{
		if (EVP_EncryptUpdate( ctx, ciphertext, &cipherLen, plaintext, bytesRead) != 1)
		{
			handleErrors("encryptFile: EncryptUpdate failed");
		}
		
		bytesWritten = write(fd_out, ciphertext, cipherLen);
		if (bytesWritten != cipherLen)
		{
			handleErrors("encryptFile: write failed");
		}
		
		totalCipherLen += cipherLen;
	}
	
	if (EVP_EncryptFinal_ex(ctx, ciphertext, &cipherLen) != 1)
	{
        handleErrors("encryptFile: EncryptFinal failed");
	}
	
    bytesWritten = write(fd_out, ciphertext, cipherLen);
    if (bytesWritten != cipherLen)
    {
		handleErrors("encryptFile: final write failed");
	}
	
    totalCipherLen += cipherLen;
	
	EVP_CIPHER_CTX_free(ctx);
    return totalCipherLen;
}



//-----------------------------------------------------------------------------


int decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
	int bytesRead, bytesWritten;
	int plainLen, totalPlainLen = 0;
	
	
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("decryptFile: failed to create CTX");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors("decryptFile: DecryptInit failed");
	
	while ((bytesRead = read(fd_in, ciphertext, CIPHER_LEN_MAX)) > 0)
	{
		if (EVP_DecryptUpdate( ctx, decryptext, &plainLen, ciphertext, bytesRead) != 1)
		{
			handleErrors("decryptFile: DecryptUpdate failed");
		}
		
		bytesWritten = write(fd_out, decryptext, plainLen);
		if (bytesWritten != plainLen)
		{
			handleErrors("decryptFile: write failed");
		}
		
		totalPlainLen += plainLen;
	}
	
	if (EVP_DecryptFinal_ex(ctx, decryptext, &plainLen) != 1)
	{
        handleErrors("decryptFile: DecryptFinal failed");
	}
	
    bytesWritten = write(fd_out, decryptext, plainLen);
    if (bytesWritten != plainLen)
    {
		handleErrors("decryptFile: final write failed");
	}
	
    totalPlainLen += plainLen;
	
	EVP_CIPHER_CTX_free(ctx);
    return totalPlainLen;
}

//***********************************************************************
// PA-02
//***********************************************************************
// Sign the 'inData' array into the 'sig' array using the private 'privKey'
// 'inLen' is the size of the input array in bytes.
// the '*sig' pointer will be allocated memory large enough to store the signature
// report the actual length in bytes of the result in 'sigLen' 
//
// Returns: 
//    1 on success, or 0 on ANY REASON OF FAILURE

int privKeySign( uint8_t **sig , size_t *sigLen , EVP_PKEY  *privKey , 
                 uint8_t *inData , size_t inLen ) 
{
    if (!sig || !sigLen || !privKey || !inData) {
        fprintf(stderr, "privKeySign: NULL parameter\n");
        return 0;
    }

    *sig = NULL;
    *sigLen = 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privKey, NULL);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_base_id(privKey) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
    }

    /* First call: obtain required signature length */
    size_t cipherLen = 0;
    if (EVP_PKEY_sign(ctx, NULL, &cipherLen, inData, inLen) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Allocate buffer for signature */
    uint8_t *out = (uint8_t *)OPENSSL_malloc(cipherLen);
    if (!out) {
        fprintf(stderr, "privKeySign: OPENSSL_malloc failed\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Second call: produce the signature */
    if (EVP_PKEY_sign(ctx, out, &cipherLen, inData, inLen) <= 0) {
        ERR_print_errors_fp(stderr);
        OPENSSL_free(out);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Success: hand buffer and length back to caller */
    *sig = out;
    *sigLen = cipherLen;

    // All is good
    EVP_PKEY_CTX_free( ctx );     // remember to do this if any failure is encountered above

    return 1;
}

//-----------------------------------------------------------------------------
// Verify that the provided signature in 'sig' when decrypted using 'pubKey' 
// matches the data in 'data'
// Returns 1 if they match, 0 otherwise

int pubKeyVerify( uint8_t *sig , size_t sigLen , EVP_PKEY  *pubKey 
           , uint8_t *data , size_t dataLen ) 
{
    // Guard against incoming NULL pointers
    if ( !sig ||  !pubKey  ||  !data  )
    {
        printf(  "\n******* pkeySign received some NULL pointers\n" ); 
        return 0 ; 
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, NULL);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_base_id(pubKey) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
    }

    // Verify the signature vs the incoming data using this context
    int decision = EVP_PKEY_verify(ctx, sig, sigLen, data, dataLen);

    // Free the context
    EVP_PKEY_CTX_free(ctx);

    if (decision < 0) {
        ERR_print_errors_fp(stderr);
        decision = 0;
    }

    return decision ;

}

//-----------------------------------------------------------------------------


size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from the 'fd_in' file descriptor
// Apply the HASH_ALGORITHM() to compute the hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, also write a copy of the incoming data stream file to 'fd_out'
// Returns actual size in bytes of the computed digest
{
    EVP_MD_CTX *mdCtx ;
    size_t nBytes ;
    unsigned int  mdLen ;

	mdCtx = EVP_MD_CTX_new();
    if (!mdCtx)
        handleErrors("fileDigest: failed to create MD_CTX");

    // Initialize the context using EVP_DigestInit_ex() so that it deploys 
    // the HASH_ALGORITHM() hashing function 
    if (EVP_DigestInit_ex(mdCtx, HASH_ALGORITHM(), NULL) != 1)
        handleErrors("fileDigest: DigestInit failed");

    while (1)   // Loop until end-of input file
    {
        uint8_t buffer[4096];

        // Read a chunk of input from fd_in. Exit the loop when End-of-File is reached
        nBytes = read(fd_in, buffer, sizeof(buffer));
        if (nBytes == 0)   // EOF
            break;
        if ((ssize_t)nBytes < 0) {
            perror("fileDigest: read failed");
            EVP_MD_CTX_free(mdCtx);
            return 0;
        }

        // EVP_DigestUpdate( )
        if (EVP_DigestUpdate(mdCtx, buffer, nBytes) != 1)
            handleErrors("fileDigest: DigestUpdate failed");

        // if ( fd_out > 0 ) send the above chunk of data to fd_out
        if (fd_out > 0) {
            ssize_t w = write(fd_out, buffer, nBytes);
            if (w != (ssize_t)nBytes) {
                handleErrors("fileDigest: write failed");
            }
        }
    }

    // EVP_DigestFinal_ex( )
    if (EVP_DigestFinal_ex(mdCtx, digest, &mdLen) != 1)
        handleErrors("fileDigest: DigestFinal failed");

    // EVP_MD_CTX_free( );
    EVP_MD_CTX_destroy(mdCtx);

    return mdLen;
}

