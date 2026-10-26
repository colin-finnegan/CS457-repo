/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By: Colin Finnegan
     
Submitted on: 9/17/2025
----------------------------------------------------------------------------*/

#include "myCrypto.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}


//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

// For the following Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm

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
