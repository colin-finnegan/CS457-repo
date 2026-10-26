/*‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐
Programming Lab‐01 Encrypt using pre‐generated Key+IV

FILE: amal/amal.c

Written By : Colin Finnegan
Submitted on: 9/7/2025

Adapted from:

	https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

	https://www.openssl.org/docs/man1.0.2/crypto/

‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐*/

#include "../myCrypto.h"

void main()
{

	uint8_t key[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ;
	unsigned key_len = 32 ; // i.e. 256 bits
	unsigned iv_len = 16 ; // i.e. 128 bits
	unsigned plaintext_len, ciphertext_len;

	/* Message to be encrypted */
	uint8_t *plaintext = (uint8_t *) "Hello World! This is Amal embracing you all with hope." ;

	/* Buffer for ciphertext. Ensure the buffer is long enough for the
	ciphertext which may be longer than the plaintext, depending on the
	algorithm and mode */
	uint8_t ciphertext[CIPHER_LEN_MAX];

	/* Initialise the crypto library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	FILE *log = fopen("amal/logAmal.txt" , "w" );
	if( ! log )
	{
		fprintf( stderr , "Amal: Could not create log file\n" ) ;
		exit(-1) ;
	}
	// Get the session symmetric key
	int fd_key , fd_iv ;
	fd_key = open("key.bin" , O_RDONLY ) ;
	if( fd_key == -1 ) {
		fprintf( stderr , "\nAmal: Could not open key.bin\n");
		fclose( log ) ; exit(-1) ;
	}

	read ( fd_key , key , key_len ) ;
	fprintf( log , "\nUsing this symmetric key of length %d bytes\n" , key_len ) ;
	BIO_dump_fp ( log , (const char *) key, key_len );
	close( fd_key ) ;
	
	// Get the session Initial Vector
	fd_iv = open("iv.bin" , O_RDONLY ) ;
	if( fd_iv == -1 ) {
		fprintf( stderr , "\nAmal: Could not open iv.bin\n" );
		fclose( log ) ; exit(-1) ;
	}

	read ( fd_iv , iv , iv_len ) ;
	fprintf( log , "\nUsing this Initial Vector of length %d bytes\n" , iv_len );
	BIO_dump_fp ( log , (const char *) iv , iv_len );
	close( fd_iv ) ;

	// Display the plaintext for debugging purposes
	plaintext_len = strlen( plaintext ) ;
	fprintf( log , "\nHexDump of Plaintext:\n" ) ;
	BIO_dump_fp ( log , (const char *) plaintext, plaintext_len );

	/* Encrypt the plaintext */
	ciphertext_len =
	encrypt( plaintext, plaintext_len , key, iv, ciphertext );

	/* Do something useful with the ciphertext here */
	fprintf( log , "\nHexDump of Ciphertext:\n" ) ;
	BIO_dump_fp ( log , (const char *) ciphertext, ciphertext_len);
	
	int fd_ciph ;
	fd_ciph = open("amal/ciphertext.bin" , O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR) ;
	if( fd_ciph == -1 )
	{
		fprintf( stderr , "\nAmal: Could not open ciphertext.bin\n" ) ;
		fclose( log ) ; exit(-1) ;
	}
	write( fd_ciph , (const char *) ciphertext, ciphertext_len ) ;
	close( fd_ciph ) ;
	fclose( log ) ;
	
	/* Clean up */
// 	EVP_cleanup();
// 	ERR_free_strings();
}