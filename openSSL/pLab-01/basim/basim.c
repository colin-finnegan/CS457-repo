/*‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐
Programming Lab‐01 Decrypt using pre‐generated Key+IV

FILE: basim/basim.c

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
	unsigned ciphertext_len, decryptedtext_len;

	// Buffer for ciphertext / Decrypted. Ensure the buffer is long enough
	uint8_t ciphertext[CIPHER_LEN_MAX] , decryptedtext[PLAINTEXT_LEN_MAX];

	/* Initialise the crypto library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	FILE *log = fopen("basim/logBasim.txt" , "w" );
	if( ! log )
	{
		fprintf( stderr , "Basim: Could not create log file\n" ) ;
		exit(-1) ;
	}
	// Get the session symmetric key
	int fd_key , fd_iv ;
	fd_key = open("key.bin" , O_RDONLY ) ;
	if( fd_key == -1 ) {
		fprintf( stderr , "\nBasim: Could not open key.bin\n");
		fclose( log ) ; exit(-1) ;
	}

	read ( fd_key , key , key_len ) ;
	fprintf( log, "\nUsing this symmetric key of length %d bytes\n" , key_len );
	BIO_dump_fp ( log, (const char *) key, key_len );
	close( fd_key ) ;

	// Get the session Initial Vector
	fd_iv = open("iv.bin" , O_RDONLY ) ;
	if( fd_iv == -1 ) {
		fprintf( stderr , "\nBasim: Could not open iv.bin\n");
		fclose( log ) ; exit(-1) ;
	}

	read ( fd_iv , iv , iv_len ) ;
	fprintf( log , "\nUsing this Initial Vector of length %d bytes\n" , iv_len );
	BIO_dump_fp ( log, (const char *) iv , iv_len );
	close( fd_iv ) ;

	/* Read in the cipher text up to CIPHER_LEN_MAX bytes */
	int fd_ciph ;
	fd_ciph = open("amal/ciphertext.bin" , O_RDONLY ) ;
	if( fd_ciph == -1 )
	{
		fprintf( stderr , "\nBasim: Could not open ciphertext.bin\n");
		fclose( log ) ; exit(-1) ;
	}

	ciphertext_len = read( fd_ciph , ciphertext , CIPHER_LEN_MAX ) ;
	fprintf( log, "\nHexDump of Cipher text:\n");
	BIO_dump_fp ( log, (const char *) ciphertext, ciphertext_len);
	close( fd_ciph ) ;

	/* Deccrypt the cipher text */
	decryptedtext_len =
	decrypt( ciphertext, ciphertext_len, key, iv, decryptedtext );

	fprintf( log, "\nHexDump of Decrypted text:\n");
	BIO_dump_fp ( log , (const char *) decryptedtext, decryptedtext_len );

	int fd_decr ;
	fd_decr = open("basim/decryptedtext.bin" , O_WRONLY | O_CREAT , S_IRUSR | S_IWUSR) ;
	if( fd_decr == -1 )
	{
		fprintf( stderr , "\nBasim: Could not open ciphertext.bin\n");
		fclose( log ) ; exit(-1) ;
	}
	write ( fd_decr , (const char *) decryptedtext, decryptedtext_len );
	close( fd_decr ) ;
	fclose( log ) ;

	/* Clean up */
// 	EVP_cleanup();
// 	ERR_free_strings();
}
