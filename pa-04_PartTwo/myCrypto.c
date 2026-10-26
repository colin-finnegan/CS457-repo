/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By: Colin Finnegan
Submitted on: 
     11/25/2025
	 
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

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int getKeyFromFile( char *keyF , myKey_t *x )
{
    int   fd_key  ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // first, read the symmetric encryption key
	if( SYMMETRIC_KEY_LEN  != read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read key from file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // Next, read the Initialialzation Vector
    if ( INITVECTOR_LEN  != read ( fd_key , x->iv , INITVECTOR_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read the IV from file '%s'\n" , keyF ); 
        return 0 ; 
    }
	
    close( fd_key ) ;
    
    return 1;
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(A)  ||  A  ||  Len(B)  ||  B  ||  Na
// All Len(*) fields are size_t integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

static ssize_t readn(int fd, void *buf, size_t n) {
    size_t nleft = n;
    ssize_t nread;
    uint8_t *ptr = (uint8_t*)buf;

    while (nleft > 0) {
        nread = read(fd, ptr, nleft);
        if (nread < 0) {
            if (errno == EINTR) continue;
            return -1;
        } else if (nread == 0) {
            break; // EOF
        }
        nleft -= nread;
        ptr += nread;
    }
    return (ssize_t)(n - nleft);
}

size_t MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t Na )
{

    if ( !log || !msg1 || !IDa || !IDb || !Na ) {
        fprintf(stderr, "MSG1_new: NULL parameter\n");
        return 0;
    }

    size_t LenA = strlen(IDa) + 1;
    size_t LenB = strlen(IDb) + 1;

    size_t LenMsg1 = LENSIZE + LenA + LENSIZE + LenB + NONCELEN;

    uint8_t *pbuf = (uint8_t *) malloc(LenMsg1);
    if (!pbuf) {
        fprintf(stderr, "MSG1_new: malloc failed for %zu bytes\n", LenMsg1);
        return 0;
    }

    uint8_t *p = pbuf;

    memcpy(p, &LenA, LENSIZE); p += LENSIZE;
    memcpy(p, IDa, LenA);      p += LenA;
    memcpy(p, &LenB, LENSIZE); p += LENSIZE;
    memcpy(p, IDb, LenB);      p += LenB;
    memcpy(p, Na, NONCELEN);   p += NONCELEN;

    *msg1 = pbuf;

    fprintf( log , "The following new MSG1 ( %lu bytes ) has been created by MSG1_new ():" , LenMsg1 ) ;
    fprintf( log , "\n" );
    BIO_dump_indent_fp( log, (const char *)pbuf, (long)LenMsg1, 4 );
    fprintf( log , "\n" );

    return LenMsg1 ;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t Na )
{

    if (!log || fd < 0 || !IDa || !IDb || !Na) {
        fprintf(stderr, "MSG1_receive: NULL/invalid parameter\n");
        exitError("MSG1_receive: NULL/invalid parameter");
    }

    size_t LenA = 0, LenB = 0;
    ssize_t r;

    // 1) Read Len(ID_A)
    r = readn(fd, &LenA, LENSIZE);
    if (r != LENSIZE) {
        fprintf(log, "Unable to receive all %lu bytes of Len(IDA) in MSG1_receive() ... EXITING\n", LENSIZE);
        fflush(log); fclose(log);
        exitError("Unable to receive all bytes LenA in MSG1_receive()");
    }

    // 2) Allocate memory for ID_A
    *IDa = (char *)malloc(LenA + 1);
    if (!(*IDa)) {
        fprintf(log, "Out of Memory allocating %u bytes for IDA in MSG1_receive() ... EXITING\n", (unsigned)LenA);
        fflush(log); fclose(log);
        exitError("Out of Memory allocating IDA in MSG1_receive()");
    }

    // Read ID_A
    r = readn(fd, *IDa, LenA);
    if (r != (ssize_t)LenA) {
        fprintf(log, "Unable to receive all %lu bytes of IDA in MSG1_receive() ... EXITING\n", LenA);
        fflush(log); fclose(log);
        exitError("Unable to receive all bytes of IDA in MSG1_receive()");
    }
    (*IDa)[LenA] = '\0';

    // 3) Read Len(ID_B)
    r = readn(fd, &LenB, LENSIZE);
    if (r != LENSIZE) {
        fprintf(log, "Unable to receive all %lu bytes of Len(IDB) in MSG1_receive() ... EXITING\n", LENSIZE);
        fflush(log); fclose(log);
        exitError("Unable to receive all bytes of LenB in MSG1_receive()");
    }

    // 4) Allocate memory for ID_B
    *IDb = (char *)malloc(LenB + 1);
    if (!(*IDb)) {
        fprintf(log, "Out of Memory allocating %u bytes for IDB in MSG1_receive() ... EXITING\n", (unsigned)LenB);
        fflush(log); fclose(log);
        exitError("Out of Memory allocating IDB in MSG1_receive()");
    }

    // Read ID_B
    r = readn(fd, *IDb, LenB);
    if (r != (ssize_t)LenB) {
        fprintf(log, "Unable to receive all %u bytes of IDB in MSG1_receive() ... EXITING\n", (unsigned)LenB);
        fflush(log); fclose(log);
        exitError("Unable to receive all bytes of IDB in MSG1_receive()");
    }
    (*IDb)[LenB] = '\0';

    // 5) Read nonce
    r = readn(fd, Na, NONCELEN);
    if (r != (ssize_t)NONCELEN) {
        fprintf(log, "Unable to receive all %lu bytes of Na in MSG1_receive() ... EXITING\n", NONCELEN);
        fflush(log); fclose(log);
        exitError("Unable to receive all bytes of Na in MSG1_receive()");
    }

    size_t LenMsg1 = LENSIZE + LenA + LENSIZE + LenB + NONCELEN;
    fprintf(log, "MSG1 ( %lu bytes ) has been received on FD %d by MSG1_receive():\n", LenMsg1, fd);
    fflush(log);

    return;
}

//***********************************************************************
// PA-04   Part  TWO
//***********************************************************************
/*  Use these static arrays from PA-01 earlier

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application

*/

// Also, use this new one for your convenience
static unsigned char   ciphertext2[ CIPHER_LEN_MAX    ] ; // Temporarily store outcome of encryption

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher
// All L() fields are size_t integers
// Set *msg2 to point at the newly built message
// Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2  

size_t MSG2_new( FILE *log , uint8_t **msg2, const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb  , Nonce_t *Na )
{

    size_t LenMsg2;
    
    if (!log || !msg2 || !Ka || !Kb || !Ks || !IDa || !IDb || !Na) {
        fprintf(stderr, "MSG2_new: NULL parameter\n");
        return 0;
    }
	
	fprintf(log, "KDC: created this session key Ks { Key , IV } (%u Bytes ) is:\n", 
            SYMMETRIC_KEY_LEN + INITVECTOR_LEN);
    uint8_t key_iv[SYMMETRIC_KEY_LEN + INITVECTOR_LEN];
	memcpy(key_iv, Ks->key, SYMMETRIC_KEY_LEN);
	memcpy(key_iv + SYMMETRIC_KEY_LEN, Ks->iv, INITVECTOR_LEN);

	// Dump as one contiguous block
	BIO_dump_indent_fp(log, (const char*)key_iv, SYMMETRIC_KEY_LEN + INITVECTOR_LEN, 4);
	fprintf(log, "\n");
	fflush(log);
    
    size_t LenA = strlen(IDa) + 1;
    size_t ticketPlainLen = SYMMETRIC_KEY_LEN + INITVECTOR_LEN + LENSIZE + LenA;
    
    //---------------------------------------------------------------------------------------
    // Construct TktPlain = { Ks.key || Ks.iv || L(IDa) || IDa }
    // Use LOCAL buffer for ticket plaintext to avoid corruption
    //---------------------------------------------------------------------------------------
    uint8_t TktPlain[CIPHER_LEN_MAX];  // LOCAL buffer
    uint8_t *tkt = TktPlain;
    
    memcpy(tkt, Ks->key, SYMMETRIC_KEY_LEN);
    tkt += SYMMETRIC_KEY_LEN;
    memcpy(tkt, Ks->iv, INITVECTOR_LEN); 
    tkt += INITVECTOR_LEN;
    memcpy(tkt, &LenA, LENSIZE);
    tkt += LENSIZE;
    memcpy(tkt, IDa, LenA);
    tkt += LenA;
    
    // Use local buffer for encrypted ticket too
    uint8_t encryptedTicket[CIPHER_LEN_MAX];
    size_t TktCipherLen = encrypt(TktPlain, ticketPlainLen, Kb->key, Kb->iv, encryptedTicket);
    
    // Log the plaintext ticket
    fprintf(log, "Plaintext Ticket (%lu Bytes) is\n", ticketPlainLen);
    BIO_dump_indent_fp(log, TktPlain, ticketPlainLen, 4);
    fprintf(log, "\n");
    fflush(log);
    
    //---------------------------------------------------------------------------------------
    // Construct MSG2 plaintext = { Ks.key || Ks.iv || L(IDb) || IDb || Na || L(TktCipher) || TktCipher }
    // Use LOCAL buffer for MSG2 plaintext
    //---------------------------------------------------------------------------------------
    uint8_t msg2Plain[CIPHER_LEN_MAX];  // LOCAL buffer
    uint8_t *p = msg2Plain;
    
    size_t LenB = strlen(IDb) + 1;
    size_t plainLen = SYMMETRIC_KEY_LEN + INITVECTOR_LEN + LENSIZE + LenB + NONCELEN + LENSIZE + TktCipherLen;
    
    // Copy Ks (key + IV)
    memcpy(p, Ks->key, SYMMETRIC_KEY_LEN);
    p += SYMMETRIC_KEY_LEN;
    memcpy(p, Ks->iv, INITVECTOR_LEN);
    p += INITVECTOR_LEN;
    
    // Copy IDb with length prefix
    memcpy(p, &LenB, LENSIZE);
    p += LENSIZE;
    memcpy(p, IDb, LenB);
    p += LenB;
    
    // Copy Na
    memcpy(p, Na, NONCELEN);
    p += NONCELEN;
    
    // Copy encrypted ticket with length prefix
    memcpy(p, &TktCipherLen, LENSIZE);
    p += LENSIZE;
    memcpy(p, encryptedTicket, TktCipherLen);
    p += TktCipherLen;
    
    // Verify we wrote the correct amount
    if ((p - msg2Plain) != plainLen) {
        fprintf(stderr, "MSG2_new: buffer size mismatch %ld != %lu\n", (p - msg2Plain), plainLen);
        return 0;
    }
    
    // Now encrypt MSG2 using Ka - can use global ciphertext2 for final output
    size_t plainCipherLen = encrypt(msg2Plain, plainLen, Ka->key, Ka->iv, ciphertext2);
    LenMsg2 = plainCipherLen;
    
    // Allocate memory for caller's msg2 buffer
    *msg2 = (uint8_t *)malloc(LenMsg2);
    if (!*msg2) {
        fprintf(stderr, "MSG2_new: malloc failed\n");
        return 0;
    }
    memcpy(*msg2, ciphertext2, LenMsg2);
	
	fprintf(log, "The following Encrypted MSG2 ( %lu bytes ) has been created by MSG2_new():  \n", LenMsg2);
    BIO_dump_indent_fp(log, *msg2, LenMsg2, 4);
    fprintf(log, "\n");
    fflush(log);
    
    // Logging for debugging
    fprintf(log, "This is the content of MSG2 ( %lu Bytes ) before Encryption:\n", plainLen);
    fprintf(log, "    Ks { key + IV } (%u Bytes) is:\n", SYMMETRIC_KEY_LEN + INITVECTOR_LEN);
    BIO_dump_indent_fp(log, msg2Plain, SYMMETRIC_KEY_LEN + INITVECTOR_LEN, 4);
    fprintf(log, "\n");
    
    fprintf(log, "    IDb (%lu Bytes) is:\n", LenB);
    BIO_dump_indent_fp(log, msg2Plain + SYMMETRIC_KEY_LEN + INITVECTOR_LEN + LENSIZE, LenB, 4);
    fprintf(log, "\n");
    
    fprintf(log, "    Na (%lu Bytes) is:\n", NONCELEN);
    BIO_dump_indent_fp(log, msg2Plain + SYMMETRIC_KEY_LEN + INITVECTOR_LEN + LENSIZE + LenB, NONCELEN, 4);
    fprintf(log, "\n");
    
    fprintf(log, "    Encrypted Ticket (%lu Bytes) is\n", TktCipherLen);
    BIO_dump_indent_fp(log, encryptedTicket, TktCipherLen, 4);
    fprintf(log, "\n");
    
    fflush(log);
    
    return LenMsg2;

}


ssize_t read_exact(int fd, uint8_t *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t nRead = read(fd, buf + total, n - total);
        if (nRead <= 0) exitError("read_exact failed");
        total += nRead;
    }
    return total;
}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields 
// *Ks, *IDb, *Na and TktCipher = Encr{ L(Ks) || Ks  || L(IDa)  || IDa }

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from the KDC
// Parse the incoming msg2 into the component fields 
// Format: Ks.key || Ks.iv || IDb || Na || tktLen || TktCipher
void MSG2_receive(FILE *log, int fd, const myKey_t *Ka, myKey_t *Ks,
                  char **IDb, Nonce_t *Na, size_t *lenTktCipher, uint8_t **tktCipher)
{
	
	if (!log || fd < 0 || !Ka || !Ks || !IDb || !Na || !lenTktCipher || !tktCipher) {
        fprintf(stderr, "MSG2_receive: NULL parameter\n");
        return;
    }
    
    fflush(log);
	

    // Step 1: Read the 8-byte length prefix
    size_t msg2Len;
    ssize_t nBytes = read_exact(fd, (uint8_t*)&msg2Len, LENSIZE);
	
    if (nBytes != LENSIZE) {
        fprintf(stderr, "MSG2_receive: failed to read MSG2 length\n");
        exitError("MSG2_receive: failed to read MSG2 length");
    }
    
    fflush(log);

    // Step 2: Read exactly msg2Len bytes of the actual encrypted message
	
    nBytes = read_exact(fd, ciphertext2, msg2Len);
	
    if (nBytes != (ssize_t)msg2Len) {
        fprintf(stderr, "MSG2_receive: failed to read full MSG2\n");
        exitError("MSG2_receive: failed to read full MSG2");
    }
	
	
	fflush(log);

    fprintf(log, "MSG2_receive() got the following Encrypted MSG2 ( %lu bytes ) Successfully\n", msg2Len);
    BIO_dump_indent_fp(log, ciphertext2, msg2Len, 4); 
    fprintf(log, "\n");
	fflush(log);
	
	fflush(log);

    size_t plainLen = decrypt(ciphertext2, msg2Len, Ka->key, Ka->iv, plaintext);
    if (plainLen == 0) {
        fprintf(stderr, "MSG2_receive: decryption failed\n");			
        exitError("MSG2_receive: decryption failed");
    }
	
	fflush(log);

    uint8_t *p = plaintext;
	
	fflush(log);

    // Copy Ks.key and Ks.iv
    memcpy(Ks->key, p, SYMMETRIC_KEY_LEN); p += SYMMETRIC_KEY_LEN;
    memcpy(Ks->iv, p, INITVECTOR_LEN); p += INITVECTOR_LEN;
	
	fflush(log);

    // Copy IDb
    size_t LenB;
	memcpy(&LenB, p, LENSIZE); p += LENSIZE;
	fflush(log);
	
    *IDb = (char *)malloc(LenB);
    if (!*IDb) exitError("malloc failed for IDb");
    memcpy(*IDb, p, LenB); p += LenB;

	fflush(log);
    // Copy Na
    memcpy(Na, p, NONCELEN); p += NONCELEN;

    // Copy Ticket length
    size_t tktLen;
    memcpy(&tktLen, p, LENSIZE); p += LENSIZE;

    // Copy Ticket cipher
    *tktCipher = (uint8_t *)malloc(tktLen);
    if (!*tktCipher) exitError("malloc failed for tktCipher");
    memcpy(*tktCipher, p, tktLen);
    *lenTktCipher = tktLen;

    // Logging
    fprintf(log, "Amal decrypted message 2 from the KDC into the following:\n");
    fprintf(log, "    Ks { Key , IV } (%u Bytes ) is:\n", SYMMETRIC_KEY_LEN + INITVECTOR_LEN);
    BIO_dump_indent_fp(log, Ks, SYMMETRIC_KEY_LEN + INITVECTOR_LEN, 4); fprintf(log, "\n");

    fprintf(log, "    IDb (%lu Bytes):   ..... MATCH\n", LenB);
	BIO_dump_indent_fp(log, *IDb, LenB, 4); fprintf(log, "\n");

    fprintf(log, "    Received Copy of Na (%lu bytes):    >>>> VALID\n", NONCELEN);
    BIO_dump_indent_fp(log, Na, NONCELEN, 4); fprintf(log, "\n");

    fprintf(log, "    Encrypted Ticket (%lu bytes):\n", tktLen);
    BIO_dump_indent_fp(log, *tktCipher, tktLen, 4); fprintf(log, "\n");

    fflush(log);
}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

size_t MSG3_new( FILE *log , uint8_t **msg3 , const size_t lenTktCipher , const uint8_t *tktCipher,  
                   const Nonce_t *Na2 )
{

    size_t    LenMsg3 ;
	
	if (!log || !msg3 || !tktCipher || !Na2)
	{
		fprintf(stderr, "MSG3_new: NULL parameter\n");
		return 0;
	}
	
	LenMsg3 = LENSIZE + lenTktCipher + NONCELEN;
	
	*msg3 = (uint8_t *)malloc(LenMsg3);
	if (!*msg3)
	{
		perror("malloc");
		return 0;
	}
	
	uint8_t *m3 = *msg3;
	
	memcpy( m3, &lenTktCipher, LENSIZE);
	m3 += LENSIZE;
	
	memcpy( m3, tktCipher, lenTktCipher);
	m3 += lenTktCipher;
	
	memcpy( m3, Na2, NONCELEN);
	m3 += NONCELEN;
	
	fprintf(log, "Amal is sending this to Basim in Message 3:\n");
	fprintf(log, "    Na2 in Message 3:\n");
	BIO_dump_indent_fp(log, (const char *)Na2, NONCELEN, 4);
	fprintf(log, "\n");
	
    fprintf( log , "The following MSG3 ( %lu bytes ) has been created by "
                   "MSG3_new ():\n" , LenMsg3 ) ;
    BIO_dump_indent_fp( log , *msg3 , LenMsg3 , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    return( LenMsg3 ) ;

}

//-----------------------------------------------------------------------------
// Receive Message #3 by Basim from Amal
// Parse the incoming msg3 into its components Ks , IDa , and Na2
// The buffers for Kb, Ks, and Na2 are pre-created by the caller
// The value of Kb is set by the caller
// The buffer for IDA is to be allocated here into *IDa

void MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 )
{

	if (!log || fd < 0 || !Kb || !Ks || !IDa || !Na2) {
        fprintf(stderr, "MSG3_receive(): NULL parameter!\n");
        exit(1);
    }

    // Read ticket length
    size_t lenTktCipher;
    if (read(fd, &lenTktCipher, LENSIZE) != LENSIZE)
        exitError("MSG3_receive: failed to read ticket length");

    // Read encrypted ticket
    uint8_t *TktCipher = malloc(lenTktCipher);
    if (read(fd, TktCipher, lenTktCipher) != lenTktCipher) {
        free(TktCipher);
        exitError("MSG3_receive: failed to read ticket");
    }

    // Read Na2
	uint8_t na2_bytes[NONCELEN];
    if (read(fd, na2_bytes, NONCELEN) != NONCELEN) {
        free(TktCipher);
        exitError("MSG3_receive: failed to read Na2");
    }
	
	for (int i = 0; i < NONCELEN; i++) 
	{
    ((uint8_t*)*Na2)[i] = na2_bytes[i];
	}

    fprintf(log, "The following Encrypted TktCipher ( %lu bytes ) was received by MSG3_receive()\n", lenTktCipher);
	BIO_dump_indent_fp(log, TktCipher, lenTktCipher, 4);
	fprintf(log, "\n");

    uint8_t decryptext[DECRYPTED_LEN_MAX];  // local buffer for decrypted ticket
    size_t LenTktPlain = decrypt(TktCipher, lenTktCipher, Kb->key, Kb->iv, decryptext);

    fprintf(log, "Here is the Decrypted Ticket ( %lu bytes ) in MSG3_receive():\n", LenTktPlain);
	BIO_dump_indent_fp(log, decryptext, LenTktPlain, 4);
	fprintf(log, "\n");

    uint8_t *q = decryptext;

    memcpy(Ks->key, q, SYMMETRIC_KEY_LEN);
    q += SYMMETRIC_KEY_LEN;

    memcpy(Ks->iv, q, INITVECTOR_LEN);
    q += INITVECTOR_LEN;

    size_t LenA;
	memcpy(&LenA, q, LENSIZE);
	q += LENSIZE;
    *IDa = malloc(LenA);
    if (!*IDa) {
        free(TktCipher);
        exitError("MSG3_receive: malloc failed for IDa");
    }
    memcpy(*IDa, q, LenA);
    q += LenA;

    free(TktCipher);
    
    fprintf(log, "Basim received Message 3 from Amal with the following content:\n");
	fprintf(log, "    Ks { Key , IV } (%u Bytes ) is:\n", SYMMETRIC_KEY_LEN + INITVECTOR_LEN);

	uint8_t key_iv[SYMMETRIC_KEY_LEN + INITVECTOR_LEN];
	memcpy(key_iv, Ks->key, SYMMETRIC_KEY_LEN);
	memcpy(key_iv + SYMMETRIC_KEY_LEN, Ks->iv, INITVECTOR_LEN);

	BIO_dump_indent_fp(log, (const char *)key_iv, SYMMETRIC_KEY_LEN + INITVECTOR_LEN, 4);
	fprintf(log, "\n");
	
	fprintf(log, "    IDa = '%s'\n", *IDa);
	
	fprintf(log, "    Na2 ( %lu Bytes ) is:\n", NONCELEN);
	BIO_dump_indent_fp(log, Na2, NONCELEN, 4);
	fprintf(log, "\n");
}

//-----------------------------------------------------------------------------
// Build a new Message #4 from Basim to Amal
// MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// A new buffer for *msg4 is allocated here
// All other arguments have been initialized by caller

// Returns the size of Message #4 after being encrypted by Ks in bytes

size_t  MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb )
{
	size_t LenMsg4;

    if (!log || !msg4 || !Ks || !fNa2 || !Nb) {
        fprintf(stderr, "MSG4_new: NULL parameter\n");
        return 0;
    }

    uint8_t *p = plaintext;

    memcpy(p, fNa2, NONCELEN);
    p += NONCELEN;

    memcpy(p, Nb, NONCELEN);
    p += NONCELEN;

    size_t LenPlain = p - plaintext;

    size_t LenCipher = encrypt(plaintext, LenPlain, Ks->key, Ks->iv, ciphertext);
    LenMsg4 = LenCipher;

    *msg4 = malloc(LenMsg4);
    if (!*msg4) {
        fprintf(stderr, "MSG4_new: malloc failed\n");
        return 0;
    }
    memcpy(*msg4, ciphertext, LenMsg4);

    fprintf(log, "Basim is sending this f( Na2 ) in MSG4:\n");
	BIO_dump_indent_fp(log, (const char *)fNa2, NONCELEN, 4);
	fprintf(log, "\n");

	fprintf(log, "Basim is sending this nonce Nb in MSG4:\n");
	BIO_dump_indent_fp(log, (const char *)Nb, NONCELEN, 4);
	fprintf(log, "\n");
	
	fprintf(log, "The following Encrypted MSG4 ( %lu bytes ) has been"
                 " created by MSG4_new ():  \n", LenMsg4);
    BIO_dump_indent_fp(log, *msg4, LenMsg4, 4);
    fprintf(log, "\n");
	fflush(log);

    return LenMsg4;
    

}

//-----------------------------------------------------------------------------
// Receive Message #4 by Amal from Basim
// Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void  MSG4_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *rcvd_fNa2 , Nonce_t *Nb )
{

	size_t LenMsg4cipher;

    if (!log || !Ks || !rcvd_fNa2 || !Nb) {
        fprintf(stderr, "MSG4_receive: NULL parameter\n");
        return;
    }


    ssize_t bytesRead = read(fd, &LenMsg4cipher, LENSIZE);
    if (bytesRead != LENSIZE) {
        fprintf(stderr, "MSG4_receive: failed to read MSG4 length, got %zd bytes\n", bytesRead);
        fprintf(log, "MSG4_receive: failed to read MSG4 length, got %zd bytes\n", bytesRead);
        fflush(log);
        return;
    }

    if (read(fd, ciphertext, LenMsg4cipher) != LenMsg4cipher) {
        fprintf(stderr, "MSG4_receive: failed to read MSG4 data\n");
		fprintf(log, "MSG4_receive: failed to read MSG4 data\n");
		fflush(log);
        return;
    }


    fprintf(log, "The following Encrypted MSG4 ( %lu bytes ) was received:\n",
            LenMsg4cipher);
    BIO_dump_indent_fp(log, ciphertext, LenMsg4cipher, 4);
    fprintf(log, "\n");
	fflush(log);

    size_t LenPlain = decrypt(ciphertext, LenMsg4cipher, Ks->key, Ks->iv, decryptext);


    uint8_t *p = decryptext;

    memcpy(rcvd_fNa2, p, NONCELEN);
    p += NONCELEN;

    memcpy(Nb, p, NONCELEN);
}

//-----------------------------------------------------------------------------
// Build a new Message #5 from Amal to Basim
// A new buffer for *msg5 is allocated here
// MSG5 = Encr( Ks  ,  { fNb }  )
// All other arguments have been initialized by caller
// Returns the size of Message #5  in bytes

size_t  MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb )
{
    size_t LenMSG5cipher;

    if (!log || !msg5 || !Ks || !fNb) {
        fprintf(stderr, "MSG5_new: NULL parameter\n");
        return 0;
    }

    memcpy(plaintext, fNb, NONCELEN);
    size_t LenPlain = NONCELEN;

    LenMSG5cipher = encrypt(plaintext, LenPlain, Ks->key, Ks->iv, ciphertext);

    *msg5 = malloc(LenMSG5cipher);
    if (!*msg5) {
        fprintf(stderr, "MSG5_new: malloc failed\n");
        return 0;
    }
    memcpy(*msg5, ciphertext, LenMSG5cipher);

    fprintf(log, "The following Encrypted MSG5 ( %lu bytes ) has been"
                 " created by MSG5_new ():  \n", LenMSG5cipher);
    BIO_dump_indent_fp(log, *msg5, LenMSG5cipher, 4);
    fprintf(log, "\n");
    fflush(log);

    return LenMSG5cipher;

}

//-----------------------------------------------------------------------------
// Receive Message 5 by Basim from Amal
// Parse the incoming msg5 into the value fNb

void  MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb )
{

    size_t LenMSG5cipher;

    if (!log || fd < 0 || !Ks || !fNb) {
        fprintf(stderr, "MSG5_receive: NULL/invalid parameter\n");
        return;
    }

    if (read(fd, &LenMSG5cipher, LENSIZE) != LENSIZE) {
        fprintf(stderr, "MSG5_receive: failed to read MSG5 length\n");
        return;
    }

    if (read(fd, ciphertext, LenMSG5cipher) != LenMSG5cipher) {
        fprintf(stderr, "MSG5_receive: failed to read MSG5 data\n");
        return;
    }

    fprintf(log, "The following Encrypted MSG5 ( %lu bytes ) has been received:\n",
            LenMSG5cipher);
    BIO_dump_indent_fp(log, ciphertext, LenMSG5cipher, 4);
    fprintf(log, "\n");
	fflush(log);

    size_t LenPlain = decrypt(ciphertext, LenMSG5cipher, Ks->key, Ks->iv, decryptext);

    if (LenPlain != NONCELEN) {
        fprintf(stderr, "MSG5_receive: unexpected plaintext length %zu\n", LenPlain);
        return;
    }
    memcpy(fNb, decryptext, NONCELEN);



}

//-----------------------------------------------------------------------------
// Utility to compute r = F( n ) for Nonce_t objects
// For our purposes, F( n ) = ( n + 1 ) mod  2^b  
// where b = number of bits in a Nonce_t object
// The value of the nonces are interpretted as BIG-Endian unsigned integers
void     fNonce( Nonce_t r , Nonce_t n )
{
    
    // Copy the input nonce as bytes
    memcpy(r, n, NONCELEN);
    
    // Add 1 to the big-endian integer (start from the LAST byte)
    int carry = 1;
    for (int i = NONCELEN - 1; i >= 0 && carry > 0; i--) {
        unsigned int sum = ((uint8_t*)r)[i] + carry;
        ((uint8_t*)r)[i] = sum & 0xFF;        // Keep only lower 8 bits
        carry = sum >> 8;                     // Carry is 1 if sum >= 256
    } 
}
