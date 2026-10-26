/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c     SKELETON

Written By: 
     1- Colin Finnegan
Submitted on: 
     11/9/2025
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//
//  ALL YOUR  CODE FORM  PREVIOUS PAs  and pLABs
//  MUST be Here

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

size_t MSG2_new( FILE* log, uint8_t **msg2, const myKey_t *Ka, const myKey_t *Kb, const char *IDa, const char *IDb, const Nonce_t Na )
{
	if (!log || !msg2 || !Ka || !Kb || !IDa || !IDb || Na)
	{
		fprintf(stderr, "MSG2_new: NULL parameter\n");
		return 0;
	}
	
	//Generate session key
	uint8_t Ks[SYMMETRIC_KEY_LEN];
	if (RAND_bytes(Ks, SYMMETRIC_KEY_LEN) != 1)
	{
		exitError("RAND_bytes failed generating Ks");
	}
	
	
	//Build ticket
	size_t LenA = strlen(IDa) + 1;
	size_t tktLen = SYMMETRIC_KEY_LEN + LenA;
	
	uint8_t *ticket = malloc(tktLen);
	
	if (!ticket)
	{
		exitError("MSG2_new: malloc ticket failed");
	}
	
	uint8_t *p = ticket;
	memcpy(p, Ks, SYMMETRIC_KEY_LEN);
	p += SYMMETRIC_KEY_LEN;
	memcpy(p, IDa, LenA);
	p += LenA;
	
	//Encrypt ticket with Basim master key
	uint8_t ENC_tkt[2048];
	unsigned ENC_tkt_len = encrypt(ticket, tktLen, Kb->key, Kb->iv, ENC_tkt);
	free(ticket);
	
	//Build plaintext for Amal
	size_t LenB = strlen(IDb) + 1;
	size_t plaintextLen = SYMMETRIC_KEY_LEN + LenB + NONCELEN + ENC_tkt_len;
	
	uint8_t *plaintext = malloc(plaintextLen);
	if (!plaintext)
	{
		exitError("MSG2_new: malloc plaintext failed");
	}
	
	p = plaintext;
	memcpy(p, Ks, SYMMETRIC_KEY_LEN);
	p += SYMMETRIC_KEY_LEN;
	memcpy(p, IDb, LenB);
	p += LenB;
	memcpy(p, Na, NONCELEN);
	p += NONCELEN;
	memcpy(p, ENC_tkt, ENC_tkt_len);
	p += ENC_tkt_len;
	
	//Encrypt plaintext wih Amal master key
	uint8_t *cipher = malloc(CIPHER_LEN_MAX);
	if (!cipher)
	{
		exitError("MSG2_new: malloc cipher failed");
	}
	
	unsigned cipherLen = encrypt(plaintext, plaintextLen, Ka->key, Ka->iv, cipher);
	free(plaintext);
	
	//Output & Return
	*msg2 = cipher;
	
	fprintf(log, "MSG2_new: Produced MSG2 (%u bytes)\n", cipherLen);
	BIO_dump_indent_fp(log, (const char*)cipher, cipherLen, 4);
	
	return cipherLen;
}


void MSG2_receive(
        FILE *log,
        uint8_t *msg2,
        size_t msg2_len,
        const myKey_t *Ka,     // Amal’s key
        uint8_t *Kab_out,
        char **IDb_out,
        Nonce_t Na_out,
        uint8_t **ticket_out,
        size_t *ticket_len_out
    )
{
    if (!log || !msg2 || !Ka || !Kab_out || !IDb_out ||
        !Na_out || !ticket_out || !ticket_len_out) {
        exitError("MSG2_receive: NULL parameter");
    }

    //------------------------------------------------------------------
    // 1) Decrypt MSG2 using Amal’s key
    //------------------------------------------------------------------
    uint8_t plaintext[4096];
    unsigned plainLen =
        decrypt(msg2, msg2_len, Ka->key, Ka->iv, plaintext);

    uint8_t *p = plaintext;

    //------------------------------------------------------------------
    // 2) Parse Kab
    //------------------------------------------------------------------
    memcpy(Kab_out, p, SYMMETRIC_KEY_LEN);
    p += SYMMETRIC_KEY_LEN;

    //------------------------------------------------------------------
    // 3) Parse IDb (null-terminated string)
    //------------------------------------------------------------------
    size_t LenB = strlen((char*)p) + 1;
    *IDb_out = malloc(LenB);
    memcpy(*IDb_out, p, LenB);
    p += LenB;

    //------------------------------------------------------------------
    // 4) Parse Nonce Na
    //------------------------------------------------------------------
    memcpy(Na_out, p, NONCELEN);
    p += NONCELEN;

    //------------------------------------------------------------------
    // 5) Remaining bytes are ENC_tkt
    //------------------------------------------------------------------
    size_t ticketLen = plainLen - (SYMMETRIC_KEY_LEN + LenB + NONCELEN);

    *ticket_out = malloc(ticketLen);
    memcpy(*ticket_out, p, ticketLen);
    *ticket_len_out = ticketLen;

    //------------------------------------------------------------------
    // 6) Log
    //------------------------------------------------------------------
    fprintf(log, "MSG2_receive: decrypted %u bytes\n", plainLen);
    BIO_dump_indent_fp(log, (const char*)plaintext, plainLen, 4);
}
