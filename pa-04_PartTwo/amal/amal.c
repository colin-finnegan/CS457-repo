/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   amal.c     SKELETON

Written By: 
     1- Colin Finnegan
Submitted on: 
     11/25/2025
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

// Generate random nonces for Amal
void  getNonce4Amal( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first nonce
			value[0] = 0x11223344 ;
			break ;

		case 2:		// the second nonce
			value[0] = 0xaabbccdd ;		
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nAmal trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}
	
//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    
    
    // Your code from pa-04_PartOne
    int      fd_A2K , fd_K2A , fd_A2B , fd_B2A  ;
    FILE    *log ;

    char *developerName = "Code by FINNEGAN" ;

    fprintf( stdout , "Starting Amal's      %s.\n" , developerName  ) ;
    
    if( argc < 5 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. KDC> <sendTo KDC> "
               "<getFr. Basim> <sendTo Basim>\n\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_K2A    = atoi(argv[1]) ;  // Read from KDC    File Descriptor
    fd_A2K    = atoi(argv[2]) ;  // Send to   KDC    File Descriptor
    fd_B2A    = atoi(argv[3]) ;  // Read from Basim  File Descriptor
    fd_A2B    = atoi(argv[4]) ;  // Send to   Basim  File Descriptor

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "\nAmal's  %s. Could not create my log file\n" , developerName  ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Amal\n" ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFrom KDC> FD=%d , <sendTo KDC> FD=%d , "
                   "<readFrom Basim> FD=%d , <sendTo Basim> FD=%d\n\n" , 
                   fd_K2A , fd_A2K , fd_B2A , fd_A2B );

    // Get Amal's master key with the KDC
    myKey_t  Ka ;  // Amal's master key with the KDC
	if (!getKeyFromFile("amal/amalKey.bin", &Ka))
    {
        fprintf(stderr, "\nCould not get Amal's Master key & IV.\n");
        fprintf(log, "\nCould not get Amal's Master key & IV.\n");
        exit(-1);
    }

    fprintf(log, "Amal has this Master Ka { key , IV }\n");
    BIO_dump_indent_fp(log, (const char *)Ka.key, SYMMETRIC_KEY_LEN, 4);
    fprintf(log, "\n");
    BIO_dump_indent_fp(log, (const char *)Ka.iv, INITVECTOR_LEN, 4);
    fprintf(log, "\n");


    Nonce_t Na, Na2;
    fprintf(log, "Amal will use these Nonces:  Na  and Na2\n");

    getNonce4Amal(1, Na);
    BIO_dump_indent_fp(log, (const char *)Na, NONCELEN, 4);
    fprintf(log, "\n");

    getNonce4Amal(2, Na2);
    BIO_dump_indent_fp(log, (const char *)Na2, NONCELEN, 4);
    fprintf(log, "\n");

    fflush(log);

    //*************************************
    // Construct & Send    Message 1
    //*************************************
	
    BANNER( log ) ;
    fprintf( log , "         MSG1 New\n");
    BANNER( log ) ;

    char *IDa = "Amal is Hope", *IDb = "Basim is Smiley" ;
    size_t  LenMsg1 ;
    uint8_t  *msg1 ;
    LenMsg1 = MSG1_new( log , &msg1 , IDa , IDb , Na ) ;
    
    if (write(fd_A2K, msg1, LenMsg1) != LenMsg1)
    {
        fprintf(stderr, "Failed to write MSG1 to pipe\n");
        exit(-1);
    }

   fprintf( log , "Amal sent message 1 ( %lu bytes ) to the KDC with:\n    "
                   "IDa ='%s'\n    "
                   "IDb = '%s'\n" , LenMsg1 , IDa , IDb ) ;
    fprintf( log , "    Na ( %lu Bytes ) is:\n" , NONCELEN ) ;
    BIO_dump_indent_fp(log, (const char *)Na, NONCELEN, 4);
    fprintf(log, "\n");
    fflush( log ) ;

    // Deallocate any memory allocated for msg1
	free(msg1);
    
    
    //*************************************
    // Receive   &   Process Message 2
    //*************************************
	
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG2 Receive\n");
    BANNER( log ) ;

	myKey_t Ks;        // Session key with Basim
	IDb = NULL;
	Nonce_t Nb;
	size_t lenTktCipher = 0;
	uint8_t *tktCipher = NULL;


	MSG2_receive(log, fd_K2A, &Ka, &Ks, &IDb, &Na, &lenTktCipher, &tktCipher);

    //*************************************
    // Construct & Send    Message 3
    //*************************************
	
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 New\n");
    BANNER( log ) ;
	
	uint8_t *msg3 = NULL;
	size_t LenMsg3 = MSG3_new(log, &msg3, lenTktCipher, tktCipher, &Na2);
	if (write(fd_A2B, msg3, LenMsg3) != LenMsg3) {
		fprintf(stderr, "Failed to write MSG3 to Basim\n");
		exit(-1);
	}

	fprintf(log, "Amal Sent the Message 3 ( %lu bytes ) to Basim\n", LenMsg3);
	fprintf(log, "\n");
	fflush(log);

	// Free MSG3 buffer
	free(msg3);

    //*************************************
    // Receive   & Process Message 4
    //*************************************
	
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 Receive\n");
    BANNER( log ) ;
	// Allocate storage for f(Na2) and Nb received from Basim
	Nonce_t rcvd_fNa2, rcvd_Nb;

	// Receive MSG4 from Basim
	MSG4_receive(log, fd_B2A, &Ks, &rcvd_fNa2, &rcvd_Nb);
	

	fprintf(log, "\nAmal is expecting back this f( Na2 ) in MSG4:\n");

	Nonce_t expected_fNa2;
	fNonce(expected_fNa2, Na2);

	BIO_dump_indent_fp(log, (const char *)expected_fNa2, NONCELEN, 4);
	fprintf(log, "\n");

	// Compare and show validation
	if (memcmp(rcvd_fNa2, expected_fNa2, NONCELEN) == 0) {
		fprintf(log, "Basim returned the following f( Na2 )   >>>> VALID\n");
	} 	else {
		fprintf(log, "Basim returned the following f( Na2 )   >>>> INVALID\n");
	}	
	BIO_dump_indent_fp(log, (const char *)rcvd_fNa2, NONCELEN, 4);
	fprintf(log, "\n");

	fprintf(log, "Amal also received this Nb :\n");
	BIO_dump_indent_fp(log, (const char *)rcvd_Nb, NONCELEN, 4);
	fprintf(log, "\n");
	
    //*************************************
    // Construct & Send    Message 5
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 New\n");
    BANNER( log ) ;
	
	fprintf(log, "Amal is sending this f( Nb ) in MSG5:\n");

	// Compute f(Nb) = Nb + 1
	Nonce_t fNb;
	fNonce(fNb, rcvd_Nb);

	BIO_dump_indent_fp(log, (const char *)fNb, NONCELEN, 4);
	fprintf(log, "\n");

	// Allocate and create MSG5
	uint8_t *msg5;
	size_t LenMsg5 = MSG5_new(log, &msg5, &Ks, &fNb);

	if (write(fd_A2B, &LenMsg5, LENSIZE) != LENSIZE) {
		fprintf(stderr, "Failed to write MSG5 length to Basim\n");
		exit(-1);
	}
	if (write(fd_A2B, msg5, LenMsg5) != LenMsg5) {
		fprintf(stderr, "Failed to write MSG5 to Basim\n");
		exit(-1);
	}
	
	fprintf(log, "Amal sent Message 5 ( %lu bytes ) to Basim\n", LenMsg5);

	// Free MSG5 buffer
	free(msg5);

    //*************************************   
    // Final Clean-Up
    //*************************************  
end_:
    fprintf( log , "\nAmal has terminated normally. Goodbye\n" ) ;  
    fclose( log ) ;
    return 0 ;
}

		