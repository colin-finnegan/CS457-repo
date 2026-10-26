/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c     SKELETON

Written By: 
     1- Colin Finnegan
Submitted on: 
     11/25/2025
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

// Generate random nonces for Basim
void  getNonce4Basim( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first and Only nonce
			value[0] = 0x66778899 ;
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nBasim trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    
    // Your code from pa-04_PartOne
    
    int       fd_A2B , fd_B2A   ;
    FILE     *log ;

    char *developerName = "Code by FINNEGAN" ;

    fprintf( stdout , "Starting Basim's     %s\n" , developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }

    fd_A2B    = atoi(argv[1]);  // Read from Amal   File Descriptor
    fd_B2A    = atoi(argv[2]);  // Send to   Amal   File Descriptor

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "Basim's %s. Could not create log file\n" , developerName ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Basim\n"  ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC
    myKey_t   Kb ;    // Basim's master key with the KDC    

    if (!getKeyFromFile("basim/basimKey.bin", &Kb))    // >>> ADDED <<<
    {
        fprintf(stderr, "\nCould not get Basim's Master key & IV.\n");
        fprintf(log, "\nCould not get Basim's Master key & IV.\n");
        exit(-1);
    }

    fprintf(log, "Basim has this Master Kb { key , IV }\n");
    BIO_dump_indent_fp(log, (const char *)Kb.key, SYMMETRIC_KEY_LEN, 4);
    fprintf(log, "\n");
    BIO_dump_indent_fp(log, (const char *)Kb.iv, INITVECTOR_LEN, 4);
    fprintf(log, "\n");
	// BIO_dump the IV indented 4 spaces to the righ

    // Get Basim's pre-created Nonces: Nb
	Nonce_t   Nb;  

	// Use getNonce4Basim () to get Basim's 1st and only nonce into Nb
    fprintf( log , "Basim will use this Nonce:  Nb\n"  ) ;
	// BIO_dump Nb indented 4 spaces to the right
	getNonce4Basim(1, Nb);
    BIO_dump_indent_fp(log, (const char *)Nb, NONCELEN, 4);
    fprintf( log , "\n" );

    fflush( log ) ;
    
	//*************************************
	// Receive and Process    Message 3
	//*************************************	
	
    BANNER( log );
	fprintf( log , "         MSG3 Receive\n");
	BANNER( log );

	// Allocate storage for session key Ks and received data
	myKey_t Ks;       // Session key shared with Amal
	char *IDa = NULL;
	Nonce_t Na2;

	MSG3_receive(log, fd_A2B, &Kb, &Ks, &IDa, &Na2);


	//*************************************
	// Construct & Send    Message 4
	//*************************************

	BANNER( log );
	fprintf( log , "         MSG4 New\n");
	BANNER( log );

	Nonce_t fNa2;
	fNonce(fNa2, Na2);


	// Allocate and create MSG4
	uint8_t *msg4;
	size_t LenMsg4 = MSG4_new(log, &msg4, &Ks, &fNa2, &Nb);

	if (write(fd_B2A, &LenMsg4, LENSIZE) != LENSIZE) {
		fprintf(stderr, "Failed to write MSG4 length to Amal\n");
		exit(-1);
	}
	if (write(fd_B2A, msg4, LenMsg4) != LenMsg4) {
		fprintf(stderr, "Failed to write MSG4 to Amal\n");
		exit(-1);
	}

	fprintf(log, "Basim Sent the above MSG4 to Amal\n");
	fprintf(log, "\n");
	fflush(log);

	// Free MSG4 buffer
	free(msg4);


	//*************************************
	// Receive   & Process Message 5
	//*************************************

	BANNER( log );
	fprintf( log , "         MSG5 Receive\n");
	BANNER( log );	

	Nonce_t rcvd_fNb;

	fprintf(log, "Basim is expecting back this f( Nb ) in MSG5:\n");

	Nonce_t expected_fNb;
	fNonce(expected_fNb, Nb);
	
	BIO_dump_indent_fp(log, (const char *)expected_fNb, NONCELEN, 4);
	fprintf(log, "\n");
	
	// Receive MSG5 from Amal
	MSG5_receive(log, fd_A2B, &Ks, &rcvd_fNb);
	
	// Validate the received f(Nb)
	if (memcmp(rcvd_fNb, expected_fNb, NONCELEN) == 0) {
		fprintf(log, "Basim received Message 5 from Amal with this f( Nb ): >>>> VALID\n");
	} else {
		fprintf(log, "Basim received Message 5 from Amal with this f( Nb ): >>>> INVALID\n");
	}	

	BIO_dump_indent_fp(log, rcvd_fNb, NONCELEN, 4);
	fprintf(log, "\n");
	
	fflush(log);
	
    //*************************************   
    // Final Clean-Up
    //*************************************
end_:
    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  

    return 0 ;
}
