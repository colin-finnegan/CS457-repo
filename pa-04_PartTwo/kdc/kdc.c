/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   kdc.c    SKELETON

Written By: 
     1- Colin Finnegan
Submitted on: 11/25/2025
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    
    // Your code from pa-04_PartOne
    
    int       fd_A2K , fd_K2A   ;
    FILE     *log ;
    
    char *developerName = "Code by FINNEGAN" ;

    fprintf( stdout , "Starting the KDC's   %s\n"  , developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <readFrom Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }

    fd_A2K    = atoi(argv[1])  ;  // Read from Amal   File Descriptor
    fd_K2A    = atoi(argv[2])  ;  // Send to   Amal   File Descriptor

    log = fopen("kdc/logKDC.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "The KDC's   %s. Could not create log file\n"  , developerName ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting the KDC\n"  ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFrom Amal> FD=%d , <sendTo Amal> FD=%d\n\n" , fd_A2K , fd_K2A );

    // Get Amal's master keys with the KDC and dump it to the log
    myKey_t  Ka ;    // Amal's master key with the KDC

    if( ! getKeyFromFile( "kdc/amalKey.bin" , &Ka ) )
    {
        fprintf( stderr , "\nCould not get Amal's Master key & IV.\n" );
        fprintf( log   , "\nCould not get Amal's Master key & IV.\n" );
        exit(-1);
    }

    fprintf( log , "Amal has this Master Ka { key , IV }\n" );
    BIO_dump_indent_fp( log , (const char*)Ka.key , SYMMETRIC_KEY_LEN, 4);

    fprintf( log , "\n" );
    BIO_dump_indent_fp( log , (const char*)Ka.iv , INITVECTOR_LEN, 4);
    fprintf( log , "\n" );
    fflush( log ) ;
    
    // Get Basim's master keys with the KDC
    myKey_t   Kb ;    // Basim's master key with the KDC    

    if( ! getKeyFromFile( "kdc/basimKey.bin" , &Kb ) )
    {
        fprintf( stderr , "\nCould not get Basim's Master key & IV.\n" );
        fprintf( log   , "\nCould not get Basim's Master key & IV.\n" );
        exit(-1);
    }

    fprintf( log , "Basim has this Master Kb { key , IV }\n" );
    BIO_dump_indent_fp( log , (const char*)Kb.key , SYMMETRIC_KEY_LEN, 4);

    fprintf( log , "\n" );
    BIO_dump_indent_fp( log , (const char*)Kb.iv , INITVECTOR_LEN, 4);
    fprintf( log , "\n" );
    fflush( log ) ;

    //*************************************
    // Receive  & Display   Message 1
    //*************************************

    BANNER( log ) ;
    fprintf( log , "         MSG1 Receive\n");
    BANNER( log ) ;

    char *IDa , *IDb ;
    Nonce_t  Na ;
    
    // Get MSG1 from Amal
    MSG1_receive( log , fd_A2K , &IDa , &IDb , Na ) ;

    fprintf( log , "\nKDC received message 1 from Amal with:\n"
                   "    IDa = '%s'\n"
                   "    IDb = '%s'\n" , IDa , IDb ) ;

    fprintf( log , "    Na ( %lu Bytes ) is:\n" , NONCELEN ) ;
     // BIO_dump the nonce Na
	BIO_dump_indent_fp( log , (const char*)Na , NONCELEN, 4);
	fprintf( log , "\n" );
    fflush( log ) ;
    

    //*************************************   
	// Construct & Send    Message 2
	//*************************************

	BANNER( log );
	fprintf( log , "         MSG2 New\n");
	BANNER( log );

	// Allocate storage for session key Ks
	myKey_t Ks;   // Session key shared between Amal and Basim

	// Generate a random session key Ks
	RAND_bytes(Ks.key, SYMMETRIC_KEY_LEN);
	RAND_bytes(Ks.iv, INITVECTOR_LEN);


	// Allocate and create MSG2
	uint8_t *msg2;

	size_t LenMsg2 = MSG2_new(log, &msg2, &Ka, &Kb, &Ks, IDa, IDb, &Na);


	if (write(fd_K2A, &LenMsg2, LENSIZE) != LENSIZE) {
		fprintf(stderr, "Failed to write MSG2 length to Amal\n");
		exit(-1);
	}
	// Send MSG2 to Amal
	if (write(fd_K2A, msg2, LenMsg2) != LenMsg2) {
		fprintf(stderr, "Failed to write MSG2 to Amal\n");
		exit(-1);
	}


	fprintf(log, "The KDC sent the Encrypted MSG2 ( %lu bytes ) to Amal Successfully\n", LenMsg2);
	fflush(log);

	// Free MSG2 buffer
	free(msg2);


    //*************************************   
    // Final Clean-Up
    //*************************************   
end_:
    fprintf( log , "\nThe KDC has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  
    return 0 ;
}
