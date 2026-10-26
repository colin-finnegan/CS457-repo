/*‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐
PA-01: Symmetric Encryption of Large Data

FILE: amal/amal.c

Written By : Colin Finnegan
Submitted on: 9/17/2025

‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐*/

#include "../myCrypto.h"

int main(int argc, char* argv[]	)
{

	FILE *log = fopen("amal/logAmal.txt" , "w" );
	if( ! log )
	{
		fprintf( stderr , "Amal: Could not create log file\n" ) ;
		exit(-1) ;
	}
	
	if (argc < 3)
	{
		fprintf( stderr , "Not enough arguments\n") ;
		exit(-1) ;
	}
	
	int controlFd = atoi(argv[1]) ;
	int dataFd = atoi(argv[2]) ;
	
	fprintf(log, "Control FD: %d, Data FD: %d\n", controlFd, dataFd);
	
	uint8_t key[32] ;
	uint8_t iv[16] ;
	
	FILE *keyFile = fopen("key.bin", "rb") ;
	if (!keyFile)
	{
		fprintf( stderr, "Cannot open keyFile\n" ) ;
		exit(-1) ;
	}
	
	FILE *ivFile = fopen("iv.bin", "rb") ;
	if (!ivFile)
	{
		fprintf( stderr, "Cannot open ivFile\n" ) ;
		exit(-1) ;
	}
		
	size_t keyBytesRead = fread(key, 1, 32, keyFile) ;
	if (keyBytesRead != 32)
	{
		fprintf( stderr, "Fewer Key bytes than expected\n" ) ;
		exit(-1) ;
	}
	
	fprintf(log, "Key: ");
	for (int i = 0; i < 32; i++) 
	{ 
		fprintf(log, "%02x", key[i]) ;
	}
	fprintf(log, "\n");
	
	size_t ivBytesRead = fread(iv, 1, 16, ivFile) ;
	if (ivBytesRead != 16)
	{
		fprintf( stderr, "Fewer IV bytes than expected\n" ) ;
		exit(-1) ;
	}
	
	fprintf(log, "IV: ");
	for (int i = 0; i < 16; i++) 
	{ 
		fprintf(log, "%02x",iv[i]) ;
	}
	fprintf(log, "\n");
	
	fclose(keyFile) ;
	fclose(ivFile) ;
	
	fflush(log) ;
	
	int plainFd = open("../bunny.mp4", O_RDONLY);
	if (plainFd < 0 )
	{
		fprintf( stderr, "Can't open bunny.mp4" );
		exit(-1) ;
	}
	
	encryptFile( plainFd, dataFd, key, iv );
	close(plainFd);
	fclose(log);
	return 0;
	
}