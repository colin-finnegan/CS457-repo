#------------------------------------------------------------------------
----
#Programming Lab-01 Encrypt / Decrypt using pre-generated Key+IV
#
#FILE: pLab-01.sh
#
#Written By : Colin Finnegan
#Submitted on: 9/7/2025
#------------------------------------------------------------------------
----
#!/bin/bash
echo 
echo "Script to run Programming Lab-01" 
echo "By: Colin Finnegan" 
echo 

rm -f genkey 		key.bin 			iv.bin
rm -f amal/amal 	amal/logAmal.txt 	amal/ciphertext.bin
rm -f basim/basim 	basim/logBasim.txt  basim/decryptedtext.bin

echo "=============================="
echo "Compiling ALL source code"
# If compilation fails, try replacing -lcrypto with -l:libcrypto.so.1.1

	gcc genkey.c 					-o genkey 		-lcrypto
	gcc amal/amal.c 	myCrypto.c 	-o amal/amal 	-lcrypto
	gcc basim/basim.c 	myCrypto.c 	-o basim/basim 	-lcrypto
	
echo
echo "Generating Key/IV"
./genkey

echo
echo "Executing Amal"
amal/amal

echo
echo "Executing Basim"
basim/basim

echo
echo "======  Amal's  LOG  ========="
cat  amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat  basim/logBasim.txt
echo
echo
