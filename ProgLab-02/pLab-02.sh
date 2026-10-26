#!/bin/bash

# "Script to run pLab-02"
# "Written by: Mohamed Aboutabl"

#echo "Amal sends an encrypted file to Basim using a symmetric session key"
#echo "The session key is exchanged with Basim using Basim's RSA public key"
echo
echo

echo "=============================="
echo "Compiling all source code"
rm -f dispatcher amal/amal   amal/logAmal.txt   basim/basim   basim/logBasim.txt   bunny.decr 
rm -f bunny.mp4

ln -s ../bunny.mp4       bunny.mp4

gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto
gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto
gcc wrappers.c     dispatcher.c -o dispatcher

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo
echo "======  Amal's  LOG  ========="
cat  amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat  basim/logBasim.txt
echo
echo

echo "=============================="
echo "Verifying File Encryption / Decryption"
echo
diff -s ../bunny.mp4 bunny.decr
echo
