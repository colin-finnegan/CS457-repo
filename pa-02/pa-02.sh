#!/bin/bash

# "Script to run Programming Assignment #2"
# "By: Mohamed Aboutabl"

# Clean up any old files from previous runs
rm -f  dispatcher  bunny.mp4 bunny.cpy
rm -f  amal/amal amal/logAmal.txt 
rm -f  basim/basim basim/logBasim.txt 

# create symbolic link to the video file one level above
# the dispatcher's  folder
ln -s  ../bunny.mp4       bunny.mp4

echo "=============================="
echo "Compiling all source"
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto
	gcc wrappers.c     dispatcher.c -o dispatcher

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt
echo

echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt
echo

echo "=============================="
echo "Verifying the File Unencrypted Transmission"
echo
diff -s bunny.mp4 bunny.cpy
echo
