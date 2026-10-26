#!/bin/bash

# "Script to Generate RSA Public/Private key Pair"

# "Written By:  1- Colin Finnegan

echo
echo

# Generate  2048-bit public/private key-pair for Amal
cd amal
rm -f *.pem 
openssl genpkey -algorithm RSA -out amal_priv_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in amal_priv_key.pem -out amal_pub_key.pem

echo "====================================="
echo "Here is Amal's RSA Key Information"
echo "====================================="
openssl  rsa -in amal_priv_key.pem -text -noout
echo
echo "====================================="

# Now, share Amal's public key with Basim using Linux Symbolic Links
cd ../basim
rm -f *.pem
ln -s  ../amal/amal_pub_key.pem  amal_pubKey.pem

#back to dispatcher's folder
cd ..
