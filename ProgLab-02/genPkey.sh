#!/bin/bash

# "Script to Generate RSA (public, private) keys"
# "Written by: Mohamed Aboutabl"

#echo "Amal sends an encrypted file to Basim using a symmetric session key"
#echo "The session key is exchanged with Basim using Basim's RSA public key"
echo
echo

# Generate public/private key-pair for Basim
cd basim
rm -f *.pem 
openssl  genpkey -algorithm RSA -out basim_priv_key.pem -pkeyopt rsa_keygen_bits:2048 

# Learn how to protect the private key using -pass pass:p@$$w0rd

openssl  rsa     -pubout        -in  basim_priv_key.pem -out     basim_pub_key.pem


echo "====================================="
echo "Here is Basim's RSA Key Information"
echo "====================================="
openssl  rsa     -text          -in  basim_priv_key.pem
echo
echo "====================================="

# Now, share Basim's public key with Amal
cd ../amal
rm -f *.pem
ln -s  ../basim/basim_pub_key.pem  basim_pub_key.pem
cd ../

