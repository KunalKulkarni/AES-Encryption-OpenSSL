Name : Kunal Kulkarni
Email: kkulkar3@binghamton.edu

Encryption Procedure:
The first plaintext block is XORed with the IV and result obtained throught the ecb_encrypt from openssl.
The subsequent results are then XORed with the new plaintext block to get the following ciphertexts.
Finally, if padding is necessary, it is done with the length of the pad needed to be added.
 
Decryption Procedure:
Similarily, the decryption procedure for CBC is followed and the result is obtained.

To compile:
g++ -I "Path to include" -L "Path to lib" main.cc fscrypt.cc -lcrypto -o ./a.out
  
To execute:
./a.out