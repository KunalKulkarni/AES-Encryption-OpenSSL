#include "fscrypt.h"
#include <string.h>
#include <stdio.h>
#define IV 0x00

//Function to XOR values
char xorValues(char a,char b);
//For Encryption
unsigned char* ciphertext;
unsigned char* currentCipher=new unsigned char[8];
unsigned char* xorBlock=new unsigned char[8];
unsigned char* pTBlock=new unsigned char[8];

//For Decryption
unsigned char* previousCipher=new unsigned char[8];
unsigned char* intBlock=new unsigned char[8];


char xorValues(char a,char b){
	char res=a^b;
	return res;
}

void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){
	
	BF_KEY key;
	BF_set_key(&key, strlen(keystr),(const unsigned char *)keystr);
	
	int totalBlocks=(bufsize/8)+1;
	
	int addBytesIndex=bufsize%8;
	*resultlen=totalBlocks*8;
	
	unsigned char* ciphertext;
	unsigned char* pText=(unsigned char*) plaintext;
	int len=8*totalBlocks;
	int firstBlock=1;
	ciphertext = new unsigned char[len];
	
	for(int i=0;i<totalBlocks;i++){
		memcpy((char*)pTBlock,(char *)pText+(8*i),8);
		//If one block only : Add padding if necessary and XOR with IV and send to encrypt
		//If last block: Add padding if necessary and XOR with Cipher result till now
		
		if(totalBlocks==1 || i==totalBlocks-1){
				
			for(int x=addBytesIndex;x<8;x++){
				pTBlock[x]=(char)(8-addBytesIndex);
			}
			
			if(totalBlocks==1){
				for(int l=0;l<8;l++){
					//printf("Current--%s",xorBlock);
					xorBlock[l]=xorValues(pTBlock[l],IV);
					firstBlock=0;
				}	
			}
			if(i==totalBlocks-1 && totalBlocks>1){	
			memcpy((char*)currentCipher,(char *)ciphertext+(8*(i-1)),8);
				for (int j = 0; j < 8; j++) {
						//printf("%s\n",xorBlock);
					xorBlock[j]=xorValues(pTBlock[j],currentCipher[j]);	
				}
			}
		}
		//If first Block: XOR with IV
		else if(firstBlock==1){
			for(int l=0;l<8;l++){
				//printf("Cuurent--%s",xorBlock);	
				xorBlock[l]=xorValues(pTBlock[l],IV);
			}	
			firstBlock=0;
		}
		//If any other block: XOR with result till now
		else{
			memcpy((char*)currentCipher,(char *)ciphertext+(8*(i-1)),8);
			for (int j = 0; j < 8; j++) {
					xorBlock[j]=xorValues(pTBlock[j],currentCipher[j]);
				}
		}
		BF_ecb_encrypt(xorBlock,ciphertext+(8*i),&key,BF_ENCRYPT);
	}
	return (void*)ciphertext;
}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){
	
	BF_KEY key;
	BF_set_key(&key, strlen(keystr),(const unsigned char *)keystr);
	
	int padAmt=0,Tbits=0;
	int totalBlocks=(bufsize/8);
	int len=totalBlocks*8;
	
	unsigned char* cText=(unsigned char*)ciphertext;
	unsigned char* pText=new unsigned char[len];
	int firstBlock=1;
	*resultlen=len;
	for(int i=0;i<totalBlocks;i++){
		
		BF_ecb_encrypt(cText+(8*i),pText+(8*i),&key,BF_DECRYPT);
		memcpy((char*)intBlock,(char*)pText+(8*i),8); 
		//If first block : XOR with IV and check for pad
		if (firstBlock==1) {
			for (int j=0;j<8;j++) {
				int exp=i+j;
				pText[8*exp]=xorValues(intBlock[j],IV);
			}
			firstBlock=0;
		}
		//If any other block: XOR with previous cipher values
		else{
			memcpy((char*)previousCipher,(char *)cText+(8*(i-1)),8);
			for (int j = 0; j < 8; j++) {
				pText[8*i+j]=xorValues(intBlock[j],previousCipher[j]);
			}
		}
		//Check for padding and to resultlen if needed
		if (i == totalBlocks - 1) {
			memcpy((char*)intBlock,(char*)pText+(8*i),8);
			padAmt = intBlock[7];
			int diff=8-padAmt;
			for (int j =diff;j<8; j++) {
				if (intBlock[j] == padAmt) 
					Tbits=Tbits+1;
			}
			//printf("Total bits%d",Tbits);
			if (Tbits == padAmt) {
			*resultlen=len-padAmt;
			}
		}
	}
	
	return (void *)pText;
}
