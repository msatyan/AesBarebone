/*
Copyright 2017 Sathyanesh Krishnan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "openssl/aes.h"
#include <stdio.h>

#define MY_BUFFSIZE            64
#define MY_CIPHER_BLOCK_SIZE   16
#define MY_AES_KEY_SIZE        128


void MyMemSet(unsigned char *p, unsigned int t);
void MyPrintBlock(const unsigned char *DataBlock, unsigned int BlockSize);

int main()
{
    AES_KEY AESkey;
    const unsigned char DataIn[] = "Let us try encrypting this message, one block size after decrypting?";
    unsigned char EncryptedDataBlock[MY_BUFFSIZE];
    unsigned char DecryptedDataBlock[MY_BUFFSIZE];
    unsigned char UserKey[16+1] = "1234567890123456"; //the actual 128-bit AES key. 

    MyMemSet(EncryptedDataBlock, sizeof(EncryptedDataBlock));
    MyMemSet(DecryptedDataBlock, sizeof(DecryptedDataBlock));

    // AESkey is a data structure holding a transformed version of the key, for efficiency.
    AES_set_encrypt_key((const unsigned char *)UserKey, MY_AES_KEY_SIZE, &AESkey);


    // AES is a block cipher, not really an encryption scheme.
    // AES_encrypt and AES_decrypt will process only one block at a time.

    // Computing AES in the forward direction
    AES_encrypt(DataIn, EncryptedDataBlock, (const AES_KEY *)&AESkey);
    MyPrintBlock(EncryptedDataBlock, MY_CIPHER_BLOCK_SIZE);

    
    MyMemSet( (unsigned char *)(&AESkey), sizeof(AESkey));
    // We don't need the old AESkey values anymore, let us reuse it then. 
    AES_set_decrypt_key((const unsigned char *)UserKey, MY_AES_KEY_SIZE, &AESkey);

    // Computing the inverse of AES
    AES_decrypt((const unsigned char *)EncryptedDataBlock, DecryptedDataBlock, (const AES_KEY *)&AESkey);

    MyPrintBlock( DecryptedDataBlock, MY_CIPHER_BLOCK_SIZE);
    MyPrintBlock( DataIn, MY_CIPHER_BLOCK_SIZE);
    
    printf("\n 123456789 123456 890");
    printf("\n %s", DecryptedDataBlock);
    printf("\nDone!");

    return(0);
}


void MyMemSet(unsigned char *p, unsigned int t)
{
    unsigned int i = 0;
    for (i = 0; i < t; ++i)
    {
        *p++ = 0;
    }
}


void MyPrintBlock(const unsigned char *DataBlock, unsigned int BlockSize)
{
    unsigned int i;
    int DisplayBlockSeparation = 0;

    for (i = 0; i < BlockSize; i++)
    {
        printf("%X", DataBlock[i] / 16);
        printf("%X", DataBlock[i] % 16);

        ++DisplayBlockSeparation;
        if (DisplayBlockSeparation == 4)
        {
            DisplayBlockSeparation = 0;
            printf(" ");
        }
    }
    printf("\n");
}

/*
209DB8C4 C032137E 7B1C915A F01CC8F3
4C657420 75732074 72792065 6E637279
4C657420 75732074 72792065 6E637279

123456789 123456 890
Let us try encry
Done!
*/
