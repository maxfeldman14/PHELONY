
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>

char * decrypt(char * iv, char * key, char * ciphertext){ 
  //crappy documentation:
  //iv and key can/should be input manually, to correspond to changing texts
  //ciphertext is what is received in the sms message
  //the output buffer, basically. strings should (might) print properly regardless of padding
  //so that's good
  //returns pointer to decrypted string

  //to compile, use -lssl and -lcrypto
  //for make, need libssl and libcrypto (in Makefile.in in mobile, i think)

  EVP_CIPHER_CTX de;
  EVP_CIPHER_CTX_init(&de);
  const EVP_CIPHER *cipher_type;

  char * plaintext;
  int bytes_written = 0;
  int ciphertext_len = 0;
  cipher_type = EVP_aes_128_cbc();

  EVP_DecryptInit_ex(&de, cipher_type, NULL, key, iv);

  if(!EVP_DecryptInit_ex(&de, NULL, NULL, NULL, NULL)){
    printf("ERROR in EVP_DecryptInit_ex \n");
    return NULL;
  }

  ciphertext_len = strlen(ciphertext);

  plaintext = (unsigned char *) malloc(ciphertext_len); 
  int plaintext_len = 0;
  if(!EVP_DecryptUpdate(&de,
                        plaintext, &bytes_written,
                        ciphertext, ciphertext_len)){
    printf("ERROR in EVP_DecryptUpdate\n");
    return NULL;
  }
  plaintext_len += bytes_written;

  //not needed, it seems (i think this only checks padding)
/*
  if(!EVP_DecryptFinal_ex(&de,
                          plaintext + bytes_written, &bytes_written)){
    printf("ERROR in EVP_DecryptFinal_ex\n");
    //return 1;
  }
  */
  plaintext_len += bytes_written;

  EVP_CIPHER_CTX_cleanup(&de);

  return plaintext;
}

int main(int argc, char **argv)
{
  char in[] = "9999999999999999";
  unsigned char iv[16];
  unsigned char key[16];
  int k = 0;
  for(k; k < 16; k++){
    iv[k] = in[k];
    key[k] = in[k];
  }

  char ciphertext[] = {  0xdd, 0x7a,
                         0x67, 0xfa,
                         0xd5, 0xb9,
                         0xa9, 0xe7,
                         0x64, 0xd5,
                         0x35, 0x8,
                         0x5e, 0x99,
                         0x71, 0x48 };
  printf("Decrypted value = %s\n",  decrypt(key, iv,  ciphertext));
  return 0;

}
