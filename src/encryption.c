#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>

unsigned char * decrypt(unsigned char * iv, unsigned char * key, unsigned char * ciphertext){ 

  EVP_CIPHER_CTX de;
  EVP_CIPHER_CTX_init(&de);
  const EVP_CIPHER *cipher_type;
  unsigned char * plaintext;
  plaintext = (unsigned char *) malloc(strlen(ciphertext));

  int bytes_written = 0;
  int ciphertext_len = 0;
  cipher_type = EVP_aes_128_cbc();

  EVP_DecryptInit_ex(&de, cipher_type, NULL, key, iv);

  if(!EVP_DecryptInit_ex(&de, NULL, NULL, NULL, NULL)){
    printf("ERROR in EVP_DecryptInit_ex \n");
    return NULL;
  }

  ciphertext_len = strlen(ciphertext);

  int plaintext_len = 0;
  if(!EVP_DecryptUpdate(&de,
                        plaintext, &bytes_written,
                        ciphertext, ciphertext_len)){
    printf("ERROR in EVP_DecryptUpdate\n");
    return NULL;
  }
  plaintext_len += bytes_written;

  if(!EVP_DecryptFinal_ex(&de,
                          plaintext + bytes_written, &bytes_written)){
    printf("ERROR in EVP_DecryptFinal_ex\n");
    return NULL;
  }
  plaintext_len += bytes_written;

  EVP_CIPHER_CTX_cleanup(&de);

  return plaintext;
}

unsigned char * encrypt( unsigned char * iv, unsigned char * key, unsigned char * plaintext){ 

  EVP_CIPHER_CTX en;
  EVP_CIPHER_CTX_init(&en);
  const EVP_CIPHER *cipher_type;
  int input_len = 0;

  unsigned char * ciphertext;
  ciphertext = (unsigned char *) malloc(strlen(plaintext));
  cipher_type = EVP_aes_128_cbc();

  //init cipher
  EVP_EncryptInit_ex(&en, cipher_type, NULL, key, iv);

  //static const int MAX_PADDING_LEN = 16;

  // We add 1 because we're encrypting a string, which has a NULL terminator
  // and want that NULL terminator to be present when we decrypt.
  input_len = strlen(plaintext) + 1;
  //ciphertext = (unsigned char *) malloc(input_len + MAX_PADDING_LEN);
  ciphertext = (unsigned char *) malloc(input_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  if(!EVP_EncryptInit_ex(&en, NULL, NULL, NULL, NULL)){
    printf("ERROR in EVP_EncryptInit_ex \n");
    return NULL;
  }

  // This function works on binary data, not strings.  So we cast our
  // string to an unsigned char * and tell it that the length is the string
  // length + 1 byte for the null terminator.
  int bytes_written = 0;
  int ciphertext_len = 0;
  //encrypt
  if(!EVP_EncryptUpdate(&en,
                        ciphertext, &bytes_written,
                        (unsigned char *) plaintext, input_len) ) {
    return NULL;
  }
  ciphertext_len += bytes_written;

  //do padding
  if(!EVP_EncryptFinal_ex(&en,
                          ciphertext + bytes_written,
                          &bytes_written)){
    printf("ERROR in EVP_EncryptFinal_ex \n");
    return NULL;
  }
  ciphertext_len += bytes_written;

  //cleanup
  EVP_CIPHER_CTX_cleanup(&en);

  return ciphertext;
}

int main(int argc, char **argv)
{
  unsigned char * in = "hello world";
  printf("Input: %s\n", in);
  unsigned char * out = NULL;
  unsigned char * final = NULL;
  //out = (unsigned char *) malloc(strlen(in));
  unsigned char * iv = "aaaaaaaaaaaaaaaa";
  unsigned char * key = "bbbbbbbbbbbbbbbb";
  out = encrypt(iv, key, in);
  printf("in: %s\n", in);
  printf("encrypted: %s\n", out);
  final = decrypt(iv, key, out); 
  printf("in: %s\n", final);
  return 0;

}
