#ifndef __ENCRYPTION__
#define __ENCRYPTION__

unsigned char *decrypt_text(unsigned char *iv, unsigned char *key, unsigned char *ciphertext);
unsigned char *encrypt_text(unsigned char *iv, unsigned char *key, unsigned char *plaintext); 

#endif
