// Format encryption definition here.
#define ENCRYPTION 1
#define DECRYPTION 0

#define SECDEEP_KEY_LEN 16

// #include <crypto/crypto.h>
#include <kernel/panic.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <tomcrypt.h>
#include <util.h>

uint8_t SECDEEP_IV[]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
uint8_t SECDEEP_KEY[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}; //128 bits

int init_FPE_state(symmetric_CTR *ctr);
void FPE_encrypt(unsigned char *plaintext, unsigned char *ciphered, unsigned int inlen);
void FPE_decrypt(unsigned char *plaintext, unsigned char *ciphered, unsigned int inlen);
