#ifndef __SECDEEP
#define __SECDEEP

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
#include <kernel/secdeep_table.h>

extern int cur_size;

int init_FPE_state(symmetric_CTR *ctr);
void FPE_encrypt(unsigned char *plaintext, unsigned char *ciphered, unsigned int inlen);
void FPE_decrypt(unsigned char *plaintext, unsigned char *ciphered, unsigned int inlen);

#endif
