#include <crypto/secdeep_fpe.h>

int cur_size = 0;
uint8_t SECDEEP_IV[]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
uint8_t SECDEEP_KEY[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}; //128 bits

// In this project, we don't implement FF1 for format-preserving encryption.
// But instead, we implement AES using CTR mode for format-preserving encryption.

int init_FPE_state(symmetric_CTR *ctr) {
  int cipher_idx = find_cipher("aes");

	if (cipher_idx < 0) {
    panic("--RL: f**king unknown cipher");
		return TEE_ERROR_NOT_SUPPORTED;
  }

  if ((int)(sizeof(SECDEEP_IV)) != cipher_descriptor[cipher_idx]->block_length) {
    panic("---RL: IV block length error.");
		return TEE_ERROR_BAD_PARAMETERS;
  }

  if (ctr_start(cipher_idx, SECDEEP_IV, SECDEEP_KEY, SECDEEP_KEY_LEN, 0, CTR_COUNTER_BIG_ENDIAN, ctr) == CRYPT_OK) {
    return TEE_SUCCESS;
  }
  else
  {
    panic("---RL: CTR starts failed.");
    return TEE_ERROR_BAD_STATE;
  }

  return TEE_SUCCESS;
}

void FPE_encrypt(unsigned char *plaintext, unsigned char *ciphered, unsigned int inlen)
{
  symmetric_CTR ctr;
  memset(ciphered, 0, inlen);
  if (init_FPE_state(&ctr) != TEE_SUCCESS) {
    panic("---RL: init aes ctr failed.");
    return;
  }

  if(ctr_encrypt(plaintext, ciphered, inlen, &ctr) != CRYPT_OK) {
    panic("---RL: encrypt aes ctr failed.");
  }
  // DMSG("RL: Plaintext - %u, ciphered - %u\n", ((uint32_t *)plaintext)[0], ((uint32_t *)ciphered)[0]);
  // EMSG("RL: I am here!3");

  //
  // WARNING!!!!
  // The following code is used for verifications only!! It needs to be deleted
  // for evaluation purposes.
  //

// #if defined(CFG_TEST_SECDEEP_FPE)
//   unsigned char test_plaintext[inlen];
//   unsigned char test_ciphered[inlen];
//   memcpy(test_ciphered, ciphered, inlen);
//   if (init_FPE_state(&ctr) != TEE_SUCCESS) {
//     panic("---RL: init aes ctr failed.");
//     return;
//   }
//   if(ctr_decrypt(test_ciphered, test_plaintext, inlen, &ctr) != CRYPT_OK) {
//     panic("---RL: encrypt aes ctr failed.");
//   }
//   for(unsigned int i = 0; i < inlen; i++) {
//     if(plaintext[i] != test_plaintext[i]){
//       panic("Cipher failed.");
//     }
//   }
// #endif

}

void FPE_decrypt(unsigned char *plaintext, unsigned char *ciphered, unsigned int inlen)
{
  symmetric_CTR ctr;
  memset(plaintext, 0, inlen);
  if (init_FPE_state(&ctr) != TEE_SUCCESS) {
    panic("---RL: init aes ctr failed.");
    return;
  }

  if(ctr_decrypt(ciphered, plaintext, inlen, &ctr) != CRYPT_OK) {
    panic("---RL: encrypt aes ctr failed.");
  }

  //
  // WARNING!!!!
  // The following code is used for verifications only!! It needs to be deleted
  // for evaluation purposes.
  //

// #if defined(CFG_TEST_SECDEEP_FPE)
//   unsigned char test_plaintext[inlen];
//   unsigned char test_ciphered[inlen];
//   memcpy(test_plaintext, plaintext, inlen);
//   if (init_FPE_state(&ctr) != TEE_SUCCESS) {
//     panic("---RL: init aes ctr failed.");
//     return;
//   }
//   if(ctr_encrypt(test_plaintext, test_ciphered, inlen, &ctr) != CRYPT_OK) {
//     panic("---RL: encrypt aes ctr failed.");
//   }
//   for(unsigned int i = 0; i < inlen; i++) {
//     assert(test_ciphered[i] == test_ciphered[i]);
//   }
// #endif
}
