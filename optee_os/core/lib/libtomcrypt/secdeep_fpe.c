#include <crypto/secdeep_fpe.h>

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
  else {
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

  //
  // WARNING!!!!
  // The following code is used for verifications only!! It needs to be deleted
  // for evaluation purposes.
  //

#if defined(CFG_TEST_SECDEEP_FPE)
  unsigned char test_plaintext[inlen];
  unsigned char test_ciphered[inlen];
  memcpy(test_ciphered, ciphered, inlen);
  FPE_decrypt(test_plaintext, test_ciphered, inlen);
  for(unsigned int i = 0; i < inlen; i++) {
    assert(plaintext[i] == test_plaintext[i]);
  }
#endif

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

#if defined(CFG_TEST_SECDEEP_FPE)
  unsigned char test_plaintext[inlen];
  unsigned char test_ciphered[inlen];
  memcpy(test_plaintext, plaintext, inlen);
  FPE_encrypt(test_plaintext, test_ciphered, inlen);
  for(unsigned int i = 0; i < inlen; i++) {
    assert(test_ciphered[i] == test_ciphered[i]);
  }
#endif
}
