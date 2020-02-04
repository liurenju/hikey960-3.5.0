// The implementation of secdeep table.
#include <kernel/secdeep_table.h>

void secdeep_hash_init(void) {
  for(int i = 0; i < HASH1_SIZE; i++) {
    initialized[i] = 0;
  }
}

// Expand or add the entry to hash table
int add_entry(int key) {
  if(!entry) {
    secdeep_hash_init();
    entry = 1;
  }

  int index = key / HASH1_SIZE;
  if (index >= HASH_MAX) {
    DMSG("Max hash value exceeded.");
    return 1;
  }

  if(initialized[index]) {
    DMSG("This entry has been initialized.");
    return 1;
  }
  initialized[index] = 1;
  hashL1[index] = (int *)malloc(sizeof(int) * HASH2_SIZE);
  return 0;
}

int hash_get_value(int key, int* value) {
  int index = key / HASH1_SIZE;
  if (index >= HASH_MAX) {
    DMSG("Cannot get the hash value. Too large!");
    return 1;
  }

  if (!initialized[index]) {
    DMSG("Cannot get the hash value. Too large!");
    return 1;
  }

  int entry_l2 = key % HASH2_SIZE;
  *value = hashL1[index][entry_l2];
  return 0;
}

int hash_add_pair(int key, int value) {
  int index = key / HASH1_SIZE;
  if (index >= HASH_MAX) {
    DMSG("Max hash value exceeded.");
    return 1;
  }

  add_entry(key);
  int entry_l2 = key % HASH2_SIZE;
  hashL1[index][entry_l2] = value;
  return 0;
}

int secdeep_hash_delete(void) {
  for(int i = 0; i < HASH1_SIZE; i++) {
    initialized[i] = 0;
  }
  entry = 0;
  return 0;
}
