// The implementation of secdeep table.
#include <kernel/secdeep_table.h>

char entry = 0;
uint32_t table_size = 0;

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
    table_size = 0;
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
  for(int i = 0; i < HASH2_SIZE; i++) {
    hashL1[index][i] = 0;
  }
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

  if(++table_size > MAX_TABLE_SIZE || thread_stack_size() > MAX_SECURE_SIZE) {
    DMSG("Renju: Max table size achieved. Because of %s\n",
      thread_stack_size() > MAX_SECURE_SIZE ? "thread_stack_size" : "table_size");
    return 1;
  }

  if (index >= HASH_MAX) {
    DMSG("Max hash value exceeded.");
    return 1;
  }

  add_entry(key);
  int entry_l2 = key % HASH2_SIZE;
  if(hashL1[index][entry_l2]) {
    if (hashL1[index][entry_l2] != value) {
      panic("secdeep: Hash collisions");
      return 1;
    }
    return 0;
  }
  hashL1[index][entry_l2] = value;
  return 0;
}

int secdeep_hash_delete(void) {
  for(int i = 0; i < HASH1_SIZE; i++) {
    initialized[i] = 0;
  }
  entry = 0;
  table_size = 0;
  return 0;
}
