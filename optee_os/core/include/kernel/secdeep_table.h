// The secdeep table related implementations.
#include <stdlib.h>
#include <trace.h>
#include <assert.h>
#include <compiler.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/panic.h>
#include <string.h>
#include <types_ext.h>
#include <util.h>

typedef struct val {
  char *value;
  char length;
} VAL;

#define HASH1_SIZE  100000
#define HASH2_SIZE  100000
#define HASH_MAX    100000

int* hashL1[HASH1_SIZE];
char initialized[HASH1_SIZE];
char entry = 0;

void secdeep_hash_init(void);
int add_entry(int key);
int hash_get_value(int key, int* value);
int hash_add_pair(int key, int value);
int secdeep_hash_delete(void);
