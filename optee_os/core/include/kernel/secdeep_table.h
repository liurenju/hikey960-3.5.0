// The secdeep table related implementations.
#ifndef __SECDEEP_TABLE
#define __SECDEEP_TABLE

#include <stdlib.h>
#include <trace.h>
#include <assert.h>
#include <compiler.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <string.h>
#include <types_ext.h>
#include <util.h>

typedef struct val {
  char *value;
  char length;
} VAL;

#define HASH1_SIZE  10000
#define HASH2_SIZE  10000
#define HASH_MAX    10000

// The following two are for evaluation purposes
#define MAX_SECURE_SIZE 10*1024*1024
#define MAX_TABLE_SIZE  MAX_SECURE_SIZE/8

uint32_t* hashL1[HASH1_SIZE];
char initialized[HASH1_SIZE];
extern char entry;
extern uint32_t table_size;

void secdeep_hash_init(void);
uint32_t add_entry(uint32_t key);
uint32_t hash_get_value(uint32_t key, uint32_t* value);
uint32_t hash_add_pair(uint32_t key, uint32_t value);
uint32_t secdeep_hash_delete(void);

#endif
