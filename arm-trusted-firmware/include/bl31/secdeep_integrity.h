/*
 * Copyright (c) 2013-2018, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

 #define SMC_CMD_SET_64BIT									0x7920
 #define SMC_CMD_SET_64BIT_DCI								0x7921
 #define VA_BITS  0x30
 #define PAGE_OFFSET 0xFFFF800000000000
 #define KIMAGE_VOFFSET 0xFFFF000008000000
#define PHYS_OFFSET 0x0

#ifndef __ASSEMBLY__
#include <stdint.h>

/* Function head of sec deep integrity checker.*/
void rl_test_sha1();
void sha1_block_data_order(uint32_t* state, uint8_t* data, uint32_t num);

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(
    uint32_t state[5],
    unsigned char buffer[64]
    );

void SHA1Init(
    SHA1_CTX * context
    );

void SHA1Update(
    SHA1_CTX * context,
    unsigned char *data,
    uint32_t len
    );

void SHA1Final(
    unsigned char digest[20],
    SHA1_CTX * context
    );

void SHA1(
    char *hash_out,
    char *str,
    int len);
#endif /* SHA1_H */
