// Implemented through openSSL.
// Ref: https://github.com/susienme/ndss2019_ginseng_arm-trusted-firmware/blob/master/spath_rust/src/sha1-armv8.S
// SHA1 is Implemented using open source sha1 implementation.

#include <stdio.h>
#include <string.h>
#include <secdeep_integrity.h>
#include <common/debug.h>

/* for uint32_t */
#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(
    uint32_t state[5],
    unsigned char buffer[64]
)
{
    uint32_t a, b, c, d, e;

    typedef union
    {
        unsigned char c[64];
        uint32_t l[16];
    } CHAR64LONG16;

#ifdef SHA1HANDSOFF
    CHAR64LONG16 block[1];      /* use array to appear as a pointer */

    memcpy(block, buffer, 64);
#else
    /* The following had better never be used because it causes the
     * pointer-to-buffer to be cast into a pointer to non-const.
     * And the result is written through.  I threw a "const" in, hoping
     * this will cause a diagnostic.
     */
    CHAR64LONG16 *block = (CHAR64LONG16 *) buffer;
#endif
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
#ifdef SHA1HANDSOFF
    memset(block, '\0', sizeof(block));
#endif
}


/* SHA1Init - Initialize new context */

void SHA1Init(
    SHA1_CTX * context
)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(
    SHA1_CTX * context,
    unsigned char *data,
    uint32_t len
)
{
    uint32_t i;

    uint32_t j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
        context->count[1]++;
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if ((j + len) > 63)
    {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64)
        {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else
        i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void SHA1Final(
    unsigned char digest[20],
    SHA1_CTX * context
)
{
    unsigned i;

    unsigned char finalcount[8];

    unsigned char c;

#if 0    /* untested "improvement" by DHR */
    /* Convert context->count to a sequence of bytes
     * in finalcount.  Second element first, but
     * big-endian order within element.
     * But we do it all backwards.
     */
    unsigned char *fcp = &finalcount[8];

    for (i = 0; i < 2; i++)
    {
        uint32_t t = context->count[i];

        int j;

        for (j = 0; j < 4; t >>= 8, j++)
            *--fcp = (unsigned char) t}
#else
    for (i = 0; i < 8; i++)
    {
        finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);      /* Endian independent */
    }
#endif
    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448)
    {
        c = 0000;
        SHA1Update(context, &c, 1);
    }
    SHA1Update(context, finalcount, 8); /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++)
    {
        digest[i] = (unsigned char)
            ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
    /* Wipe variables */
    memset(context, '\0', sizeof(*context));
    memset(&finalcount, '\0', sizeof(finalcount));
}

void SHA1(
    char *hash_out,
    char *str,
    uint64_t len)
{
    SHA1_CTX ctx;
    unsigned int ii;

    SHA1Init(&ctx);
    for (ii=0; ii<len; ii+=1)
        SHA1Update(&ctx, (unsigned char*)str + ii, 1);
    SHA1Final((unsigned char *)hash_out, &ctx);
    hash_out[20] = '\0';
}

void rl_test_sha1() {
  char input[] = "hello renju";
  char output[20];
  SHA1(output, input, strlen(input));

  // int i = 0;
  // RENJU_DEBUG("\n\n\n\n\n----------Renju--------------------\n");
  // for(; i < 20; i++) {
  //   RENJU_DEBUG("%02x ", output[i]);
  // }
  // RENJU_DEBUG("\n----------Renju--------------------\n\n\n\n\n");
  return;
}

void dci(uint64_t dest_pa) {
  asm volatile (
			"dc ivac, %0\n"  \
			"dmb sy\n" \
			"isb sy\n" \
			:
			: "r" (dest_pa)
			: "memory"
			);
}

void dcci(uint64_t dest_pa) {
  asm volatile (
      "dc civac, %0\n"  \
			"dmb sy\n" \
			"isb sy\n"
			:
			: "r" (dest_pa)
			: "memory"
	);
}

// uint64_t BIT(uint64_t nr) {
//   return ((uint64_t) 1) << nr;
// }

uint64_t __pa(uint64_t x) {
  if ((x & BIT_64(VA_BITS -1)) == 0) {
    return x- KIMAGE_VOFFSET;
  }

  return ((x & !PAGE_OFFSET) + PHYS_OFFSET);
}

void _set64bit(uint64_t dest_va, uint64_t src_val, int bdci) {
  uint64_t dest_pa = __pa(dest_va);
  if (bdci) {
    dci(dest_pa);
  }

  asm volatile (
      "mrs x15, sctlr_el3\n"  \
  		"bic x15, x15, #1\n"  \
  		"mov x9, %0\n" \
  		"mov x10, %1\n" \
			"msr sctlr_el3, x15\n" \
			"isb sy\n" \
			"str x10, [x9]\n"  \
			"dmb sy\n" \
			"orr x15, x15, #1\n" \
			"msr sctlr_el3, x15\n" \
			"isb sy"
			:
			: "r" (dest_pa), "r" (src_val)
			: "memory",
			"x15", 	// sctrl save
			"x9", 	// dest_pa
			"x10"	// src_Val
	);

  if (bdci) {
    dcci(dest_pa);
  }
}

uint64_t KERN_PA(uint64_t addr) {
  uint64_t pa;
  asm volatile(
	  "mrs x15, sctlr_el3\n" \
		"bic x15, x15, #1\n"  \
		"mov x10, %1\n" \
		"msr sctlr_el3, x15\n"  \
		"isb sy\n"  \
		"ldr x9, [x10]\n" \
		"dmb sy\n"  \
		"orr x15, x15, #1\n"  \
		"msr sctlr_el3, x15\n"  \
		"isb sy\n"  \
		"mov %0, x9"
		: "=r" (pa)
		: "r" (addr)
		: "memory",
		"x15", 	// sctrl save
		"x9", 	// out
		"x10"	// src_Val
	);
  return pa;
}

uint64_t check_pte(uint64_t addr, uint64_t upper, uint64_t lower) {
  int i = 0;
  for(; i < 512; i++) {
    uint64_t pte = KERN_PA(addr + 8 * i);
    if(pte){
      if(pte > lower && pte < upper) return 1;
      if((pte = pte & 0b11) == 0b11) {
        if((pte & 0xFFFFFFFFF000) > lower && (pte & 0xFFFFFFFFF000) < upper) {
          return 1;
        }
      }
    }
  }
  return 0;
}

uint64_t check_pmd(uint64_t addr, uint64_t upper, uint64_t lower) {
  int i = 0;
  for(; i < 512 ; i++) {
    uint64_t pmd_e = KERN_PA(addr + 8 * i);
    if (pmd_e) {
      if (pmd_e > lower && pmd_e < upper) return 1;
      uint64_t pte = (pmd_e & 0xFFFFFFFFF000);
      return check_pmd(pte, upper, lower);
    }
  }
  return 0;
}

uint64_t check_pud(uint64_t addr, uint64_t upper, uint64_t lower) {
  int i = 0;
  for(; i < 512 ; i++) {
    uint64_t pud_e = KERN_PA(addr + 8 * i);
    if (pud_e) {
      if (pud_e > lower && pud_e < upper) return 1;
      uint64_t pmd_e = pud_e & 0xFFFFFFFFF000;
      return check_pmd(pmd_e, upper, lower);
    }
  }
  return 0;
}

uint64_t getTtbr1() {
  uint64_t ret;
  asm volatile (
    "mrs %0, ttbr1_el1"
		: "=r" (ret)
		:
		: "memory"
  );
  return ret;
}

uint64_t safeMapping(uint64_t upper, uint64_t lower) {
  // walk the page table to ensure the mapping is safe.
  uint64_t ttbr1 = getTtbr1();
  int i = 0;

  for(;i < 512; i++) {
    uint64_t pgd_e = KERN_PA(ttbr1 + 8 * i);
    if(pgd_e) {
      uint64_t pud_e = (pgd_e & 0xFFFFFFFFF000);
      if (pud_e > lower && pud_e < upper) {
        // Unsafe
        return 1;
      }
      return check_pud(pud_e, upper, lower);
    }
  }
  return 0;
}

uint8_t loading_integrity(
  uint64_t base_addr,
  uint64_t size,
  char* expected_hash
) {
  char real_hash[20];
  SHA1(real_hash, (char *)base_addr, size);

  for(int i = 0; i < 20; i++) {
    if(expected_hash[i] != real_hash[i]) {
      return 1;
    }
  }

  return 0;
}

void code_integrity_request(uint64_t smc_cmd, uint64_t a1,
  uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t sp1) {
    if(smc_cmd == SMC_CMD_SET_64BIT) {
      if(!safeMapping(a3, a4)) {
        _set64bit(a1, a2, 0);
      }
    }
    else if(smc_cmd == SMC_CMD_SET_64BIT_DCI) {
      if(!safeMapping(a3, a4)) {
        _set64bit(a1, a2, 1);
      }
    }
    else if(smc_cmd == SMC_CMD_PROGRAM_ENTRY) {
      // RENJU LIU: For evaluation purpose, we directly use the hash.
      char expected_hash[20];
      SHA1(expected_hash, (char *)a1, a2);
      if(loading_integrity(a1, a2, expected_hash)) {
        ERROR("\n\n\n-----ERROR----\nThe program has been tampered.\n\n\n\n");
      }
    }
    else {
      // Other commands;
    }
    // hello world
  }
