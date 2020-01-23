#ifndef _SEC_DEEP_ENABLED
#define _SEC_DEEP_ENABLED
#endif

// #include <linux/printk.h>
#define PAGE_TABLE_READ_ONLY
#define RENJU_DEBUG(...)	printk(KERN_ERR __VA_ARGS__)

#define SMC_CMD_SET_64BIT									0x7920
#define SMC_CMD_SET_64BIT_DCI								0x7921

#define NST_MASK 	0x8000000000000000
#define NST_SHIFT	63

#define APT_MASK	0x6000000000000000
#define APT_SHIFT	61

#define UXNT_MASK	0x1000000000000000
#define UXNT_SHIFT 	60

#define PXNT_MASK	0x800000000000000
#define PXNT_SHIFT 	59

#define RES0_MASK	0x7000000000000
#define RES0_SHIFT	48

#define PUD_ADDR_MASK 			0xFFFFFFFFF000
#define PMD_ADDR_MASK 			PUD_ADDR_MASK
#define PT_ADDR_MASK 			PUD_ADDR_MASK
#define OA_ADDR_MASK 			PUD_ADDR_MASK
#define PMD_BLOLCK_ADDR_MASK	0xFFFFFFE00000

// for BLOCK
#define BLOCK_UXN_SHIFT			54
#define BLOCK_UXN_MASK			(1ULL << BLOCK_UXN_SHIFT)

#define BLOCK_PXN_SHIFT			53
#define BLOCK_PXN_MASK			(1ULL << BLOCK_PXN_SHIFT)

#define BLOCK_CONT_SHIFT		53
#define BLOCK_CONT_MASK			(1ULL << BLOCK_CONT_SHIFT)

#define BLOCK_NG_SHIFT			11
#define BLOCK_NG_MASK			(1ULL << BLOCK_NG_SHIFT)

#define BLOCK_AF_SHIFT			10
#define BLOCK_AF_MASK			(1ULL << BLOCK_AF_SHIFT)

#define BLOCK_SH_SHIFT			8
#define BLOCK_SH_MASK			(0b11ULL << BLOCK_SH_SHIFT)

#define BLOCK_AP_SHIFT			6
#define BLOCK_AP_MASK			(0b11ULL << BLOCK_AP_SHIFT)

#define BLOCK_NS_SHIFT			5
#define BLOCK_NS_MASK			(1ULL << BLOCK_NS_SHIFT)

#define BLOCK_ATTR_IDX_SHIFT	2
#define BLOCK_ATTR_IDX_MASK		(0b111ULL << BLOCK_ATTR_IDX_SHIFT)

#define PTE_UXN_SHIFT 			BLOCK_UXN_SHIFT
#define PTE_UXN_MASK 			BLOCK_UXN_MASK
#define PTE_PXN_SHIFT 			BLOCK_PXN_SHIFT
#define PTE_PXN_MASK 			BLOCK_PXN_MASK
#define PTE_CONT_SHIFT 			BLOCK_CONT_SHIFT
#define PTE_CONT_MASK 			BLOCK_CONT_MASK
#define PTE_NG_SHIFT 			BLOCK_NG_SHIFT
#define PTE_NG_MASK 			BLOCK_NG_MASK
#define PTE_AF_SHIFT 			BLOCK_AF_SHIFT
#define PTE_AF_MASK 			BLOCK_AF_MASK
#define PTE_SH_SHIFT 			BLOCK_SH_SHIFT
#define PTE_SH_MASK 			BLOCK_SH_MASK
#define PTE_AP_SHIFT 			BLOCK_AP_SHIFT
#define PTE_AP_MASK 			BLOCK_AP_MASK
#define PTE_NS_SHIFT 			BLOCK_NS_SHIFT
#define PTE_NS_MASK 			BLOCK_NS_MASK
#define PTE_ATTR_IDX_SHIFT 		BLOCK_ATTR_IDX_SHIFT
#define PTE_ATTR_IDX_MASK 		BLOCK_ATTR_IDX_MASK

#define GET_FIELD(e, name)\
	(e & name##_MASK) >> name##_SHIFT

#define GET_BLOCK_FIELD(e, name)\
	(e & BLOCK_##name##_MASK) >> BLOCK_##name##_SHIFT

#define GET_PTE_FIELD(e, name)\
	(e & PTE_##name##_MASK) >> PTE_##name##_SHIFT

#ifndef __ASSEMBLY__
#define dc_invalidate_single(addr)	\
	asm volatile (					\
		"dc ivac, %0\n"		\
		"dmb sy\n"					\
		"isb sy"					\
		:							\
		: "r" (addr)			\
		:							\
		)
#endif
