// Borrowed from google and Ginseng
// Ref: https://github.com/susienme/ndss2019_ginseng_arm-trusted-firmware/blob/master/spath_rust/src/sha1-armv8.S
// Ref: https://android.googlesource.com/platform/external/boringssl
#include <secdeep_integrity.h>

#if defined(__aarch64__)
#define ARMV8_SHA1 (1 << 3)
.text

.globl  sha1_block_data_order
.hidden sha1_block_data_order
.type sha1_block_data_order,%function
.align 6

sha1_block_data_order:
	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	adrp	x4,.Lconst
	add	x4,x4,:lo12:.Lconst
	eor	v1.16b,v1.16b,v1.16b
	ld1	{v0.4s},[x0],#16
	ld1	{v1.s}[0],[x0]
	sub	x0,x0,#16
	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[x4]

.Loop_hw:
	ld1	{v4.16b,v5.16b,v6.16b,v7.16b},[x1],#64
	sub	x2,x2,#1
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b

	add	v20.4s,v16.4s,v4.4s
	rev32	v6.16b,v6.16b
	orr	v22.16b,v0.16b,v0.16b	// offload

	add	v21.4s,v16.4s,v5.4s
	rev32	v7.16b,v7.16b
.inst	0x5e280803	//sha1h v3.16b,v0.16b
.inst	0x5e140020	//sha1c v0.16b,v1.16b,v20.4s		// 0
	add	v20.4s,v16.4s,v6.4s
.inst	0x5e0630a4	//sha1su0 v4.16b,v5.16b,v6.16b
.inst	0x5e280802	//sha1h v2.16b,v0.16b		// 1
.inst	0x5e150060	//sha1c v0.16b,v3.16b,v21.4s
	add	v21.4s,v16.4s,v7.4s
.inst	0x5e2818e4	//sha1su1 v4.16b,v7.16b
.inst	0x5e0730c5	//sha1su0 v5.16b,v6.16b,v7.16b
.inst	0x5e280803	//sha1h v3.16b,v0.16b		// 2
.inst	0x5e140040	//sha1c v0.16b,v2.16b,v20.4s
	add	v20.4s,v16.4s,v4.4s
.inst	0x5e281885	//sha1su1 v5.16b,v4.16b
.inst	0x5e0430e6	//sha1su0 v6.16b,v7.16b,v4.16b
.inst	0x5e280802	//sha1h v2.16b,v0.16b		// 3
.inst	0x5e150060	//sha1c v0.16b,v3.16b,v21.4s
	add	v21.4s,v17.4s,v5.4s
.inst	0x5e2818a6	//sha1su1 v6.16b,v5.16b
.inst	0x5e053087	//sha1su0 v7.16b,v4.16b,v5.16b
.inst	0x5e280803	//sha1h v3.16b,v0.16b		// 4
.inst	0x5e140040	//sha1c v0.16b,v2.16b,v20.4s
	add	v20.4s,v17.4s,v6.4s
.inst	0x5e2818c7	//sha1su1 v7.16b,v6.16b
.inst	0x5e0630a4	//sha1su0 v4.16b,v5.16b,v6.16b
.inst	0x5e280802	//sha1h v2.16b,v0.16b		// 5
.inst	0x5e151060	//sha1p v0.16b,v3.16b,v21.4s
	add	v21.4s,v17.4s,v7.4s
.inst	0x5e2818e4	//sha1su1 v4.16b,v7.16b
.inst	0x5e0730c5	//sha1su0 v5.16b,v6.16b,v7.16b
.inst	0x5e280803	//sha1h v3.16b,v0.16b		// 6
.inst	0x5e141040	//sha1p v0.16b,v2.16b,v20.4s
	add	v20.4s,v17.4s,v4.4s
.inst	0x5e281885	//sha1su1 v5.16b,v4.16b
.inst	0x5e0430e6	//sha1su0 v6.16b,v7.16b,v4.16b
.inst	0x5e280802	//sha1h v2.16b,v0.16b		// 7
.inst	0x5e151060	//sha1p v0.16b,v3.16b,v21.4s
	add	v21.4s,v17.4s,v5.4s
.inst	0x5e2818a6	//sha1su1 v6.16b,v5.16b
.inst	0x5e053087	//sha1su0 v7.16b,v4.16b,v5.16b
.inst	0x5e280803	//sha1h v3.16b,v0.16b		// 8
.inst	0x5e141040	//sha1p v0.16b,v2.16b,v20.4s
	add	v20.4s,v18.4s,v6.4s
.inst	0x5e2818c7	//sha1su1 v7.16b,v6.16b
.inst	0x5e0630a4	//sha1su0 v4.16b,v5.16b,v6.16b
.inst	0x5e280802	//sha1h v2.16b,v0.16b		// 9
.inst	0x5e151060	//sha1p v0.16b,v3.16b,v21.4s
	add	v21.4s,v18.4s,v7.4s
.inst	0x5e2818e4	//sha1su1 v4.16b,v7.16b
.inst	0x5e0730c5	//sha1su0 v5.16b,v6.16b,v7.16b
.inst	0x5e280803	//sha1h v3.16b,v0.16b		// 10
.inst	0x5e142040	//sha1m v0.16b,v2.16b,v20.4s
	add	v20.4s,v18.4s,v4.4s
.inst	0x5e281885	//sha1su1 v5.16b,v4.16b
.inst	0x5e0430e6	//sha1su0 v6.16b,v7.16b,v4.16b
.inst	0x5e280802	//sha1h v2.16b,v0.16b		// 11
.inst	0x5e152060	//sha1m v0.16b,v3.16b,v21.4s
	add	v21.4s,v18.4s,v5.4s
.inst	0x5e2818a6	//sha1su1 v6.16b,v5.16b
.inst	0x5e053087	//sha1su0 v7.16b,v4.16b,v5.16b
.inst	0x5e280803	//sha1h v3.16b,v0.16b		// 12
.inst	0x5e142040	//sha1m v0.16b,v2.16b,v20.4s
	add	v20.4s,v18.4s,v6.4s
.inst	0x5e2818c7	//sha1su1 v7.16b,v6.16b
.inst	0x5e0630a4	//sha1su0 v4.16b,v5.16b,v6.16b
.inst	0x5e280802	//sha1h v2.16b,v0.16b		// 13
.inst	0x5e152060	//sha1m v0.16b,v3.16b,v21.4s
	add	v21.4s,v19.4s,v7.4s
.inst	0x5e2818e4	//sha1su1 v4.16b,v7.16b
.inst	0x5e0730c5	//sha1su0 v5.16b,v6.16b,v7.16b
.inst	0x5e280803	//sha1h v3.16b,v0.16b		// 14
.inst	0x5e142040	//sha1m v0.16b,v2.16b,v20.4s
	add	v20.4s,v19.4s,v4.4s
.inst	0x5e281885	//sha1su1 v5.16b,v4.16b
.inst	0x5e0430e6	//sha1su0 v6.16b,v7.16b,v4.16b
.inst	0x5e280802	//sha1h v2.16b,v0.16b		// 15
.inst	0x5e151060	//sha1p v0.16b,v3.16b,v21.4s
	add	v21.4s,v19.4s,v5.4s
.inst	0x5e2818a6	//sha1su1 v6.16b,v5.16b
.inst	0x5e053087	//sha1su0 v7.16b,v4.16b,v5.16b
.inst	0x5e280803	//sha1h v3.16b,v0.16b		// 16
.inst	0x5e141040	//sha1p v0.16b,v2.16b,v20.4s
	add	v20.4s,v19.4s,v6.4s
.inst	0x5e2818c7	//sha1su1 v7.16b,v6.16b
.inst	0x5e280802	//sha1h v2.16b,v0.16b		// 17
.inst	0x5e151060	//sha1p v0.16b,v3.16b,v21.4s
	add	v21.4s,v19.4s,v7.4s

.inst	0x5e280803	//sha1h v3.16b,v0.16b		// 18
.inst	0x5e141040	//sha1p v0.16b,v2.16b,v20.4s

.inst	0x5e280802	//sha1h v2.16b,v0.16b		// 19
.inst	0x5e151060	//sha1p v0.16b,v3.16b,v21.4s

	add	v1.4s,v1.4s,v2.4s
	add	v0.4s,v0.4s,v22.4s

	cbnz	x2,.Loop_hw

	st1	{v0.4s},[x0],#16
	st1	{v1.s}[0],[x0]

	ldr	x29,[sp],#16
	ret
.size	sha1_block_data_order,.-sha1_block_data_order
.align	6
.Lconst:
.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999	//K_00_19
.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1	//K_20_39
.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc	//K_40_59
.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6	//K_60_79
.LOPENSSL_armcap_P:
#ifdef	__ILP32__
.long	OPENSSL_armcap_P-.
#else
.quad	OPENSSL_armcap_P-.
#endif
.byte	83,72,65,49,32,98,108,111,99,107,32,116,114,97,110,115,102,111,114,109,32,102,111,114,32,65,82,77,118,56,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	2
.align	2
.comm	OPENSSL_armcap_P,4,4
#endif
