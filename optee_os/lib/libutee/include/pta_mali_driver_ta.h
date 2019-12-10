#define TA_NAME		"mali_driver.ta"

//62a0838c-1aeb-11ea-978f-2e728ce88125
#define STATS_UUID \
		{ 0x62a0838c, 0x1aeb, 0x11ea, \
			{ 0x97, 0x8f, 0x2e, 0x72, 0x8c, 0xe8, 0x81, 0x25 } }

/*
  MACROs for the control commands
*/
#define READ_COMMANDS   1
#define WRITE_COMMANDS  2
#define JD_SUBMIT       3
#define IRQ_REQUESTS    4

/* GPU IRQ Tags */
#define	JOB_IRQ_TAG	0
#define MMU_IRQ_TAG	1
#define GPU_IRQ_TAG	2
