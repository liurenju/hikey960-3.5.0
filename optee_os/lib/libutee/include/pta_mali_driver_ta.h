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

/**
 * enum irqreturn
 * @IRQ_NONE		interrupt was not from this device or was not handled
 * @IRQ_HANDLED		interrupt was handled by this device
 * @IRQ_WAKE_THREAD	handler requests to wake the handler thread
 */
enum irqreturn {
	IRQ_NONE		= (0 << 0),
	IRQ_HANDLED		= (1 << 0),
	IRQ_WAKE_THREAD		= (1 << 1),
};

typedef enum irqreturn irqreturn_t;
#define IRQ_RETVAL(x)	((x) ? IRQ_HANDLED : IRQ_NONE)
