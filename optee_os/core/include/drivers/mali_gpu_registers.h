// The registers mapping of GPU
#define COHERENCY_ACE_LITE 0
#define COHERENCY_ACE      1
#define COHERENCY_NONE     31
#define COHERENCY_FEATURE_BIT(x) (1 << (x))

/*
  MACROs for the control commands
*/
#define READ_COMMANDS   1
#define WRITE_COMMANDS  2

/* GPU IRQ Tags */
#define	JOB_IRQ_TAG	0
#define MMU_IRQ_TAG	1
#define GPU_IRQ_TAG	2

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

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


/*
 * Begin Register Offsets
 */

#define GPU_PHYS_BASE           0xE82C0000
#define GPU_CONTROL_BASE        (GPU_PHYS_BASE + 0x0000)
#define GPU_CONTROL_REG(r)      (GPU_CONTROL_BASE + (r))
#define GPU_ID                  0x000	/* (RO) GPU and revision identifier */
#define L2_FEATURES             0x004	/* (RO) Level 2 cache features */
#define CORE_FEATURES           0x008	/* (RO) Shader Core Features */
#define TILER_FEATURES          0x00C	/* (RO) Tiler Features */
#define MEM_FEATURES            0x010	/* (RO) Memory system features */
#define MMU_FEATURES            0x014	/* (RO) MMU features */
#define AS_PRESENT              0x018	/* (RO) Address space slots present */
#define JS_PRESENT              0x01C	/* (RO) Job slots present */
#define GPU_IRQ_RAWSTAT         0x020	/* (RW) */
#define GPU_IRQ_CLEAR           0x024	/* (WO) */
#define GPU_IRQ_MASK            0x028	/* (RW) */
#define GPU_IRQ_STATUS          0x02C	/* (RO) */

/* IRQ flags */
#define GPU_FAULT               (1 << 0)	/* A GPU Fault has occurred */
#define MULTIPLE_GPU_FAULTS     (1 << 7)	/* More than one GPU Fault occurred. */
#define RESET_COMPLETED         (1 << 8)	/* Set when a reset has completed. Intended to use with SOFT_RESET
						   commands which may take time. */
#define POWER_CHANGED_SINGLE    (1 << 9)	/* Set when a single core has finished powering up or down. */
#define POWER_CHANGED_ALL       (1 << 10)	/* Set when all cores have finished powering up or down
						   and the power manager is idle. */

#define PRFCNT_SAMPLE_COMPLETED (1 << 16)	/* Set when a performance count sample has completed. */
#define CLEAN_CACHES_COMPLETED  (1 << 17)	/* Set when a cache clean operation has completed. */

#define GPU_IRQ_REG_ALL (GPU_FAULT | MULTIPLE_GPU_FAULTS | RESET_COMPLETED \
			| POWER_CHANGED_ALL | PRFCNT_SAMPLE_COMPLETED)

#define GPU_COMMAND             0x030	/* (WO) */
#define GPU_STATUS              0x034	/* (RO) */
#define LATEST_FLUSH            0x038	/* (RO) */

#define GROUPS_L2_COHERENT      (1 << 0)	/* Cores groups are l2 coherent */
#define GPU_DBGEN               (1 << 8)	/* DBGEN wire status */

#define GPU_FAULTSTATUS         0x03C	/* (RO) GPU exception type and fault status */
#define GPU_FAULTADDRESS_LO     0x040	/* (RO) GPU exception fault address, low word */
#define GPU_FAULTADDRESS_HI     0x044	/* (RO) GPU exception fault address, high word */

#define PWR_KEY                 0x050	/* (WO) Power manager key register */
#define PWR_OVERRIDE0           0x054	/* (RW) Power manager override settings */
#define PWR_OVERRIDE1           0x058	/* (RW) Power manager override settings */

#define PRFCNT_BASE_LO          0x060	/* (RW) Performance counter memory region base address, low word */
#define PRFCNT_BASE_HI          0x064	/* (RW) Performance counter memory region base address, high word */
#define PRFCNT_CONFIG           0x068	/* (RW) Performance counter configuration */
#define PRFCNT_JM_EN            0x06C	/* (RW) Performance counter enable flags for Job Manager */
#define PRFCNT_SHADER_EN        0x070	/* (RW) Performance counter enable flags for shader cores */
#define PRFCNT_TILER_EN         0x074	/* (RW) Performance counter enable flags for tiler */
#define PRFCNT_MMU_L2_EN        0x07C	/* (RW) Performance counter enable flags for MMU/L2 cache */

#define CYCLE_COUNT_LO          0x090	/* (RO) Cycle counter, low word */
#define CYCLE_COUNT_HI          0x094	/* (RO) Cycle counter, high word */
#define TIMESTAMP_LO            0x098	/* (RO) Global time stamp counter, low word */
#define TIMESTAMP_HI            0x09C	/* (RO) Global time stamp counter, high word */

#define THREAD_MAX_THREADS		0x0A0	/* (RO) Maximum number of threads per core */
#define THREAD_MAX_WORKGROUP_SIZE 0x0A4	/* (RO) Maximum workgroup size */
#define THREAD_MAX_BARRIER_SIZE 0x0A8	/* (RO) Maximum threads waiting at a barrier */
#define THREAD_FEATURES         0x0AC	/* (RO) Thread features */
#define THREAD_TLS_ALLOC        0x310   /* (RO) Number of threads per core that TLS must be allocated for*/

#define TEXTURE_FEATURES_0      0x0B0	/* (RO) Support flags for indexed texture formats 0..31 */
#define TEXTURE_FEATURES_1      0x0B4	/* (RO) Support flags for indexed texture formats 32..63 */
#define TEXTURE_FEATURES_2      0x0B8	/* (RO) Support flags for indexed texture formats 64..95 */
#define TEXTURE_FEATURES_3      0x0BC	/* (RO) Support flags for texture order */

#define TEXTURE_FEATURES_REG(n) GPU_CONTROL_REG(TEXTURE_FEATURES_0 + ((n) << 2))

#define JS0_FEATURES            0x0C0	/* (RO) Features of job slot 0 */
#define JS1_FEATURES            0x0C4	/* (RO) Features of job slot 1 */
#define JS2_FEATURES            0x0C8	/* (RO) Features of job slot 2 */
#define JS3_FEATURES            0x0CC	/* (RO) Features of job slot 3 */
#define JS4_FEATURES            0x0D0	/* (RO) Features of job slot 4 */
#define JS5_FEATURES            0x0D4	/* (RO) Features of job slot 5 */
#define JS6_FEATURES            0x0D8	/* (RO) Features of job slot 6 */
#define JS7_FEATURES            0x0DC	/* (RO) Features of job slot 7 */
#define JS8_FEATURES            0x0E0	/* (RO) Features of job slot 8 */
#define JS9_FEATURES            0x0E4	/* (RO) Features of job slot 9 */
#define JS10_FEATURES           0x0E8	/* (RO) Features of job slot 10 */
#define JS11_FEATURES           0x0EC	/* (RO) Features of job slot 11 */
#define JS12_FEATURES           0x0F0	/* (RO) Features of job slot 12 */
#define JS13_FEATURES           0x0F4	/* (RO) Features of job slot 13 */
#define JS14_FEATURES           0x0F8	/* (RO) Features of job slot 14 */
#define JS15_FEATURES           0x0FC	/* (RO) Features of job slot 15 */

#define JS_FEATURES_REG(n)      GPU_CONTROL_REG(JS0_FEATURES + ((n) << 2))

#define SHADER_PRESENT_LO       0x100	/* (RO) Shader core present bitmap, low word */
#define SHADER_PRESENT_HI       0x104	/* (RO) Shader core present bitmap, high word */

#define TILER_PRESENT_LO        0x110	/* (RO) Tiler core present bitmap, low word */
#define TILER_PRESENT_HI        0x114	/* (RO) Tiler core present bitmap, high word */

#define L2_PRESENT_LO           0x120	/* (RO) Level 2 cache present bitmap, low word */
#define L2_PRESENT_HI           0x124	/* (RO) Level 2 cache present bitmap, high word */

#define STACK_PRESENT_LO        0xE00   /* (RO) Core stack present bitmap, low word */
#define STACK_PRESENT_HI        0xE04   /* (RO) Core stack present bitmap, high word */


#define SHADER_READY_LO         0x140	/* (RO) Shader core ready bitmap, low word */
#define SHADER_READY_HI         0x144	/* (RO) Shader core ready bitmap, high word */

#define TILER_READY_LO          0x150	/* (RO) Tiler core ready bitmap, low word */
#define TILER_READY_HI          0x154	/* (RO) Tiler core ready bitmap, high word */

#define L2_READY_LO             0x160	/* (RO) Level 2 cache ready bitmap, low word */
#define L2_READY_HI             0x164	/* (RO) Level 2 cache ready bitmap, high word */

#define STACK_READY_LO          0xE10   /* (RO) Core stack ready bitmap, low word */
#define STACK_READY_HI          0xE14   /* (RO) Core stack ready bitmap, high word */


#define SHADER_PWRON_LO         0x180	/* (WO) Shader core power on bitmap, low word */
#define SHADER_PWRON_HI         0x184	/* (WO) Shader core power on bitmap, high word */

#define TILER_PWRON_LO          0x190	/* (WO) Tiler core power on bitmap, low word */
#define TILER_PWRON_HI          0x194	/* (WO) Tiler core power on bitmap, high word */

#define L2_PWRON_LO             0x1A0	/* (WO) Level 2 cache power on bitmap, low word */
#define L2_PWRON_HI             0x1A4	/* (WO) Level 2 cache power on bitmap, high word */

#define STACK_PWRON_LO          0xE20   /* (RO) Core stack power on bitmap, low word */
#define STACK_PWRON_HI          0xE24   /* (RO) Core stack power on bitmap, high word */


#define SHADER_PWROFF_LO        0x1C0	/* (WO) Shader core power off bitmap, low word */
#define SHADER_PWROFF_HI        0x1C4	/* (WO) Shader core power off bitmap, high word */

#define TILER_PWROFF_LO         0x1D0	/* (WO) Tiler core power off bitmap, low word */
#define TILER_PWROFF_HI         0x1D4	/* (WO) Tiler core power off bitmap, high word */

#define L2_PWROFF_LO            0x1E0	/* (WO) Level 2 cache power off bitmap, low word */
#define L2_PWROFF_HI            0x1E4	/* (WO) Level 2 cache power off bitmap, high word */

#define STACK_PWROFF_LO         0xE30   /* (RO) Core stack power off bitmap, low word */
#define STACK_PWROFF_HI         0xE34   /* (RO) Core stack power off bitmap, high word */


#define SHADER_PWRTRANS_LO      0x200	/* (RO) Shader core power transition bitmap, low word */
#define SHADER_PWRTRANS_HI      0x204	/* (RO) Shader core power transition bitmap, high word */

#define TILER_PWRTRANS_LO       0x210	/* (RO) Tiler core power transition bitmap, low word */
#define TILER_PWRTRANS_HI       0x214	/* (RO) Tiler core power transition bitmap, high word */

#define L2_PWRTRANS_LO          0x220	/* (RO) Level 2 cache power transition bitmap, low word */
#define L2_PWRTRANS_HI          0x224	/* (RO) Level 2 cache power transition bitmap, high word */

#define STACK_PWRTRANS_LO       0xE40   /* (RO) Core stack power transition bitmap, low word */
#define STACK_PWRTRANS_HI       0xE44   /* (RO) Core stack power transition bitmap, high word */


#define SHADER_PWRACTIVE_LO     0x240	/* (RO) Shader core active bitmap, low word */
#define SHADER_PWRACTIVE_HI     0x244	/* (RO) Shader core active bitmap, high word */

#define TILER_PWRACTIVE_LO      0x250	/* (RO) Tiler core active bitmap, low word */
#define TILER_PWRACTIVE_HI      0x254	/* (RO) Tiler core active bitmap, high word */

#define L2_PWRACTIVE_LO         0x260	/* (RO) Level 2 cache active bitmap, low word */
#define L2_PWRACTIVE_HI         0x264	/* (RO) Level 2 cache active bitmap, high word */

#define COHERENCY_FEATURES      0x300	/* (RO) Coherency features present */
#define COHERENCY_ENABLE        0x304	/* (RW) Coherency enable */

#define JM_CONFIG               0xF00   /* (RW) Job Manager configuration register (Implementation specific register) */
#define SHADER_CONFIG           0xF04	/* (RW) Shader core configuration settings (Implementation specific register) */
#define TILER_CONFIG            0xF08   /* (RW) Tiler core configuration settings (Implementation specific register) */
#define L2_MMU_CONFIG           0xF0C	/* (RW) Configuration of the L2 cache and MMU (Implementation specific register) */

#define JOB_CONTROL_BASE        (GPU_PHYS_BASE + 0x1000)

#define JOB_CONTROL_REG(r)      (JOB_CONTROL_BASE + (r))

#define JOB_IRQ_RAWSTAT         0x000	/* Raw interrupt status register */
#define JOB_IRQ_CLEAR           0x004	/* Interrupt clear register */
#define JOB_IRQ_MASK            0x008	/* Interrupt mask register */
#define JOB_IRQ_STATUS          0x00C	/* Interrupt status register */
#define JOB_IRQ_JS_STATE        0x010	/* status==active and _next == busy snapshot from last JOB_IRQ_CLEAR */
#define JOB_IRQ_THROTTLE        0x014	/* cycles to delay delivering an interrupt externally. The JOB_IRQ_STATUS is NOT affected by this, just the delivery of the interrupt.  */

/* JOB IRQ flags */
#define JOB_IRQ_GLOBAL_IF       (1 << 31)   /* Global interface interrupt received */

#define JOB_SLOT0               0x800	/* Configuration registers for job slot 0 */
#define JOB_SLOT1               0x880	/* Configuration registers for job slot 1 */
#define JOB_SLOT2               0x900	/* Configuration registers for job slot 2 */
#define JOB_SLOT3               0x980	/* Configuration registers for job slot 3 */
#define JOB_SLOT4               0xA00	/* Configuration registers for job slot 4 */
#define JOB_SLOT5               0xA80	/* Configuration registers for job slot 5 */
#define JOB_SLOT6               0xB00	/* Configuration registers for job slot 6 */
#define JOB_SLOT7               0xB80	/* Configuration registers for job slot 7 */
#define JOB_SLOT8               0xC00	/* Configuration registers for job slot 8 */
#define JOB_SLOT9               0xC80	/* Configuration registers for job slot 9 */
#define JOB_SLOT10              0xD00	/* Configuration registers for job slot 10 */
#define JOB_SLOT11              0xD80	/* Configuration registers for job slot 11 */
#define JOB_SLOT12              0xE00	/* Configuration registers for job slot 12 */
#define JOB_SLOT13              0xE80	/* Configuration registers for job slot 13 */
#define JOB_SLOT14              0xF00	/* Configuration registers for job slot 14 */
#define JOB_SLOT15              0xF80	/* Configuration registers for job slot 15 */

#define JOB_SLOT_REG(n, r)      (JOB_CONTROL_REG(JOB_SLOT0 + ((n) << 7)) + (r))

#define JS_HEAD_LO             0x00	/* (RO) Job queue head pointer for job slot n, low word */
#define JS_HEAD_HI             0x04	/* (RO) Job queue head pointer for job slot n, high word */
#define JS_TAIL_LO             0x08	/* (RO) Job queue tail pointer for job slot n, low word */
#define JS_TAIL_HI             0x0C	/* (RO) Job queue tail pointer for job slot n, high word */
#define JS_AFFINITY_LO         0x10	/* (RO) Core affinity mask for job slot n, low word */
#define JS_AFFINITY_HI         0x14	/* (RO) Core affinity mask for job slot n, high word */
#define JS_CONFIG              0x18	/* (RO) Configuration settings for job slot n */
#define JS_XAFFINITY           0x1C	/* (RO) Extended affinity mask for job
					   slot n */

#define JS_COMMAND             0x20	/* (WO) Command register for job slot n */
#define JS_STATUS              0x24	/* (RO) Status register for job slot n */

#define JS_HEAD_NEXT_LO        0x40	/* (RW) Next job queue head pointer for job slot n, low word */
#define JS_HEAD_NEXT_HI        0x44	/* (RW) Next job queue head pointer for job slot n, high word */

#define JS_AFFINITY_NEXT_LO    0x50	/* (RW) Next core affinity mask for job slot n, low word */
#define JS_AFFINITY_NEXT_HI    0x54	/* (RW) Next core affinity mask for job slot n, high word */
#define JS_CONFIG_NEXT         0x58	/* (RW) Next configuration settings for job slot n */
#define JS_XAFFINITY_NEXT      0x5C	/* (RW) Next extended affinity mask for
					   job slot n */

#define JS_COMMAND_NEXT        0x60	/* (RW) Next command register for job slot n */

#define JS_FLUSH_ID_NEXT       0x70	/* (RW) Next job slot n cache flush ID */

#define MEMORY_MANAGEMENT_BASE  (GPU_PHYS_BASE + 0x2000)
#define MMU_REG(r)              (MEMORY_MANAGEMENT_BASE + (r))

#define MMU_IRQ_RAWSTAT         0x000	/* (RW) Raw interrupt status register */
#define MMU_IRQ_CLEAR           0x004	/* (WO) Interrupt clear register */
#define MMU_IRQ_MASK            0x008	/* (RW) Interrupt mask register */
#define MMU_IRQ_STATUS          0x00C	/* (RO) Interrupt status register */

#define MMU_AS0                 0x400	/* Configuration registers for address space 0 */
#define MMU_AS1                 0x440	/* Configuration registers for address space 1 */
#define MMU_AS2                 0x480	/* Configuration registers for address space 2 */
#define MMU_AS3                 0x4C0	/* Configuration registers for address space 3 */
#define MMU_AS4                 0x500	/* Configuration registers for address space 4 */
#define MMU_AS5                 0x540	/* Configuration registers for address space 5 */
#define MMU_AS6                 0x580	/* Configuration registers for address space 6 */
#define MMU_AS7                 0x5C0	/* Configuration registers for address space 7 */
#define MMU_AS8                 0x600	/* Configuration registers for address space 8 */
#define MMU_AS9                 0x640	/* Configuration registers for address space 9 */
#define MMU_AS10                0x680	/* Configuration registers for address space 10 */
#define MMU_AS11                0x6C0	/* Configuration registers for address space 11 */
#define MMU_AS12                0x700	/* Configuration registers for address space 12 */
#define MMU_AS13                0x740	/* Configuration registers for address space 13 */
#define MMU_AS14                0x780	/* Configuration registers for address space 14 */
#define MMU_AS15                0x7C0	/* Configuration registers for address space 15 */

#define MMU_AS_REG(n, r)        (MMU_REG(MMU_AS0 + ((n) << 6)) + (r))

#define AS_TRANSTAB_LO         0x00	/* (RW) Translation Table Base Address for address space n, low word */
#define AS_TRANSTAB_HI         0x04	/* (RW) Translation Table Base Address for address space n, high word */
#define AS_MEMATTR_LO          0x08	/* (RW) Memory attributes for address space n, low word. */
#define AS_MEMATTR_HI          0x0C	/* (RW) Memory attributes for address space n, high word. */
#define AS_LOCKADDR_LO         0x10	/* (RW) Lock region address for address space n, low word */
#define AS_LOCKADDR_HI         0x14	/* (RW) Lock region address for address space n, high word */
#define AS_COMMAND             0x18	/* (WO) MMU command register for address space n */
#define AS_FAULTSTATUS         0x1C	/* (RO) MMU fault status register for address space n */
#define AS_FAULTADDRESS_LO     0x20	/* (RO) Fault Address for address space n, low word */
#define AS_FAULTADDRESS_HI     0x24	/* (RO) Fault Address for address space n, high word */
#define AS_STATUS              0x28	/* (RO) Status flags for address space n */


/* (RW) Translation table configuration for address space n, low word */
#define AS_TRANSCFG_LO         0x30
/* (RW) Translation table configuration for address space n, high word */
#define AS_TRANSCFG_HI         0x34
/* (RO) Secondary fault address for address space n, low word */
#define AS_FAULTEXTRA_LO       0x38
/* (RO) Secondary fault address for address space n, high word */
#define AS_FAULTEXTRA_HI       0x3C

/* End Register Offsets */

/*
 * MMU_IRQ_RAWSTAT register values. Values are valid also for
   MMU_IRQ_CLEAR, MMU_IRQ_MASK, MMU_IRQ_STATUS registers.
 */

#define MMU_PAGE_FAULT_FLAGS   16

/* Macros returning a bitmask to retrieve page fault or bus error flags from
 * MMU registers */
#define MMU_PAGE_FAULT(n)      (1UL << (n))
#define MMU_BUS_ERROR(n)       (1UL << ((n) + MMU_PAGE_FAULT_FLAGS))

/*
 * Begin LPAE MMU TRANSTAB register values
 */
#define AS_TRANSTAB_LPAE_ADDR_SPACE_MASK   0xfffff000
#define AS_TRANSTAB_LPAE_ADRMODE_UNMAPPED  (0u << 0)
#define AS_TRANSTAB_LPAE_ADRMODE_IDENTITY  (1u << 1)
#define AS_TRANSTAB_LPAE_ADRMODE_TABLE     (3u << 0)
#define AS_TRANSTAB_LPAE_READ_INNER        (1u << 2)
#define AS_TRANSTAB_LPAE_SHARE_OUTER       (1u << 4)

#define AS_TRANSTAB_LPAE_ADRMODE_MASK      0x00000003

/*
 * Begin AARCH64 MMU TRANSTAB register values
 */
#define MMU_HW_OUTA_BITS 40
#define AS_TRANSTAB_BASE_MASK ((1ULL << MMU_HW_OUTA_BITS) - (1ULL << 4))

/*
 * Begin MMU STATUS register values
 */
#define AS_STATUS_AS_ACTIVE 0x01

#define AS_FAULTSTATUS_EXCEPTION_CODE_MASK                    (0x7<<3)
#define AS_FAULTSTATUS_EXCEPTION_CODE_TRANSLATION_FAULT       (0x0<<3)
#define AS_FAULTSTATUS_EXCEPTION_CODE_PERMISSION_FAULT        (0x1<<3)
#define AS_FAULTSTATUS_EXCEPTION_CODE_TRANSTAB_BUS_FAULT      (0x2<<3)
#define AS_FAULTSTATUS_EXCEPTION_CODE_ACCESS_FLAG             (0x3<<3)

#define AS_FAULTSTATUS_EXCEPTION_CODE_ADDRESS_SIZE_FAULT      (0x4<<3)
#define AS_FAULTSTATUS_EXCEPTION_CODE_MEMORY_ATTRIBUTES_FAULT (0x5<<3)

#define AS_FAULTSTATUS_ACCESS_TYPE_MASK                  (0x3<<8)
#define AS_FAULTSTATUS_ACCESS_TYPE_ATOMIC                (0x0<<8)
#define AS_FAULTSTATUS_ACCESS_TYPE_EX                    (0x1<<8)
#define AS_FAULTSTATUS_ACCESS_TYPE_READ                  (0x2<<8)
#define AS_FAULTSTATUS_ACCESS_TYPE_WRITE                 (0x3<<8)

/*
 * Begin MMU TRANSCFG register values
 */

#define AS_TRANSCFG_ADRMODE_LEGACY      0
#define AS_TRANSCFG_ADRMODE_UNMAPPED    1
#define AS_TRANSCFG_ADRMODE_IDENTITY    2
#define AS_TRANSCFG_ADRMODE_AARCH64_4K  6
#define AS_TRANSCFG_ADRMODE_AARCH64_64K 8

#define AS_TRANSCFG_ADRMODE_MASK        0xF


/*
 * Begin TRANSCFG register values
 */
#define AS_TRANSCFG_PTW_MEMATTR_MASK (3ull << 24)
#define AS_TRANSCFG_PTW_MEMATTR_NON_CACHEABLE (1ull << 24)
#define AS_TRANSCFG_PTW_MEMATTR_WRITE_BACK (2ull << 24)

#define AS_TRANSCFG_PTW_SH_MASK ((3ull << 28))
#define AS_TRANSCFG_PTW_SH_OS (2ull << 28)
#define AS_TRANSCFG_PTW_SH_IS (3ull << 28)
#define AS_TRANSCFG_R_ALLOCATE (1ull << 30)
/*
 * Begin Command Values
 */

/* JS_COMMAND register commands */
#define JS_COMMAND_NOP         0x00	/* NOP Operation. Writing this value is ignored */
#define JS_COMMAND_START       0x01	/* Start processing a job chain. Writing this value is ignored */
#define JS_COMMAND_SOFT_STOP   0x02	/* Gently stop processing a job chain */
#define JS_COMMAND_HARD_STOP   0x03	/* Rudely stop processing a job chain */
#define JS_COMMAND_SOFT_STOP_0 0x04	/* Execute SOFT_STOP if JOB_CHAIN_FLAG is 0 */
#define JS_COMMAND_HARD_STOP_0 0x05	/* Execute HARD_STOP if JOB_CHAIN_FLAG is 0 */
#define JS_COMMAND_SOFT_STOP_1 0x06	/* Execute SOFT_STOP if JOB_CHAIN_FLAG is 1 */
#define JS_COMMAND_HARD_STOP_1 0x07	/* Execute HARD_STOP if JOB_CHAIN_FLAG is 1 */

#define JS_COMMAND_MASK        0x07    /* Mask of bits currently in use by the HW */

/* AS_COMMAND register commands */
#define AS_COMMAND_NOP         0x00	/* NOP Operation */
#define AS_COMMAND_UPDATE      0x01	/* Broadcasts the values in AS_TRANSTAB and ASn_MEMATTR to all MMUs */
#define AS_COMMAND_LOCK        0x02	/* Issue a lock region command to all MMUs */
#define AS_COMMAND_UNLOCK      0x03	/* Issue a flush region command to all MMUs */
#define AS_COMMAND_FLUSH       0x04	/* Flush all L2 caches then issue a flush region command to all MMUs
					   (deprecated - only for use with T60x) */
#define AS_COMMAND_FLUSH_PT    0x04	/* Flush all L2 caches then issue a flush region command to all MMUs */
#define AS_COMMAND_FLUSH_MEM   0x05	/* Wait for memory accesses to complete, flush all the L1s cache then
					   flush all L2 caches then issue a flush region command to all MMUs */

/* Possible values of JS_CONFIG and JS_CONFIG_NEXT registers */
#define JS_CONFIG_START_FLUSH_NO_ACTION        (0u << 0)
#define JS_CONFIG_START_FLUSH_CLEAN            (1u << 8)
#define JS_CONFIG_START_FLUSH_CLEAN_INVALIDATE (3u << 8)
#define JS_CONFIG_START_MMU                    (1u << 10)
#define JS_CONFIG_JOB_CHAIN_FLAG               (1u << 11)
#define JS_CONFIG_END_FLUSH_NO_ACTION          JS_CONFIG_START_FLUSH_NO_ACTION
#define JS_CONFIG_END_FLUSH_CLEAN              (1u << 12)
#define JS_CONFIG_END_FLUSH_CLEAN_INVALIDATE   (3u << 12)
#define JS_CONFIG_ENABLE_FLUSH_REDUCTION       (1u << 14)
#define JS_CONFIG_DISABLE_DESCRIPTOR_WR_BK     (1u << 15)
#define JS_CONFIG_THREAD_PRI(n)                ((n) << 16)

/* JS_XAFFINITY register values */
#define JS_XAFFINITY_XAFFINITY_ENABLE (1u << 0)
#define JS_XAFFINITY_TILER_ENABLE     (1u << 8)
#define JS_XAFFINITY_CACHE_ENABLE     (1u << 16)

/* JS_STATUS register values */

/* NOTE: Please keep this values in sync with enum base_jd_event_code in mali_base_kernel.h.
 * The values are separated to avoid dependency of userspace and kernel code.
 */

/* Group of values representing the job status insead a particular fault */
#define JS_STATUS_NO_EXCEPTION_BASE   0x00
#define JS_STATUS_INTERRUPTED         (JS_STATUS_NO_EXCEPTION_BASE + 0x02)	/* 0x02 means INTERRUPTED */
#define JS_STATUS_STOPPED             (JS_STATUS_NO_EXCEPTION_BASE + 0x03)	/* 0x03 means STOPPED */
#define JS_STATUS_TERMINATED          (JS_STATUS_NO_EXCEPTION_BASE + 0x04)	/* 0x04 means TERMINATED */

/* General fault values */
#define JS_STATUS_FAULT_BASE          0x40
#define JS_STATUS_CONFIG_FAULT        (JS_STATUS_FAULT_BASE)	/* 0x40 means CONFIG FAULT */
#define JS_STATUS_POWER_FAULT         (JS_STATUS_FAULT_BASE + 0x01)	/* 0x41 means POWER FAULT */
#define JS_STATUS_READ_FAULT          (JS_STATUS_FAULT_BASE + 0x02)	/* 0x42 means READ FAULT */
#define JS_STATUS_WRITE_FAULT         (JS_STATUS_FAULT_BASE + 0x03)	/* 0x43 means WRITE FAULT */
#define JS_STATUS_AFFINITY_FAULT      (JS_STATUS_FAULT_BASE + 0x04)	/* 0x44 means AFFINITY FAULT */
#define JS_STATUS_BUS_FAULT           (JS_STATUS_FAULT_BASE + 0x08)	/* 0x48 means BUS FAULT */

/* Instruction or data faults */
#define JS_STATUS_INSTRUCTION_FAULT_BASE  0x50
#define JS_STATUS_INSTR_INVALID_PC        (JS_STATUS_INSTRUCTION_FAULT_BASE)	/* 0x50 means INSTR INVALID PC */
#define JS_STATUS_INSTR_INVALID_ENC       (JS_STATUS_INSTRUCTION_FAULT_BASE + 0x01)	/* 0x51 means INSTR INVALID ENC */
#define JS_STATUS_INSTR_TYPE_MISMATCH     (JS_STATUS_INSTRUCTION_FAULT_BASE + 0x02)	/* 0x52 means INSTR TYPE MISMATCH */
#define JS_STATUS_INSTR_OPERAND_FAULT     (JS_STATUS_INSTRUCTION_FAULT_BASE + 0x03)	/* 0x53 means INSTR OPERAND FAULT */
#define JS_STATUS_INSTR_TLS_FAULT         (JS_STATUS_INSTRUCTION_FAULT_BASE + 0x04)	/* 0x54 means INSTR TLS FAULT */
#define JS_STATUS_INSTR_BARRIER_FAULT     (JS_STATUS_INSTRUCTION_FAULT_BASE + 0x05)	/* 0x55 means INSTR BARRIER FAULT */
#define JS_STATUS_INSTR_ALIGN_FAULT       (JS_STATUS_INSTRUCTION_FAULT_BASE + 0x06)	/* 0x56 means INSTR ALIGN FAULT */
/* NOTE: No fault with 0x57 code defined in spec. */
#define JS_STATUS_DATA_INVALID_FAULT      (JS_STATUS_INSTRUCTION_FAULT_BASE + 0x08)	/* 0x58 means DATA INVALID FAULT */
#define JS_STATUS_TILE_RANGE_FAULT        (JS_STATUS_INSTRUCTION_FAULT_BASE + 0x09)	/* 0x59 means TILE RANGE FAULT */
#define JS_STATUS_ADDRESS_RANGE_FAULT     (JS_STATUS_INSTRUCTION_FAULT_BASE + 0x0A)	/* 0x5A means ADDRESS RANGE FAULT */

/* Other faults */
#define JS_STATUS_MEMORY_FAULT_BASE   0x60
#define JS_STATUS_OUT_OF_MEMORY       (JS_STATUS_MEMORY_FAULT_BASE)	/* 0x60 means OUT OF MEMORY */
#define JS_STATUS_UNKNOWN             0x7F	/* 0x7F means UNKNOWN */

/* GPU_COMMAND values */
#define GPU_COMMAND_NOP                0x00	/* No operation, nothing happens */
#define GPU_COMMAND_SOFT_RESET         0x01	/* Stop all external bus interfaces, and then reset the entire GPU. */
#define GPU_COMMAND_HARD_RESET         0x02	/* Immediately reset the entire GPU. */
#define GPU_COMMAND_PRFCNT_CLEAR       0x03	/* Clear all performance counters, setting them all to zero. */
#define GPU_COMMAND_PRFCNT_SAMPLE      0x04	/* Sample all performance counters, writing them out to memory */
#define GPU_COMMAND_CYCLE_COUNT_START  0x05	/* Starts the cycle counter, and system timestamp propagation */
#define GPU_COMMAND_CYCLE_COUNT_STOP   0x06	/* Stops the cycle counter, and system timestamp propagation */
#define GPU_COMMAND_CLEAN_CACHES       0x07	/* Clean all caches */
#define GPU_COMMAND_CLEAN_INV_CACHES   0x08	/* Clean and invalidate all caches */
#define GPU_COMMAND_SET_PROTECTED_MODE 0x09	/* Places the GPU in protected mode */

/* End Command Values */

/* GPU_STATUS values */
#define GPU_STATUS_PRFCNT_ACTIVE           (1 << 2)	/* Set if the performance counters are active. */
#define GPU_STATUS_PROTECTED_MODE_ACTIVE   (1 << 7)	/* Set if protected mode is active */

/* PRFCNT_CONFIG register values */
#define PRFCNT_CONFIG_MODE_SHIFT      0 /* Counter mode position. */
#define PRFCNT_CONFIG_AS_SHIFT        4 /* Address space bitmap position. */
#define PRFCNT_CONFIG_SETSELECT_SHIFT 8 /* Set select position. */

#define PRFCNT_CONFIG_MODE_OFF    0	/* The performance counters are disabled. */
#define PRFCNT_CONFIG_MODE_MANUAL 1	/* The performance counters are enabled, but are only written out when a PRFCNT_SAMPLE command is issued using the GPU_COMMAND register. */
#define PRFCNT_CONFIG_MODE_TILE   2	/* The performance counters are enabled, and are written out each time a tile finishes rendering. */

/* AS<n>_MEMATTR values from MMU_MEMATTR_STAGE1: */
/* Use GPU implementation-defined caching policy. */
#define AS_MEMATTR_IMPL_DEF_CACHE_POLICY 0x88ull
/* The attribute set to force all resources to be cached. */
#define AS_MEMATTR_FORCE_TO_CACHE_ALL    0x8Full
/* Inner write-alloc cache setup, no outer caching */
#define AS_MEMATTR_WRITE_ALLOC           0x8Dull

/* Set to implementation defined, outer caching */
#define AS_MEMATTR_AARCH64_OUTER_IMPL_DEF 0x88ull
/* Set to write back memory, outer caching */
#define AS_MEMATTR_AARCH64_OUTER_WA       0x8Dull
/* Set to inner non-cacheable, outer-non-cacheable
 * Setting defined by the alloc bits is ignored, but set to a valid encoding:
 * - no-alloc on read
 * - no alloc on write
 */
#define AS_MEMATTR_AARCH64_NON_CACHEABLE  0x4Cull

/* Use GPU implementation-defined  caching policy. */
#define AS_MEMATTR_LPAE_IMPL_DEF_CACHE_POLICY 0x48ull
/* The attribute set to force all resources to be cached. */
#define AS_MEMATTR_LPAE_FORCE_TO_CACHE_ALL    0x4Full
/* Inner write-alloc cache setup, no outer caching */
#define AS_MEMATTR_LPAE_WRITE_ALLOC           0x4Dull
/* Set to implementation defined, outer caching */
#define AS_MEMATTR_LPAE_OUTER_IMPL_DEF        0x88ull
/* Set to write back memory, outer caching */
#define AS_MEMATTR_LPAE_OUTER_WA              0x8Dull
/* There is no LPAE support for non-cacheable, since the memory type is always
 * write-back.
 * Marking this setting as reserved for LPAE
 */
#define AS_MEMATTR_LPAE_NON_CACHEABLE_RESERVED

/* Symbols for default MEMATTR to use
 * Default is - HW implementation defined caching */
#define AS_MEMATTR_INDEX_DEFAULT               0
#define AS_MEMATTR_INDEX_DEFAULT_ACE           3

/* HW implementation defined caching */
#define AS_MEMATTR_INDEX_IMPL_DEF_CACHE_POLICY 0
/* Force cache on */
#define AS_MEMATTR_INDEX_FORCE_TO_CACHE_ALL    1
/* Write-alloc */
#define AS_MEMATTR_INDEX_WRITE_ALLOC           2
/* Outer coherent, inner implementation defined policy */
#define AS_MEMATTR_INDEX_OUTER_IMPL_DEF        3
/* Outer coherent, write alloc inner */
#define AS_MEMATTR_INDEX_OUTER_WA              4
/* Normal memory, inner non-cacheable, outer non-cacheable (ARMv8 mode only) */
#define AS_MEMATTR_INDEX_NON_CACHEABLE         5

/* JS<n>_FEATURES register */

#define JS_FEATURE_NULL_JOB              (1u << 1)
#define JS_FEATURE_SET_VALUE_JOB         (1u << 2)
#define JS_FEATURE_CACHE_FLUSH_JOB       (1u << 3)
#define JS_FEATURE_COMPUTE_JOB           (1u << 4)
#define JS_FEATURE_VERTEX_JOB            (1u << 5)
#define JS_FEATURE_GEOMETRY_JOB          (1u << 6)
#define JS_FEATURE_TILER_JOB             (1u << 7)
#define JS_FEATURE_FUSED_JOB             (1u << 8)
#define JS_FEATURE_FRAGMENT_JOB          (1u << 9)

/* End JS<n>_FEATURES register */

/* L2_MMU_CONFIG register */
#define L2_MMU_CONFIG_ALLOW_SNOOP_DISPARITY_SHIFT       (23)
#define L2_MMU_CONFIG_ALLOW_SNOOP_DISPARITY             (0x1 << L2_MMU_CONFIG_ALLOW_SNOOP_DISPARITY_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT        (24)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_READS              (0x3 << L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_OCTANT       (0x1 << L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_QUARTER      (0x2 << L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_HALF         (0x3 << L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT)

#define L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT       (26)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES             (0x3 << L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_OCTANT      (0x1 << L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_QUARTER     (0x2 << L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_HALF        (0x3 << L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT)

#define L2_MMU_CONFIG_3BIT_LIMIT_EXTERNAL_READS_SHIFT      (12)
#define L2_MMU_CONFIG_3BIT_LIMIT_EXTERNAL_READS            (0x7 << L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT)

#define L2_MMU_CONFIG_3BIT_LIMIT_EXTERNAL_WRITES_SHIFT     (15)
#define L2_MMU_CONFIG_3BIT_LIMIT_EXTERNAL_WRITES           (0x7 << L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT)

/* End L2_MMU_CONFIG register */

/* THREAD_* registers */

/* THREAD_FEATURES IMPLEMENTATION_TECHNOLOGY values */
#define IMPLEMENTATION_UNSPECIFIED  0
#define IMPLEMENTATION_SILICON      1
#define IMPLEMENTATION_FPGA         2
#define IMPLEMENTATION_MODEL        3

/* Default values when registers are not supported by the implemented hardware */
#define THREAD_MT_DEFAULT     256
#define THREAD_MWS_DEFAULT    256
#define THREAD_MBS_DEFAULT    256
#define THREAD_MR_DEFAULT     1024
#define THREAD_MTQ_DEFAULT    4
#define THREAD_MTGS_DEFAULT   10

/* End THREAD_* registers */

/* SHADER_CONFIG register */

#define SC_ALT_COUNTERS             (1ul << 3)
#define SC_OVERRIDE_FWD_PIXEL_KILL  (1ul << 4)
#define SC_SDC_DISABLE_OQ_DISCARD   (1ul << 6)
#define SC_LS_ALLOW_ATTR_TYPES      (1ul << 16)
#define SC_LS_PAUSEBUFFER_DISABLE   (1ul << 16)
#define SC_TLS_HASH_ENABLE          (1ul << 17)
#define SC_LS_ATTR_CHECK_DISABLE    (1ul << 18)
#define SC_ENABLE_TEXGRD_FLAGS      (1ul << 25)
/* End SHADER_CONFIG register */

/* TILER_CONFIG register */

#define TC_CLOCK_GATE_OVERRIDE      (1ul << 0)

/* End TILER_CONFIG register */

/* JM_CONFIG register */

#define JM_TIMESTAMP_OVERRIDE  (1ul << 0)
#define JM_CLOCK_GATE_OVERRIDE (1ul << 1)
#define JM_JOB_THROTTLE_ENABLE (1ul << 2)
#define JM_JOB_THROTTLE_LIMIT_SHIFT (3)
#define JM_MAX_JOB_THROTTLE_LIMIT (0x3F)
#define JM_FORCE_COHERENCY_FEATURES_SHIFT (2)
#define JM_IDVS_GROUP_SIZE_SHIFT (16)
#define JM_MAX_IDVS_GROUP_SIZE (0x3F)
/* End JM_CONFIG register */


/* GPU_ID register */
#define GPU_ID_VERSION_STATUS_SHIFT       0
#define GPU_ID_VERSION_MINOR_SHIFT        4
#define GPU_ID_VERSION_MAJOR_SHIFT        12
#define GPU_ID_VERSION_PRODUCT_ID_SHIFT   16
#define GPU_ID_VERSION_STATUS             (0xFu  << GPU_ID_VERSION_STATUS_SHIFT)
#define GPU_ID_VERSION_MINOR              (0xFFu << GPU_ID_VERSION_MINOR_SHIFT)
#define GPU_ID_VERSION_MAJOR              (0xFu  << GPU_ID_VERSION_MAJOR_SHIFT)
#define GPU_ID_VERSION_PRODUCT_ID  (0xFFFFu << GPU_ID_VERSION_PRODUCT_ID_SHIFT)

/* Values for GPU_ID_VERSION_PRODUCT_ID bitfield */
#define GPU_ID_PI_T60X                    0x6956u
#define GPU_ID_PI_T62X                    0x0620u
#define GPU_ID_PI_T76X                    0x0750u
#define GPU_ID_PI_T72X                    0x0720u
#define GPU_ID_PI_TFRX                    0x0880u
#define GPU_ID_PI_T86X                    0x0860u
#define GPU_ID_PI_T82X                    0x0820u
#define GPU_ID_PI_T83X                    0x0830u

/* New GPU ID format when PRODUCT_ID is >= 0x1000 (and not 0x6956) */
#define GPU_ID_PI_NEW_FORMAT_START        0x1000
#define GPU_ID_IS_NEW_FORMAT(product_id)  ((product_id) != GPU_ID_PI_T60X && \
						(product_id) >= \
						GPU_ID_PI_NEW_FORMAT_START)

#define GPU_ID2_VERSION_STATUS_SHIFT      0
#define GPU_ID2_VERSION_MINOR_SHIFT       4
#define GPU_ID2_VERSION_MAJOR_SHIFT       12
#define GPU_ID2_PRODUCT_MAJOR_SHIFT       16
#define GPU_ID2_ARCH_REV_SHIFT            20
#define GPU_ID2_ARCH_MINOR_SHIFT          24
#define GPU_ID2_ARCH_MAJOR_SHIFT          28
#define GPU_ID2_VERSION_STATUS            (0xFu << GPU_ID2_VERSION_STATUS_SHIFT)
#define GPU_ID2_VERSION_MINOR             (0xFFu << GPU_ID2_VERSION_MINOR_SHIFT)
#define GPU_ID2_VERSION_MAJOR             (0xFu << GPU_ID2_VERSION_MAJOR_SHIFT)
#define GPU_ID2_PRODUCT_MAJOR             (0xFu << GPU_ID2_PRODUCT_MAJOR_SHIFT)
#define GPU_ID2_ARCH_REV                  (0xFu << GPU_ID2_ARCH_REV_SHIFT)
#define GPU_ID2_ARCH_MINOR                (0xFu << GPU_ID2_ARCH_MINOR_SHIFT)
#define GPU_ID2_ARCH_MAJOR                (0xFu << GPU_ID2_ARCH_MAJOR_SHIFT)
#define GPU_ID2_PRODUCT_MODEL  (GPU_ID2_ARCH_MAJOR | GPU_ID2_PRODUCT_MAJOR)
#define GPU_ID2_VERSION        (GPU_ID2_VERSION_MAJOR | \
								GPU_ID2_VERSION_MINOR | \
								GPU_ID2_VERSION_STATUS)

/* Helper macro to create a partial GPU_ID (new format) that defines
   a product ignoring its version. */
#define GPU_ID2_PRODUCT_MAKE(arch_major, arch_minor, arch_rev, product_major) \
		((((u32)arch_major) << GPU_ID2_ARCH_MAJOR_SHIFT)  | \
		 (((u32)arch_minor) << GPU_ID2_ARCH_MINOR_SHIFT)  | \
		 (((u32)arch_rev) << GPU_ID2_ARCH_REV_SHIFT)      | \
		 (((u32)product_major) << GPU_ID2_PRODUCT_MAJOR_SHIFT))

/* Helper macro to create a partial GPU_ID (new format) that specifies the
   revision (major, minor, status) of a product */
#define GPU_ID2_VERSION_MAKE(version_major, version_minor, version_status) \
		((((u32)version_major) << GPU_ID2_VERSION_MAJOR_SHIFT)  | \
		 (((u32)version_minor) << GPU_ID2_VERSION_MINOR_SHIFT)  | \
		 (((u32)version_status) << GPU_ID2_VERSION_STATUS_SHIFT))

/* Helper macro to create a complete GPU_ID (new format) */
#define GPU_ID2_MAKE(arch_major, arch_minor, arch_rev, product_major, \
	version_major, version_minor, version_status) \
		(GPU_ID2_PRODUCT_MAKE(arch_major, arch_minor, arch_rev, \
			product_major) | \
		 GPU_ID2_VERSION_MAKE(version_major, version_minor,     \
			version_status))

/* Helper macro to create a partial GPU_ID (new format) that identifies
   a particular GPU model by its arch_major and product_major. */
#define GPU_ID2_MODEL_MAKE(arch_major, product_major) \
		((((u32)arch_major) << GPU_ID2_ARCH_MAJOR_SHIFT)  | \
		(((u32)product_major) << GPU_ID2_PRODUCT_MAJOR_SHIFT))

/* Strip off the non-relevant bits from a product_id value and make it suitable
   for comparison against the GPU_ID2_PRODUCT_xxx values which identify a GPU
   model. */
#define GPU_ID2_MODEL_MATCH_VALUE(product_id) \
		((((u32)product_id) << GPU_ID2_PRODUCT_MAJOR_SHIFT) & \
		    GPU_ID2_PRODUCT_MODEL)

#define GPU_ID2_PRODUCT_TMIX              GPU_ID2_MODEL_MAKE(6, 0)
#define GPU_ID2_PRODUCT_THEX              GPU_ID2_MODEL_MAKE(6, 1)
#define GPU_ID2_PRODUCT_TSIX              GPU_ID2_MODEL_MAKE(7, 0)
#define GPU_ID2_PRODUCT_TDVX              GPU_ID2_MODEL_MAKE(7, 3)
#define GPU_ID2_PRODUCT_TNOX              GPU_ID2_MODEL_MAKE(7, 1)
#define GPU_ID2_PRODUCT_TGOX              GPU_ID2_MODEL_MAKE(7, 2)
#define GPU_ID2_PRODUCT_TKAX              GPU_ID2_MODEL_MAKE(8, 0)
#define GPU_ID2_PRODUCT_TBOX              GPU_ID2_MODEL_MAKE(8, 2)
#define GPU_ID2_PRODUCT_TEGX              GPU_ID2_MODEL_MAKE(8, 3)
#define GPU_ID2_PRODUCT_TTRX              GPU_ID2_MODEL_MAKE(9, 0)
#define GPU_ID2_PRODUCT_TNAX              GPU_ID2_MODEL_MAKE(9, 1)
#define GPU_ID2_PRODUCT_TBEX              GPU_ID2_MODEL_MAKE(9, 2)
#define GPU_ID2_PRODUCT_TULX              GPU_ID2_MODEL_MAKE(10, 0)
#define GPU_ID2_PRODUCT_TIDX              GPU_ID2_MODEL_MAKE(10, 3)
#define GPU_ID2_PRODUCT_TVAX              GPU_ID2_MODEL_MAKE(10, 4)

/* Values for GPU_ID_VERSION_STATUS field for PRODUCT_ID GPU_ID_PI_T60X */
#define GPU_ID_S_15DEV0                   0x1
#define GPU_ID_S_EAC                      0x2

/* Helper macro to create a GPU_ID assuming valid values for id, major,
   minor, status */
#define GPU_ID_MAKE(id, major, minor, status) \
		((((u32)id) << GPU_ID_VERSION_PRODUCT_ID_SHIFT) | \
		(((u32)major) << GPU_ID_VERSION_MAJOR_SHIFT) |   \
		(((u32)minor) << GPU_ID_VERSION_MINOR_SHIFT) |   \
		(((u32)status) << GPU_ID_VERSION_STATUS_SHIFT))
