#include <arm.h>
#include <assert.h>
#include <drivers/mali_gpu.h>
#include <keep.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <util.h>
#include <io.h>
#include <trace.h>

// This driver mainly protects the device interrupts and the memory-mapped IO
// for the GPU. Most of them should not be directly forwarded for non-secure
// world interrupt handling.

/*
	Allowable GPU access
*/
u32* write_green_commands = {
	MMU_REG(MMU_IRQ_MASK),
	MMU_REG(MMU_IRQ_CLEAR),
	GPU_CONTROL_REG(GPU_IRQ_MASK),
	GPU_CONTROL_REG(GPU_COMMAND),
	GPU_CONTROL_REG(GPU_IRQ_CLEAR),
};

u32* read_green_commands = {
	MMU_REG(MMU_IRQ_MASK),
	MMU_REG(MMU_IRQ_CLEAR),
	GPU_CONTROL_REG(GPU_IRQ_MASK),
	GPU_CONTROL_REG(GPU_COMMAND),
	GPU_CONTROL_REG(GPU_IRQ_CLEAR),
};

int should_execute_command(u32 command, int type) {
	int i = 0;
	u32* green_commands;
	switch (type) {
		case READ_COMMANDS:
			green_commands = read_green_commands;
			break;
		case WRITE_COMMANDS:
			green_commands = write_green_commands;
			break;
		default:
			EMSG("GPU Error: Unknown commands - %d", type);
			return 0;
	}

	for(; i < sizeof(*green_commands)/sizeof(u32) + 1; i++){
		if(*command == green_commands[i]) {
			return 1;
		}
	}
	return 0;
}

//securely read from the given register
u32 sec_kbase_reg_read(u32* __iomem mem, uint32_t command)
{
	u32 val;
	if(should_execute_command(command, READ_COMMANDS){
		val = (uint32_t *)(mem + command);
	}
	else {
		// Needs to modify here, but temporarily put a placeholder here.
		val = (uint32_t *)(mem + command);
	}
	DMSG("r: reg %08x val %08x", mem, val);
	return val;
}

//securely write to a given register
u32 sec_kbase_reg_write(u32* __iomem mem, u32 value, uint32_t command)
{
	if(should_execute_command(command, WRITE_COMMANDS) {
		*(mem + command) = value;
		return 0;
	}
	else {
		// Needs to modify here, but temporarily put a placeholder here.
		*(mem + command) = value;
		return 0;
	}
	DMSG("w: reg %08x val %08x", offset, value);
	return -1;
}

// This is the essentail function when a job is done from the GPU,
// and sent the corresponding interrupts (signals) for further processing.
void kbase_jd_done(struct kbase_jd_atom *katom, int slot_nr,
		ktime_t *end_timestamp, kbasep_js_atom_done_code done_code)
{
	struct kbase_context *kctx;
	struct kbase_device *kbdev;

	KBASE_DEBUG_ASSERT(katom);
	kctx = katom->kctx;
	KBASE_DEBUG_ASSERT(kctx);
	kbdev = kctx->kbdev;
	KBASE_DEBUG_ASSERT(kbdev);

	if (done_code & KBASE_JS_ATOM_DONE_EVICTED_FROM_NEXT)
		katom->event_code = BASE_JD_EVENT_REMOVED_FROM_NEXT;

	KBASE_TRACE_ADD(kbdev, JD_DONE, kctx, katom, katom->jc, 0);

	kbase_job_check_leave_disjoint(kbdev, katom);

	katom->slot_nr = slot_nr;

	atomic_inc(&kctx->work_count);

#ifdef CONFIG_DEBUG_FS
	/* a failed job happened and is waiting for dumping*/
	if (!katom->will_fail_event_code &&
			kbase_debug_job_fault_process(katom, katom->event_code))
		return;
#endif

	WARN_ON(work_pending(&katom->work));
	INIT_WORK(&katom->work, kbase_jd_done_worker);
	queue_work(kctx->jctx.job_done_wq, &katom->work);
}

// This is the entry from the user space data to communicate with the driver.
int sec_kbase_jd_submit(void __user *user_addr, void *output)
{
	struct sec_base_jd_atom_v2* temp = (struct sec_base_jd_atom_v2*) output;
	if(tee_svc_copy_from_user(temp, user_addr, sizeof(struct sec_base_jd_atom_v2)) != 0) {
		return -1;
	}
	if(!perform_encryption_decryption_data(temp)) {
		EMSG("Mali: submit jd - Data encryption is wrong.");
		return -1;
	}
	return 0;
}

int perform_encryption_decryption_data(struct sec_base_jd_atom_v2* data) {
	// Perform the proposed mechanisms to encrypt and decrypt the data.

	//TODO: We will add the details later in the driver.
	data->udata = data->udata;
	return 0;
}

// JOB IRQ secure handler
static irqreturn_t sec_kbase_job_irq_handler(int irq, void *data)
{
	uint32_t val = sec_kbase_reg_read(data, JOB_CONTROL_REG(JOB_IRQ_STATUS));
	if (!val)
		return IRQ_NONE;
	return IRQ_HANDLED;
}

// MMU IRQ secure handler
static irqreturn_t sec_kbase_mmu_irq_handler(int irq, void *data)
{
	uint32_t val = kbase_reg_read(kbdev, MMU_REG(MMU_IRQ_STATUS));
	if (!val)
		return IRQ_NONE;
	return IRQ_HANDLED;
}

// GPU IRQ secure handler
static irqreturn_t sec_kbase_gpu_irq_handler(int irq, void *data)
{
	uint32_t val = kbase_reg_read(kbdev, GPU_CONTROL_REG(GPU_IRQ_STATUS));

	if (!val)
		return IRQ_NONE;
	return IRQ_HANDLED;
}

// Interrupt handler simply forwards the interrupts to normal world
// for handling checking.
irqreturn_t sec_irq_handler_base(int irq) {
	DMSG("Calling into irq handler.");
	switch (irq) {
		case JOB_IRQ_TAG:
			return sec_kbase_job_irq_handler(irq);
		case MMU_IRQ_TAG:
			return sec_kbase_mmu_irq_handler(irq);
		case GPU_IRQ_TAG:
			return sec_kbase_gpu_irq_handler(irq);
		default:
			EMSG("Unexpected IRQ signal.");
			break;
	}
	return IRQ_NONE;
}
