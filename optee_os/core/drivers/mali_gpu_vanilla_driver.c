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
		if(command == green_commands[i]) {
			return 1;
		}
	}
	return 0;
}

//securely read from the given register
u32 sec_kbase_reg_read(u32 __iomem mem)
{
	u32 val;
	if(should_execute_command(mem), READ_COMMANDS){
		val = readl(mem);
	}
	else {
		// Needs to modify here, but temporarily put a placeholder here.
		val = readl(mem);
	}
	DMSG("r: reg %08x val %08x", mem, val);
	return val;
}

//securely write to a given register
void sec_kbase_reg_write(u32 __iomem mem, u32 value)
{
	if(should_execute_command(mem), WRITE_COMMANDS) {
		writel(value, mem);
	}
	else {
		// Needs to modify here, but temporarily put a placeholder here.
		writel(value, mem);
	}
	DMSG("w: reg %08x val %08x", offset, value);
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
int sec_kbase_jd_submit(struct kbase_context *kctx,
		void __user *user_addr, u32 nr_atoms, u32 stride,
		bool uk6_atom)
{
	struct kbase_jd_context *jctx = &kctx->jctx;
	int err = 0;
	int i;
	bool need_to_try_schedule_context = false;
	struct kbase_device *kbdev;
	u32 latest_flush;

	/*
	 * kbase_jd_submit isn't expected to fail and so all errors with the
	 * jobs are reported by immediately failing them (through event system)
	 */
	kbdev = kctx->kbdev;

	beenthere(kctx, "%s", "Enter");

	if (kbase_ctx_flag(kctx, KCTX_SUBMIT_DISABLED)) {
		dev_err(kbdev->dev, "Attempt to submit to a context that has SUBMIT_DISABLED set on it");
		return -EINVAL;
	}

	if (stride != sizeof(base_jd_atom_v2)) {
		dev_err(kbdev->dev, "Stride passed to job_submit doesn't match kernel");
		return -EINVAL;
	}

	/* All atoms submitted in this call have the same flush ID */
	latest_flush = kbase_backend_get_current_flush_id(kbdev);

	for (i = 0; i < nr_atoms; i++) {
		struct base_jd_atom_v2 user_atom;
		struct kbase_jd_atom *katom;

		if (copy_from_user(&user_atom, user_addr,
					sizeof(user_atom)) != 0) {
			err = -EINVAL;
			break;
		}

		user_addr = (void __user *)((uintptr_t) user_addr + stride);

		mutex_lock(&jctx->lock);
#ifndef compiletime_assert
#define compiletime_assert_defined
#define compiletime_assert(x, msg) do { switch (0) { case 0: case (x):; } } \
while (false)
#endif
		compiletime_assert((1 << (8*sizeof(user_atom.atom_number))) ==
					BASE_JD_ATOM_COUNT,
			"BASE_JD_ATOM_COUNT and base_atom_id type out of sync");
		compiletime_assert(sizeof(user_atom.pre_dep[0].atom_id) ==
					sizeof(user_atom.atom_number),
			"BASE_JD_ATOM_COUNT and base_atom_id type out of sync");
#ifdef compiletime_assert_defined
#undef compiletime_assert
#undef compiletime_assert_defined
#endif
		katom = &jctx->atoms[user_atom.atom_number];

		/* Record the flush ID for the cache flush optimisation */
		katom->flush_id = latest_flush;

		while (katom->status != KBASE_JD_ATOM_STATE_UNUSED) {
			/* Atom number is already in use, wait for the atom to
			 * complete
			 */
			mutex_unlock(&jctx->lock);

			kbase_js_sched_all(kbdev);

			if (wait_event_killable(katom->completed,
					katom->status ==
					KBASE_JD_ATOM_STATE_UNUSED) != 0) {
				/* We're being killed so the result code
				 * doesn't really matter
				 */
				return 0;
			}
			mutex_lock(&jctx->lock);
		}

		need_to_try_schedule_context |=
				       jd_submit_atom(kctx, &user_atom, katom);

		/* Register a completed job as a disjoint event when the GPU is in a disjoint state
		 * (ie. being reset or replaying jobs).
		 */
		kbase_disjoint_event_potential(kbdev);

		mutex_unlock(&jctx->lock);
	}

	if (need_to_try_schedule_context)
		kbase_js_sched_all(kbdev);

	return err;
}

u32 perform_encryption_decryption_data(u32 data) {
	// Perform the proposed mechanisms to encrypt and decrypt the data.

	//TODO: We will add the details later in the driver.
	return data;
}

// JOB IRQ secure handler
static irqreturn_t kbase_job_irq_handler(int irq, void *data)
{
	unsigned long flags;
	struct kbase_device *kbdev = kbase_untag(data);
	u32 val;

	spin_lock_irqsave(&kbdev->pm.backend.gpu_powered_lock, flags);

	if (!kbdev->pm.backend.gpu_powered) {
		/* GPU is turned off - IRQ is not for us */
		spin_unlock_irqrestore(&kbdev->pm.backend.gpu_powered_lock,
									flags);
		return IRQ_NONE;
	}

	val = kbase_reg_read(kbdev, JOB_CONTROL_REG(JOB_IRQ_STATUS));

#ifdef CONFIG_MALI_DEBUG
	if (!kbdev->pm.backend.driver_ready_for_irqs)
		dev_warn(kbdev->dev, "%s: irq %d irqstatus 0x%x before driver is ready\n",
				__func__, irq, val);
#endif /* CONFIG_MALI_DEBUG */
	spin_unlock_irqrestore(&kbdev->pm.backend.gpu_powered_lock, flags);

	if (!val)
		return IRQ_NONE;

	dev_dbg(kbdev->dev, "%s: irq %d irqstatus 0x%x\n", __func__, irq, val);

	kbase_job_done(kbdev, val);

	return IRQ_HANDLED;
}

// MMU IRQ secure handler
static irqreturn_t kbase_mmu_irq_handler(int irq, void *data)
{
	unsigned long flags;
	struct kbase_device *kbdev = kbase_untag(data);
	u32 val;

	spin_lock_irqsave(&kbdev->pm.backend.gpu_powered_lock, flags);

	if (!kbdev->pm.backend.gpu_powered) {
		/* GPU is turned off - IRQ is not for us */
		spin_unlock_irqrestore(&kbdev->pm.backend.gpu_powered_lock,
									flags);
		return IRQ_NONE;
	}

	atomic_inc(&kbdev->faults_pending);

	val = kbase_reg_read(kbdev, MMU_REG(MMU_IRQ_STATUS));

#ifdef CONFIG_MALI_DEBUG
	if (!kbdev->pm.backend.driver_ready_for_irqs)
		dev_warn(kbdev->dev, "%s: irq %d irqstatus 0x%x before driver is ready\n",
				__func__, irq, val);
#endif /* CONFIG_MALI_DEBUG */
	spin_unlock_irqrestore(&kbdev->pm.backend.gpu_powered_lock, flags);

	if (!val) {
		atomic_dec(&kbdev->faults_pending);
		return IRQ_NONE;
	}

	dev_dbg(kbdev->dev, "%s: irq %d irqstatus 0x%x\n", __func__, irq, val);

	kbase_mmu_interrupt(kbdev, val);

	atomic_dec(&kbdev->faults_pending);

	return IRQ_HANDLED;
}

// GPU IRQ secure handler
static irqreturn_t kbase_gpu_irq_handler(int irq, void *data)
{
	unsigned long flags;
	struct kbase_device *kbdev = kbase_untag(data);
	u32 val;

	spin_lock_irqsave(&kbdev->pm.backend.gpu_powered_lock, flags);

	if (!kbdev->pm.backend.gpu_powered) {
		/* GPU is turned off - IRQ is not for us */
		spin_unlock_irqrestore(&kbdev->pm.backend.gpu_powered_lock,
									flags);
		return IRQ_NONE;
	}

	val = kbase_reg_read(kbdev, GPU_CONTROL_REG(GPU_IRQ_STATUS));

#ifdef CONFIG_MALI_DEBUG
	if (!kbdev->pm.backend.driver_ready_for_irqs)
		dev_dbg(kbdev->dev, "%s: irq %d irqstatus 0x%x before driver is ready\n",
				__func__, irq, val);
#endif /* CONFIG_MALI_DEBUG */
	spin_unlock_irqrestore(&kbdev->pm.backend.gpu_powered_lock, flags);

	if (!val)
		return IRQ_NONE;

	dev_dbg(kbdev->dev, "%s: irq %d irqstatus 0x%x\n", __func__, irq, val);

	kbase_gpu_interrupt(kbdev, val);

	return IRQ_HANDLED;
}
