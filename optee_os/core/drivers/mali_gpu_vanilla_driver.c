#include <arm.h>
#include <assert.h>
#include <drivers/mali_gpu.h>
#include <keep.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <util.h>
#include <io.h>
#include <trace.h>
#include <string.h>
#include <tee/tee_svc.h>

// This driver mainly protects the device interrupts and the memory-mapped IO
// for the GPU. Most of them should not be directly forwarded for non-secure
// world interrupt handling.

/*
	Allowable GPU access
*/
u32 write_green_commands[] = {
	MMU_REG(MMU_IRQ_MASK),
	MMU_REG(MMU_IRQ_CLEAR),
	GPU_CONTROL_REG(GPU_IRQ_MASK),
	GPU_CONTROL_REG(GPU_COMMAND),
	GPU_CONTROL_REG(GPU_IRQ_CLEAR),
};

u32 read_green_commands[] = {
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

	for(; i < 5; i++){
		if(command == green_commands[i]) {
			return 1;
		}
	}
	return 0;
}

//securely read from the given register
u32 sec_kbase_reg_read(u32* mem, uint32_t command)
{
	u32 val;
	if (should_execute_command(command, READ_COMMANDS))
	{
		val = *(mem + command);
	}
	else {
		// Needs to modify here, but temporarily put a placeholder here.
		val = *(mem + command);
	}
	DMSG("r: reg %08x val %08x", command, val);
	return val;
}

u8 perform_encryption_decryption_data(u8 data, char* key __unused){
	//Renju Liu: TODO: Implement aes here.
	return data;
}

//securely write to a given register
u32 sec_kbase_reg_write(u32* mem, u32 value, uint32_t command)
{
	if(should_execute_command(command, WRITE_COMMANDS))
	{
		*(mem + command) = value;
		return 0;
	}
	else {
		// Needs to modify here, but temporarily put a placeholder here.
		*(mem + command) = value;
		return 0;
	}
	DMSG("w: reg %08x val %08x", command, value);
	return -1;
}

// This is the entry from the user space data to communicate with the driver.
int sec_kbase_jd_submit(void *user_addr, void *output)
{
	struct sec_base_jd_atom_v2* temp = (struct sec_base_jd_atom_v2*) output;
	if(tee_svc_copy_from_user(temp, user_addr, sizeof(struct sec_base_jd_atom_v2)) != 0) {
		return -1;
	}
	return 0;
}

// JOB IRQ secure handler
irqreturn_t sec_kbase_job_irq_handler(int irq __unused, void *data, uint32_t *out)
{
	uint32_t val = sec_kbase_reg_read(data, JOB_CONTROL_REG(JOB_IRQ_STATUS));

	if (!val){
		out = NULL;
		return IRQ_NONE;
	}
	memcpy(out, &val, sizeof(uint32_t));
	return IRQ_HANDLED;
}

// MMU IRQ secure handler
irqreturn_t sec_kbase_mmu_irq_handler(int irq __unused, void *data, uint32_t* out)
{
	uint32_t val = sec_kbase_reg_read(data, MMU_REG(MMU_IRQ_STATUS));

	if (!val){
		out = NULL;
		return IRQ_NONE;
	}
	memcpy(out, &val, sizeof(uint32_t));
	return IRQ_HANDLED;
}

// GPU IRQ secure handler
irqreturn_t sec_kbase_gpu_irq_handler(int irq __unused, void *data, uint32_t* out)
{
	uint32_t val = sec_kbase_reg_read(data, GPU_CONTROL_REG(GPU_IRQ_STATUS));

	if (!val){
		out = NULL;
		return IRQ_NONE;
	}
	memcpy(out, &val, sizeof(uint32_t));
	return IRQ_HANDLED;
}

// Interrupt handler simply forwards the interrupts to normal world
// for handling checking.
irqreturn_t sec_irq_handler_base(int irq, void *data, uint32_t* out) {
	DMSG("Calling into irq handler.");
	switch (irq) {
		case JOB_IRQ_TAG:
			return sec_kbase_job_irq_handler(irq, data, out);
		case MMU_IRQ_TAG:
			return sec_kbase_mmu_irq_handler(irq, data, out);
		case GPU_IRQ_TAG:
			return sec_kbase_gpu_irq_handler(irq, data, out);
		default:
			EMSG("Unexpected IRQ signal.");
			break;
	}
	return IRQ_NONE;
}
