/*
 header file for mali gpu vanilla driver.
*/

#include <drivers/maligpu_registers.h>
// The MACRO definitions
#define u64_to_user_ptr(x) ((void __user *)(uintptr_t)x)

// Secure driver functions
u32 sec_kbase_reg_read(void __iomem reg, u32 offset);
u32 sec_kbase_reg_write(void __iomem reg, u32 offset, u32 value);

int sec_kbase_jd_submit(struct kbase_context *kctx,
		void __user *user_addr, u32 nr_atoms, u32 stride,
		bool uk6_atom);
irqreturn_t sec_kbase_gpu_irq_handler(int irq, void *data);
void kbase_jd_done(struct kbase_jd_atom *katom, int slot_nr,
		ktime_t *end_timestamp, kbasep_js_atom_done_code done_code)

int should_execute_command(u32 command, int type);
u32 perform_encryption_decryption_data(u32 data);
