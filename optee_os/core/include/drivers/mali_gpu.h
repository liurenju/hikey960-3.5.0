/*
 header file for mali gpu vanilla driver.
*/

#include <drivers/mali_gpu_registers.h>
#include <drivers/mali_gpu_data_structure.h>
// The MACRO definitions
#define u64_to_user_ptr(x) ((void *)(uintptr_t)x)

// Secure driver functions
u32 sec_kbase_reg_read(u32* mem, uint32_t command);
u32 sec_kbase_reg_write(u32* mem, u32 value, uint32_t command);

int sec_kbase_jd_submit(void *user_addr, void *output);

irqreturn_t sec_irq_handler_base(int irq, void *data, uint32_t* out);
irqreturn_t sec_kbase_gpu_irq_handler(int irq, void *data, uint32_t* out);
irqreturn_t sec_kbase_mmu_irq_handler(int irq, void *data, uint32_t* out);
irqreturn_t sec_kbase_job_irq_handler(int irq, void *data, uint32_t *out);

int should_execute_command(u32 command, int type);
u8 perform_encryption_decryption_data(u8 data, char* key);
