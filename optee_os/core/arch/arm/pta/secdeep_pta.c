#include <pta_secdeep.h>
#include <kernel/msg_param.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <arm.h>
#include <assert.h>
#include <drivers/mali_gpu.h>
#include <keep.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <util.h>
#include <io.h>
#include <trace.h>
#include <crypto/secdeep_fpe.h>

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	// struct tee_ta_session *s;
	// DMSG("Opening the session.");
	return TEE_SUCCESS;
}

static TEE_Result sanitize_data(void* input, uint32_t size, void* output, uint32_t unit_size) {
	// unsigned char result[size];
	// unsigned char data[size];
	// memcpy(data, input, size);

	// DMSG("Sanitizing data.");
	for(uint32_t i = 0; i < size / unit_size; i++){
		// DMSG("unit size: %d", unit_size);
		FPE_encrypt((unsigned char*)input + i * unit_size, (unsigned char*)output + i * unit_size, unit_size);
		if(unit_size == sizeof(uint32_t)) {
			uint32_t key = ((uint32_t *)input)[i];
			uint32_t value = ((uint32_t *)output)[i];
			// DMSG("RL-- key: %u, value: %u", key, value);
			hash_add_pair(key, value);
		}
	}
	// memcpy(output, result, size);
	return TEE_SUCCESS;
}

static TEE_Result desanitize_data(void* input, uint32_t size, void* output, uint32_t unit_size) {
	// unsigned char result[size];
	// unsigned char data[size];
	// memcpy(data, input, size);

	// DMSG("Desanitizing data.");
	for(uint32_t i = 0; i < size / unit_size; i++) {
		if(unit_size != sizeof(uint32_t)) EMSG("Fuck! size has some issues.");
		if(unit_size == sizeof(uint32_t)) {
				uint32_t key = ((uint32_t *)input)[i];
				uint32_t value = 0;
				if(!hash_get_value(key, &value)) {
					memcpy((unsigned char*)output + i * unit_size, &value, unit_size);
					// DMSG("RL-- key: %u, value: %u", key, value);
					continue;
				}
				// DMSG("RL2-- key: %u, value: %u", key, value);
			}

		FPE_decrypt((unsigned char*)output + i * unit_size, (unsigned char*)input + i * unit_size, unit_size);
	}
	// memcpy(output, result, size);
	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {

	case SANITIZE_DATA:
	{
		unsigned char* temp_buf = (unsigned char *)malloc(params[0].memref.size);
		if(!temp_buf) {
			secdeep_hash_delete();
			temp_buf = (unsigned char *)malloc(params[0].memref.size);
		}
		if(!temp_buf) {
			return TEE_ERROR_RESET_TEE;
		}
		uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
  						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
  						   TEE_PARAM_TYPE_VALUE_INOUT,
  						   TEE_PARAM_TYPE_NONE);
		uint32_t unit_size = params[2].value.a;
		memcpy(temp_buf, params[0].memref.buffer, params[0].memref.size);
    if (param_types != exp_param_types){
      EMSG("Secdeep encryption: unexpected read param type.");
      return TEE_ERROR_BAD_PARAMETERS;
    }
		sanitize_data(temp_buf, params[0].memref.size, params[1].memref.buffer, unit_size);
		free(temp_buf);
		return TEE_SUCCESS;
	}

	case DESANITIZE_DATA:
	{
		unsigned char* temp_buf = (unsigned char *)malloc(params[0].memref.size);
		if(!temp_buf) {
			secdeep_hash_delete();
			temp_buf = (unsigned char *)malloc(params[0].memref.size);
		}
		if(!temp_buf) {
			return TEE_ERROR_RESET_TEE;
		}

		uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
  						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
  						   TEE_PARAM_TYPE_VALUE_INOUT,
  						   TEE_PARAM_TYPE_NONE);
		memcpy(temp_buf, params[0].memref.buffer, params[0].memref.size);
    if (param_types != exp_param_types){
      EMSG("Secdeep encryption: unexpected read param type.");
      return TEE_ERROR_BAD_PARAMETERS;
    }
		uint32_t unit_size = params[2].value.a;
		desanitize_data(temp_buf, params[0].memref.size, params[1].memref.buffer, unit_size);
		free(temp_buf);
		return TEE_SUCCESS;
	}

	case READ_COMMANDS:
	{
    uint32_t* mem_address = (uint32_t*)params[0].memref.buffer;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
  						   TEE_PARAM_TYPE_VALUE_INOUT,
  						   TEE_PARAM_TYPE_NONE,
  						   TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types){
      EMSG("Mali driver: unexpected read param type.");
      return TEE_ERROR_BAD_PARAMETERS;
    }
		uint32_t offset = (uint32_t)params[1].value.a;
    uint32_t returned_value = sec_kbase_reg_read(mem_address, offset);
    if (returned_value == 0xdeadbeef) {
			EMSG("Mali driver: failed to read.");
			return TEE_ERROR_BAD_STATE;
    }
    params[1].value.b = returned_value;
		return TEE_SUCCESS;
	}

	case WRITE_COMMANDS:
	{
    uint32_t* mem_address = (uint32_t*)params[0].memref.buffer;
		uint32_t offset = (uint32_t) params[1].value.a;
    uint32_t value = (uint32_t) params[1].value.b;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
  						   TEE_PARAM_TYPE_VALUE_INPUT,
  						   TEE_PARAM_TYPE_NONE,
  						   TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types) {
      EMSG("Mali driver: unexpected write param type.");
      return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t return_value = sec_kbase_reg_write(mem_address, value, offset);
    if(return_value != TEE_SUCCESS) {
      EMSG("Mali driver: memory address not permissible to write.");
      return TEE_ERROR_BAD_STATE;
    }
    return TEE_SUCCESS;
	}

	case JD_SUBMIT:
	{
		uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
								 TEE_PARAM_TYPE_MEMREF_OUTPUT,
								 TEE_PARAM_TYPE_NONE,
								 TEE_PARAM_TYPE_NONE);

		if (param_types != exp_param_types) {
			EMSG("Mali driver: unexpected jd submit param type.");
			return TEE_ERROR_BAD_PARAMETERS;
		}

		uint32_t return_value = sec_kbase_jd_submit(params[0].memref.buffer, params[1].memref.buffer);
		if (return_value != TEE_SUCCESS){
			EMSG("Mali driver: jd failed to submit");
      return TEE_ERROR_BAD_STATE;
		}
    return TEE_SUCCESS;
	}

  case IRQ_HANDLING:
	{
		uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
								 TEE_PARAM_TYPE_MEMREF_INPUT,
								 TEE_PARAM_TYPE_NONE,
								 TEE_PARAM_TYPE_NONE);

		if (param_types != exp_param_types) {
      EMSG("Mali driver: unexpected interrupt handler param type.");
      return TEE_ERROR_BAD_PARAMETERS;
    }

		uint32_t irq_signal = (uint32_t)params[0].value.a;
		uint32_t out = (uint32_t)params[0].value.b;
		irqreturn_t return_status = sec_irq_handler_base(irq_signal, params[1].memref.buffer, &out);
		if (return_status == IRQ_NONE) {
			EMSG("Mali driver: handling IRQ signal error.");
			return TEE_ERROR_BAD_STATE;
		}
    return TEE_SUCCESS;
	}
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = SECDEEP_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
       .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
