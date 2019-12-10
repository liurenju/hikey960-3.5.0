#include <pta_mali_driver_ta.h>
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

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct tee_ta_session *s;

	/* Check that we're called from a user TA */
	s = tee_ta_get_calling_session();
	if (!s)
		return TEE_ERROR_ACCESS_DENIED;
	if (!is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
  DMSG("Mali driver invoke command called.");
	switch (cmd_id) {
	case READ_COMMANDS:
    uint32_t mem_address = (uint32_t)params[0].value.a;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
  						   TEE_PARAM_TYPE_NONE,
  						   TEE_PARAM_TYPE_NONE,
  						   TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types){
      EMSG("Mali driver: unexpected read param type.");
      return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t returned_value = sec_kbase_reg_read(mem_address);
    if (returned_value == 0xdeadbeef) {

    }
    params[0].value.b = returned_value;
		return TEE_SUCCESS;
  case WRITE_COMMANDS:
    uint32_t mem_address = (uint32_t)params[0].value.a;
    uint32_t value = (uint32_t) params[1].value.a;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
  						   TEE_PARAM_TYPE_INPUT,
  						   TEE_PARAM_TYPE_NONE,
  						   TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types) {
      EMSG("Mali driver: unexpected write param type.");
      return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t return_value = sec_kbase_reg_write(mem_address, value);
    if(return_value != TEE_SUCCESS) {
      EMSG("Mali driver: memory address not permissible to write.")
      return TEE_ERROR_BAD_STATE;
    }
    return TEE_SUCCESS;

  case JD_SUBMIT:
    return TEE_SUCCESS;

  case IRQ_HANDLING:
    kbase_job_irq_handler
    return TEE_SUCCESS;
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = MALI_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
       .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
