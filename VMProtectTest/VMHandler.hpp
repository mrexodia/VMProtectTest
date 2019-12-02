#pragma once

class x86_instruction;

enum handler_type
{
	vmprotect_handler_pushb,
	vmprotect_handler_pushw,
	vmprotect_handler_pushd,
	vmprotect_handler_pushq,

	vmprotect_handler_push_vmvar,
	vmprotect_handler_push_sp,

	vmprotect_handler_popd,
	vmprotect_handler_popq,

	vmprotect_handler_fetch,		// ds?
	vmprotect_handler_fetchss,

	vmprotect_handler_write,

	// binary op
	vmprotect_handler_add,			// add(op, op)
	vmprotect_handler_shr,			// shr(op, op_w)
	vmprotect_handler_nor,			// nor(op, op)

	vmprotect_handler_mul,			// mul(op, op)
	vmprotect_handler_imul,			// imul(op, op)
};

enum
{
	vm_segment_cs,
	vm_segment_ds,
	vm_segment_ss,
	vm_segment_fs,
	vm_segment_gs,
	vm_segment_scratch,
};

class VMHandler
{
public:
	VMHandler();
	~VMHandler();

	unsigned long long compute_next_handler_address(void *context);

private:
	std::shared_ptr<int> m_basic_blocks;
	handler_type m_type;
};