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
	vmp_size_byte,
	vmp_size_word,
	vmp_size_dword,
	vmp_size_qword,
};

enum vmp_segment
{
	vmp_segment_es,
	vmp_segment_cs,
	vmp_segment_ss,
	vmp_segment_ds,
	vmp_segment_fs,
	vmp_segment_gs,
	vmp_segment_scratch
};

class VMPMemory
{
	vmp_segment m_segment;
};

class VMPRegister
{
	//
};

class VMPExpression
{
	// VMPMemory or VMPRegister
};

class VMP_Push
{
	// register or memory or immediate
	VMPExpression m_expr;
};
class VMP_Pop
{
	// register or memory
	VMPExpression m_expr;
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