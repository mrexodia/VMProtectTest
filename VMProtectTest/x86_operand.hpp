#pragma once

class x86_operand
{
public:
	//x86_operand();
	explicit x86_operand(const xed_operand_t* op);

	// Operands Access
	xed_operand_enum_t get_name() const
	{
		return xed_operand_name(this->m_op);
	}
	xed_operand_visibility_enum_t get_visibility() const
	{
		return xed_operand_operand_visibility(this->m_op);
	}
	xed_operand_type_enum_t get_type() const
	{
		return xed_operand_type(this->m_op);
	}
	xed_operand_element_xtype_enum_t get_xtype() const
	{
		return xed_operand_xtype(this->m_op);
	}
	xed_operand_width_enum_t get_width() const
	{
		return xed_operand_width(this->m_op);
	}
	xed_uint32_t get_width_bits(const xed_uint32_t eosz) const
	{
		return xed_operand_width_bits(this->m_op, eosz);
	}
	xed_nonterminal_enum_t get_nonterminal_name() const
	{
		return xed_operand_nonterminal_name(this->m_op);
	}
	xed_reg_enum_t get_reg() const // Careful with this one – use xed_decoded_inst_get_reg()! This one is probably not what you think it is.
	{
		return xed_operand_reg(this->m_op);
	}
	xed_uint_t template_is_register() const // Careful with this one
	{
		return xed_operand_template_is_register(this->m_op);
	}
	xed_uint32_t imm() const
	{
		return xed_operand_imm(this->m_op);
	}
	void print(char* buf, int buflen) const
	{
		xed_operand_print(this->m_op, buf, buflen);
	}

	// Operand Enum Name Classification
	static xed_uint_t is_register(xed_operand_enum_t name)
	{
		return xed_operand_is_register(name);
	}
	static xed_uint_t is_memory_addressing_register(xed_operand_enum_t name)
	{
		return xed_operand_is_memory_addressing_register(name);
	}

	// Operand Read/Written
	xed_operand_action_enum_t get_rw() const
	{
		return xed_operand_rw(this->m_op);
	}
	bool is_read() const
	{
		return xed_operand_read(this->m_op) != 0;
	}
	bool is_read_only() const
	{
		return xed_operand_read_only(this->m_op) != 0;
	}
	bool is_written() const
	{
		return xed_operand_written(this->m_op) != 0;
	}
	bool is_written_only() const
	{
		return xed_operand_written_only(this->m_op) != 0;
	}
	bool is_read_written() const
	{
		return xed_operand_read_and_written(this->m_op) != 0;
	}
	bool is_conditional_read() const
	{
		return xed_operand_conditional_read(this->m_op) != 0;
	}
	bool is_conditional_written() const
	{
		return xed_operand_conditional_write(this->m_op) != 0;
	}

	// helpers
	bool is_register() const
	{
		return x86_operand::is_register(this->get_name());
	}
	bool is_memory() const
	{
		return this->get_name() == XED_OPERAND_MEM0 || this->get_name() == XED_OPERAND_MEM1;
	}
	bool is_immediate() const
	{
		return this->get_name() == XED_OPERAND_IMM0 || this->get_name() == XED_OPERAND_IMM1;
	}
	bool is_branch() const
	{
		return this->get_name() == XED_OPERAND_RELBR
			//|| this->get_name() == XED_OPERAND_PTR
			;
	}

private:
	const xed_operand_t* m_op;
};