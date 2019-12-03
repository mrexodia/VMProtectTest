#pragma once

class x86_register
{
public:
	x86_register(xed_reg_enum_t xed_reg = XED_REG_INVALID);
	~x86_register();

	bool is_valid() const
	{
		return this->m_xed_reg != XED_REG_INVALID;
	}

	// operators
	operator bool() const
	{
		return this->is_valid();
	}
	operator xed_reg_enum_t() const
	{
		return this->m_xed_reg;
	}
	bool operator==(const x86_register& cmp) const
	{
		return this->m_xed_reg == cmp.m_xed_reg;
	}
	bool operator==(xed_reg_enum_t cmp) const
	{
		return this->m_xed_reg == cmp;
	}
	bool operator!=(const x86_register& cmp) const
	{
		return this->m_xed_reg != cmp.m_xed_reg;
	}
	bool operator!=(xed_reg_enum_t cmp) const
	{
		return this->m_xed_reg != cmp;
	}
	bool operator<(x86_register cmp) const
	{
		return this->m_xed_reg < cmp.m_xed_reg;
	}

	// wrappers
	const char* get_name() const
	{
		return xed_reg_enum_t2str(this->m_xed_reg);
	}
	xed_reg_class_enum_t get_class() const
	{
		return xed_reg_class(this->m_xed_reg);
	}
	const char* get_class_name() const
	{
		return xed_reg_class_enum_t2str(this->get_class());
	}

	// Returns the specific width GPR reg class (like XED_REG_CLASS_GPR32 or XED_REG_CLASS_GPR64) for a given GPR register.
	// Or XED_REG_INVALID if not a GPR.
	xed_reg_class_enum_t get_gpr_class() const
	{
		return xed_gpr_reg_class(this->m_xed_reg);
	}
	x86_register get_largest_enclosing_register32() const
	{
		return xed_get_largest_enclosing_register32(this->m_xed_reg);
	}
	x86_register get_largest_enclosing_register() const
	{
		return xed_get_largest_enclosing_register(this->m_xed_reg);
	}
	xed_uint32_t get_width_bits() const
	{
		return xed_get_register_width_bits(this->m_xed_reg);
	}
	xed_uint32_t get_width_bits64() const
	{
		return xed_get_register_width_bits64(this->m_xed_reg);
	}

	// helpers - GPR
	bool is_gpr() const;
	bool is_low_gpr() const;
	bool is_high_gpr() const;
	x86_register get_gpr8_low() const;	// al, cl, dl, bl
	x86_register get_gpr8_high() const;	// ah, ch, dh, bh
	x86_register get_gpr16() const;		// ax, cx, dx, bx
	x86_register get_gpr32() const;		// eax, ecx, edx, ebx
	x86_register get_gpr64() const;		// rax, rcx, rdx, rbx

	// flag
	bool is_flag() const;

private:
	xed_reg_enum_t m_xed_reg;
};