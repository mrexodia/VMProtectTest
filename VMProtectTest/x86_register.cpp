#include "pch.h"

#include "x86_register.hpp"

x86_register::x86_register(xed_reg_enum_t xed_reg) : m_xed_reg(xed_reg)
{
}
x86_register::~x86_register()
{
}

bool x86_register::is_gpr() const
{
	return this->get_class() == XED_REG_CLASS_GPR;
}
bool x86_register::is_low_gpr() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_CL:
		case XED_REG_DL:
		case XED_REG_BL:
		case XED_REG_SPL:
		case XED_REG_BPL:
		case XED_REG_SIL:
		case XED_REG_DIL:
			return true;

		case XED_REG_AH:
		case XED_REG_CH:
		case XED_REG_DH:
		case XED_REG_BH:
			return false;

		default:
		{
			throw std::invalid_argument(__FUNCTION__);
		}
	}
}
bool x86_register::is_high_gpr() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_CL:
		case XED_REG_DL:
		case XED_REG_BL:
		case XED_REG_SPL:
		case XED_REG_BPL:
		case XED_REG_SIL:
		case XED_REG_DIL:
			return false;

		case XED_REG_AH:
		case XED_REG_CH:
		case XED_REG_DH:
		case XED_REG_BH:
			return true;

		default:
		{
			throw std::invalid_argument(__FUNCTION__);
		}
	}
}
x86_register x86_register::get_gpr8_low() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_AH:
		case XED_REG_AX:
		case XED_REG_EAX:
			return XED_REG_AL;

		case XED_REG_CL:
		case XED_REG_CH:
		case XED_REG_CX:
		case XED_REG_ECX:
			return XED_REG_CL;

		case XED_REG_DL:
		case XED_REG_DH:
		case XED_REG_DX:
		case XED_REG_EDX:
			return XED_REG_DL;

		case XED_REG_BL:
		case XED_REG_BH:
		case XED_REG_BX:
		case XED_REG_EBX:
			return XED_REG_BL;

		case XED_REG_SPL:
		case XED_REG_SP:
		case XED_REG_ESP:
			return XED_REG_SPL;

		case XED_REG_BPL:
		case XED_REG_BP:
		case XED_REG_EBP:
			return XED_REG_BPL;

		case XED_REG_SIL:
		case XED_REG_SI:
		case XED_REG_ESI:
			return XED_REG_SIL;

		case XED_REG_DIL:
		case XED_REG_DI:
		case XED_REG_EDI:
			return XED_REG_DIL;

		default:
		{
			throw std::runtime_error(__FUNCTION__);
		}
	}
}
x86_register x86_register::get_gpr8_high() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_AH:
		case XED_REG_AX:
		case XED_REG_EAX:
			return XED_REG_AH;

		case XED_REG_CL:
		case XED_REG_CH:
		case XED_REG_CX:
		case XED_REG_ECX:
			return XED_REG_CH;

		case XED_REG_DL:
		case XED_REG_DH:
		case XED_REG_DX:
		case XED_REG_EDX:
			return XED_REG_DH;

		case XED_REG_BL:
		case XED_REG_BH:
		case XED_REG_BX:
		case XED_REG_EBX:
			return XED_REG_BH;

		case XED_REG_SPL:
		case XED_REG_SP:
		case XED_REG_ESP:
			return XED_REG_INVALID;

		case XED_REG_BPL:
		case XED_REG_BP:
		case XED_REG_EBP:
			return XED_REG_INVALID;

		case XED_REG_SIL:
		case XED_REG_SI:
		case XED_REG_ESI:
			return XED_REG_INVALID;

		case XED_REG_DIL:
		case XED_REG_DI:
		case XED_REG_EDI:
			return XED_REG_INVALID;

		default:
		{
			throw std::runtime_error(__FUNCTION__);
		}
	}
}
x86_register x86_register::get_gpr16() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_AH:
		case XED_REG_AX:
		case XED_REG_EAX:
			return XED_REG_AX;

		case XED_REG_CL:
		case XED_REG_CH:
		case XED_REG_CX:
		case XED_REG_ECX:
			return XED_REG_CX;

		case XED_REG_DL:
		case XED_REG_DH:
		case XED_REG_DX:
		case XED_REG_EDX:
			return XED_REG_DX;

		case XED_REG_BL:
		case XED_REG_BH:
		case XED_REG_BX:
		case XED_REG_EBX:
			return XED_REG_BX;

		case XED_REG_SPL:
		case XED_REG_SP:
		case XED_REG_ESP:
			return XED_REG_SP;

		case XED_REG_BPL:
		case XED_REG_BP:
		case XED_REG_EBP:
			return XED_REG_BP;

		case XED_REG_SIL:
		case XED_REG_SI:
		case XED_REG_ESI:
			return XED_REG_SI;

		case XED_REG_DIL:
		case XED_REG_DI:
		case XED_REG_EDI:
			return XED_REG_DI;

		default:
		{
			throw std::runtime_error(__FUNCTION__);
		}
	}
}
x86_register x86_register::get_gpr32() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_AH:
		case XED_REG_AX:
		case XED_REG_EAX:
			return XED_REG_EAX;

		case XED_REG_CL:
		case XED_REG_CH:
		case XED_REG_CX:
		case XED_REG_ECX:
			return XED_REG_ECX;

		case XED_REG_DL:
		case XED_REG_DH:
		case XED_REG_DX:
		case XED_REG_EDX:
			return XED_REG_EDX;

		case XED_REG_BL:
		case XED_REG_BH:
		case XED_REG_BX:
		case XED_REG_EBX:
			return XED_REG_EBX;

		case XED_REG_SPL:
		case XED_REG_SP:
		case XED_REG_ESP:
			return XED_REG_ESP;

		case XED_REG_BPL:
		case XED_REG_BP:
		case XED_REG_EBP:
			return XED_REG_EBP;

		case XED_REG_SIL:
		case XED_REG_SI:
		case XED_REG_ESI:
			return XED_REG_ESI;

		case XED_REG_DIL:
		case XED_REG_DI:
		case XED_REG_EDI:
			return XED_REG_EDI;

		default:
		{
			throw std::runtime_error(__FUNCTION__);
		}
	}
}
x86_register x86_register::get_gpr64() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_AH:
		case XED_REG_AX:
		case XED_REG_EAX:
		case XED_REG_RAX:
			return XED_REG_RAX;

		case XED_REG_CL:
		case XED_REG_CH:
		case XED_REG_CX:
		case XED_REG_ECX:
		case XED_REG_RCX:
			return XED_REG_RCX;

		case XED_REG_DL:
		case XED_REG_DH:
		case XED_REG_DX:
		case XED_REG_EDX:
		case XED_REG_RDX:
			return XED_REG_RDX;

		case XED_REG_BL:
		case XED_REG_BH:
		case XED_REG_BX:
		case XED_REG_EBX:
		case XED_REG_RBX:
			return XED_REG_RBX;

		case XED_REG_SPL:
		case XED_REG_SP:
		case XED_REG_ESP:
		case XED_REG_RSP:
			return XED_REG_RSP;

		case XED_REG_BPL:
		case XED_REG_BP:
		case XED_REG_EBP:
		case XED_REG_RBP:
			return XED_REG_RBP;

		case XED_REG_SIL:
		case XED_REG_SI:
		case XED_REG_ESI:
		case XED_REG_RSI:
			return XED_REG_RSI;

		case XED_REG_DIL:
		case XED_REG_DI:
		case XED_REG_EDI:
		case XED_REG_RDI:
			return XED_REG_RDI;

		default:
		{
			throw std::runtime_error(__FUNCTION__);
		}
	}
}