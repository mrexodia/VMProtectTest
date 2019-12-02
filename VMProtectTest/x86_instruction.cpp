#include "pch.h"

#include "x86_instruction.hpp"

x86_instruction::x86_instruction(unsigned long long addr) : m_addr(addr)
{
}
x86_instruction::~x86_instruction()
{
}

void x86_instruction::decode(const void* buf, unsigned int length,
	xed_machine_mode_enum_t mmode, xed_address_width_enum_t stack_addr_width)
{
	// initialize for xed_decode
	xed_decoded_inst_t *xedd = this;
	xed_decoded_inst_zero(xedd);
	xed_decoded_inst_set_mode(xedd, mmode, stack_addr_width);

	// decode array of bytes to xed_decoded_inst_t
	memcpy(this->m_bytes, buf, length);
	xed_error_enum_t xed_error = xed_decode(xedd, this->m_bytes, length);
	switch (xed_error)
	{
		case XED_ERROR_NONE:				// OK
		{
			break;
		}
		default:
		{
			std::cout << std::hex << this->m_addr << length << std::endl;
			throw std::runtime_error("xed_decode failed");
		}
	}
}

const x86_operand x86_instruction::get_operand(unsigned int i) const &
{
	const xed_inst_t* xi = xed_decoded_inst_inst(this);
	return x86_operand(xed_inst_operand(xi, i));
}
std::vector<x86_operand> x86_instruction::get_operands() const
{
	std::vector<x86_operand> operands;
	const xed_inst_t *xi = xed_decoded_inst_inst(this);
	const uint32_t noperands = xed_inst_noperands(xi);
	for (uint32_t i = 0; i < noperands; i++)
	{
		const xed_operand_t *operand = xed_inst_operand(xi, i);
		operands.push_back(x86_operand(operand));
	}
	return operands;
}
std::vector<xed_uint8_t> x86_instruction::get_bytes() const
{
	std::vector<xed_uint8_t> bytes;
	xed_uint_t len = this->get_length();
	for (xed_uint_t i = 0; i < len; i++)
		bytes.push_back(this->get_byte(i));
	return bytes;
}

void x86_instruction::get_read_written_registers(std::vector<x86_register>* read_registers, std::vector<x86_register>* written_registers) const
{
	const std::vector<x86_operand> operands = this->get_operands();
	for (const x86_operand& operand : operands)
	{
		x86_register targetReg;
		bool hasRead = false, hasWritten = false;
		if (operand.is_register())
		{
			// Operand is register
			targetReg = this->get_register(operand.get_name());
			hasRead = operand.is_read();
			hasWritten = operand.is_written();
		}
		else if (operand.is_memory())
		{
			// Ignore memory
			continue;
		}
		else if (operand.is_immediate())
		{
			// Ignore immediate
			continue;
		}
		else if (operand.get_name() == XED_OPERAND_BASE0 || operand.get_name() == XED_OPERAND_BASE1)
		{
			// BASE?
			targetReg = this->get_register(operand.get_name());
			hasRead = operand.is_read();
			hasWritten = operand.is_written();
			// printf("\t\t%p BASE0/BASE1 %s R:%d W:%d\n", addr, access_register.get_name(), read, write);
		}
		else if (operand.is_branch())
		{
			// Ignore branch
			continue;
		}
		else if (operand.get_name() == XED_OPERAND_AGEN)
		{
			// Ignore agen
			continue;
		}
		else
		{
			std::stringstream ss;
			ss << __FUNCTION__;
			ss << " operand name: " << operand.get_name();
			throw std::invalid_argument(ss.str());
		}

		if (targetReg != XED_REG_STACKPUSH && targetReg != XED_REG_INVALID)
		{
			if (hasRead)
				read_registers->push_back(targetReg);

			if (hasWritten)
				written_registers->push_back(targetReg);
		}
	}

	// check memory operands
	const xed_uint_t memops = this->get_number_of_memory_operands();
	for (xed_uint_t i = 0; i < memops; i++)
	{
		const x86_register baseReg = this->get_base_register(i);
		const x86_register indexReg = this->get_index_register(i);
		const x86_register segReg = this->get_segment_register(i);

		if (baseReg)	read_registers->push_back(baseReg);
		if (indexReg)	read_registers->push_back(indexReg);
		if (segReg)		read_registers->push_back(segReg);
	}
}
std::vector<x86_register> x86_instruction::get_read_registers() const
{
	std::vector<x86_register> readRegs, writtenRegs;
	this->get_read_written_registers(&readRegs, &writtenRegs);
	return readRegs;
}
std::vector<x86_register> x86_instruction::get_written_registers() const
{
	std::vector<x86_register> readRegs, writtenRegs;
	this->get_read_written_registers(&readRegs, &writtenRegs);
	return writtenRegs;
}

bool x86_instruction::is_branch() const
{
	switch (this->get_category())
	{
		case XED_CATEGORY_COND_BR:
		case XED_CATEGORY_UNCOND_BR:
			return true;

		default:
			return false;
	}
}

std::string x86_instruction::get_string() const
{
	char buf[64];
	this->sprintf(buf, 64);
	return buf;
}
void x86_instruction::sprintf(char* buf, int length) const
{
	xed_format_context(XED_SYNTAX_INTEL, this, buf, length, this->m_addr, 0, 0);
}
void x86_instruction::print() const
{
	char buf[64];
	this->sprintf(buf, 64);
	printf("%016llX %s\n", this->get_addr(), buf);
}