#pragma once

#include "x86_operand.hpp"
#include "x86_register.hpp"

// The xed_decoded_inst_t has more information than the xed_encoder_request_t, 
// but both types are derived from a set of common fields called the xed_operand_values_t.

// The decoder has an operands array that holds order of the decoded operands. 
// This array indicates whether or not the operands are read or written.
class x86_instruction : private xed_decoded_inst_t
{
public:
	x86_instruction(unsigned long long addr = 0);
	~x86_instruction();

	void decode(const void *buf, unsigned int length);

	// xed functions
	inline const char* get_name() const
	{
		return xed_iclass_enum_t2str(this->get_iclass());
	}
	inline xed_category_enum_t get_category() const
	{
		return xed_decoded_inst_get_category(this);
	}
	inline xed_extension_enum_t get_extension() const
	{
		return xed_decoded_inst_get_extension(this);
	}
	inline xed_isa_set_enum_t get_isa_set() const
	{
		return xed_decoded_inst_get_isa_set(this);
	}
	inline xed_iclass_enum_t get_iclass() const
	{
		return xed_decoded_inst_get_iclass(this);
	}

	// bytes
	inline xed_uint_t get_length() const
	{
		return xed_decoded_inst_get_length(this);
	}
	inline xed_uint_t get_byte(xed_uint_t byte_index) const
	{
		return xed_decoded_inst_get_byte(this, byte_index);
	}

	inline unsigned int get_operand_length_bits(unsigned int operand_index) const
	{
		return xed_decoded_inst_operand_length_bits(this, operand_index);
	}
	inline xed_iform_enum_t get_iform_enum() const
	{
		return xed_decoded_inst_get_iform_enum(this);
	}

	// operands
	inline const xed_operand_values_t* operands_const()
	{
		return xed_decoded_inst_operands_const(this);
	}

	// register
	inline x86_register get_register(xed_operand_enum_t name = XED_OPERAND_REG0) const
	{
		return xed_decoded_inst_get_reg(this, name);
	}

	// memory
	inline xed_uint_t get_number_of_memory_operands() const
	{
		return xed_decoded_inst_number_of_memory_operands(this);
	}
	inline bool is_mem_read(unsigned int mem_idx = 0) const
	{
		return xed_decoded_inst_mem_read(this, mem_idx) != 0;
	}
	inline bool is_mem_written(unsigned int mem_idx = 0) const
	{
		return xed_decoded_inst_mem_written(this, mem_idx) != 0;
	}
	inline bool is_mem_written_only(unsigned int mem_idx = 0) const
	{
		return xed_decoded_inst_mem_written_only(this, mem_idx);
	}
	inline x86_register get_segment_register(unsigned int mem_idx = 0) const
	{
		return xed_decoded_inst_get_seg_reg(this, mem_idx);
	}
	inline x86_register get_base_register(unsigned int mem_idx = 0) const
	{
		return xed_decoded_inst_get_base_reg(this, mem_idx);
	}
	inline x86_register get_index_register(unsigned int mem_idx = 0) const
	{
		return xed_decoded_inst_get_index_reg(this, mem_idx);
	}
	inline xed_uint_t get_scale(unsigned int mem_idx = 0) const
	{
		return xed_decoded_inst_get_scale(this, mem_idx);
	}
	inline xed_uint_t has_displacement() const
	{
		return xed_operand_values_has_memory_displacement(this);
	}
	inline xed_int64_t get_memory_displacement(unsigned int mem_idx = 0) const
	{
		return xed_decoded_inst_get_memory_displacement(this, mem_idx);
	}
	inline xed_uint_t get_memory_displacement_width(unsigned int mem_idx = 0) const
	{
		return xed_decoded_inst_get_memory_displacement_width(this, mem_idx);
	}
	inline xed_uint_t get_memory_displacement_width_bits(unsigned int mem_idx = 0) const
	{
		return xed_decoded_inst_get_memory_displacement_width_bits(this, mem_idx);
	}
	inline xed_uint_t get_memory_operand_length(unsigned int mem_idx = 0) const
	{
		return xed_decoded_inst_get_memory_operand_length(this, mem_idx);
	}

	// branch
	inline xed_int32_t get_branch_displacement() const
	{
		return xed_decoded_inst_get_branch_displacement(this);
	}
	inline xed_uint_t get_branch_displacement_width() const
	{
		return xed_decoded_inst_get_branch_displacement_width(this);
	}
	inline xed_uint_t get_branch_displacement_width_bits() const
	{
		return xed_decoded_inst_get_branch_displacement_width_bits(this);
	}

	// immediate
	inline xed_uint_t get_immediate_width() const
	{
		return xed_decoded_inst_get_immediate_width(this);
	}
	inline xed_uint_t get_immediate_width_bits() const
	{
		return xed_decoded_inst_get_immediate_width_bits(this);
	}
	inline bool get_immediate_is_signed() const
	{
		// Return true if the first immediate (IMM0) is signed.
		return xed_decoded_inst_get_immediate_is_signed(this) == 1;
	}
	inline xed_int32_t get_signed_immediate() const
	{
		return xed_decoded_inst_get_signed_immediate(this);
	}
	inline xed_uint64_t get_unsigned_immediate() const
	{
		if (!this->get_signed_immediate())
			return xed_decoded_inst_get_unsigned_immediate(this);

		return xed_sign_extend_arbitrary_to_64(
			xed_decoded_inst_get_signed_immediate(this), this->get_immediate_width_bits());
	}
	inline xed_uint8_t get_second_immediate() const
	{
		return xed_decoded_inst_get_second_immediate(this);
	}

	// modification
	inline void set_scale(xed_uint_t scale)
	{
		xed_decoded_inst_set_scale(this, scale);
	}
	inline void set_memory_displacement(xed_int64_t disp, xed_uint_t length_bytes)
	{
		xed_decoded_inst_set_memory_displacement(this, disp, length_bytes);
	}
	inline void set_branch_displacement(xed_int32_t disp, xed_uint_t length_bytes)
	{
		xed_decoded_inst_set_branch_displacement(this, disp, length_bytes);
	}
	inline void set_immediate_signed(xed_int32_t x, xed_uint_t length_bytes)
	{
		xed_decoded_inst_set_immediate_signed(this, x, length_bytes);
	}
	inline void set_immediate_unsigned(xed_uint64_t x, xed_uint_t length_bytes)
	{
		xed_decoded_inst_set_immediate_unsigned(this, x, length_bytes);
	}
	inline void set_memory_displacement_bits(xed_int64_t disp, xed_uint_t length_bits)
	{
		xed_decoded_inst_set_memory_displacement_bits(this, disp, length_bits);
	}
	inline void set_branch_displacement_bits(xed_int32_t disp, xed_uint_t length_bits)
	{
		xed_decoded_inst_set_branch_displacement_bits(this, disp, length_bits);
	}
	inline void set_immediate_signed_bits(xed_int32_t x, xed_uint_t length_bits)
	{
		xed_decoded_inst_set_immediate_signed_bits(this, x, length_bits);
	}
	inline void set_immediate_unsigned_bits(xed_uint64_t x, xed_uint_t length_bits)
	{
		xed_decoded_inst_set_immediate_unsigned_bits(this, x, length_bits);
	}

	// flags
	inline xed_bool_t uses_rflags() const
	{
		return xed_decoded_inst_uses_rflags(this);
	}
	inline const xed_flag_set_t* get_read_flag_set() const
	{
		const xed_simple_flag_t* rfi = xed_decoded_inst_get_rflags_info(this);
		return xed_simple_flag_get_read_flag_set(rfi);
	}
	inline const xed_flag_set_t* get_written_flag_set() const
	{
		const xed_simple_flag_t* rfi = xed_decoded_inst_get_rflags_info(this);
		return xed_simple_flag_get_written_flag_set(rfi);
	}

	// my functions
	inline unsigned long long get_addr() const
	{
		return this->m_addr;
	}
	const x86_operand get_operand(unsigned int i) const &;
	std::vector<x86_operand> get_operands() const;
	std::vector<xed_uint8_t> get_bytes() const;

	void get_read_written_registers(std::vector<x86_register>* read_registers, std::vector<x86_register>* written_registers) const;
	std::vector<x86_register> get_read_registers() const;
	std::vector<x86_register> get_written_registers() const;

	// additional
	bool is_branch() const;

	// debug functions
	std::string get_string() const;
	void sprintf(char* buf, int length) const;
	void print() const;

private:
	unsigned long long m_addr;
	xed_uint8_t m_bytes[16];
};