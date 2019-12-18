#pragma once

#include "AbstractStream.hpp"

struct BasicBlock
{
	// first instruction that starts basic block
	unsigned long long leader;

	std::list<std::shared_ptr<x86_instruction>> instructions;

	// when last instruction can't follow
	bool terminator;

	// dead registers when it enters basic block
	std::map<x86_register, bool> dead_registers;
	xed_uint32_t dead_flags;

	std::shared_ptr<BasicBlock> next_basic_block, target_basic_block;
};

extern std::shared_ptr<BasicBlock> make_cfg(AbstractStream& stream, unsigned long long address);