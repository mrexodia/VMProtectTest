#include "pch.h"

#include "CFG.hpp"
#include "AbstractStream.hpp"
#include "x86_instruction.hpp"

// deob
// optimizations
unsigned int apply_dead_store_elimination(std::list<std::shared_ptr<x86_instruction>>& instructions,
	std::map<x86_register, bool>& dead_registers, xed_uint32_t& dead_flags)
{
	unsigned int removed_bytes = 0;
	for (auto it = instructions.rbegin(); it != instructions.rend();)
	{
		const std::shared_ptr<x86_instruction> instr = *it;
		bool canRemove = true;
		std::vector<x86_register> readRegs, writtenRegs;
		xed_uint32_t read_flags = 0, written_flags = 0, alive_flags = ~dead_flags;
		instr->get_read_written_registers(&readRegs, &writtenRegs);

		// do not remove last? xd
		if (it == instructions.rbegin())
		{
			//goto update_dead_registers;
		}

		// check flags
		if (instr->uses_rflags())
		{
			read_flags = instr->get_read_flag_set()->flat;
			written_flags = instr->get_written_flag_set()->flat;
			if (alive_flags & written_flags)
			{
				// alive_flags being written by the instruction thus can't remove right?
				goto update_dead_registers;
			}
		}

		// check registers
		for (const x86_register& writtenRegister : writtenRegs)
		{
			if (writtenRegister.is_flag())
				continue;

			std::vector<x86_register> checks;
			if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR64)
			{
				checks.push_back(writtenRegister.get_gpr8_low());
				checks.push_back(writtenRegister.get_gpr8_high());
				checks.push_back(writtenRegister.get_gpr16());
				checks.push_back(writtenRegister.get_gpr32());
			}
			else if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR32)
			{
				checks.push_back(writtenRegister.get_gpr8_low());
				checks.push_back(writtenRegister.get_gpr8_high());
				checks.push_back(writtenRegister.get_gpr16());
			}
			else if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR16)
			{
				checks.push_back(writtenRegister.get_gpr8_low());
				checks.push_back(writtenRegister.get_gpr8_high());
			}
			checks.push_back(writtenRegister);

			for (const auto& check : checks)
			{
				if (!check.is_valid())
					continue;

				auto pair = dead_registers.find(check);
				if (pair == dead_registers.end() || !pair->second)
				{
					// Ž€‚ñ‚¾ƒŒƒWƒXƒ^‚Ìê‡‚Í‘±‚¯‚é
					goto update_dead_registers;
				}
			}
		}

		// check memory operand
		for (xed_uint_t j = 0, memops = instr->get_number_of_memory_operands(); j < memops; j++)
		{
			if (instr->is_mem_written(j))
			{
				// ƒƒ‚ƒŠ‚Ö‚Ì‘‚«ž‚Ý‚ª‚ ‚éê‡‚ÍÁ‚³‚È‚¢
				canRemove = false;
				break;
			}
		}

		// íœ‚·‚é
		if (canRemove)
		{
			removed_bytes += instr->get_length();
			//printf("remove ");
			//instr->print();

			// REMOVE NOW
			instructions.erase(--(it.base()));
			continue;
		}

		// update dead registers
	update_dead_registers:

		// check flags
		if (instr->uses_rflags())
		{
			dead_flags |= written_flags;	// add written flags
			dead_flags &= ~read_flags;		// and remove read flags
		}

		for (const x86_register& writtenRegister : writtenRegs)
		{
			if (writtenRegister.is_flag() || writtenRegister.get_class() == XED_REG_CLASS_IP)
				continue;

			if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR64)
			{
				dead_registers[writtenRegister.get_gpr8_low()] = true;
				dead_registers[writtenRegister.get_gpr8_high()] = true;
				dead_registers[writtenRegister.get_gpr16()] = true;
				dead_registers[writtenRegister.get_gpr32()] = true;
			}
			else if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR32)
			{
				dead_registers[writtenRegister.get_gpr8_low()] = true;
				dead_registers[writtenRegister.get_gpr8_high()] = true;
				dead_registers[writtenRegister.get_gpr16()] = true;
			}
			else if (writtenRegister.get_gpr_class() == XED_REG_CLASS_GPR16)
			{
				dead_registers[writtenRegister.get_gpr8_low()] = true;
				dead_registers[writtenRegister.get_gpr8_high()] = true;
			}
			dead_registers[writtenRegister] = true;
		}
		for (const x86_register& readRegister : readRegs)
		{
			if (readRegister.is_flag() || readRegister.get_class() == XED_REG_CLASS_IP)
				continue;

			if (readRegister.get_gpr_class() == XED_REG_CLASS_GPR64)
			{
				dead_registers[readRegister.get_gpr8_low()] = false;
				dead_registers[readRegister.get_gpr8_high()] = false;
				dead_registers[readRegister.get_gpr16()] = false;
				dead_registers[readRegister.get_gpr32()] = false;
			}
			else if (readRegister.get_gpr_class() == XED_REG_CLASS_GPR32)
			{
				dead_registers[readRegister.get_gpr8_low()] = false;
				dead_registers[readRegister.get_gpr8_high()] = false;
				dead_registers[readRegister.get_gpr16()] = false;
			}
			else if (readRegister.get_gpr_class() == XED_REG_CLASS_GPR16)
			{
				dead_registers[readRegister.get_gpr8_low()] = false;
				dead_registers[readRegister.get_gpr8_high()] = false;
			}
			dead_registers[readRegister] = false;
		}

		++it;
	}

	return removed_bytes;
}
unsigned int deobfuscate_basic_block(std::shared_ptr<BasicBlock>& basic_block)
{
	// all registers / memories should be considered 'ALIVE' when it enters basic block or when it leaves basic block
	std::map<x86_register, bool> dead_registers;
	xed_uint32_t dead_flags = 0;
	if (basic_block->terminator)
	{
		// for vmp handlers
		std::vector<x86_register> dead_ =
		{
			XED_REG_RAX, XED_REG_RCX, XED_REG_RDX
		};

		for (int i = 0; i < dead_.size(); i++)
		{
			const x86_register &reg = dead_[i];
			dead_registers[reg.get_gpr8_low()] = true;
			dead_registers[reg.get_gpr8_high()] = true;
			dead_registers[reg.get_gpr16()] = true;
			dead_registers[reg.get_gpr32()] = true;
			dead_registers[reg] = true;
		}

		// all flags must be dead
		dead_flags = 0xFFFFFFFF;
	}
	else
	{
		// if dead in both :)
		if (basic_block->next_basic_block && basic_block->target_basic_block)
		{
			const std::map<x86_register, bool>& dead_registers1 = basic_block->next_basic_block->dead_registers;
			const std::map<x86_register, bool>& dead_registers2 = basic_block->target_basic_block->dead_registers;
			for (const auto& pair : dead_registers1)
			{
				const x86_register& dead_reg = pair.first;
				if (!pair.second)
					continue;

				auto it = dead_registers2.find(dead_reg);
				if (it != dead_registers2.end() && it->second)
					dead_registers.insert(std::make_pair(dead_reg, true));
			}

			const xed_uint32_t dead_flags1 = basic_block->next_basic_block->dead_flags;
			const xed_uint32_t dead_flags2 = basic_block->target_basic_block->dead_flags;
			dead_flags = dead_flags1 & dead_flags2;
		}
		else if (basic_block->next_basic_block)
		{
			dead_registers = basic_block->next_basic_block->dead_registers;
			dead_flags = basic_block->next_basic_block->dead_flags;
		}
		else if (basic_block->target_basic_block)
		{
			dead_registers = basic_block->target_basic_block->dead_registers;
			dead_flags = basic_block->target_basic_block->dead_flags;
		}
		else
		{
			throw std::runtime_error("?");
		}
	}

	unsigned int removed_bytes = apply_dead_store_elimination(basic_block->instructions, dead_registers, dead_flags);
	basic_block->dead_registers = dead_registers;
	basic_block->dead_flags = dead_flags;
	return removed_bytes;
}

//
bool modifiesIP(const std::shared_ptr<x86_instruction>& instruction)
{
	for (const x86_register& reg : instruction->get_written_registers())
	{
		if (reg.get_class() == XED_REG_CLASS_IP)
			return true;
	}
	return false;
}
bool isCall0(const std::shared_ptr<x86_instruction>& instruction)
{
	static xed_uint8_t s_bytes[5] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
	const auto bytes = instruction->get_bytes();
	if (bytes.size() != 5)
		return false;

	for (int i = 0; i < 5; i++)
	{
		if (s_bytes[i] != bytes[i])
			return false;
	}
	return true;
}

//
void identify_leaders_sub(AbstractStream& stream, unsigned long long leader,
	std::set<unsigned long long>& leaders, std::list<std::pair<unsigned long long, unsigned long long>>& visit)
{
	// The first instruction is a leader.
	leaders.insert(leader);

	// visit<start, end(include)>
	auto is_visit = [&visit](unsigned long long address) -> bool
	{
		for (const auto &pair : visit)
		{
			if (pair.first <= address && address <= pair.second)
			{
				// already visited
				return true;
			}
		}
		return false;
	};

	// read one instruction
	unsigned long long addr = leader;
	while (!is_visit(addr))
	{
		stream.seek(addr);
		const std::shared_ptr<x86_instruction> instr = stream.readNext();
		if (!modifiesIP(instr))
		{
			// read next instruction
			addr = instr->get_addr() + instr->get_length();
			continue;
		}

		// leader -> addr
		visit.push_back(std::make_pair<>(leader, addr));

		switch (instr->get_category())
		{
			case XED_CATEGORY_COND_BR:		// conditional branch
			{
				// The target of a conditional or an unconditional goto/jump instruction is a leader.
				const unsigned long long target = instr->get_addr() + instr->get_length() + instr->get_branch_displacement();
				identify_leaders_sub(stream, target, leaders, visit);

				// The instruction that immediately follows a conditional or an unconditional goto/jump instruction is a leader.
				identify_leaders_sub(stream, instr->get_addr() + instr->get_length(), leaders, visit);
				break;
			}
			case XED_CATEGORY_UNCOND_BR:	// unconditional branch
			{
				xed_uint_t width = instr->get_branch_displacement_width();
				if (width == 0)
				{
					std::cout << "basic block ends with indirect unconditional branch" << std::endl;
					return;
				}

				// The target of a conditional or an unconditional goto/jump instruction is a leader.
				const unsigned long long target = instr->get_addr() + instr->get_length() + instr->get_branch_displacement();
				identify_leaders_sub(stream, target, leaders, visit);
				break;
			}
			case XED_CATEGORY_CALL:
			{
				// uh.
				if (isCall0(instr))
				{
					// call +5 is not leader or some shit
					addr = instr->get_addr() + instr->get_length();
					continue;
				}
				else
				{
					// call is considered as unconditional jump for VMP
					const unsigned long long target = instr->get_addr() + instr->get_length() + instr->get_branch_displacement();
					identify_leaders_sub(stream, target, leaders, visit);
				}
				break;
			}
			case XED_CATEGORY_RET:
			{
				std::cout << "basic block ends with ret" << std::endl;
				break;
			}
			default:
			{
				std::cout << std::hex << instr->get_addr() << ": " << instr->get_string() << std::endl;
				throw std::runtime_error("undefined EIP modify instruction");
			}
		}

		// done i guess
		return;
	}
}
void identify_leaders(AbstractStream& stream, unsigned long long leader, std::set<unsigned long long>& leaders)
{
	std::list<std::pair<unsigned long long, unsigned long long>> visit;
	identify_leaders_sub(stream, leader, leaders, visit);
}

std::shared_ptr<BasicBlock> make_basic_blocks(AbstractStream& stream, unsigned long long address,
	const std::set<unsigned long long>& leaders, std::map<unsigned long long, std::shared_ptr<BasicBlock>>& basic_blocks)
{
	// return basic block if it exists
	auto it = basic_blocks.find(address);
	if (it != basic_blocks.end())
		return it->second;

	// make basic block
	std::shared_ptr<BasicBlock> current_basic_block = std::make_shared<BasicBlock>();
	current_basic_block->leader = address;
	current_basic_block->terminator = false;
	current_basic_block->dead_flags = 0;
	basic_blocks.insert(std::make_pair(address, current_basic_block));

	// and seek
	stream.seek(address);
	for (;;)
	{
		const std::shared_ptr<x86_instruction> instruction = stream.readNext();
		unsigned long long next_address = instruction->get_addr();
		if (!current_basic_block->instructions.empty() && leaders.count(next_address) > 0)
		{
			// make basic block with a leader
			current_basic_block->next_basic_block = make_basic_blocks(stream, next_address, leaders, basic_blocks);
			goto return_basic_block;
		}

		current_basic_block->instructions.push_back(instruction);
		switch (instruction->get_category())
		{
			case XED_CATEGORY_COND_BR:		// conditional branch
			{
				// follow jump
				const unsigned long long target_address = instruction->get_addr() + instruction->get_length() + instruction->get_branch_displacement();
				if (leaders.count(target_address) <= 0)
				{
					// should be "identify_leaders" bug
					throw std::runtime_error("conditional branch target is somehow not leader.");
				}

				current_basic_block->target_basic_block = make_basic_blocks(stream, target_address, leaders, basic_blocks);
				current_basic_block->next_basic_block = make_basic_blocks(stream, instruction->get_addr() + instruction->get_length(), leaders, basic_blocks);
				goto return_basic_block;
			}
			case XED_CATEGORY_UNCOND_BR:	// unconditional branch
			{
				xed_uint_t width = instruction->get_branch_displacement_width();
				if (width == 0)
				{
					current_basic_block->terminator = true;
					return current_basic_block;
				}

				// follow unconditional branch (target should be leader)
				const unsigned long long target_address = instruction->get_addr() + instruction->get_length() + instruction->get_branch_displacement();
				if (leaders.count(target_address) <= 0)
				{
					// should be "identify_leaders" bug
					throw std::runtime_error("unconditional branch target is somehow not leader.");
				}

				current_basic_block->target_basic_block = make_basic_blocks(stream, target_address, leaders, basic_blocks);
				goto return_basic_block;
			}
			case XED_CATEGORY_CALL:
			{
				if (isCall0(instruction))
				{
					// call +5 is not leader or some shit
					break;
				}
				else
				{
					// follow call
					const unsigned long long target_address = instruction->get_addr() + instruction->get_length() + instruction->get_branch_displacement();
					if (leaders.count(target_address) <= 0)
					{
						// should be "identify_leaders" bug
						throw std::runtime_error("call's target is somehow not leader.");
					}

					current_basic_block->target_basic_block = make_basic_blocks(stream, target_address, leaders, basic_blocks);
					goto return_basic_block;
				}
			}
			case XED_CATEGORY_RET:			// or return
			{
				current_basic_block->terminator = true;
				goto return_basic_block;
			}
			default:
			{
				break;
			}
		}
	}

return_basic_block:
	return current_basic_block;
}

std::shared_ptr<BasicBlock> make_cfg(AbstractStream& stream, unsigned long long address)
{
	// identify leaders
	std::set<unsigned long long> leaders;
	identify_leaders(stream, address, leaders);

	// make basic blocks
	std::map<unsigned long long, std::shared_ptr<BasicBlock>> basic_blocks;
	std::shared_ptr<BasicBlock> first_basic_block = make_basic_blocks(stream, address, leaders, basic_blocks);

	// deobfuscate
	constexpr bool _deobfuscate = 1;
	if (_deobfuscate)
	{
		// can possibly improve by checking dead_registers/flags after deobfuscate
		unsigned int removed_bytes;
		/*
		do
		{
			removed_bytes = 0;
			for (auto& pair : basic_blocks)
				removed_bytes += deobfuscate_basic_block(pair.second);
		} while (removed_bytes);*/
		for (int i = 0; i < 10; i++)
		{
			removed_bytes = 0;
			for (auto it = basic_blocks.rbegin(); it != basic_blocks.rend(); ++it)
				removed_bytes += deobfuscate_basic_block(it->second);
		}
	}
	return first_basic_block;
}