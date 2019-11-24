#include "pch.h"

#include "deobfuscator.hpp"
#include "x86_instruction.hpp"
#include "ProcessStream.hpp"
#include <triton/api.hpp>
#include <triton/x86Specifications.hpp>
#pragma comment(lib, "triton.lib")

// structures
struct BasicBlock
{
	// first instruction that starts basic block
	unsigned long long leader;

	std::list<std::shared_ptr<x86_instruction>> instructions;

	// when last instruction can't follow
	bool terminator;

	// dead registers when it enters basic block
	std::map<x86_register, bool> dead_registers;

	std::shared_ptr<BasicBlock> next_basic_block, target_basic_block;
};

bool modifiesIP(const std::shared_ptr<x86_instruction>& instruction)
{
	for (const x86_register& reg : instruction->get_written_registers())
	{
		if (reg.get_largest_enclosing_register() == XED_REG_RIP)
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

// CFG
void identify_leaders(AbstractStream& stream, unsigned long long leader,
	std::set<unsigned long long>& leaders, std::set<unsigned long long>& visit)
{
	// The first instruction is a leader.
	leaders.insert(leader);

	// read one instruction
	unsigned long long addr = leader;
	for (;;)
	{
		if (visit.count(addr) > 0)
			return;

		stream.seek(addr);
		const std::shared_ptr<x86_instruction> instr = stream.readNext();
		visit.insert(addr);
		if (!modifiesIP(instr))
		{
			// read next instruction
			addr = instr->get_addr() + instr->get_length();
			continue;
		}

		switch (instr->get_category())
		{
			case XED_CATEGORY_COND_BR:		// conditional branch
			{
				// The target of a conditional or an unconditional goto/jump instruction is a leader.
				unsigned long long target = instr->get_addr() + instr->get_length() + instr->get_branch_displacement();
				leaders.insert(target);
				leaders.insert(instr->get_addr() + instr->get_length());
				return;
			}
			case XED_CATEGORY_UNCOND_BR:	// unconditional branch
			{
				xed_uint_t width = instr->get_branch_displacement_width();
				if (width == 0)
				{
					// can't follow anymore
					std::cout << std::hex << instr->get_addr() << " reached????????" << std::endl;
					return;
				}

				// The target of a conditional or an unconditional goto/jump instruction is a leader.
				unsigned long long target = instr->get_addr() + instr->get_length() + instr->get_branch_displacement();
				leaders.insert(target);
				return;
			}
			case XED_CATEGORY_CALL:
			{
				// uh.
				if (isCall0(instr))
				{
					// call +5 is not leader or some shit
					break;
				}
				else
				{
					// call is considered as unconditional jump
					unsigned long long target = instr->get_addr() + instr->get_length() + instr->get_branch_displacement();
					leaders.insert(target);
					return;
				}

//				[[fallthrough]] ;
			}
			case XED_CATEGORY_RET:
			{
				// can't follow anymore
				std::cout << std::hex << instr->get_addr() << "can't follow anymore" << std::endl;
				return;
			}
			default:
			{
				std::cout << std::hex << instr->get_addr() << ": " << instr->get_string() << std::endl;
				throw std::runtime_error("undefined EIP modify instruction");
			}
		}

		// move next
		addr = instr->get_addr() + instr->get_length();
	}
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
				xed_uint_t width = instruction->get_branch_displacement_width();
				if (width == 0)
				{
					throw std::runtime_error("is there even this conditional branch?????");
				}

				// follow jump
				unsigned long long target_address = instruction->get_addr() + instruction->get_length() + instruction->get_branch_displacement();
				if (leaders.count(target_address) <= 0)
				{
					std::cout << target_address << std::endl;
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
					std::cout << std::hex << "Basic block ends with: " << instruction->get_addr() << " - " << instruction->get_string() << std::endl;
					return current_basic_block;
				}

				// follow unconditional branch (target should be leader)
				unsigned long long target_address = instruction->get_addr() + instruction->get_length() + instruction->get_branch_displacement();
				if (leaders.count(target_address) <= 0)
				{
					std::cout << instruction->get_addr() << " " << target_address << std::endl;
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
					unsigned long long target_address = instruction->get_addr() + instruction->get_length() + instruction->get_branch_displacement();
					if (leaders.count(target_address) <= 0)
					{
						std::cout << instruction->get_addr() << " " << target_address << std::endl;
						throw std::runtime_error("call's target is somehow not leader.");
					}

					current_basic_block->target_basic_block = make_basic_blocks(stream, target_address, leaders, basic_blocks);
					goto return_basic_block;
				}

//				[[fallthrough]] ;
			}
			case XED_CATEGORY_RET:			// or return
			{
				current_basic_block->terminator = true;
				std::cout << std::hex << "Basic block ends with: " << instruction->get_addr() << " - " << instruction->get_string() << std::endl;
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

// dead store elimination based on register
unsigned int apply_dead_store_elimination(std::list<std::shared_ptr<x86_instruction>>& instructions, std::map<x86_register, bool>& dead_registers)
{
	unsigned int removed_bytes = 0;
	for (auto it = instructions.rbegin(); it != instructions.rend();)
	{
		const auto& instr = *it;
		bool canRemove = true;
		std::vector<x86_operand> operands;
		std::vector<x86_register> readRegs, writtenRegs;
		instr->get_read_written_registers(&readRegs, &writtenRegs);

		// do not remove last? xd
		if (it == instructions.rbegin())
		{
			//goto update_dead_registers;
		}

		// check if instruction can be removed
		for (const auto& writtenRegister : writtenRegs)
		{
			//std::cout << writtenRegister.get_largest_enclosing_register32().get_name();
			auto pair = dead_registers.find(writtenRegister.get_largest_enclosing_register32());
			if (pair == dead_registers.end() || !pair->second)
			{
				// Ž€‚ñ‚¾ƒŒƒWƒXƒ^‚Ìê‡‚Í‘±‚¯‚é
				goto update_dead_registers;
			}
		}

		// check memory operand
		operands = instr->get_operands();
		for (size_t i = 0; canRemove && i < operands.size(); i++)
		{
			if (!operands[i].is_memory())
				continue;

			xed_uint_t memops = instr->get_number_of_memory_operands();
			for (xed_uint_t j = 0; j < memops; j++)
			{
				if (instr->is_mem_written(j))
				{
					// ƒƒ‚ƒŠ‚Ö‚Ì‘‚«ž‚Ý‚ª‚ ‚éê‡‚ÍÁ‚³‚È‚¢
					canRemove = false;
					break;
				}
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
		for (const auto& writtenRegister : writtenRegs)
		{
			const x86_register reg = writtenRegister.get_largest_enclosing_register32();
			if (reg != XED_REG_EIP)
				dead_registers[reg] = true;
		}
		for (const auto& readRegister : readRegs)
		{
			const x86_register reg = readRegister.get_largest_enclosing_register32();
			dead_registers[reg] = false;
		}

		/*if (it->get_iclass() == XED_ICLASS_POPFD)
		{
			for (xed_reg_enum_t i = XED_REG_FLAGS_FIRST; i <= XED_REG_FLAGS_LAST;)
			{
				dead_registers[i] = true;
				i = xed_reg_enum_t(i + 1);
			}
		}*/

		++it;
	}

	return removed_bytes;
}
/*unsigned int apply_dead_store_elimination2(std::list<std::shared_ptr<x86_instruction>>& instructions, std::map<x86_memory_operand, bool>& dead_memories)
{
	unsigned int removed_bytes = 0;
	for (auto it = instructions.begin(); it != instructions.end(); ++ it)
	{
		const auto& instr = *it;
		xed_uint_t memops = instr->get_number_of_memory_operands();
		for (xed_uint_t j = 0; j < memops; j++)
		{
			if (instr->is_mem_written_only(j))
			{
				x86_memory_operand memory_operand;
				memory_operand.segment_register = instr->get_segment_register(j);
				memory_operand.base_register = instr->get_base_register(j);
				memory_operand.index_register = instr->get_index_register(j);
				memory_operand.scale = instr->get_scale(j);
				memory_operand.displacement = instr->get_memory_displacement(j);

				auto it = dead_memories.find(memory_operand);
				if (it == dead_memories.end() || !it->second)
				{
					dead_memories[memory_operand] = true;
				}
				else
				{
					// remove now
				}
			}
			else if (instr->is_mem_read(j))
			{
				x86_memory_operand memory_operand;
				memory_operand.segment_register = instr->get_segment_register(j);
				memory_operand.base_register = instr->get_base_register(j);
				memory_operand.index_register = instr->get_index_register(j);
				memory_operand.scale = instr->get_scale(j);
				memory_operand.displacement = instr->get_memory_displacement(j);
				dead_memories[memory_operand] = false;
			}
		}
	}

	return removed_bytes;
}*/

unsigned int deobfuscate_basic_block(std::shared_ptr<BasicBlock>& basic_block)
{
	// all registers / memories should be considered 'ALIVE' when it enters basic block or when it leaves basic block
	std::map<x86_register, bool> dead_registers;
	if (basic_block->terminator)
	{
		// for vmp handlers
		dead_registers[XED_REG_EAX] = true;			// dead
		dead_registers[XED_REG_EBX] = false;
		dead_registers[XED_REG_ECX] = true;			// dead
		dead_registers[XED_REG_EDX] = true;			// dead
		dead_registers[XED_REG_ESI] = false;
		dead_registers[XED_REG_EDI] = false;
		dead_registers[XED_REG_EBP] = false;
		dead_registers[XED_REG_ESP] = false;
		dead_registers[XED_REG_EIP] = false;
		dead_registers[XED_REG_EFLAGS] = true;
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
		}
		else if (basic_block->next_basic_block)
		{
			dead_registers = basic_block->next_basic_block->dead_registers;
		}
		else if (basic_block->target_basic_block)
		{
			dead_registers = basic_block->target_basic_block->dead_registers;
		}
		else
		{
			throw std::runtime_error("?");
		}
	}

	unsigned int removed_bytes = apply_dead_store_elimination(basic_block->instructions, dead_registers);
	basic_block->dead_registers = dead_registers;
	return removed_bytes;
}

void print_basic_blocks(const std::shared_ptr<BasicBlock> &first_basic_block)
{
	std::set<unsigned long long> visit_for_print;
	std::shared_ptr<BasicBlock> basic_block = first_basic_block;
	for (auto it = basic_block->instructions.begin(); it != basic_block->instructions.end();)
	{
		const auto& instruction = *it;
		if (++it != basic_block->instructions.end())
		{
			// loop until it reaches end
			instruction->print();
			continue;
		}

		// dont print unconditional jmp, they are annoying
		if (instruction->get_category() != XED_CATEGORY_UNCOND_BR
			|| instruction->get_branch_displacement_width() == 0)
		{
			instruction->print();
		}

		visit_for_print.insert(basic_block->leader);
		if (basic_block->next_basic_block && visit_for_print.count(basic_block->next_basic_block->leader) <= 0)
		{
			// print next
			basic_block = basic_block->next_basic_block;
		}
		else if (basic_block->target_basic_block && visit_for_print.count(basic_block->target_basic_block->leader) <= 0)
		{
			// it ends with jmp?
			basic_block = basic_block->target_basic_block;
		}
		else
		{
			// perhaps finishes?
			break;
		}

		it = basic_block->instructions.begin();
	}
}

void deobfuscate_vmp(ProcessStream& stream, unsigned long long handler_address)
{
	// explore until it finds ret/jmp r32?
	std::set<unsigned long long> visit;
	std::set<unsigned long long> leaders;

	// not the best impl :|
	leaders.insert(handler_address);
	auto old_leaders_size = leaders.size();
	do
	{
		old_leaders_size = leaders.size();
		for (unsigned long long leader : leaders)
			identify_leaders(stream, leader, leaders, visit);
		std::cout << "leaders_size: " << leaders.size() << std::endl;
	} while (old_leaders_size != leaders.size());

	std::cout << "+make_basic_blocks:" << std::endl;
	std::map<unsigned long long, std::shared_ptr<BasicBlock>> basic_blocks;
	std::shared_ptr<BasicBlock> first_basic_block = make_basic_blocks(stream, handler_address, leaders, basic_blocks);
	std::cout << "-make_basic_blocks:" << std::endl;

	// not the best impl :|
	unsigned int removed_bytes;
	for (int i = 0; i < 10; i++)
	{
		removed_bytes = 0;
		for (auto& pair : basic_blocks)
			removed_bytes += deobfuscate_basic_block(pair.second);
		printf("removed %d\n", removed_bytes);
	}

	// print them
	std::cout << std::endl;
	print_basic_blocks(first_basic_block);
	std::cout << std::endl;

	// symblic execution
	auto triton_api = std::make_unique<triton::API>();
	triton_api->setArchitecture(triton::arch::ARCH_X86);
	triton_api->setAstRepresentationMode(triton::ast::representations::PYTHON_REPRESENTATION);

	triton_api->symbolizeRegister(triton_api->registers.x86_esi, "x86_esi")->setAlias("p-code");
	auto edi = triton_api->symbolizeRegister(triton_api->registers.x86_esi, "x86_edi");
	triton_api->setConcreteVariableValue(edi, 1024);

	//triton_api->addCallback(best_simplification);
	//triton_api->addCallback(check_concrete_register);
	//triton_api->addCallback(set_concrete_register);
	//triton_api->addCallback(check_concrete_memory);
	//triton_api->addCallback(set_concrete_memory);

	std::shared_ptr<BasicBlock> basic_block = first_basic_block;
	for (auto it = basic_block->instructions.begin(); it != basic_block->instructions.end();)
	{
		const auto& instruction = *it;
		const std::vector<xed_uint8_t> bytes = instruction->get_bytes();
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], bytes.size());
		triton_instruction.setAddress(instruction->get_addr());

		triton_api->processing(triton_instruction);
		if (++it != basic_block->instructions.end())
		{
			// loop until it reaches end
			std::cout << triton_instruction << std::endl;
			continue;
		}

		if (!instruction->is_branch())
		{
			std::cout << triton_instruction << std::endl;
		}

		if (basic_block->next_basic_block && basic_block->target_basic_block)
		{
			// it ends with conditional branch
			if (triton_instruction.isConditionTaken())
			{
				basic_block = basic_block->target_basic_block;
			}
			else
			{
				basic_block = basic_block->next_basic_block;
			}
		}
		else if (basic_block->target_basic_block)
		{
			// it ends with jmp?
			basic_block = basic_block->target_basic_block;
		}
		else if (basic_block->next_basic_block)
		{
			// just follow :)
			basic_block = basic_block->next_basic_block;
		}
		else
		{
			// perhaps finishes?
			break;
		}

		it = basic_block->instructions.begin();
	}

	/*for (const auto& pair : triton_api->getSymbolicExpressions())
	{
		auto expr = pair.second;
		std::cout << "\tSymExpr" << pair.first << " : " << expr << std::endl;
		if (expr->isRegister())
		{
			std::cout << "\t\t" << expr->getOriginRegister() << std::endl;
		}
		else if (expr->isMemory())
		{
			std::cout << "\t\t" << expr->getOriginMemory() << std::endl;
			auto memoryAst = triton_api->getMemoryAst(expr->getOriginMemory());
			std::cout << "\t\t" << memoryAst->evaluate() << std::endl;
		}
	}

	triton::ast::SharedAbstractNode esi_ast = triton_api->getRegisterAst(triton_api->registers.x86_esi);
	std::cout << "esi: " << triton_api->processSimplification(esi_ast, true) << std::endl;

	triton::ast::SharedAbstractNode edi_ast = triton_api->getRegisterAst(triton_api->registers.x86_edi);
	std::cout << "edi: " << triton_api->processSimplification(edi_ast, true) << std::endl;*/
}
void vmprotect_test(unsigned long pid)
{
	ProcessStream stream;
	if (!stream.open(pid))
		throw std::runtime_error("open failed");

	deobfuscate_vmp(stream, 0x0040C890);
	//deobfuscate_vmp(stream, 0x004892AF);
	//deobfuscate_vmp(stream, 0x00493FB7);
	//deobfuscate_vmp(stream, 0x0043CEBF);
	//deobfuscate_vmp(stream, 0x0042EDA2);
}