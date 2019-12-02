#include "pch.h"

#include "VMProtectAnalyzer.hpp"
#include "x86_instruction.hpp"
#include "AbstractStream.hpp"

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
	xed_uint32_t dead_flags;

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
		for (const auto& writtenRegister : writtenRegs)
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

		for (const auto& writtenRegister : writtenRegs)
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
		for (int i = 0; i < 3; i++)
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

// helper?
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
		do
		{
			removed_bytes = 0;
			for (auto& pair : basic_blocks)
				removed_bytes += deobfuscate_basic_block(pair.second);
		}
		while (removed_bytes);
	}

	// print them
	constexpr bool _print = 0;
	if (_print)
	{
		std::cout << std::endl;
		print_basic_blocks(first_basic_block);
		std::cout << std::endl;
	}
	return first_basic_block;
}



triton::ast::SharedAbstractNode b(triton::API& ctx, const triton::ast::SharedAbstractNode& node)
{
	if (node->getType() == triton::ast::BVXOR_NODE)
	{
		if (node->getChildren()[0]->equalTo(node->getChildren()[1]))
			return ctx.getAstContext()->bv(0, node->getBitvectorSize());
	}
	return node;
}

// VMProtectAnalyzer
VMProtectAnalyzer::VMProtectAnalyzer(triton::arch::architecture_e arch)
{
	triton_api = std::make_shared<triton::API>();
	triton_api->setArchitecture(arch);
	triton_api->setMode(triton::modes::ALIGNED_MEMORY, true);

	this->m_scratch_size = 0;
	this->m_temp = 0;
}
VMProtectAnalyzer::~VMProtectAnalyzer()
{
}

bool VMProtectAnalyzer::is_x64() const
{
	const triton::arch::architecture_e architecture = this->triton_api->getArchitecture();
	switch (architecture)
	{
		case triton::arch::ARCH_X86:
			return false;

		case triton::arch::ARCH_X86_64:
			return true;

		default:
			throw std::runtime_error("invalid architecture");
	}
}

triton::uint64 VMProtectAnalyzer::get_bp() const
{
	switch (triton_api->getArchitecture())
	{
		case triton::arch::ARCH_X86:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_ebp).convert_to<triton::uint64>();

		case triton::arch::ARCH_X86_64:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_rbp).convert_to<triton::uint64>();

		default:
			throw std::runtime_error("invalid architecture");
	}
}
triton::uint64 VMProtectAnalyzer::get_sp() const
{
	switch (triton_api->getArchitecture())
	{
		case triton::arch::ARCH_X86:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_esp).convert_to<triton::uint64>();

		case triton::arch::ARCH_X86_64:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_rsp).convert_to<triton::uint64>();

		default:
			throw std::runtime_error("invalid architecture");
	}
}
triton::uint64 VMProtectAnalyzer::get_ip() const
{
	switch (triton_api->getArchitecture())
	{
		case triton::arch::ARCH_X86:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_eip).convert_to<triton::uint64>();

		case triton::arch::ARCH_X86_64:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_rip).convert_to<triton::uint64>();

		default:
			throw std::runtime_error("invalid architecture");
	}
}

void VMProtectAnalyzer::symbolize_registers()
{
	// symbolize all registers;
	if (this->is_x64())
	{
		triton::engines::symbolic::SharedSymbolicVariable symvar_eax = triton_api->symbolizeRegister(triton_api->registers.x86_rax);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ebx = triton_api->symbolizeRegister(triton_api->registers.x86_rbx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ecx = triton_api->symbolizeRegister(triton_api->registers.x86_rcx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_edx = triton_api->symbolizeRegister(triton_api->registers.x86_rdx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_esi = triton_api->symbolizeRegister(triton_api->registers.x86_rsi);
		triton::engines::symbolic::SharedSymbolicVariable symvar_edi = triton_api->symbolizeRegister(triton_api->registers.x86_rdi);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ebp = triton_api->symbolizeRegister(triton_api->registers.x86_rbp);
		triton::engines::symbolic::SharedSymbolicVariable symvar_esp = triton_api->symbolizeRegister(triton_api->registers.x86_rsp);


		triton::engines::symbolic::SharedSymbolicVariable symvar_r8 = triton_api->symbolizeRegister(triton_api->registers.x86_r8);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r9 = triton_api->symbolizeRegister(triton_api->registers.x86_r9);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r10 = triton_api->symbolizeRegister(triton_api->registers.x86_r10);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r11 = triton_api->symbolizeRegister(triton_api->registers.x86_r11);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r12 = triton_api->symbolizeRegister(triton_api->registers.x86_r12);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r13 = triton_api->symbolizeRegister(triton_api->registers.x86_r13);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r14 = triton_api->symbolizeRegister(triton_api->registers.x86_r14);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r15 = triton_api->symbolizeRegister(triton_api->registers.x86_r15);

		symvar_eax->setAlias("rax");
		symvar_ebx->setAlias("rbx");
		symvar_ecx->setAlias("rcx");
		symvar_edx->setAlias("rdx");
		symvar_esi->setAlias("rsi");
		symvar_edi->setAlias("rdi");
		symvar_ebp->setAlias("rbp");
		symvar_esp->setAlias("rsp");
		symvar_r8->setAlias("r8");
		symvar_r9->setAlias("r9");
		symvar_r10->setAlias("r10");
		symvar_r11->setAlias("r11");
		symvar_r12->setAlias("r12");
		symvar_r13->setAlias("r13");
		symvar_r14->setAlias("r14");
		symvar_r15->setAlias("r15");
	}
	else
	{
		triton::engines::symbolic::SharedSymbolicVariable symvar_eax = triton_api->symbolizeRegister(triton_api->registers.x86_eax);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ebx = triton_api->symbolizeRegister(triton_api->registers.x86_ebx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ecx = triton_api->symbolizeRegister(triton_api->registers.x86_ecx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_edx = triton_api->symbolizeRegister(triton_api->registers.x86_edx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_esi = triton_api->symbolizeRegister(triton_api->registers.x86_esi);
		triton::engines::symbolic::SharedSymbolicVariable symvar_edi = triton_api->symbolizeRegister(triton_api->registers.x86_edi);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ebp = triton_api->symbolizeRegister(triton_api->registers.x86_ebp);
		triton::engines::symbolic::SharedSymbolicVariable symvar_esp = triton_api->symbolizeRegister(triton_api->registers.x86_esp);
		symvar_eax->setAlias("eax");
		symvar_ebx->setAlias("ebx");
		symvar_ecx->setAlias("ecx");
		symvar_edx->setAlias("edx");
		symvar_esi->setAlias("esi");
		symvar_edi->setAlias("edi");
		symvar_ebp->setAlias("ebp");
		symvar_esp->setAlias("esp");
	}
}

void VMProtectAnalyzer::load(AbstractStream& stream,
	unsigned long long module_base, unsigned long long vmp0_address, unsigned long long vmp0_size)
{
	// concretize vmp section memory
	unsigned long long vmp_section_address = (module_base + vmp0_address);
	unsigned long long vmp_section_size = vmp0_size;
	void *vmp0 = malloc(vmp_section_size);

	stream.seek(vmp_section_address);
	if (stream.read(vmp0, vmp_section_size) != vmp_section_size)
		throw std::runtime_error("stream.read failed");

	triton_api->setConcreteMemoryAreaValue(vmp_section_address, (const triton::uint8 *)vmp0, vmp_section_size);
	free(vmp0);
}
void VMProtectAnalyzer::analyze_vm_enter(AbstractStream& stream, unsigned long long address)
{
	// reset symbolic
	triton_api->concretizeAllMemory();
	//triton_api->concretizeAllRegister();
	this->symbolize_registers();

	// set esp
	const triton::arch::Register sp_register = this->is_x64() ? triton_api->registers.x86_rsp : triton_api->registers.x86_esp;
	triton_api->setConcreteRegisterValue(sp_register, 0x1000);

	const triton::uint64 previous_sp = this->get_sp();
	bool check_flags = true;

	std::shared_ptr<BasicBlock> basic_block = make_cfg(stream, address);
	for (auto it = basic_block->instructions.begin(); it != basic_block->instructions.end();)
	{
		const std::shared_ptr<x86_instruction> instruction = *it;
		const std::vector<xed_uint8_t> bytes = instruction->get_bytes();

		// fix ip
		if (this->is_x64())
			triton_api->setConcreteRegisterValue(triton_api->registers.x86_rip, instruction->get_addr());
		else
			triton_api->setConcreteRegisterValue(triton_api->registers.x86_eip, instruction->get_addr());

		// do stuff with triton
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], (triton::uint32)bytes.size());
		triton_instruction.setAddress(instruction->get_addr());
		triton_api->processing(triton_instruction);

		// check flags
		if (check_flags)
		{
			// symbolize eflags if pushfd
			if (triton_instruction.getType() == triton::arch::x86::ID_INS_PUSHFD)
			{
				const auto stores = triton_instruction.getStoreAccess();
				if (stores.size() != 1)
					throw std::runtime_error("bluh");

				triton_api->symbolizeMemory(stores.begin()->first)->setAlias("eflags");
			}
			else if (triton_instruction.getType() == triton::arch::x86::ID_INS_PUSHFQ)
			{
				const auto stores = triton_instruction.getStoreAccess();
				if (stores.size() != 1)
					throw std::runtime_error("bluh");

				triton_api->symbolizeMemory(stores.begin()->first)->setAlias("rflags");
			}

			// written_register
			for (const auto &pair : triton_instruction.getWrittenRegisters())
			{
				const triton::arch::Register &written_register = pair.first;
				if (written_register.getId() == triton::arch::ID_REG_X86_EFLAGS)
				{
					check_flags = false;
					break;
				}
			}
		}

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

	const triton::uint64 bp = this->get_bp();
	const triton::uint64 sp = this->get_sp();
	const triton::uint64 scratch_size = bp - sp;
	const triton::uint64 scratch_length = scratch_size / triton_api->getGprSize();
	const triton::uint64 var_length = (previous_sp - bp) / triton_api->getGprSize();
	for (triton::uint64 i = 0; i < var_length; i++)
	{
		triton::ast::SharedAbstractNode mem_ast = triton_api->getMemoryAst(
			triton::arch::MemoryAccess(previous_sp - (i * triton_api->getGprSize()) - triton_api->getGprSize(), triton_api->getGprSize()));
		triton::ast::SharedAbstractNode simplified = triton_api->processSimplification(mem_ast, true);
		if (simplified->getType() == triton::ast::BV_NODE)
		{
			triton::uint64 val = simplified->evaluate().convert_to<triton::uint64>();

			char buf[1024];
			if (this->is_x64())
				sprintf_s(buf, 1024, "push Qword(0x%llX)", val);
			else
				sprintf_s(buf, 1024, "push Dword(0x%llX)", val);
			output_strings.push_back(buf);
		}
		else if (simplified->getType() == triton::ast::VARIABLE_NODE)
		{
			char buf[1024];
			sprintf_s(buf, 1024, "push %s",
				reinterpret_cast<triton::ast::VariableNode *>(simplified.get())->getSymbolicVariable()->getAlias().c_str());
			output_strings.push_back(buf);
		}
		else
		{
			throw std::runtime_error("vm enter error");
		}
	}

	printf("scratch_size: 0x%016llX, scratch_length: %lld\n", scratch_size, scratch_length);
	this->m_scratch_size = scratch_size;
}
void VMProtectAnalyzer::analyze_vm_handler(AbstractStream& stream, unsigned long long handler_address)
{
	// reset
	triton_api->concretizeAllMemory();
	triton_api->concretizeAllRegister();

	// allocate scratch area
	const triton::arch::Register rb_register = this->is_x64() ? triton_api->registers.x86_rbp : triton_api->registers.x86_ebp;
	const triton::arch::Register sp_register = this->is_x64() ? triton_api->registers.x86_rsp : triton_api->registers.x86_esp;
	const triton::arch::Register si_register = this->is_x64() ? triton_api->registers.x86_rsi : triton_api->registers.x86_esi;

	constexpr unsigned long c_stack_base = 0x1000;
	triton_api->setConcreteRegisterValue(rb_register, c_stack_base);
	triton_api->setConcreteRegisterValue(sp_register, c_stack_base - this->m_scratch_size);

	unsigned int arg0 = c_stack_base;
	triton_api->setConcreteMemoryAreaValue(c_stack_base, (const triton::uint8*)&arg0, 4);

	// ebp = VM's "stack" pointer
	triton::engines::symbolic::SharedSymbolicVariable symvar_stack = triton_api->symbolizeRegister(rb_register);

	// esi = pointer to VM bytecode
	triton::engines::symbolic::SharedSymbolicVariable symvar_bytecode = triton_api->symbolizeRegister(si_register);

	symvar_stack->setAlias("stack");
	symvar_bytecode->setAlias("bytecode");

	// yo...
	VMPHandlerContext context;
	context.scratch_area_size = this->is_x64() ? 0x140 : 0x60;
	context.address = handler_address;
	context.stack = triton_api->getConcreteRegisterValue(rb_register).convert_to<triton::uint64>();
	context.bytecode = triton_api->getConcreteRegisterValue(si_register).convert_to<triton::uint64>();
	context.x86_sp = triton_api->getConcreteRegisterValue(sp_register).convert_to<triton::uint64>();
	context.symvar_stack = symvar_stack;
	context.symvar_bytecode = symvar_bytecode;
	//context.symvar_x86_sp = symvar_x86_sp;

	std::shared_ptr<BasicBlock> basic_block;
	auto handler_it = this->m_handlers.find(handler_address);
	if (handler_it == this->m_handlers.end())
	{
		basic_block = make_cfg(stream, handler_address);
		this->m_handlers.insert(std::make_pair(handler_address, basic_block));
	}
	else
	{
		basic_block = handler_it->second;
	}

	for (auto it = basic_block->instructions.begin(); it != basic_block->instructions.end();)
	{
		const std::shared_ptr<x86_instruction> xed_instruction = *it;
		const std::vector<xed_uint8_t> bytes = xed_instruction->get_bytes();

		// do stuff with triton
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], (triton::uint32)bytes.size());
		triton_instruction.setAddress(xed_instruction->get_addr());
		triton_api->processing(triton_instruction);
		if (++it != basic_block->instructions.end())
		{
			// check store
			this->storeAccess(triton_instruction, &context);

			// check load
			this->loadAccess(triton_instruction, &context);

			// loop until it reaches end
			std::cout << "\t" << triton_instruction << std::endl;
			continue;
		}

		if (!xed_instruction->is_branch())
		{
			std::cout << "\t" << triton_instruction << std::endl;
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

	this->categorize_handler(&context);
}
void VMProtectAnalyzer::analyze_vm_exit(unsigned long long handler_address)
{
	// not the best impl but faspofkapwskefo
	std::stack<x86_register> modified_registers;
	const triton::arch::Register rb_register = this->is_x64() ? triton_api->registers.x86_rbp : triton_api->registers.x86_ebp;
	const triton::uint64 previous_stack = triton_api->getConcreteRegisterValue(rb_register).convert_to<triton::uint64>();

	std::shared_ptr<BasicBlock> basic_block = this->m_handlers[handler_address];
	for (auto it = basic_block->instructions.begin(); it != basic_block->instructions.end();)
	{
		const auto instruction = *it;
		const std::vector<xed_uint8_t> bytes = instruction->get_bytes();

		// do stuff with triton
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], (triton::uint32)bytes.size());
		triton_instruction.setAddress(instruction->get_addr());
		triton_api->processing(triton_instruction);

		std::vector<x86_register> written_registers = instruction->get_written_registers();
		for (const auto& reg : written_registers)
		{
			if (this->is_x64())
			{
				if ((reg == XED_REG_RFLAGS || reg.get_gpr_class() == XED_REG_CLASS_GPR64) && reg != XED_REG_RSP)
				{
					modified_registers.push(reg);
				}
			}
			else
			{
				if ((reg == XED_REG_EFLAGS || reg.get_gpr_class() == XED_REG_CLASS_GPR32) && reg != XED_REG_ESP)
				{
					modified_registers.push(reg);
				}
			}
		}

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

	std::set<x86_register> _set;
	std::stack<x86_register> _final;
	while (!modified_registers.empty())
	{
		x86_register r = modified_registers.top();
		modified_registers.pop();

		if (_set.count(r) == 0)
		{
			_set.insert(r);
			_final.push(r);
		}
	}

	while (!_final.empty())
	{
		x86_register r = _final.top();
		_final.pop();

		std::string s = "pop " + std::string(r.get_name());
		this->output_strings.push_back(s);
	}
	this->output_strings.push_back("ret");
}

void VMProtectAnalyzer::loadAccess(triton::arch::Instruction &triton_instruction, VMPHandlerContext *context)
{
	const auto& loadAccess = triton_instruction.getLoadAccess();
	for (const std::pair<triton::arch::MemoryAccess, triton::ast::SharedAbstractNode>& pair : loadAccess)
	{
		const triton::arch::MemoryAccess &mem = pair.first;
		const triton::ast::SharedAbstractNode &mem_ast = pair.second;
		const triton::uint64 address = mem.getAddress();
		triton::ast::SharedAbstractNode lea_ast = mem.getLeaAst();
		if (!lea_ast)
		{
			// most likely can be ignored
			continue;
		}

		lea_ast = triton_api->processSimplification(lea_ast, true);
		if (!lea_ast->isSymbolized())
		{
			// most likely can be ignored
			continue;
		}

		const triton::arch::Register& dest_register = this->get_dest_register(triton_instruction);
		if (context->is_bytecode_address(lea_ast))
		{
			switch (mem.getSize())
			{
				case 1:
				case 2:
				case 4:
				case 8:
				{
					// valid mem size
					break;
				}
				default:
				{
					std::stringstream ss;
					ss << "invalid mem size";
					throw std::runtime_error(ss.str());
				}
			}

			// symbolize register as bytecode
			std::string alias = "bytecode-" + std::to_string(mem.getSize());
			const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
			symvar->setAlias(alias);
			context->bytecodes.insert(std::make_pair(symvar->getId(), symvar));

			printf("loads %dbytes from bytecode, stores to %s\n", mem.getSize(), dest_register.getName().c_str());
		}
		else if (context->is_scratch_area(lea_ast))
		{
			unsigned long long offset = lea_ast->evaluate().convert_to<unsigned long long>() - context->x86_sp;

			char var_name[64];
			sprintf_s(var_name, 64, "VM_VAR_%lld", offset);

			const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
			symvar->setAlias(var_name);
			context->vmvars.insert(std::make_pair(symvar->getId(), symvar));

			std::cout << dest_register.getName() << "= [x86_sp + 0x" << std::hex << offset << "]" << std::endl;
		}
		else if (context->is_stack_address(lea_ast))
		{
			unsigned long long arg_offset = address - context->stack;
			if (arg_offset == 0)
			{
				printf("loads arg0 to %s\n", dest_register.getName().c_str());
				const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
				symvar->setAlias("arg0");
				context->arguments.insert(std::make_pair(symvar->getId(), symvar));
			}
			else if (arg_offset == 2)
			{
				printf("loads arg1 to %s\n", dest_register.getName().c_str());
				const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
				symvar->setAlias("arg1");
				context->arguments.insert(std::make_pair(symvar->getId(), symvar));
			}
			else if (arg_offset == 4)
			{
				printf("loads arg1 to %s\n", dest_register.getName().c_str());
				const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
				symvar->setAlias("arg1");
				context->arguments.insert(std::make_pair(symvar->getId(), symvar));
			}
			else if (arg_offset == 8)
			{
				printf("loads arg2 to %s\n", dest_register.getName().c_str());
				const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
				symvar->setAlias("arg2");
				context->arguments.insert(std::make_pair(symvar->getId(), symvar));
			}
			else
			{
				printf("%016llX\n", arg_offset);
				throw std::runtime_error("ikdaidfjoajsdofijowesfawef");
			}
		}
		else if (context->is_fetch_arguments(lea_ast))
		{
			if (mem.getConstSegmentRegister().getId() == triton::arch::ID_REG_INVALID)
			{
				// DS?
			}

			std::string alias = "fetch_" + mem.getConstSegmentRegister().getName() + ":"
				+ reinterpret_cast<triton::ast::VariableNode *>(lea_ast.get())->getSymbolicVariable()->getAlias();
			const triton::arch::Register &segment_register = mem.getConstSegmentRegister();

			const triton::arch::Register& dest_register = this->get_dest_register(triton_instruction);
			const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
			symvar->setAlias(alias);
			context->fetched.insert(std::make_pair(symvar->getId(), symvar));

			printf("fetched to %s\n", dest_register.getName().c_str());
		}
		else
		{
			std::cout << triton_instruction << std::endl;
			std::cout << lea_ast << std::endl;
			//throw std::runtime_error("unknown memory read has found.");
		}
	}
}
void VMProtectAnalyzer::storeAccess(triton::arch::Instruction &triton_instruction, VMPHandlerContext *context)
{
	const auto& storeAccess = triton_instruction.getStoreAccess();
	for (const std::pair<triton::arch::MemoryAccess, triton::ast::SharedAbstractNode>& pair : storeAccess)
	{
		const triton::arch::MemoryAccess &mem = pair.first;
		const triton::ast::SharedAbstractNode &mem_ast = pair.second;
		const triton::uint64 address = mem.getAddress();
		triton::ast::SharedAbstractNode lea_ast = mem.getLeaAst();
		if (!lea_ast)
		{
			// most likely can be ignored
			continue;
		}

		lea_ast = triton_api->processSimplification(lea_ast, true);
		if (!lea_ast->isSymbolized())
		{
			// most likely can be ignored
			continue;
		}

		if (context->is_scratch_area(lea_ast))
		{
			// mov MEM, REG
			const triton::arch::Register& source_register = this->get_source_register(triton_instruction);
			const triton::ast::SharedAbstractNode register_ast = triton_api->processSimplification(triton_api->getRegisterAst(source_register), true);
			context->insert_scratch(lea_ast, register_ast);

			unsigned long long offset = lea_ast->evaluate().convert_to<unsigned long long>() - context->x86_sp;
			std::cout << "[x86_sp + 0x" << std::hex << offset << "] = " << register_ast << std::endl;
		}
		else if (context->is_stack_address(lea_ast))
		{
			// stores to stack
			const triton::arch::Register& source_register = this->get_source_register(triton_instruction);
			const triton::ast::SharedAbstractNode register_ast = triton_api->processSimplification(triton_api->getRegisterAst(source_register), true);
			context->insert_scratch(lea_ast, register_ast);
			std::cout << "[" << lea_ast << "]=" << register_ast << std::endl;
		}
		else if (context->is_fetch_arguments(lea_ast))
		{
			// mov MEM, REG
			const triton::arch::Register& source_register = this->get_source_register(triton_instruction);
			const triton::ast::SharedAbstractNode register_ast = triton_api->processSimplification(triton_api->getRegisterAst(source_register), true);
			context->insert_scratch(lea_ast, register_ast);

			std::cout << "[" << lea_ast << "]=" << register_ast << std::endl;
		}
		else
		{
			std::cout << lea_ast << std::endl;
		}
	}
}
void VMProtectAnalyzer::categorize_handler(VMPHandlerContext *context)
{
	const triton::arch::Register rb_register = this->is_x64() ? triton_api->registers.x86_rbp : triton_api->registers.x86_ebp;
	const triton::arch::Register sp_register = this->is_x64() ? triton_api->registers.x86_rsp : triton_api->registers.x86_esp;
	const triton::arch::Register si_register = this->is_x64() ? triton_api->registers.x86_rsi : triton_api->registers.x86_esi;
	const triton::uint64 bytecode = triton_api->getConcreteRegisterValue(si_register).convert_to<triton::uint64>();
	const triton::uint64 sp = triton_api->getConcreteRegisterValue(sp_register).convert_to<triton::uint64>();
	const triton::uint64 stack = triton_api->getConcreteRegisterValue(rb_register).convert_to<triton::uint64>();

	std::cout << "handlers outputs:" << std::endl;
	printf("\tbytecode: 0x%016llX -> 0x%016llX\n", context->bytecode, bytecode);
	if (std::abs(long long(context->bytecode - bytecode)) > 16)
	{
		// jmp handler?
	}
	printf("\tsp: 0x%016llX -> 0x%016llX\n", context->x86_sp, sp);
	printf("\tstack: 0x%016llX -> 0x%016llX\n", context->stack, stack);
	for (const auto &pair : context->destinations)
	{
		std::cout << "\t" << pair.second.first << "(0x" << std::hex << pair.first << ")="
			<< triton_api->processSimplification(pair.second.second, true) << std::endl;
	}

	bool handler_detected = false;
	auto it = context->destinations.begin();
	if (context->destinations.size() == 0)
	{
		const triton::ast::SharedAbstractNode simplified_stack_ast =
			triton_api->processSimplification(triton_api->getRegisterAst(rb_register), true);

		const triton::ast::SharedAbstractNode simplified_sp_ast =
			triton_api->processSimplification(triton_api->getRegisterAst(sp_register), true);

		const triton::ast::SharedAbstractNode simplified_bytecode_ast =
			triton_api->processSimplification(triton_api->getRegisterAst(si_register), true);

		if (simplified_stack_ast->getType() == triton::ast::VARIABLE_NODE
			&& reinterpret_cast<triton::ast::VariableNode *>(simplified_stack_ast.get())->getSymbolicVariable()->getAlias() == "arg0")
		{
			// EBP is loaded from ARG0
			std::cout << "Store SP handler detected" << std::endl;
			output_strings.push_back("pop esp"); // XD
			handler_detected = true;
		}
		else
		{
			std::set<triton::ast::SharedAbstractNode> symvars = context->collect_symvars(simplified_sp_ast);
			if (symvars.size() == 1)
			{
				triton::ast::VariableNode *varnode = reinterpret_cast<triton::ast::VariableNode *>(symvars.begin()->get());
				if (varnode->getSymbolicVariable()->getId() == context->symvar_stack->getId())
				{
					// sp = computed by stack
					analyze_vm_exit(context->address);
					std::cout << "Ret handler detected" << std::endl;
					handler_detected = true;
				}
			}

			symvars = context->collect_symvars(simplified_bytecode_ast);
			if (symvars.size() == 1)
			{
				triton::ast::VariableNode *varnode = reinterpret_cast<triton::ast::VariableNode *>(symvars.begin()->get());
				if (context->arguments.find(varnode->getSymbolicVariable()->getId()) != context->arguments.end())
				{
					// bytecode can be computed by arg -> Jmp handler perhaps
					std::cout << "Jmp handler detected" << std::endl;
					handler_detected = true;
				}
			}
		}
	}
	else if (context->destinations.size() == 1)
	{
		const triton::ast::SharedAbstractNode simplified = triton_api->processSimplification(it->second.second, true);
		std::set<triton::ast::SharedAbstractNode> symvars = context->collect_symvars(simplified);

		// check if push handlers
		triton::sint64 stack_offset = stack - context->stack;	// needs to be signed
		const triton::uint64 runtime_address = it->first;
		if (context->is_result_address(runtime_address) && stack_offset < 0)
		{
			// push handlers
			if (simplified->getType() == triton::ast::VARIABLE_NODE)
			{
				triton::ast::VariableNode *varnode = reinterpret_cast<triton::ast::VariableNode *>(simplified.get());
				if (context->vmvars.find(varnode->getSymbolicVariable()->getId()) != context->vmvars.end())
				{
					// push VM_VAR
					std::cout << "push VM_VAR handler detected" << std::endl;
					handler_detected = true;

					// disgusting impl
					auto xd = varnode->getSymbolicVariable()->getAlias().find("VM_VAR_");
					if (xd != std::string::npos)
					{
						unsigned long long vm_var_offset = std::stoi(varnode->getSymbolicVariable()->getAlias().substr(xd + strlen("VM_VAR_")));
						char buf[256];
						if (stack_offset == (-8))
							sprintf_s(buf, 256, "push qdword Scratch:[0x%llX]", vm_var_offset);
						else if (stack_offset == (-4))
							sprintf_s(buf, 256, "push dword Scratch:[0x%llX]", vm_var_offset);
						output_strings.push_back(buf);
					}
					else
					{
						output_strings.push_back("push DWORD Scratch:[DWORD(idk)]");
					}
				}
				else if (varnode->getSymbolicVariable()->getAlias() == "stack")
				{
					// push stack(ebp)
					std::cout << "push SP handler detected" << std::endl;
					handler_detected = true;

					// dbg
					output_strings.push_back("push " + sp_register.getName());
				}
			}
			else if (symvars.size() == 1)
			{
				triton::ast::VariableNode *varnode = reinterpret_cast<triton::ast::VariableNode *>(symvars.begin()->get());
				if (context->bytecodes.find(varnode->getSymbolicVariable()->getId()) != context->bytecodes.end())
				{
					// node is constructed by single bytecode, -> it's considered const
					if (stack_offset == (-8))
					{
						const triton::uint64 immediate = simplified->evaluate().convert_to<triton::uint64>();
						std::cout << "push Qword(" << immediate << ") handler detected" << std::endl;
						handler_detected = true;

						// dbg
						char buf[256];
						sprintf_s(buf, 256, "push Qword(0x%llX)", immediate);
						output_strings.push_back(buf);
					}
					else if (stack_offset == (-4))
					{
						const triton::uint64 immediate = simplified->evaluate().convert_to<triton::uint64>();
						std::cout << "push Dword(" << immediate << ") handler detected" << std::endl;
						handler_detected = true;

						// dbg
						char buf[256];
						sprintf_s(buf, 256, "push Dword(0x%llX)", immediate);
						output_strings.push_back(buf);
					}
					else if (stack_offset == (-2))
					{
						const triton::uint64 immediate = simplified->evaluate().convert_to<triton::uint64>();
						std::cout << "push Word(" << immediate << ") handler detected" << std::endl;
						handler_detected = true;

						// dbg
						char buf[256];
						sprintf_s(buf, 256, "push Word(0x%llX)", immediate);
						output_strings.push_back(buf);
					}
					else
					{
						throw std::runtime_error("invalid stack offset");
					}
				}
			}

			if (!handler_detected)
			{
				std::cout << "unknown push handler detected" << std::endl;
			}
		}

		if (simplified->getType() == triton::ast::VARIABLE_NODE)
		{
			triton::ast::VariableNode *varnode = reinterpret_cast<triton::ast::VariableNode *>(simplified.get());
			if (context->is_scratch_area_address(runtime_address)
				&& stack_offset == 8
				&& varnode->getSymbolicVariable()->getAlias() == "arg0")
			{
				// POP [VM_VAR]
				std::cout << "pop qword [VM_VAR] handler detected" << std::endl;
				handler_detected = true;

				// dbg
				char buf[256];
				sprintf_s(buf, 256, "pop qword Scratch:[0x%llX]", it->first - context->x86_sp);
				output_strings.push_back(buf);
			}

			else if (context->is_scratch_area_address(runtime_address)
				&& stack_offset == 4
				&& varnode->getSymbolicVariable()->getAlias() == "arg0")
			{
				// POP [VM_VAR]
				std::cout << "pop dword ptr [VM_VAR] handler detected" << std::endl;
				handler_detected = true;

				// dbg
				char buf[256];
				sprintf_s(buf, 256, "pop dword Scratch:[0x%llX]", it->first - context->x86_sp);
				output_strings.push_back(buf);
			}

			else if (runtime_address == context->stack
				&& context->stack == stack
				&& varnode->getSymbolicVariable()->getAlias() == "fetch_ss:arg0")	// holy fuck
			{
				// pop t0
				// push dword ss:[t0]
				std::cout << "fetch ss handler detected" << std::endl;
				handler_detected = true;

				// pop t0
				std::string variable_name = "t" + std::to_string(++this->m_temp);
				char buf[256];
				sprintf_s(buf, 256, "pop %s", variable_name.c_str());
				output_strings.push_back(buf);

				// push DWORD SS:[t0]
				sprintf_s(buf, 256, "push SS:[%s]", variable_name.c_str());
				output_strings.push_back(buf);
			}

			else if (runtime_address == context->stack
				&& context->stack == stack
				&& varnode->getSymbolicVariable()->getAlias() == "fetch_unknown:arg0")	// holy fuck
			{
				// t = pop()
				// t1 = fetch(t)
				// push(t1)
				std::cout << "fetch handler detected" << std::endl;
				handler_detected = true;

				// pop t0
				std::string variable_name = "t" + std::to_string(++this->m_temp);
				char buf[256];
				sprintf_s(buf, 256, "pop %s", variable_name.c_str());
				output_strings.push_back(buf);

				// push DWORD SS:[t0]
				sprintf_s(buf, 256, "push dword ptr [%s]", variable_name.c_str());
				output_strings.push_back(buf);
			}
			else if (runtime_address == (context->stack + 2)
				&& context->stack == (stack - 2)
				&& varnode->getSymbolicVariable()->getAlias() == "fetch_unknown:arg0")
			{
				// pop t0
				// push word ptr [t0]
				std::cout << "fetch2 handler detected" << std::endl;
				handler_detected = true;

				// pop t0
				std::string variable_name = "t" + std::to_string(++this->m_temp);
				char buf[256];
				sprintf_s(buf, 256, "pop %s", variable_name.c_str());
				output_strings.push_back(buf);

				// push DWORD SS:[t0]
				sprintf_s(buf, 256, "push word ptr [%s]", variable_name.c_str());
				output_strings.push_back(buf);
			}

			else if (stack_offset == 8) // this needs to be updated
			{
				// pop t0
				// pop t1
				// [t0] = t1
				std::string t0 = "t" + std::to_string(++this->m_temp);
				std::string t1 = "t" + std::to_string(++this->m_temp);

				// push dword ss:[t0]
				std::cout << "write4 handler detected" << std::endl;
				handler_detected = true;

				// pop t0
				char buf[256];
				sprintf_s(buf, 256, "pop %s", t0.c_str());
				output_strings.push_back(buf);

				// pop t1
				sprintf_s(buf, 256, "pop %s", t1.c_str());
				output_strings.push_back(buf);

				// [t1] = t0
				sprintf_s(buf, 256, "[%s] = %s", t0.c_str(), t1.c_str());
				output_strings.push_back(buf);
			}
		}

	}
	else if (context->destinations.size() == 2)
	{
		for (; it != context->destinations.end(); it++)
		{
			const triton::ast::SharedAbstractNode simplified = triton_api->processSimplification(it->second.second, true);
			std::set<triton::ast::SharedAbstractNode> symvars = context->collect_symvars(simplified);
			if (symvars.size() == 2) // binary operations
			{
				// (bvadd arg0 arg1)
				if (simplified->getType() == triton::ast::BVADD_NODE)
				{
					// add handler right?
					std::vector<triton::ast::SharedAbstractNode>& add_children = simplified->getChildren();
					if (add_children.size() == 2
						&& add_children[0]->getType() == triton::ast::VARIABLE_NODE
						&& add_children[1]->getType() == triton::ast::VARIABLE_NODE)
					{
						std::cout << "ADD handler detected" << std::endl;
						handler_detected = true;

						// t0 = pop
						// t1 = pop
						// t2 = t0 + t1
						// push t2
						// push flags t2
						std::string t0 = "t" + std::to_string(++this->m_temp);
						std::string t1 = "t" + std::to_string(++this->m_temp);
						std::string t2 = "t" + std::to_string(++this->m_temp);

						// pop pop add push push
						// dbg
						char buf[256];
						sprintf_s(buf, 256, "pop %s", t0.c_str());
						output_strings.push_back(buf);

						sprintf_s(buf, 256, "pop %s", t1.c_str());
						output_strings.push_back(buf);

						sprintf_s(buf, 256, "%s = %s + %s", t2.c_str(), t0.c_str(), t1.c_str());
						output_strings.push_back(buf);

						sprintf_s(buf, 256, "push %s", t2.c_str());
						output_strings.push_back(buf);

						sprintf_s(buf, 256, "push flags %s", t2.c_str());
						output_strings.push_back(buf);
					}
				}
				else if (simplified->getType() == triton::ast::BVLSHR_NODE)
				{
					// (bvlshr arg0 (concat (_ bv0 1B) ((_ extract 4 0) arg1)))
					std::cout << "SHR handler detected" << std::endl;
					handler_detected = true;

					// t0 = pop
					// t1 = pop
					// t2 = t0 << t1
					// push t2
					// push flags t2
					std::string t0 = "t" + std::to_string(++this->m_temp);
					std::string t1 = "t" + std::to_string(++this->m_temp);
					std::string t2 = "t" + std::to_string(++this->m_temp);

					// pop pop add push push
					// dbg
					char buf[256];
					sprintf_s(buf, 256, "pop %s", t0.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "pop %s", t1.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "%s = SHR(%s, %s)", t2.c_str(), t0.c_str(), t1.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "push %s", t2.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "push flags %s", t2.c_str());
					output_strings.push_back(buf);
				}
				else if (simplified->getType() == triton::ast::BVNOT_NODE)
				{
					// (bvnot (bvor arg0 arg1))
					std::cout << "NOR handler detected" << std::endl;
					handler_detected = true;

					// t0 = pop
					// t1 = pop
					// t2 = ~t0 & ~t1
					// push t2
					// push flags t2
					std::string t0 = "t" + std::to_string(++this->m_temp);
					std::string t1 = "t" + std::to_string(++this->m_temp);
					std::string t2 = "t" + std::to_string(++this->m_temp);

					// pop pop add push push
					// dbg
					char buf[256];
					sprintf_s(buf, 256, "pop %s", t0.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "pop %s", t1.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "%s = NOR(%s, %s)", t2.c_str(), t0.c_str(), t1.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "push %s", t2.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "push flags %s", t2.c_str());
					output_strings.push_back(buf);
				}
			}
		}
	}
	else if (context->destinations.size() == 3)
	{
		for (; it != context->destinations.end(); it++)
		{
			const triton::ast::SharedAbstractNode simplified = triton_api->processSimplification(it->second.second, true);
			std::set<triton::ast::SharedAbstractNode> symvars = context->collect_symvars(simplified);
			if (symvars.size() == 2)
			{
				// (bvmul arg1 arg0)
				if (simplified->getType() == triton::ast::BVMUL_NODE)
				{
					// add handler right?
					std::vector<triton::ast::SharedAbstractNode>& add_children = simplified->getChildren();
					if (add_children.size() == 2
						&& add_children[0]->getType() == triton::ast::VARIABLE_NODE
						&& add_children[1]->getType() == triton::ast::VARIABLE_NODE)
					{
						std::cout << "(MUL/IMUL) handler detected" << std::endl;
						handler_detected = true;

						// dbg
						char buf[256];
						sprintf_s(buf, 256, "mul/imul(x, y)");
						output_strings.push_back(buf);
					}
				}
			}
		}
	}

	if (!handler_detected)
	{
		this->print_output();
		getchar();
	}
}