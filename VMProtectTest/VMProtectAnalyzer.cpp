#include "pch.h"

#include "VMProtectAnalyzer.hpp"
#include "x86_instruction.hpp"
#include "AbstractStream.hpp"
#include "CFG.hpp"
#include "IR.hpp"

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

// variablenode?
triton::engines::symbolic::SharedSymbolicVariable get_symbolic_var(const triton::ast::SharedAbstractNode &node)
{
	return node->getType() == triton::ast::VARIABLE_NODE ? 
		std::dynamic_pointer_cast<triton::ast::VariableNode>(node)->getSymbolicVariable() : nullptr;
}
std::set<triton::ast::SharedAbstractNode> collect_symvars(const triton::ast::SharedAbstractNode &parent)
{
	std::set<triton::ast::SharedAbstractNode> result;
	if (!parent)
		return result;

	if (parent->getChildren().empty() && parent->isSymbolized())
	{
		// this must be variable node right?
		assert(parent->getType() == triton::ast::VARIABLE_NODE);
		result.insert(parent);
	}

	for (const triton::ast::SharedAbstractNode &child : parent->getChildren())
	{
		if (!child->getChildren().empty())
		{
			// go deep if symbolized
			if (child->isSymbolized())
			{
				auto _new = collect_symvars(child);
				result.insert(_new.begin(), _new.end());
			}
		}
		else if (child->isSymbolized())
		{
			// this must be variable node right?
			assert(child->getType() == triton::ast::VARIABLE_NODE);
			result.insert(child);
		}
	}
	return result;
}
bool is_unary_operation(const triton::arch::Instruction &triton_instruction)
{
	switch (triton_instruction.getType())
	{
		case triton::arch::x86::ID_INS_INC:
		case triton::arch::x86::ID_INS_DEC:
		case triton::arch::x86::ID_INS_NEG:
		case triton::arch::x86::ID_INS_NOT:
			return true;

		default:
			return false;
	}
}
bool is_binary_operation(const triton::arch::Instruction &triton_instruction)
{
	switch (triton_instruction.getType())
	{
		case triton::arch::x86::ID_INS_ADD:
		case triton::arch::x86::ID_INS_SUB:
		case triton::arch::x86::ID_INS_SHL:
		case triton::arch::x86::ID_INS_SHR:
		case triton::arch::x86::ID_INS_RCR:
		case triton::arch::x86::ID_INS_RCL:
		case triton::arch::x86::ID_INS_ROL:
		case triton::arch::x86::ID_INS_ROR:
		case triton::arch::x86::ID_INS_AND:
		case triton::arch::x86::ID_INS_OR:
		case triton::arch::x86::ID_INS_XOR:
		case triton::arch::x86::ID_INS_CMP:
		case triton::arch::x86::ID_INS_TEST:
			return true;

		default:
			return false;
	}
}


// VMProtectAnalyzer
VMProtectAnalyzer::VMProtectAnalyzer(triton::arch::architecture_e arch)
{
	triton_api = std::make_shared<triton::API>();
	triton_api->setArchitecture(arch);
	triton_api->setMode(triton::modes::ALIGNED_MEMORY, true);
	//triton_api->setAstRepresentationMode(triton::ast::representations::PYTHON_REPRESENTATION);
	this->m_scratch_size = 0;
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

triton::arch::Register VMProtectAnalyzer::get_bp_register() const
{
	return this->is_x64() ? triton_api->registers.x86_rbp : triton_api->registers.x86_ebp;
}
triton::arch::Register VMProtectAnalyzer::get_sp_register() const
{
	const triton::arch::CpuInterface *_cpu = triton_api->getCpuInstance();
	if (!_cpu)
		throw std::runtime_error("CpuInterface is nullptr");

	return _cpu->getStackPointer();
}
triton::arch::Register VMProtectAnalyzer::get_ip_register() const
{
	const triton::arch::CpuInterface *_cpu = triton_api->getCpuInstance();
	if (!_cpu)
		throw std::runtime_error("CpuInterface is nullptr");

	return _cpu->getProgramCounter();
}

triton::uint64 VMProtectAnalyzer::get_bp() const
{
	return triton_api->getConcreteRegisterValue(this->get_bp_register()).convert_to<triton::uint64>();
}
triton::uint64 VMProtectAnalyzer::get_sp() const
{
	return triton_api->getConcreteRegisterValue(this->get_sp_register()).convert_to<triton::uint64>();
}
triton::uint64 VMProtectAnalyzer::get_ip() const
{
	return triton_api->getConcreteRegisterValue(this->get_ip_register()).convert_to<triton::uint64>();
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
		//triton::engines::symbolic::SharedSymbolicVariable symvar_esp = triton_api->symbolizeRegister(triton_api->registers.x86_rsp);

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
		//symvar_esp->setAlias("rsp");
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
		//triton::engines::symbolic::SharedSymbolicVariable symvar_esp = triton_api->symbolizeRegister(triton_api->registers.x86_esp);
		symvar_eax->setAlias("eax");
		symvar_ebx->setAlias("ebx");
		symvar_ecx->setAlias("ecx");
		symvar_edx->setAlias("edx");
		symvar_esi->setAlias("esi");
		symvar_edi->setAlias("edi");
		symvar_ebp->setAlias("ebp");
		//symvar_esp->setAlias("esp");
	}
}

const triton::arch::Register& VMProtectAnalyzer::get_source_register(const triton::arch::Instruction &triton_instruction) const
{
	if (triton_instruction.getType() == triton::arch::x86::ID_INS_POP)
	{
		// idk...
		return  triton_api->registers.x86_eflags;
	}

	if (triton_instruction.getType() != triton::arch::x86::ID_INS_MOV)
	{
		std::stringstream ss;
		ss << "memory has written by undefined opcode\n"
			<< "\t" << triton_instruction << "\"\n"
			<< "\tFile: " << __FILE__ << ", L: " << __LINE__;
		throw std::runtime_error(ss.str());
	}

	// mov MEM,REG
	const std::vector<triton::arch::OperandWrapper> &operands = triton_instruction.operands;
	if (operands.size() != 2
		|| operands[0].getType() != triton::arch::OP_MEM
		|| operands[1].getType() != triton::arch::OP_REG)
	{
		std::stringstream ss;
		ss << "memory has written by unknown instruction\n"
			<< "\t" << triton_instruction << "\"\n"
			<< "\tFile: " << __FILE__ << ", L: " << __LINE__;
		throw std::runtime_error(ss.str());
	}
	return operands[1].getConstRegister();
}
const triton::arch::Register& VMProtectAnalyzer::get_dest_register(const triton::arch::Instruction &triton_instruction) const
{
	const triton::uint32 instruction_type = triton_instruction.getType();
	if (instruction_type != triton::arch::x86::ID_INS_MOV
		&& instruction_type != triton::arch::x86::ID_INS_MOVZX)
	{
		std::stringstream ss;
		ss << "memory has read by undefined opcode\n"
			<< "\t" << triton_instruction << "\"\n"
			<< "\tFile: " << __FILE__ << ", L: " << __LINE__;
		throw std::runtime_error(ss.str());
	}

	// [mov|movzx] REG,MEM
	const std::vector<triton::arch::OperandWrapper> &operands = triton_instruction.operands;
	if (operands.size() != 2
		|| operands[0].getType() != triton::arch::OP_REG
		|| operands[1].getType() != triton::arch::OP_MEM)
	{
		std::stringstream ss;
		ss << "memory has read by unknown instruction\n"
			<< "\t" << triton_instruction << "\"\n"
			<< "\tFile: " << __FILE__ << ", L: " << __LINE__;
		throw std::runtime_error(ss.str());
	}
	return operands[0].getConstRegister();
}

bool VMProtectAnalyzer::is_bytecode_address(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context)
{
	// return true if lea_ast is constructed by bytecode
	const std::set<triton::ast::SharedAbstractNode> symvars = collect_symvars(lea_ast);
	if (symvars.empty())
		return false;

	for (auto it = symvars.begin(); it != symvars.end(); ++it)
	{
		const triton::ast::SharedAbstractNode &node = *it;
		const triton::engines::symbolic::SharedSymbolicVariable &symvar = std::dynamic_pointer_cast<triton::ast::VariableNode>(node)->getSymbolicVariable();
		if (symvar->getId() != context->symvar_bytecode->getId())
			return false;
	}
	return true;
}
bool VMProtectAnalyzer::is_stack_address(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context)
{
	// return true if lea_ast is constructed by stack
	const std::set<triton::ast::SharedAbstractNode> symvars = collect_symvars(lea_ast);
	if (symvars.empty())
		return false;

	for (auto it = symvars.begin(); it != symvars.end(); ++it)
	{
		const triton::ast::SharedAbstractNode &node = *it;
		const triton::engines::symbolic::SharedSymbolicVariable &symvar = std::dynamic_pointer_cast<triton::ast::VariableNode>(node)->getSymbolicVariable();
		if (symvar != context->symvar_stack)
			return false;
	}
	return true;
}
bool VMProtectAnalyzer::is_scratch_area_address(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context)
{
	// size is hardcoded for now (can see in any push handler perhaps)
	const triton::uint64 runtime_address = lea_ast->evaluate().convert_to<triton::uint64>();
	return context->x86_sp <= runtime_address && runtime_address < (context->x86_sp + context->scratch_area_size);
}
bool VMProtectAnalyzer::is_fetch_arguments(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context)
{
	if (lea_ast->getType() != triton::ast::VARIABLE_NODE)
		return false;

	const triton::engines::symbolic::SharedSymbolicVariable &symvar =
		std::dynamic_pointer_cast<triton::ast::VariableNode>(lea_ast)->getSymbolicVariable();
	return context->arguments.find(symvar->getId()) != context->arguments.end();
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

// vm-enter
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
		triton_api->setConcreteRegisterValue(this->get_ip_register(), instruction->get_addr());

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

		if (instruction->get_category() != XED_CATEGORY_UNCOND_BR || instruction->get_branch_displacement_width() == 0)
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
				std::dynamic_pointer_cast<triton::ast::VariableNode>(simplified)->getSymbolicVariable()->getAlias().c_str());
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


// vm-handler
void VMProtectAnalyzer::symbolize_memory(const triton::arch::MemoryAccess& mem, VMPHandlerContext *context)
{
	const triton::uint64 address = mem.getAddress();
	triton::ast::SharedAbstractNode lea_ast = mem.getLeaAst();
	if (!lea_ast)
	{
		// most likely can be ignored
		return;
	}

	lea_ast = triton_api->processSimplification(lea_ast, true);
	if (!lea_ast->isSymbolized())
	{
		// most likely can be ignored
		return;
	}

	if (this->is_bytecode_address(lea_ast, context))
	{
		// bytecode can be considered const value
		triton_api->taintMemory(mem);
	}

	// lea_ast = context + const
	else if (this->is_scratch_area_address(lea_ast, context))
	{
		// [EBP+offset]
		const triton::uint64 scratch_offset = lea_ast->evaluate().convert_to<triton::uint64>() - context->x86_sp;

		triton::engines::symbolic::SharedSymbolicVariable symvar_vmreg = triton_api->symbolizeMemory(mem);
		context->scratch_variables.insert(std::make_pair(symvar_vmreg->getId(), symvar_vmreg));
		std::cout << "Load Scratch:[0x" << std::hex << scratch_offset << "]" << std::endl;

		// TempVar = VM_REG
		auto temp_variable = IR::Variable::create_variable(mem.getSize());

		auto ir_imm = std::make_shared<IR::Immediate>(scratch_offset);
		std::shared_ptr<IR::Expression> right_expression = std::make_shared<IR::Memory>(ir_imm, IR::ir_segment_scratch, (IR::ir_size)mem.getSize());

		auto assign = std::make_shared<IR::Assign>(temp_variable, right_expression);
		context->m_statements.push_back(assign);
		context->m_expression_map[symvar_vmreg->getId()] = temp_variable;
		symvar_vmreg->setAlias(temp_variable->get_name());
	}
	else if (this->is_stack_address(lea_ast, context))
	{
		const triton::uint64 offset = address - context->stack;

		triton::engines::symbolic::SharedSymbolicVariable symvar_arg = triton_api->symbolizeMemory(mem);
		context->arguments.insert(std::make_pair(symvar_arg->getId(), symvar_arg));
		std::cout << "Load [EBP+0x" << std::hex << offset << "]" << std::endl;

		// test i guess
		char v[1024];
		sprintf_s(v, 1024, "[SP+0x%llX]", offset);

		// TempVar = ARG (possibly pop)
		auto temp_variable = IR::Variable::create_variable(mem.getSize());
		auto assign = std::make_shared<IR::Assign>(temp_variable, std::make_shared<IR::Variable>(v, (IR::ir_size)mem.getSize()));
		context->m_statements.push_back(assign);
		context->m_expression_map[symvar_arg->getId()] = temp_variable;
		symvar_arg->setAlias(temp_variable->get_name());
	}
	else if (this->is_fetch_arguments(lea_ast, context))
	{
		// lea_ast == VM_REG_X
		triton::arch::Register segment_register = mem.getConstSegmentRegister();
		if (segment_register.getId() == triton::arch::ID_REG_INVALID)
		{
			// DS?
			//segment_register = triton_api->registers.x86_ds;
		}
		triton::engines::symbolic::SharedSymbolicVariable symvar_source = get_symbolic_var(lea_ast);

		const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeMemory(mem);
		std::cout << "Deref(" << lea_ast << "," << segment_register.getName() << ")" << std::endl;

		// IR
		auto it = context->m_expression_map.find(symvar_source->getId());
		if (it == context->m_expression_map.end())
			throw std::runtime_error("what do you mean");

		// declare Temp
		auto temp_variable = IR::Variable::create_variable(mem.getSize());

		// Temp = deref(expr)
		std::shared_ptr<IR::Expression> expr = it->second;
		std::shared_ptr<IR::Expression> deref = std::make_shared<IR::Dereference>(expr, (IR::ir_segment)segment_register.getId(), (IR::ir_size)mem.getSize());
		context->m_statements.push_back(std::make_shared<IR::Assign>(temp_variable, deref));
		context->m_expression_map[symvar->getId()] = temp_variable;
		symvar->setAlias(temp_variable->get_name());
	}
	else
	{
		std::cout << "unknown read addr: " << std::hex << address << " " << lea_ast << std::endl;
	}
}
std::vector<std::shared_ptr<IR::Expression>> VMProtectAnalyzer::save_expressions(triton::arch::Instruction &triton_instruction, VMPHandlerContext *context)
{
	std::vector<std::shared_ptr<IR::Expression>> expressions;
	if (!is_unary_operation(triton_instruction) && !is_binary_operation(triton_instruction))
	{
		return expressions;
	}

	bool do_it = false;
	for (const auto& operand : triton_instruction.operands)
	{
		if (operand.getType() == triton::arch::operand_e::OP_IMM)
		{
			expressions.push_back(std::make_shared<IR::Immediate>(
				operand.getConstImmediate().getValue()));
		}
		else if (operand.getType() == triton::arch::operand_e::OP_MEM)
		{
			const triton::arch::MemoryAccess& _mem = operand.getConstMemory();
			triton::engines::symbolic::SharedSymbolicVariable _symvar = get_symbolic_var(triton_api->processSimplification(triton_api->getMemoryAst(_mem), true));
			if (_symvar)
			{
				// load symbolic
				auto _it = context->m_expression_map.find(_symvar->getId());
				if (_it != context->m_expression_map.end())
				{
					expressions.push_back(_it->second);
					do_it = true;
					continue;
				}
			}

			// otherwise immediate
			expressions.push_back(std::make_shared<IR::Immediate>(
				triton_api->getConcreteMemoryValue(_mem).convert_to<triton::uint64>()));
		}
		else if (operand.getType() == triton::arch::operand_e::OP_REG)
		{
			const triton::arch::Register& _reg = operand.getConstRegister();
			triton::engines::symbolic::SharedSymbolicVariable _symvar = get_symbolic_var(triton_api->processSimplification(triton_api->getRegisterAst(_reg), true));
			if (_symvar)
			{
				if (_symvar->getId() == context->symvar_stack->getId())
				{
					// nope...
					do_it = false;
					break;
				}

				// load symbolic
				auto _it = context->m_expression_map.find(_symvar->getId());
				if (_it != context->m_expression_map.end())
				{
					expressions.push_back(_it->second);
					do_it = true;
					continue;
				}
			}

			// otherwise immediate
			expressions.push_back(std::make_shared<IR::Immediate>(
				triton_api->getConcreteRegisterValue(_reg).convert_to<triton::uint64>()));
		}
		else
			throw std::runtime_error("invalid operand type");
	}
	if (!do_it)
		expressions.clear();
	return expressions;
}
void VMProtectAnalyzer::check_arity_operation(triton::arch::Instruction &triton_instruction, const std::vector<std::shared_ptr<IR::Expression>> &operands_expressions, VMPHandlerContext *context)
{
	if (triton_instruction.getType() == triton::arch::x86::ID_INS_CPUID)
	{
		std::shared_ptr<IR::Cpuid> statement = std::make_shared<IR::Cpuid>();
		context->m_statements.push_back(statement);

		auto symvar_eax = this->triton_api->symbolizeRegister(triton_api->registers.x86_eax);
		auto symvar_ebx = this->triton_api->symbolizeRegister(triton_api->registers.x86_ebx);
		auto symvar_ecx = this->triton_api->symbolizeRegister(triton_api->registers.x86_ecx);
		auto symvar_edx = this->triton_api->symbolizeRegister(triton_api->registers.x86_edx);
		context->m_expression_map[symvar_eax->getId()] = std::make_shared<IR::Register>(triton_api->registers.x86_eax);
		context->m_expression_map[symvar_ebx->getId()] = std::make_shared<IR::Register>(triton_api->registers.x86_ebx);
		context->m_expression_map[symvar_ecx->getId()] = std::make_shared<IR::Register>(triton_api->registers.x86_ecx);
		context->m_expression_map[symvar_edx->getId()] = std::make_shared<IR::Register>(triton_api->registers.x86_edx);
		symvar_eax->setAlias("cpuid_eax");
		symvar_ebx->setAlias("cpuid_ebx");
		symvar_ecx->setAlias("cpuid_ecx");
		symvar_edx->setAlias("cpuid_edx");
		return;
	}
	else if (triton_instruction.getType() == triton::arch::x86::ID_INS_RDTSC)
	{
		std::shared_ptr<IR::Statement> statement = std::make_shared<IR::Rdtsc>();
		context->m_statements.push_back(statement);

		auto symvar_eax = this->triton_api->symbolizeRegister(triton_api->registers.x86_eax);
		auto symvar_edx = this->triton_api->symbolizeRegister(triton_api->registers.x86_edx);
		context->m_expression_map[symvar_eax->getId()] = std::make_shared<IR::Register>(triton_api->registers.x86_eax);
		context->m_expression_map[symvar_edx->getId()] = std::make_shared<IR::Register>(triton_api->registers.x86_edx);
		symvar_eax->setAlias("rdtsc_eax");
		symvar_edx->setAlias("rdtsc_edx");
		return;
	}

	bool unary = is_unary_operation(triton_instruction) && operands_expressions.size() == 1;
	bool binary = is_binary_operation(triton_instruction) && operands_expressions.size() == 2;
	if (!unary && !binary)
		return;

	// symbolize left operand
	triton::engines::symbolic::SharedSymbolicVariable symvar;
	const auto &operand0 = triton_instruction.operands[0];
	if (operand0.getType() == triton::arch::operand_e::OP_REG)
	{
		const triton::arch::Register& _reg = operand0.getConstRegister();
		triton_api->concretizeRegister(_reg);
		symvar = triton_api->symbolizeRegister(_reg);
	}
	else if (operand0.getType() == triton::arch::operand_e::OP_MEM)
	{
		const triton::arch::MemoryAccess& _mem = operand0.getConstMemory();
		triton_api->concretizeMemory(_mem);
		symvar = triton_api->symbolizeMemory(_mem);
	}
	else
	{
		throw std::runtime_error("invalid operand type");
	}


	std::shared_ptr<IR::Variable> temp_variable = IR::Variable::create_variable(operand0.getSize());
	std::shared_ptr<IR::Expression> expr;
	if (unary)
	{
		// unary
		auto op0_expression = operands_expressions[0];
		switch (triton_instruction.getType())
		{
			case triton::arch::x86::ID_INS_INC:
			{
				expr = std::make_shared<IR::Inc>(op0_expression);
				break;
			}
			case triton::arch::x86::ID_INS_DEC:
			{
				expr = std::make_shared<IR::Dec>(op0_expression);
				break;
			}
			case triton::arch::x86::ID_INS_NEG:
			{
				expr = std::make_shared<IR::Neg>(op0_expression);
				break;
			}
			case triton::arch::x86::ID_INS_NOT:
			{
				expr = std::make_shared<IR::Not>(op0_expression);
				break;
			}
			default:
			{
				throw std::runtime_error("unknown unary operation");
			}
		}
	}
	else
	{
		// binary
		auto op0_expression = operands_expressions[0];
		auto op1_expression = operands_expressions[1];
		switch (triton_instruction.getType())
		{
			case triton::arch::x86::ID_INS_ADD:
			{
				expr = std::make_shared<IR::Add>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_SUB:
			{
				expr = std::make_shared<IR::Sub>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_SHL:
			{
				expr = std::make_shared<IR::Shl>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_SHR:
			{
				expr = std::make_shared<IR::Shr>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_RCR:
			{
				expr = std::make_shared<IR::Rcr>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_RCL:
			{
				expr = std::make_shared<IR::Rcl>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_ROL:
			{
				expr = std::make_shared<IR::Rol>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_ROR:
			{
				expr = std::make_shared<IR::Ror>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_AND:
			{
				expr = std::make_shared<IR::And>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_OR:
			{
				expr = std::make_shared<IR::Or>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_XOR:
			{
				expr = std::make_shared<IR::Xor>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_CMP:
			{
				expr = std::make_shared<IR::Cmp>(op0_expression, op1_expression);
				break;
			}
			case triton::arch::x86::ID_INS_TEST:
			{
				expr = std::make_shared<IR::Test>(op0_expression, op1_expression);
				break;
			}
			default:
			{
				throw std::runtime_error("unknown binary operation");
			}
		}
	}
	context->m_statements.push_back(std::make_shared<IR::Assign>(temp_variable, expr));
	context->m_expression_map[symvar->getId()] = temp_variable;
	symvar->setAlias(temp_variable->get_name());
}
void VMProtectAnalyzer::check_store_access(triton::arch::Instruction &triton_instruction, VMPHandlerContext *context)
{
	const auto& storeAccess = triton_instruction.getStoreAccess();
	for (const std::pair<triton::arch::MemoryAccess, triton::ast::SharedAbstractNode>& pair : storeAccess)
	{
		const triton::arch::MemoryAccess &mem = pair.first;
		//const triton::ast::SharedAbstractNode &mem_ast = pair.second;
		const triton::ast::SharedAbstractNode &mem_ast = triton_api->getMemoryAst(mem);
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

		if (this->is_scratch_area_address(lea_ast, context))
		{
			const triton::uint64 scratch_offset = lea_ast->evaluate().convert_to<triton::uint64>() - context->x86_sp;
			std::cout << "modifies [x86_sp + 0x" << std::hex << scratch_offset << "]" << std::endl;

			// create IR (VM_REG = mem_ast)
			auto source_node = triton_api->processSimplification(mem_ast, true);
			triton::engines::symbolic::SharedSymbolicVariable symvar = get_symbolic_var(source_node);
			if (symvar)
			{
				auto ir_imm = std::make_shared<IR::Immediate>(scratch_offset);
				std::shared_ptr<IR::Expression> v1 = std::make_shared<IR::Memory>(ir_imm, IR::ir_segment_scratch, (IR::ir_size)mem.getSize());
				auto it = context->m_expression_map.find(symvar->getId());
				if (it != context->m_expression_map.end())
				{
					std::shared_ptr<IR::Expression> expr = it->second;
					context->m_statements.push_back(std::make_shared<IR::Assign>(v1, expr));
				}
				else if (symvar->getId() == context->symvar_stack->getId())
				{
					std::shared_ptr<IR::Expression> expr = std::make_shared<IR::Register>(this->get_sp_register());
					context->m_statements.push_back(std::make_shared<IR::Assign>(v1, expr));
				}
				else if (symvar->getAlias().find("eflags") != std::string::npos)
				{
					std::shared_ptr<IR::Expression> expr = std::make_shared<IR::Register>(triton_api->registers.x86_eflags);
					context->m_statements.push_back(std::make_shared<IR::Assign>(v1, expr));
				}
				else
				{
					printf("%s\n", symvar->getAlias().c_str());
					throw std::runtime_error("what do you mean 2");
				}
			}
			else
			{
				std::cout << "source_node: " << source_node << std::endl;
			}
		}
		else if (this->is_stack_address(lea_ast, context))
		{
			// stores to stack
			const triton::uint64 stack_offset = address - context->stack;

			std::shared_ptr<IR::Expression> expr;
			auto get_expr = [this, context](std::shared_ptr<triton::API> ctx, triton::ast::SharedAbstractNode mem_ast)
			{
				std::shared_ptr<IR::Expression> expr;
				auto simplified_source_node = ctx->processSimplification(mem_ast, true);
				if (!simplified_source_node->isSymbolized())
				{
					// expression is immediate
					expr = std::make_shared<IR::Immediate>(simplified_source_node->evaluate().convert_to<triton::uint64>());
				}
				else
				{
					triton::engines::symbolic::SharedSymbolicVariable _symvar = get_symbolic_var(simplified_source_node);
					if (_symvar)
					{
						auto _it = context->m_expression_map.find(_symvar->getId());
						if (_it == context->m_expression_map.end())
						{
							throw std::runtime_error("what do you mean...");
						}
						expr = _it->second;
					}
				}
				return expr;
			};
			expr = get_expr(this->triton_api, mem_ast);
			if (!expr && mem.getSize() == 2)
			{
				const triton::arch::MemoryAccess _mem(mem.getAddress(), 1);
				expr = get_expr(this->triton_api, triton_api->getMemoryAst(_mem));
			}

			// should be push
			if (expr)
			{
				auto ir_stack = context->m_expression_map[context->symvar_stack->getId()];
				auto ir_stack_address = std::make_shared<IR::Add>(ir_stack, std::make_shared<IR::Immediate>(stack_offset));

				std::shared_ptr<IR::Expression> v1 = std::make_shared<IR::Memory>(
					ir_stack_address, (IR::ir_segment)mem.getConstSegmentRegister().getId(), (IR::ir_size)mem.getSize());
				context->m_statements.push_back(std::make_shared<IR::Assign>(v1, expr));
			}
			else
			{
				std::cout << "unknown store addr: " << std::hex << address << ", lea_ast: " << lea_ast 
					<< ", simplified_source_node: " << triton_api->processSimplification(mem_ast, true) << std::endl;
			}
		}
		else
		{
			// create IR (VM_REG = mem_ast)
			// get right expression
			std::shared_ptr<IR::Expression> expr;
			auto simplified_source_node = triton_api->processSimplification(mem_ast, true);
			if (!simplified_source_node->isSymbolized())
			{
				// expression is immediate
				expr = std::make_shared<IR::Immediate>(simplified_source_node->evaluate().convert_to<triton::uint64>());
			}
			else
			{
				triton::engines::symbolic::SharedSymbolicVariable symvar1 = get_symbolic_var(simplified_source_node);
				if (symvar1)
				{
					auto _it = context->m_expression_map.find(symvar1->getId());
					if (_it == context->m_expression_map.end())
					{
						throw std::runtime_error("what do you mean...");
					}
					expr = _it->second;
				}
			}

			triton::engines::symbolic::SharedSymbolicVariable symvar0 = get_symbolic_var(lea_ast);
			if (symvar0 && expr)
			{
				auto it0 = context->m_expression_map.find(symvar0->getId());
				if (it0 != context->m_expression_map.end())
				{
					std::shared_ptr<IR::Expression> v1 = std::make_shared<IR::Memory>(it0->second, 
						(IR::ir_segment)mem.getConstSegmentRegister().getId(), (IR::ir_size)mem.getSize());
					context->m_statements.push_back(std::make_shared<IR::Assign>(v1, expr));
				}
				else
				{
					throw std::runtime_error("what do you mean 2");
				}
			}
			else
			{
				std::cout << "unknown store addr: " << std::hex << address << ", lea_ast: " << lea_ast << ", simplified_source_node: " << simplified_source_node << std::endl;
			}
		}
	}
}

void VMProtectAnalyzer::analyze_vm_handler(AbstractStream& stream, unsigned long long handler_address)
{
	this->m_scratch_size = 0xC0; // test

	// reset
	triton_api->concretizeAllMemory();
	triton_api->concretizeAllRegister();

	// allocate scratch area
	const triton::arch::Register bp_register = this->get_bp_register();
	const triton::arch::Register sp_register = this->get_sp_register();
	const triton::arch::Register si_register = this->is_x64() ? triton_api->registers.x86_rsi : triton_api->registers.x86_esi;
	const triton::arch::Register ip_register = this->get_ip_register();

	constexpr unsigned long c_stack_base = 0x1000;
	triton_api->setConcreteRegisterValue(bp_register, c_stack_base);
	triton_api->setConcreteRegisterValue(sp_register, c_stack_base - this->m_scratch_size);

	unsigned int arg0 = c_stack_base;
	triton_api->setConcreteMemoryAreaValue(c_stack_base, (const triton::uint8*)&arg0, 4);

	// ebp = VM's "stack" pointer
	triton::engines::symbolic::SharedSymbolicVariable symvar_stack = triton_api->symbolizeRegister(bp_register);

	// esi = pointer to VM bytecode
	triton::engines::symbolic::SharedSymbolicVariable symvar_bytecode = triton_api->symbolizeRegister(si_register);

	// x86 stack pointer
	triton::engines::symbolic::SharedSymbolicVariable symvar_x86_sp = triton_api->symbolizeRegister(sp_register);

	symvar_stack->setAlias("stack");
	symvar_bytecode->setAlias("bytecode");
	symvar_x86_sp->setAlias("sp");

	// yo...
	VMPHandlerContext context;
	context.scratch_area_size = this->is_x64() ? 0x140 : 0x60;
	context.address = handler_address;
	context.stack = triton_api->getConcreteRegisterValue(bp_register).convert_to<triton::uint64>();
	context.bytecode = triton_api->getConcreteRegisterValue(si_register).convert_to<triton::uint64>();
	context.x86_sp = triton_api->getConcreteRegisterValue(sp_register).convert_to<triton::uint64>();
	context.symvar_stack = symvar_stack;
	context.symvar_bytecode = symvar_bytecode;
	context.symvar_x86_sp = symvar_x86_sp;

	// expr
	std::shared_ptr<IR::Expression> ir_stack = std::make_shared<IR::Variable>("STACK", (IR::ir_size)sp_register.getSize());
	context.m_expression_map.insert(std::make_pair(symvar_stack->getId(), ir_stack));
	//

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

	triton::uint64 expected_return_address = 0;
	for (auto it = basic_block->instructions.begin(); it != basic_block->instructions.end();)
	{
		const std::shared_ptr<x86_instruction> xed_instruction = *it;
		const std::vector<xed_uint8_t> bytes = xed_instruction->get_bytes();
		bool mem_read = false;
		for (xed_uint_t j = 0, memops = xed_instruction->get_number_of_memory_operands(); j < memops; j++)
		{
			if (xed_instruction->is_mem_read(j))
			{
				mem_read = true;
				break;
			}
		}

		// do stuff with triton
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], (triton::uint32)bytes.size());
		triton_instruction.setAddress(xed_instruction->get_addr());

		// fix ip
		triton_api->setConcreteRegisterValue(ip_register, xed_instruction->get_addr());

		// DIS
		triton_api->disassembly(triton_instruction);
		if (mem_read 
			&& (triton_instruction.getType() != triton::arch::x86::ID_INS_POP
				&& triton_instruction.getType() != triton::arch::x86::ID_INS_POPFD)) // no need but makes life easier
		{
			for (auto& operand : triton_instruction.operands)
			{
				if (operand.getType() == triton::arch::OP_MEM)
				{
					triton_api->getSymbolicEngine()->initLeaAst(operand.getMemory());
					this->symbolize_memory(operand.getConstMemory(), &context);
				}
			}
		}
		std::vector<std::shared_ptr<IR::Expression>> operands_expressions = this->save_expressions(triton_instruction, &context);

		triton_api->processing(triton_instruction);

		// lol
		this->check_arity_operation(triton_instruction, operands_expressions, &context);

		// check store
		this->check_store_access(triton_instruction, &context);

		if (xed_instruction->get_category() != XED_CATEGORY_UNCOND_BR
			|| xed_instruction->get_branch_displacement_width() == 0)
		{
			std::cout << "\t" << triton_instruction << std::endl;
		}

		// symbolize eflags
		static std::string ins_name;
		for (const auto& pair : xed_instruction->get_written_registers())
		{
			if (pair.is_flag())
			{
				ins_name = xed_instruction->get_name();
				break;
			}
		}
		if (triton_instruction.getType() == triton::arch::x86::ID_INS_PUSHFD)
		{
			triton::arch::MemoryAccess _mem(this->get_sp(), 4);
			triton::engines::symbolic::SharedSymbolicVariable _symvar = triton_api->symbolizeMemory(_mem);
			_symvar->setAlias(ins_name + "_eflags");

			auto ir_eflags = std::make_shared<IR::Register>(triton_api->registers.x86_eflags);
			context.m_expression_map.insert(std::make_pair(_symvar->getId(), ir_eflags));
		}
		else if (triton_instruction.getType() == triton::arch::x86::ID_INS_PUSHFQ)
		{
			triton::arch::MemoryAccess _mem(this->get_sp(), 8);
			triton::engines::symbolic::SharedSymbolicVariable _symvar = triton_api->symbolizeMemory(_mem);
			_symvar->setAlias(ins_name + "_eflags");

			auto ir_eflags = std::make_shared<IR::Register>(triton_api->registers.x86_eflags);
			context.m_expression_map.insert(std::make_pair(_symvar->getId(), ir_eflags));
		}

		if (++it != basic_block->instructions.end())
		{
			// loop until it reaches end
			continue;
		}

		if (triton_instruction.getType() == triton::arch::x86::ID_INS_CALL)
		{
			expected_return_address = xed_instruction->get_addr() + 5;
		}
		else if (triton_instruction.getType() == triton::arch::x86::ID_INS_RET)
		{
			if (expected_return_address != 0 && this->get_ip() == expected_return_address)
			{
				basic_block = make_cfg(stream, expected_return_address);
				it = basic_block->instructions.begin();
			}
		}

		while (it == basic_block->instructions.end())
		{
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
				goto l_categorize_handler;
			}
			it = basic_block->instructions.begin();
		}
	}

l_categorize_handler:
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
void VMProtectAnalyzer::categorize_handler(VMPHandlerContext *context)
{
	const triton::arch::Register rb_register = this->is_x64() ? triton_api->registers.x86_rbp : triton_api->registers.x86_ebp;
	const triton::arch::Register sp_register = this->is_x64() ? triton_api->registers.x86_rsp : triton_api->registers.x86_esp;
	const triton::arch::Register si_register = this->is_x64() ? triton_api->registers.x86_rsi : triton_api->registers.x86_esi;
	const triton::uint64 bytecode = triton_api->getConcreteRegisterValue(si_register).convert_to<triton::uint64>();
	const triton::uint64 sp = this->get_sp();
	const triton::uint64 stack = this->get_bp();

	std::cout << "handlers outputs:" << std::endl;
	printf("\tbytecode: 0x%016llX -> 0x%016llX\n", context->bytecode, bytecode);
	printf("\tsp: 0x%016llX -> 0x%016llX\n", context->x86_sp, sp);
	printf("\tstack: 0x%016llX -> 0x%016llX\n", context->stack, stack);

	bool handler_detected = false;

	// check if push
	triton::sint64 stack_offset = stack - context->stack;	// needs to be signed
	if (stack_offset)
	{
		// just for testing purpose
		std::shared_ptr<IR::Expression> ir_stack = context->m_expression_map[context->symvar_stack->getId()];
		std::shared_ptr<IR::Expression> _add = std::make_shared<IR::Add>(ir_stack, std::make_shared<IR::Immediate>(stack_offset));
		context->m_statements.push_back(std::make_shared<IR::Assign>(ir_stack, _add));
	}

	if (0)
	{
		// convert to push/pop

		// constant propagation
		std::map<std::shared_ptr<IR::Expression>, std::shared_ptr<IR::Expression>> assigned;
		for (auto it = context->m_statements.begin(); it != context->m_statements.end(); ++it)
		{
			const std::shared_ptr<IR::Statement> &expr = *it;
			if (expr->get_type() == IR::ir_statement_assign)
			{
				std::shared_ptr<IR::Assign> _assign = std::dynamic_pointer_cast<IR::Assign>(expr);
				const auto rvalue = _assign->get_right();
				if (rvalue->get_type() == IR::expr_unary_operation)
				{
					std::shared_ptr<IR::UnaryOperation> unary_expr = std::dynamic_pointer_cast<IR::UnaryOperation>(rvalue);
					auto assigned_it = assigned.find(unary_expr->get_expression());
					if (assigned_it != assigned.end())
					{
						unary_expr->set_expression(assigned_it->second);
					}
				}
				else if (rvalue->get_type() == IR::expr_binary_operation)
				{
					std::shared_ptr<IR::BinaryOperation> binary_op = std::dynamic_pointer_cast<IR::BinaryOperation>(rvalue);
					auto assigned_it = assigned.find(binary_op->get_expression0());
					if (assigned_it != assigned.end())
					{
						binary_op->set_expression0(assigned_it->second);
					}

					assigned_it = assigned.find(binary_op->get_expression1());
					if (assigned_it != assigned.end())
					{
						binary_op->set_expression1(assigned_it->second);
					}
				}
				else if (rvalue->get_type() == IR::expr_variable)
				{
					auto assigned_it = assigned.find(rvalue);
					if (assigned_it != assigned.end()
						&& assigned.find(assigned_it->second) == assigned.end())
					{
						_assign->set_right(assigned_it->second);
					}
				}
				else if (rvalue->get_type() == IR::expr_deref)
				{
					std::shared_ptr<IR::Dereference> deref_expr = std::dynamic_pointer_cast<IR::Dereference>(rvalue);
					auto assigned_it = assigned.find(deref_expr->get_expression());
					if (assigned_it != assigned.end())
					{
						deref_expr->set_expression(assigned_it->second);
					}
				}

				assigned[_assign->get_left()] = _assign->get_right();
			}
		}

		// simplify
		for (int i = 0; i < 10; i++)
		{
			for (auto it = context->m_statements.begin(); it != context->m_statements.end(); ++it)
			{
				const std::shared_ptr<IR::Statement> statement = *it;
				switch (statement->get_type())
				{
					case IR::ir_statement_assign:
					{
						std::shared_ptr<IR::Assign> _assign = std::dynamic_pointer_cast<IR::Assign>(statement);
						std::shared_ptr<IR::Expression> simplified_rvalue = simplify_expression(_assign->get_right());
						_assign->set_right(simplified_rvalue);
						*it = _assign;
						break;
					}
					case IR::ir_statement_push:
					{
						std::shared_ptr<IR::Push> _statement = std::dynamic_pointer_cast<IR::Push>(statement);
						std::shared_ptr<IR::Expression> simplified_rvalue = simplify_expression(_statement->get_expression());
						_statement->set_expression(simplified_rvalue);
						*it = _statement;
						break;
					}
					case IR::ir_statement_pop:
					{
						std::shared_ptr<IR::Pop> _statement = std::dynamic_pointer_cast<IR::Pop>(statement);
						std::shared_ptr<IR::Expression> simplified_rvalue = simplify_expression(_statement->get_expression());
						_statement->set_expression(simplified_rvalue);
						*it = _statement;
						break;
					}
					default:
						break;
				}
			}
		}
	}

	for (const std::shared_ptr<IR::Statement> &expr : context->m_statements)
	{
		std::stringstream ss;
		ss << "\t" << expr;
		output_strings.push_back(ss.str());
	}

	if (!handler_detected)
	{
		//this->print_output();
		//output_strings.clear();
		//getchar();
	}
}