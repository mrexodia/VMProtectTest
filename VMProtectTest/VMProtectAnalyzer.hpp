#pragma once

#include "AbstractStream.hpp"

struct BasicBlock;

struct VMPHandlerContext
{
	// before start
	triton::uint64 scratch_area_size;
	triton::uint64 address;
	triton::uint64 stack, bytecode, x86_sp;
	triton::engines::symbolic::SharedSymbolicVariable symvar_stack, symvar_bytecode, symvar_x86_sp;

	// load
	std::map<triton::usize, triton::engines::symbolic::SharedSymbolicVariable> bytecodes, vmvars, arguments, fetched;

	// <runtime_address, <dest, source>>
	std::map<triton::uint64, std::pair<triton::ast::SharedAbstractNode, triton::ast::SharedAbstractNode>> destinations;


public:
	// explore and collect variable_node
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
	//

	bool is_bytecode_address(triton::uint64 address) const
	{
		// i assume max length is 16
		return (this->bytecode - 16) <= address && address < (this->bytecode + 16);
	}
	bool is_scratch_area_address(triton::uint64 address) const
	{
		// size is hardcoded for now (can see in any push handler perhaps)
		return x86_sp <= address && address < (x86_sp + this->scratch_area_size);
	}
	bool is_arguments_address(triton::uint64 address) const
	{
		// dont know about bottom, 3args maximum?
		return stack <= address && address <= (stack + 12);
	}
	bool is_result_address(triton::uint64 address) const
	{
		// dont know about bottom
		return (x86_sp + this->scratch_area_size) <= address && address < stack;
	}

	// check by ast
	bool is_bytecode_address(const triton::ast::SharedAbstractNode &leaAst)
	{
		// bvadd(p-code-1, const)
		const auto symvars = collect_symvars(leaAst);
		if (symvars.empty())
			return false;

		for (auto it = symvars.begin(); it != symvars.end(); ++it)
		{
			const triton::ast::SharedAbstractNode &node = *it;
			const triton::engines::symbolic::SharedSymbolicVariable &symvar = std::dynamic_pointer_cast<triton::ast::VariableNode>(node)->getSymbolicVariable();
			if (symvar->getId() != this->symvar_bytecode->getId())
				return false;
		}
		return true;
	}
	bool is_stack_address(const triton::ast::SharedAbstractNode &leaAst)
	{
		// bvadd(stack, const) or stack
		const auto symvars = collect_symvars(leaAst);
		if (symvars.empty())
			return false;

		for (auto it = symvars.begin(); it != symvars.end(); ++it)
		{
			const triton::ast::SharedAbstractNode &node = *it;
			const triton::engines::symbolic::SharedSymbolicVariable &symvar = std::dynamic_pointer_cast<triton::ast::VariableNode>(node)->getSymbolicVariable();
			if (symvar != this->symvar_stack)
				return false;
		}
		return true;
	}
	bool is_scratch_area(const triton::ast::SharedAbstractNode &leaAst)
	{
		// bvadd(DECRYPT(p-code-1), x86_sp) -> scrach area
		return this->is_scratch_area_address(leaAst->evaluate().convert_to<triton::uint64>());
	}
	bool is_fetch_arguments(const triton::ast::SharedAbstractNode &leaAst)
	{
		if (leaAst->getType() != triton::ast::VARIABLE_NODE)
			return false;

		const triton::engines::symbolic::SharedSymbolicVariable &symvar = std::dynamic_pointer_cast<triton::ast::VariableNode>(leaAst)->getSymbolicVariable();
		return this->arguments.find(symvar->getId()) != this->arguments.end();
	}

	// 
	void insert_scratch(const triton::ast::SharedAbstractNode &n1, const triton::ast::SharedAbstractNode &n2)
	{
		const triton::uint64 runtime_address = n1->evaluate().convert_to<triton::uint64>();
		this->destinations[runtime_address] = std::make_pair(n1, n2);
	}
};

class VMProtectAnalyzer
{
public:
	VMProtectAnalyzer(triton::arch::architecture_e arch = triton::arch::ARCH_X86);
	~VMProtectAnalyzer();

	//
	bool is_x64() const;

	triton::uint64 get_bp() const;
	triton::uint64 get_sp() const;
	triton::uint64 get_ip() const;

	// helpers
	void symbolize_registers();

	const triton::arch::Register& get_source_register(const triton::arch::Instruction &triton_instruction) const
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
	const triton::arch::Register& get_dest_register(const triton::arch::Instruction &triton_instruction) const
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

		// mov REG,MEM
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

	// work-sub
	void loadAccess(triton::arch::Instruction &triton_instruction, VMPHandlerContext *context);
	void storeAccess(triton::arch::Instruction &triton_instruction, VMPHandlerContext *context);
	void categorize_handler(VMPHandlerContext *context);

	// work
	void load(AbstractStream& stream,
		unsigned long long module_base, unsigned long long vmp0_address, unsigned long long vmp0_size);
	void analyze_vm_enter(AbstractStream& stream, unsigned long long address);
	void analyze_vm_handler(AbstractStream& stream, unsigned long long handler_address);
	void analyze_vm_exit(unsigned long long handler_address);

	void print_output()
	{
		for (const std::string &s : output_strings)
		{
			std::cout << s << std::endl;
		}
	}

private:
	std::shared_ptr<triton::API> triton_api;
	std::list<std::string> output_strings;

	// after vm_enter
	unsigned long long m_scratch_size;

	// runtimeshit
	int m_temp;
	std::map<triton::uint64, std::shared_ptr<BasicBlock>> m_handlers;
};