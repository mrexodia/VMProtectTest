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

	const triton::arch::Register& get_source_register(const triton::arch::Instruction &triton_instruction) const;
	const triton::arch::Register& get_dest_register(const triton::arch::Instruction &triton_instruction) const;

	// lea ast
	bool is_bytecode_address(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context);
	bool is_stack_address(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context);
	bool is_scratch_area_address(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context);
	bool is_fetch_arguments(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context);

	//
	bool is_push(VMPHandlerContext *context);
	bool is_pop(VMPHandlerContext *context);

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