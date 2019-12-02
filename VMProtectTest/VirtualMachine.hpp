#pragma once

class VirtualMachine
{
	struct Context
	{
		triton::uint64 address;
		triton::arch::Register _register;
		bool is_register;
	};

public:
	VirtualMachine();
	~VirtualMachine();

	void start_virtual_machine(unsigned long long pos);
	void categorize_handler(unsigned long long pos);

private:
	// themida: sp == stack
	Context m_bytecode, m_sp, m_stack;
};