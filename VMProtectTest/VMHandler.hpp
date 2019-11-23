#pragma once

class x86_instruction;

enum
{
	vmprotect_handler_popd,
};

class VMHandler
{
public:
	VMHandler();
	~VMHandler();

	unsigned long long compute_next_handler_address(void *context);

private:
	std::list<std::shared_ptr<x86_instruction>> instrs;
};