#pragma once

class VirtualMachine
{
public:
	VirtualMachine();
	~VirtualMachine();

	void start_virtual_machine(unsigned long long pos);
	void categorize_handler(unsigned long long pos);

private:

};