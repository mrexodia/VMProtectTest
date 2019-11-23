#include "pch.h"

#include "VirtualMachine.hpp"
#include "AbstractStream.hpp"

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

				[[fallthrough]];
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

// VirtualMachine
VirtualMachine::VirtualMachine()
{
}
VirtualMachine::~VirtualMachine()
{
}

void VirtualMachine::start_virtual_machine(unsigned long long pos)
{

}
void VirtualMachine::categorize_handler()
{
	/*
		00000000004892AF movzx eax, byte ptr [esi]
		00000000004892B8 lea esi, ptr [esi+0x1]

		00000000004892BE xor al, bl
		00000000004892C3 sub al, 0x3a
		00000000004892CE ror al, 0x1
		00000000004892D1 neg al
		00000000004892DF not al
		00000000004892EA xor bl, al

		00000000004892EF mov ecx, dword ptr [ebp]
		000000000041A261 lea ebp, ptr [ebp+0x4]
		000000000041A267 mov dword ptr [esp+eax*1], ecx

		000000000041A26A mov eax, dword ptr [esi]
		000000000041A26C add esi, 0x4
		000000000041A273 xor eax, ebx
		000000000041A275 ror eax, 0x1
		000000000041A27E xor eax, 0x4acb3db9
		000000000045F79C sub eax, 0x458c0140
		0000000000496B0F rol eax, 0x1
		0000000000496B13 xor ebx, eax
		0000000000474C45 add edi, eax
		0000000000437E65 jmp edi
	*/
}