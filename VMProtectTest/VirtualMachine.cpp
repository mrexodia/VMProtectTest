#include "pch.h"

#include "VirtualMachine.hpp"
#include "AbstractStream.hpp"

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
void VirtualMachine::categorize_handler(unsigned long long pos)
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